"""gate.py — the destroy-and-rebuild gate's own decision logic.

Mocked at ONE seam: `kubectl()`. Everything above it is real. These tests are
about the decisions the gate makes given what a cluster reports — "is this node
healthy", "is this fingerprint different", "has etcd got the members it should" —
not about whether the code invokes the commands it invokes.

Every check is exercised in both directions. A verify that can only pass is how
a half-rolled DaemonSet got through (ADR-080).
"""

from __future__ import annotations

import json
import types

import pytest

import gate


def fake_kubectl(monkeypatch, mapping, default=None):
    def _k(args, timeout=60):
        for key, payload in mapping.items():
            if key in args:
                if isinstance(payload, str):
                    return types.SimpleNamespace(
                        returncode=0, stdout=payload, stderr=""
                    )
                if payload is None:
                    return types.SimpleNamespace(
                        returncode=1, stdout="", stderr="not found"
                    )
                return types.SimpleNamespace(
                    returncode=0, stdout=json.dumps(payload), stderr=""
                )
        if default is None:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="unmatched")
        return types.SimpleNamespace(
            returncode=0, stdout=json.dumps(default), stderr=""
        )

    monkeypatch.setattr(gate, "kubectl", _k)


# ------------------------------------------------------------------- fixtures


def node(name, ready="True", version="v1.36.3+k0s"):
    return {
        "metadata": {"name": name},
        "status": {
            "conditions": [{"type": "Ready", "status": ready}],
            "nodeInfo": {"kubeletVersion": version},
        },
    }


def pod(name, phase="Running", ready=True, ns="kube-system"):
    return {
        "metadata": {"name": name, "namespace": ns},
        "status": {"phase": phase, "containerStatuses": [{"ready": ready}]},
    }


def ds(name, desired, ready):
    return {
        "metadata": {"name": name},
        "status": {"desiredNumberScheduled": desired, "numberReady": ready},
    }


# ---------------------------------------------------------------- node health


def test_healthy_nodes_lists_only_ready_ones(monkeypatch):
    """Seam is provision.node_ready_states — which SSHes to the bootstrap node —
    NOT gate.kubectl. Mocking the wrong one makes this test take 10s and fail."""
    monkeypatch.setattr(
        gate.provision,
        "node_ready_states",
        lambda vm: {"a": True, "b": False, "c": True},
    )
    assert sorted(gate.healthy_nodes()) == ["a", "c"]


def test_healthy_nodes_empty_when_the_cluster_cannot_be_reached(monkeypatch):
    """Must not raise: the gate polls this while a cluster is still coming up."""
    monkeypatch.setattr(gate.provision, "node_ready_states", lambda vm: None)
    assert gate.healthy_nodes() == []


def test_node_kubelet_version_reads_the_reported_version(monkeypatch):
    monkeypatch.setattr(
        gate,
        "kubectl",
        lambda a, timeout=60: types.SimpleNamespace(
            returncode=0, stdout="v1.36.9+k0s\n", stderr=""
        ),
    )
    assert gate.node_kubelet_version("a") == "v1.36.9+k0s"


def test_node_kubelet_version_none_when_the_query_fails(monkeypatch):
    monkeypatch.setattr(
        gate,
        "kubectl",
        lambda a, timeout=60: types.SimpleNamespace(
            returncode=1, stdout="", stderr="x"
        ),
    )
    assert gate.node_kubelet_version("a") is None


# ------------------------------------------------------------- unhealthy pods


def test_unhealthy_pods_clean_when_everything_is_ready(monkeypatch):
    fake_kubectl(
        monkeypatch,
        {
            "get pods": {"items": [pod("a"), pod("b")]},
            "get daemonsets": {"items": [ds("ka", 2, 2)]},
        },
    )
    assert gate._unhealthy_pods() == []


def test_unhealthy_pods_flags_a_pod_that_is_running_but_not_ready(monkeypatch):
    fake_kubectl(
        monkeypatch,
        {
            "get pods": {"items": [pod("sick", ready=False)]},
            "get daemonsets": {"items": []},
        },
    )
    assert any("sick" in b for b in gate._unhealthy_pods())


def test_unhealthy_pods_flags_a_pending_pod(monkeypatch):
    fake_kubectl(
        monkeypatch,
        {
            "get pods": {"items": [pod("waiting", phase="Pending")]},
            "get daemonsets": {"items": []},
        },
    )
    assert any("waiting" in b for b in gate._unhealthy_pods())


def test_unhealthy_pods_ignores_completed_jobs(monkeypatch):
    fake_kubectl(
        monkeypatch,
        {
            "get pods": {"items": [pod("migrate", phase="Succeeded")]},
            "get daemonsets": {"items": []},
        },
    )
    assert gate._unhealthy_pods() == []


def test_unhealthy_pods_flags_a_daemonset_mid_rollout(monkeypatch):
    """THE ADR-080 regression: four ready pods with a fifth not yet created used
    to read as 'all system pods Running and ready'."""
    fake_kubectl(
        monkeypatch,
        {
            "get pods": {"items": [pod(f"ka-{i}") for i in range(4)]},
            "get daemonsets": {"items": [ds("konnectivity-agent", 5, 4)]},
        },
    )
    assert any("konnectivity-agent" in b for b in gate._unhealthy_pods())


def test_unhealthy_pods_returns_none_when_the_api_is_unreachable(monkeypatch):
    """None means keep polling; [] would mean healthy and would let a rebuild
    declare success against an unreachable API server."""
    monkeypatch.setattr(
        gate,
        "kubectl",
        lambda a, timeout=60: types.SimpleNamespace(
            returncode=1, stdout="", stderr="x"
        ),
    )
    assert gate._unhealthy_pods() is None


# ------------------------------------------------------------------ fingerprint

# ------------------------------------------------------------------- compare


def test_compare_reports_every_difference(capsys):
    a = {"one": 1, "two": 2}
    b = {"one": 9, "two": 9}
    assert gate.compare_fingerprints(a, b, "python", "ansible") is False
    out = capsys.readouterr().out
    assert "one" in out and "two" in out


def test_compare_agrees_on_identical_states():
    a = {"nodes": ["x"], "workloads": {"ka": 5}}
    assert gate.compare_fingerprints(a, dict(a), "python", "ansible") is True


def test_compare_flags_a_key_present_on_only_one_side(capsys):
    assert gate.compare_fingerprints({"only-a": 1}, {}, "python", "ansible") is False
    assert "only-a" in capsys.readouterr().out


def test_compare_recurses_into_nested_dicts(capsys):
    a = {"platform": {"flux": {"source": "oci://one"}}}
    b = {"platform": {"flux": {"source": "oci://two"}}}
    assert gate.compare_fingerprints(a, b, "python", "ansible") is False
    assert "platform.flux.source" in capsys.readouterr().out


# ----------------------------------------------------------------------- etcd


def test_etcd_members_parsed_from_the_member_list(monkeypatch):
    payload = json.dumps(
        {"members": {"a": "https://10.0.0.1:2380", "b": "https://10.0.0.2:2380"}}
    )
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=payload, stderr=""),
    )
    vm = types.SimpleNamespace(name="a", static_ip="10.0.0.1")
    assert gate._etcd_members(vm) == {"a", "b"}


def test_etcd_members_empty_when_the_query_fails(monkeypatch):
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="", stderr="down"),
    )
    vm = types.SimpleNamespace(name="a", static_ip="10.0.0.1")
    assert gate._etcd_members(vm) == set()


# ------------------------------------------------------------------ topology


def test_all_vms_covers_every_vm_in_the_fleet():
    pairs = gate.all_vms()
    assert len(pairs) == 5
    assert len({vm.name for _, vm in pairs}) == 5


def test_bootstrap_vm_is_unique_and_marked():
    vm = gate.bootstrap_vm()
    assert vm.bootstrap is True
