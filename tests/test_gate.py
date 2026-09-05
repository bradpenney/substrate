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


# --------------------------------------------------------------- ADR-097
# Pod distribution. Five rebuilds passed every health check while the whole
# platform sat on one hypervisor, because readiness was asserted and placement
# never was. These cover the pure functions; the IO wrapper is exercised by the
# rebuild itself, per the coverage policy.


def _pod(node, owner_kind=None, phase="Running"):
    """Minimal pod document shaped like the API server's, for these tests."""
    meta = {"name": "p"}
    if owner_kind:
        meta["ownerReferences"] = [{"kind": owner_kind}]
    return {"metadata": meta, "spec": {"nodeName": node}, "status": {"phase": phase}}


def test_daemonset_pods_do_not_count_toward_distribution():
    """DaemonSets run one per node by definition and hide real concentration.

    Counting them turned a measured 39-vs-3 split into a reassuring 66-vs-21,
    which is the exact arithmetic that made five rebuilds look balanced.
    """
    payload = {
        "items": [_pod("a", owner_kind="DaemonSet") for _ in range(10)]
        + [_pod("b", owner_kind="DaemonSet") for _ in range(10)]
        + [_pod("a") for _ in range(5)]
    }
    assert gate.schedulable_pods_by_node(payload) == {"a": 5}


def test_job_and_non_running_pods_are_excluded():
    """A Job pod is transient and a Pending pod has no node worth counting."""
    payload = {
        "items": [
            _pod("a", owner_kind="Job"),
            _pod("a", phase="Succeeded"),
            _pod("a", phase="Pending"),
            _pod("a"),
        ]
    }
    assert gate.schedulable_pods_by_node(payload) == {"a": 1}


def test_a_ready_node_running_nothing_is_a_failure():
    """The ADR-097 signature: the node joined after everything was placed."""
    failures = gate.concentration_failures(
        {"a": 5, "b": 5}, {"a": "h1", "b": "h1", "c": "h2"}, ["a", "b", "c"]
    )
    assert any("c is Ready but runs no scheduled pods" in f for f in failures)


def test_one_hypervisor_holding_almost_everything_is_a_failure():
    """41 of 43 on one host passed every other check in the real incident."""
    counts = {"a": 20, "b": 21, "c": 2}
    node_hv = {"a": "server2", "b": "server2", "c": "server1"}
    failures = gate.concentration_failures(counts, node_hv, ["a", "b", "c"])
    assert any("server2 holds 41/43" in f for f in failures)


def test_an_evenly_spread_fleet_passes():
    """The check must not fire on the state it is meant to protect."""
    counts = {"a": 10, "b": 8, "c": 12, "d": 11}
    node_hv = {"a": "server1", "b": "server1", "c": "server2", "d": "server2"}
    assert gate.concentration_failures(counts, node_hv, ["a", "b", "c", "d"]) == []


def test_a_pod_on_an_unknown_node_is_reported_not_guessed():
    """Attributing it to a guessed hypervisor would hide the finding."""
    failures = gate.concentration_failures(
        {"a": 5, "mystery": 5}, {"a": "server1"}, ["a"]
    )
    assert any("unknown node 'mystery'" in f for f in failures)


def test_an_empty_cluster_fails_rather_than_dividing_by_zero():
    """No pods at all is a failure, not a vacuously perfect spread."""
    failures = gate.concentration_failures({}, {"a": "server1"}, [])
    assert failures == ["no scheduled pods found at all"]


def test_nodes_map_to_hypervisors_from_config_not_name_prefixes():
    """A renamed VM must not be silently attributed to the wrong host."""
    mapping = gate.node_to_hypervisor()
    assert mapping
    for host, vm in gate.all_vms():
        assert mapping[vm.name] == host.name


def test_a_failure_prone_host_may_not_hold_the_majority():
    """The state a naive remediation produced: 74% onto the weaker failure domain.

    A symmetric 80% cap passes this. It is still the wrong shape — server2's
    4.5 GiB cannot absorb what server1 holds when server1 goes down, which is
    the same reasoning that keeps the etcd majority off it (ADR-046).
    """
    counts = {"s1-vm1": 18, "s1-vm2": 13, "s2-vm1": 4, "s2-vm2": 2, "s2-vm3": 5}
    node_hv = {
        "s1-vm1": "server1",
        "s1-vm2": "server1",
        "s2-vm1": "server2",
        "s2-vm2": "server2",
        "s2-vm3": "server2",
    }
    nodes = sorted(node_hv)
    assert gate.concentration_failures(counts, node_hv, nodes) == []
    failures = gate.concentration_failures(counts, node_hv, nodes, {"server1"})
    assert any("server1 holds 31/42" in f and "limit 50%" in f for f in failures)
    assert any("may not come back unattended" in f for f in failures)


def test_a_dedicated_host_may_hold_the_majority():
    """60% on the always-on host is the DESIGNED state, not a finding."""
    counts = {"a": 4, "b": 6}
    node_hv = {"a": "server1", "b": "server2"}
    failures = gate.concentration_failures(counts, node_hv, ["a", "b"], {"server1"})
    assert failures == []


def test_the_original_pile_still_fails_under_the_asymmetric_rule():
    """93% on the dedicated host must not become acceptable by adding the flag."""
    counts = {"s1-vm1": 1, "s1-vm2": 2, "s2-vm1": 16, "s2-vm2": 12, "s2-vm3": 11}
    node_hv = {
        "s1-vm1": "server1",
        "s1-vm2": "server1",
        "s2-vm1": "server2",
        "s2-vm2": "server2",
        "s2-vm3": "server2",
    }
    failures = gate.concentration_failures(
        counts, node_hv, sorted(node_hv), {"server1"}
    )
    assert any("server2 holds 39/42" in f and "limit 80%" in f for f in failures)


def test_the_fleet_declares_exactly_one_failure_prone_host():
    """Exactly one host is unreliable, and it is not the VRRP-preferred one.

    Asserted against whichever site.yml the suite is pointed at, so running it
    against the real fleet checks the live config too — which is the point of
    conftest honouring $SUBSTRATE_SITE_FILE.
    """
    prone = gate.failure_prone_hypervisors()
    assert len(prone) == 1
    assert prone < {host.name for host in gate.HOSTS}
