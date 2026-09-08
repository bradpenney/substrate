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


# --------------------------------------------------------------------------
# critical-pair spread (eighth criterion)
#
# The seventh criterion measures AGGREGATE share and passed on 2026-09-07 at
# 24%/76% while both BIND primaries ran on s2-vm1 — a single-domain LAN
# resolver, reported as healthy. These assert the property that miss revealed.
# --------------------------------------------------------------------------

BIND_SPEC = [
    {
        "name": "BIND primaries",
        "namespace": "bindy-system",
        "selector": {"bindy.firestoned.io/role": "primary"},
        "min_replicas": 2,
        "why": "one host takes the LAN offline",
    }
]


def _bind_pod(name, node, namespace="bindy-system", labels=None, phase="Running"):
    """One pod as `kubectl get pods -A -o json` reports it."""
    return {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"bindy.firestoned.io/role": "primary", **(labels or {})},
        },
        "spec": {"nodeName": node},
        "status": {"phase": phase},
    }


def _payload(*pods):
    return {"items": list(pods)}


NODE_HV = {
    "s1-vm1": "server1",
    "s1-vm2": "server1",
    "s2-vm1": "server2",
    "s2-vm2": "server2",
}


def test_both_replicas_on_one_hypervisor_is_a_failure():
    """The exact 2026-09-07 state: both primaries on s2-vm1, gate said PASS."""
    payload = _payload(
        _bind_pod("homelab-primary-0-x", "s2-vm1"),
        _bind_pod("homelab-primary-1-y", "s2-vm1"),
    )
    failures = gate.critical_pair_failures(payload, NODE_HV, BIND_SPEC)
    assert any("ONE failure domain" in f for f in failures)
    assert any("server2 (2)" in f for f in failures)


def test_replicas_on_two_nodes_of_the_SAME_hypervisor_still_fail():
    """Different hostnames are not different failure domains.

    This is the whole reason `kubernetes.io/hostname` is the wrong topology
    key: s2-vm1 and s2-vm2 are separate nodes on one physical machine, and a
    spread that only looks at node names calls this redundant.
    """
    payload = _payload(
        _bind_pod("homelab-primary-0-x", "s2-vm1"),
        _bind_pod("homelab-primary-1-y", "s2-vm2"),
    )
    failures = gate.critical_pair_failures(payload, NODE_HV, BIND_SPEC)
    assert any("ONE failure domain" in f for f in failures)


def test_replicas_spanning_both_hypervisors_pass():
    """The check must not fire on the state it exists to protect."""
    payload = _payload(
        _bind_pod("homelab-primary-0-x", "s1-vm1"),
        _bind_pod("homelab-primary-1-y", "s2-vm1"),
    )
    assert gate.critical_pair_failures(payload, NODE_HV, BIND_SPEC) == []


def test_a_selector_that_matches_nothing_fails_rather_than_passing():
    """A check that passes because it found nothing has stopped checking.

    Renaming a label upstream would otherwise make this criterion vacuously
    true forever, which is the failure mode the whole gate exists to close.
    """
    payload = _payload(_bind_pod("something-else", "s1-vm1", labels={}))
    payload["items"][0]["metadata"]["labels"] = {"app": "unrelated"}
    failures = gate.critical_pair_failures(payload, NODE_HV, BIND_SPEC)
    assert any("expected at least 2" in f for f in failures)


def test_a_scaled_down_workload_fails_rather_than_passing():
    """One replica is trivially 'spread'. It is also not redundant."""
    payload = _payload(_bind_pod("homelab-primary-0-x", "s1-vm1"))
    failures = gate.critical_pair_failures(payload, NODE_HV, BIND_SPEC)
    assert any("found 1 Running replica" in f for f in failures)


def test_a_pending_replica_does_not_count_as_placed():
    """A Pending pod has no node, so it is in no failure domain yet."""
    payload = _payload(
        _bind_pod("homelab-primary-0-x", "s2-vm1"),
        _bind_pod("homelab-primary-1-y", None, phase="Pending"),
    )
    failures = gate.critical_pair_failures(payload, NODE_HV, BIND_SPEC)
    assert any("found 1 Running replica" in f for f in failures)


def test_a_replica_on_an_unknown_node_is_reported_not_guessed():
    """The fleet definition and the cluster disagreeing is itself the finding."""
    payload = _payload(
        _bind_pod("homelab-primary-0-x", "s1-vm1"),
        _bind_pod("homelab-primary-1-y", "mystery"),
    )
    failures = gate.critical_pair_failures(payload, NODE_HV, BIND_SPEC)
    assert any("unknown node 'mystery'" in f for f in failures)


def test_the_selector_requires_every_label_not_any():
    """A partial match would widen the selector to most of a namespace."""
    spec = [
        {
            **BIND_SPEC[0],
            "selector": {
                "bindy.firestoned.io/role": "primary",
                "app.kubernetes.io/part-of": "bindy",
            },
        }
    ]
    payload = _payload(
        _bind_pod("primary-0", "s1-vm1", labels={"app.kubernetes.io/part-of": "bindy"}),
        # role matches, part-of does not — must NOT be counted.
        _bind_pod("impostor", "s2-vm1", labels={"app.kubernetes.io/part-of": "other"}),
    )
    failures = gate.critical_pair_failures(payload, NODE_HV, spec)
    assert any("found 1 Running replica" in f for f in failures)


def test_pods_in_another_namespace_are_not_counted():
    """Namespace is part of the identity, not a hint."""
    payload = _payload(
        _bind_pod("primary-0", "s1-vm1"),
        _bind_pod("primary-1", "s2-vm1", namespace="somewhere-else"),
    )
    failures = gate.critical_pair_failures(payload, NODE_HV, BIND_SPEC)
    assert any("found 1 Running replica" in f for f in failures)


def test_the_shipped_bind_spec_matches_the_operators_real_labels():
    """Guards the selector against the labels bindy actually applies.

    Taken from a live `kubectl get pod -o jsonpath='{.metadata.labels}'` on
    2026-09-08. If bindy renames one of these, this fails loudly here instead
    of turning the criterion into a permanent silent pass.
    """
    live = {
        "app": "bind9",
        "app.kubernetes.io/component": "dns-server",
        "app.kubernetes.io/instance": "homelab-primary-0",
        "app.kubernetes.io/managed-by": "Bind9Cluster",
        "app.kubernetes.io/name": "bind9",
        "app.kubernetes.io/part-of": "bindy",
        "bindy.firestoned.io/role": "primary",
    }
    spec = next(s for s in gate.CRITICAL_PAIRS if "BIND" in s["name"])
    assert all(live.get(k) == v for k, v in spec["selector"].items())


# --------------------------------------------------------------------------
# hypervisor topology labels (ninth criterion, ADR-144)
#
# The label is what every spread constraint in the platform reasons about, and
# nothing else verifies it exists or agrees with site.yml.
# --------------------------------------------------------------------------

LABEL = gate.HYPERVISOR_LABEL


def _node(name, hypervisor=None):
    """One node as `kubectl get nodes -o json` reports it."""
    labels = {"kubernetes.io/hostname": name}
    if hypervisor is not None:
        labels[LABEL] = hypervisor
    return {"metadata": {"name": name, "labels": labels}}


def _nodes(*items):
    return {"items": list(items)}


def test_every_node_labelled_to_match_site_yml_passes():
    """The state the check exists to protect."""
    payload = _nodes(
        _node("s1-vm1", "server1"),
        _node("s1-vm2", "server1"),
        _node("s2-vm1", "server2"),
    )
    assert gate.node_label_failures(payload, NODE_HV) == []


def test_an_unlabelled_node_is_a_failure():
    """A node with no failure domain is skipped by every spread constraint."""
    payload = _nodes(_node("s1-vm1", "server1"), _node("s2-vm1"))
    failures = gate.node_label_failures(payload, NODE_HV)
    assert any("s2-vm1 carries no" in f for f in failures)


def test_partial_labelling_is_caught_here_not_by_the_spread():
    """The silent one.

    With NO node labelled, a DoNotSchedule constraint leaves the pod Pending —
    loud. With only SOME labelled, unlabelled nodes are excluded from spreading
    and both replicas can sit in one domain while the constraint reports
    perfect satisfaction, because skew across a single domain is always zero.
    """
    payload = _nodes(
        _node("s1-vm1"),
        _node("s1-vm2"),
        _node("s2-vm1", "server2"),
        _node("s2-vm2", "server2"),
    )
    failures = gate.node_label_failures(payload, NODE_HV)
    assert any("s1-vm1 carries no" in f for f in failures)
    assert any("one failure domain (server2)" in f for f in failures)


def test_a_label_that_disagrees_with_site_yml_is_a_failure():
    """Drift, not absence. A node moved between hypervisors and nobody relabelled."""
    payload = _nodes(_node("s1-vm1", "server2"), _node("s2-vm1", "server2"))
    failures = gate.node_label_failures(payload, NODE_HV)
    assert any("but site.yml says 'server1'" in f for f in failures)


def test_one_domain_fails_even_when_every_label_agrees():
    """A spread over a single domain is satisfied vacuously, not correctly."""
    payload = _nodes(_node("s2-vm1", "server2"), _node("s2-vm2", "server2"))
    failures = gate.node_label_failures(payload, NODE_HV)
    assert any("one failure domain" in f for f in failures)


def test_a_node_the_fleet_definition_does_not_know_is_reported():
    """site.yml and the cluster disagreeing is itself the finding."""
    payload = _nodes(_node("s1-vm1", "server1"), _node("mystery", "server1"))
    failures = gate.node_label_failures(payload, NODE_HV)
    assert any("'mystery' is in the cluster but not in site.yml" in f for f in failures)


def test_the_asserted_label_is_the_one_the_build_actually_renders(repo_root):
    """The gate restates the label rather than importing it — on purpose.

    A gate that read the same constant the renderer writes would agree with
    itself and could never report that the two had diverged. That independence
    is only worth having if the restated value is right, so this pins it to the
    string the cloud-config template actually emits, in both the Python and
    Rust renderers.
    """
    j2 = (
        repo_root / "ansible/roles/k0s_node/templates/cloud-config.yaml.j2"
    ).read_text()
    rs = (repo_root / "crates/substrate-core/src/render.rs").read_text()
    assert f"--labels={gate.HYPERVISOR_LABEL}=" in j2
    assert f'"{gate.HYPERVISOR_LABEL}"' in rs
