"""Regression tests for the readiness gate (ADR-080, bug-026).

`compare` reported `konnectivity-agent: python=4 vs ansible=5` on two rebuilds
that were both correct. The readiness check asked whether every pod that EXISTS
is ready — which a DaemonSet mid-rollout satisfies trivially — and the
fingerprint sampled numberReady immediately afterwards.
"""

from __future__ import annotations

import json
import types

import gate


def _fake_kubectl(pods, daemonsets):
    def _k(args, timeout=60):
        payload = {"items": daemonsets} if args.startswith("get daemonsets") else {"items": pods}
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
    return _k


def _ready_pod(name):
    return {"metadata": {"name": name},
            "status": {"phase": "Running", "containerStatuses": [{"ready": True}]}}


def _ds(name, desired, ready):
    return {"metadata": {"name": name},
            "status": {"desiredNumberScheduled": desired, "numberReady": ready}}


def test_fully_rolled_out_is_clean(monkeypatch):
    monkeypatch.setattr(gate, "kubectl", _fake_kubectl(
        [_ready_pod(f"ka-{i}") for i in range(5)], [_ds("konnectivity-agent", 5, 5)]))
    assert gate._unhealthy_pods() == []


def test_daemonset_mid_rollout_is_caught(monkeypatch):
    """THE regression: 4 ready pods, 5 desired. This used to pass."""
    monkeypatch.setattr(gate, "kubectl", _fake_kubectl(
        [_ready_pod(f"ka-{i}") for i in range(4)], [_ds("konnectivity-agent", 5, 4)]))
    bad = gate._unhealthy_pods()
    assert any("konnectivity-agent" in b for b in bad), bad


def test_unobserved_daemonset_is_not_treated_as_satisfied(monkeypatch):
    """desired == 0 means the controller has not seen it yet, not 'nothing to do'."""
    monkeypatch.setattr(gate, "kubectl", _fake_kubectl([], [_ds("konnectivity-agent", 0, 0)]))
    assert gate._unhealthy_pods() != []


def test_unready_pod_still_caught(monkeypatch):
    pod = {"metadata": {"name": "coredns-1"},
           "status": {"phase": "Running", "containerStatuses": [{"ready": False}]}}
    monkeypatch.setattr(gate, "kubectl", _fake_kubectl([pod], [_ds("konnectivity-agent", 1, 1)]))
    assert any("coredns-1" in b for b in gate._unhealthy_pods())


def test_completed_pods_are_ignored(monkeypatch):
    """One-shot jobs are not meant to stay up."""
    pod = {"metadata": {"name": "migrate-1"}, "status": {"phase": "Succeeded"}}
    monkeypatch.setattr(gate, "kubectl", _fake_kubectl([pod], [_ds("konnectivity-agent", 1, 1)]))
    assert gate._unhealthy_pods() == []


def test_api_unreachable_returns_none_not_empty(monkeypatch):
    """None means 'keep polling'; [] would mean 'everything is healthy' and would
    let a rebuild declare success against an unreachable API server."""
    monkeypatch.setattr(gate, "kubectl",
                        lambda a, timeout=60: types.SimpleNamespace(returncode=1, stdout="", stderr="x"))
    assert gate._unhealthy_pods() is None
