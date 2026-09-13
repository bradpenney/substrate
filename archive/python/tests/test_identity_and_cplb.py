"""Security-critical behaviour in the identity and control-plane-LB tooling.

Both modules read 0% before this. What matters in them is not line count: it is
a small number of refusals and rendered configs where being wrong is expensive
and silent.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load(filename, name):
    spec = importlib.util.spec_from_file_location(name, REPO / filename)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def ccc():
    return _load("create-client-cert.py", "ccc")


@pytest.fixture(scope="module")
def cplb():
    return _load("deploy-cplb.py", "cplb")


# ------------------------------------------------------- forbidden identities


def test_system_masters_is_forbidden(ccc):
    """An O of system:masters bypasses RBAC entirely, and a client certificate
    CANNOT be revoked — Kubernetes implements no CRL and no OCSP. Issuing one by
    accident is unfixable short of rotating the cluster CA."""
    assert "system:masters" in ccc.FORBIDDEN_GROUPS


def test_node_identities_are_forbidden_too(ccc):
    """system:nodes grants the kubelet API surface; node-admins is its admin
    counterpart. Neither belongs on a human's certificate."""
    assert {"system:nodes", "system:node-admins"} <= ccc.FORBIDDEN_GROUPS


def test_forbidden_groups_is_a_set_of_exact_strings(ccc):
    """RBAC matches the O value exactly, so these are compared as strings, not
    prefixes. A substring check would let `system:masters-ish` through, and an
    over-broad one would block a legitimate group that merely starts the same."""
    assert isinstance(ccc.FORBIDDEN_GROUPS, (set, frozenset))
    assert all(isinstance(g, str) for g in ccc.FORBIDDEN_GROUPS)
    assert "system:masters" in ccc.FORBIDDEN_GROUPS
    assert "system:mastersx" not in ccc.FORBIDDEN_GROUPS


# ------------------------------------------------------------- haproxy config


def test_haproxy_config_renders_and_is_not_empty(cplb):
    cfg = cplb.haproxy_cfg()
    assert isinstance(cfg, str) and len(cfg) > 100


def test_haproxy_logs_state_changes_but_not_every_request(cplb):
    """`warning` drops the per-request access log (info) while keeping every
    state change: "server is DOWN" is alert and "no server available" is emerg,
    both more severe than warning, so both still reach the journal."""
    cfg = cplb.haproxy_cfg()
    assert "log /dev/log local0 warning" in cfg


def test_haproxy_marks_itself_as_managed(cplb):
    """A hand-edit on the host would otherwise be invisible and then silently
    overwritten by the next deploy."""
    assert "do not edit by hand" in cplb.haproxy_cfg().lower()


def test_haproxy_backend_covers_every_controller(cplb):
    """konnectivity needs one agent connection per SERVER, which a VRRP virtual
    IP cannot provide — that is failover, not distribution. Every controller must
    appear in the backend or agents pile onto whichever holds the VIP."""
    cfg = cplb.haproxy_cfg()
    controllers = cplb.controllers()
    assert controllers, "no controllers resolved from the site config"
    for name, ip in controllers:
        assert ip in cfg, f"{name} ({ip}) missing from the haproxy backend"


def test_keepalived_config_differs_per_host(cplb):
    """Both hypervisors run keepalived; identical config would mean two nodes
    claiming the same priority for the same VRRP router id."""
    import hosts

    names = [h.name for h in hosts.HOSTS]
    if len(names) < 2:
        pytest.skip("fixture has a single hypervisor")
    a, b = cplb.keepalived_cfg(names[0]), cplb.keepalived_cfg(names[1])
    assert a != b, "keepalived config is identical on both hypervisors"
