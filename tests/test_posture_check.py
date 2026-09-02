"""Tests for the thing that asserts everything else.

posture-check.py had 0% coverage while being the component that decides whether
14 security invariants still hold. Its own failure mode is the worst kind: if a
check silently degraded into always-passing, it would report "all invariants
hold" forever and nothing would notice — the exact shape of the readiness gate
that passed a half-rolled DaemonSet (ADR-080), and that one shipped.

So every check here is exercised in BOTH directions: it must flag the bad state,
and it must stay quiet on the good one. A test that only proves a check can pass
is what let this class of defect through in the first place.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

import models

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def pc(monkeypatch):
    """A freshly imported posture-check with empty failures/notes.

    Imported per-test because the module keeps `failures` and `notes` as module
    globals; sharing one instance would let results bleed between tests.
    """
    spec = importlib.util.spec_from_file_location("pc", REPO / "posture-check.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["pc"] = m
    spec.loader.exec_module(m)
    m.failures.clear()
    m.notes.clear()
    monkeypatch.setattr(m, "KUBECTL", "/nonexistent/kubectl", raising=False)
    return m


def fake_kubectl(pc, mapping):
    """Route kubectl(*args) to canned JSON keyed by a substring of the args."""

    def _k(*args):
        joined = " ".join(args)
        for key, payload in mapping.items():
            if key in joined:
                return payload
        return {"items": []}

    pc.kubectl = _k
    return _k


def ns(name, **labels):
    return {"metadata": {"name": name, "labels": labels or {}}}


# ---------------------------------------------------------------- pod security


def test_pod_security_flags_a_namespace_with_no_enforce_label(pc):
    fake_kubectl(
        pc,
        {
            "namespaces": {
                "items": [
                    ns("a", **{"pod-security.kubernetes.io/enforce": "restricted"}),
                    ns("unlabelled"),
                ]
            }
        },
    )
    pc.check_pod_security()
    assert any("unlabelled" in f for f in pc.failures), pc.failures


def test_pod_security_quiet_when_every_namespace_is_labelled(pc):
    fake_kubectl(
        pc,
        {
            "namespaces": {
                "items": [
                    ns("a", **{"pod-security.kubernetes.io/enforce": "baseline"}),
                    ns("b", **{"pod-security.kubernetes.io/enforce": "privileged"}),
                ]
            }
        },
    )
    pc.check_pod_security()
    assert pc.failures == []


# ---------------------------------------------------------------- default deny


def _netpol(namespace, types_=("Ingress", "Egress"), selector=None):
    return {
        "metadata": {"namespace": namespace},
        "spec": {
            "podSelector": {} if selector is None else selector,
            "policyTypes": list(types_),
        },
    }


def test_default_deny_flags_a_namespace_with_no_policy(pc):
    fake_kubectl(
        pc,
        {
            "namespaces": {"items": [ns("covered"), ns("bare")]},
            "networkpolicy": {"items": [_netpol("covered")]},
        },
    )
    pc.check_default_deny()
    assert any("bare" in f for f in pc.failures), pc.failures


def test_default_deny_rejects_an_ingress_only_policy(pc):
    """Ingress-only is not default-deny: egress stays wide open."""
    fake_kubectl(
        pc,
        {
            "namespaces": {"items": [ns("half")]},
            "networkpolicy": {"items": [_netpol("half", ("Ingress",))]},
        },
    )
    pc.check_default_deny()
    assert any("half" in f for f in pc.failures), pc.failures


def test_default_deny_rejects_a_policy_that_is_not_catch_all(pc):
    """A podSelector that matches only some pods does not make a namespace
    default-deny, however many policyTypes it lists."""
    fake_kubectl(
        pc,
        {
            "namespaces": {"items": [ns("targeted")]},
            "networkpolicy": {
                "items": [_netpol("targeted", selector={"matchLabels": {"app": "x"}})]
            },
        },
    )
    pc.check_default_deny()
    assert any("targeted" in f for f in pc.failures), pc.failures


# --------------------------------------------------------------- cluster admin


def _crb(role, subjects):
    return {
        "roleRef": {"name": role},
        "subjects": [{"kind": k, "name": n} for k, n in subjects],
    }


def test_cluster_admin_flags_an_unexpected_subject(pc):
    expected = next(iter(pc.EXPECTED_CLUSTER_ADMIN))
    kind, name = expected.split("/", 1)
    fake_kubectl(
        pc,
        {
            "clusterrolebinding": {
                "items": [_crb("cluster-admin", [(kind, name), ("User", "mallory")])]
            }
        },
    )
    pc.check_cluster_admin()
    assert any("mallory" in f for f in pc.failures), pc.failures


def test_cluster_admin_quiet_on_the_expected_set(pc):
    subs = [tuple(s.split("/", 1)) for s in pc.EXPECTED_CLUSTER_ADMIN]
    fake_kubectl(pc, {"clusterrolebinding": {"items": [_crb("cluster-admin", subs)]}})
    pc.check_cluster_admin()
    assert pc.failures == []


def test_cluster_admin_ignores_bindings_to_other_roles(pc):
    """Only cluster-admin holders matter; a `view` binding is not a finding."""
    fake_kubectl(
        pc,
        {
            "clusterrolebinding": {
                "items": [_crb("view", [("User", "someone-harmless")])]
            }
        },
    )
    pc.check_cluster_admin()
    assert pc.failures == []


# ----------------------------------------------------------------------- flux


def _kust(name, status="True", reason="ReconciliationSucceeded"):
    return {
        "metadata": {"name": name},
        "status": {
            "conditions": [{"type": "Ready", "status": status, "reason": reason}]
        },
    }


def test_flux_flags_a_genuinely_failed_kustomization(pc):
    fake_kubectl(
        pc,
        {
            "kustomization": {
                "items": [_kust("apps", status="False", reason="BuildFailed")]
            }
        },
    )
    pc.check_flux()
    assert any("apps" in f for f in pc.failures), pc.failures


@pytest.mark.parametrize(
    "reason", ["Progressing", "ProgressingWithRetry", "DependencyNotReady"]
)
def test_flux_tolerates_mid_reconcile_states(pc, reason):
    """Regression: a Kustomization that is merely reconciling was once reported
    as broken, which turned every deploy into a false alarm."""
    fake_kubectl(
        pc,
        {
            "kustomization": {
                "items": [_kust("infrastructure", status="False", reason=reason)]
            }
        },
    )
    pc.check_flux()
    assert pc.failures == [], pc.failures


def test_flux_flags_a_kustomization_with_no_ready_condition(pc):
    """No Ready condition at all is not the same as healthy."""
    fake_kubectl(
        pc,
        {"kustomization": {"items": [{"metadata": {"name": "orphan"}, "status": {}}]}},
    )
    pc.check_flux()
    assert any("orphan" in f for f in pc.failures), pc.failures


# ------------------------------------------------------------- supply chain


def _oci(verify=True, identity=True, verified="True"):
    spec = {}
    if verify:
        spec["verify"] = {"provider": "cosign"}
        if identity:
            spec["verify"]["matchOIDCIdentity"] = [{"issuer": "^https://x$"}]
    return {
        "spec": spec,
        "status": {"conditions": [{"type": "SourceVerified", "status": verified}]},
    }


def test_source_verified_flags_removed_verification(pc):
    """spec.verify can be deleted and Flux keeps reconciling perfectly — the
    failure is invisible by construction."""
    fake_kubectl(pc, {"ocirepository": _oci(verify=False)})
    pc.check_source_verified()
    assert any("NO LONGER signature-verified" in f for f in pc.failures), pc.failures


def test_source_verified_flags_missing_identity_pinning(pc):
    """Without matchOIDCIdentity cosign accepts ANY valid Sigstore signature."""
    fake_kubectl(pc, {"ocirepository": _oci(identity=False)})
    pc.check_source_verified()
    assert any("matchOIDCIdentity" in f for f in pc.failures), pc.failures


def test_source_verified_flags_a_failed_verification(pc):
    fake_kubectl(pc, {"ocirepository": _oci(verified="False")})
    pc.check_source_verified()
    assert any("NOT verified" in f for f in pc.failures), pc.failures


def test_source_verified_quiet_when_pinned_and_verified(pc):
    fake_kubectl(pc, {"ocirepository": _oci()})
    pc.check_source_verified()
    assert pc.failures == []


# --------------------------------------------------------------------- selinux


def _selinux_output(pc, monkeypatch, mode, permissive):
    def _run(cmd, **kw):
        return types.SimpleNamespace(
            returncode=0, stdout=f"{mode}\n{permissive}\n", stderr=""
        )

    monkeypatch.setattr(pc.subprocess, "run", _run)


def test_selinux_flags_permissive_mode(pc, monkeypatch):
    _selinux_output(pc, monkeypatch, "Permissive", 0)
    pc.check_selinux()
    assert any("expected Enforcing" in f for f in pc.failures), pc.failures


def test_selinux_flags_permissive_domains_even_when_enforcing(pc, monkeypatch):
    """`getenforce` says Enforcing while individual domains are exempted — a
    per-domain opt-out of the whole control that the mode alone cannot show."""
    _selinux_output(pc, monkeypatch, "Enforcing", 3)
    pc.check_selinux()
    assert any("permissive" in f for f in pc.failures), pc.failures


def test_selinux_quiet_when_enforcing_and_clean(pc, monkeypatch):
    _selinux_output(pc, monkeypatch, "Enforcing", 0)
    pc.check_selinux()
    assert pc.failures == []


# --------------------------------------------------------------------- kubectl


def test_kubectl_records_a_failure_rather_than_returning_silently(pc, monkeypatch):
    """Callers do `if not d: return`, so a failed query MUST register a failure
    here or the check would pass by doing nothing."""
    monkeypatch.setattr(
        pc.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="", stderr="boom"),
    )
    assert pc.kubectl("get", "namespaces") is None
    assert any("failed" in f for f in pc.failures), pc.failures


def test_kubectl_records_a_failure_on_unparseable_json(pc, monkeypatch):
    monkeypatch.setattr(
        pc.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(
            returncode=0, stdout="not json", stderr=""
        ),
    )
    assert pc.kubectl("get", "namespaces") is None
    assert any("unparseable" in f for f in pc.failures), pc.failures


# ------------------------------------------------------------------ jit grant


def _run_returning(pc, monkeypatch, table):
    """Route subprocess.run by the first distinctive token in argv."""

    def _run(cmd, **kw):
        joined = " ".join(cmd)
        for key, (rc, out) in table.items():
            if key in joined:
                return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")
        return types.SimpleNamespace(returncode=1, stdout="", stderr="unmatched")

    monkeypatch.setattr(pc.subprocess, "run", _run)


def test_jit_grant_absent_is_the_healthy_state(pc, monkeypatch):
    """kubectl exits non-zero because the binding does not exist — which is
    exactly what "no standing privilege" looks like."""
    _run_returning(pc, monkeypatch, {"clusterrolebinding": (1, "")})
    pc.check_no_standing_grant()
    assert pc.failures == []
    assert any("none outstanding" in n for n in pc.notes)


def test_jit_grant_without_an_expiry_is_a_failure(pc, monkeypatch):
    """A binding with no expiry annotation is standing cluster-admin wearing the
    name of a temporary grant."""
    crb = json.dumps({"metadata": {"annotations": {}}})
    _run_returning(pc, monkeypatch, {"clusterrolebinding": (0, crb)})
    pc.check_no_standing_grant()
    assert any("NO expiry" in f for f in pc.failures), pc.failures


def test_jit_grant_with_unparseable_json_is_still_flagged(pc, monkeypatch):
    """Garbage must not be read as 'no annotations, therefore fine' silently —
    the check still has to conclude something."""
    _run_returning(pc, monkeypatch, {"clusterrolebinding": (0, "not json")})
    pc.check_no_standing_grant()
    assert pc.failures or pc.notes


# --------------------------------------------------------------- failed units


def test_failed_units_flags_a_watched_unit_that_is_failed(pc, monkeypatch):
    def _run(cmd, **kw):
        j = " ".join(cmd)
        if "is-system-running" in j:
            return types.SimpleNamespace(returncode=0, stdout="running\n", stderr="")
        if "is-failed" in j:
            failed = pc.WATCHED_UNITS[0] in j
            return types.SimpleNamespace(
                returncode=0, stdout="failed\n" if failed else "active\n", stderr=""
            )
        if "show" in j:
            return types.SimpleNamespace(
                returncode=0, stdout="Sat 2026-08-30\n", stderr=""
            )
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(pc.subprocess, "run", _run)
    pc.check_failed_units()
    assert any(pc.WATCHED_UNITS[0] in f for f in pc.failures), pc.failures


def test_failed_units_quiet_when_everything_is_active(pc, monkeypatch):
    def _run(cmd, **kw):
        j = " ".join(cmd)
        out = "running\n" if "is-system-running" in j else "active\n"
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(pc.subprocess, "run", _run)
    pc.check_failed_units()
    assert pc.failures == []


def test_failed_units_flags_a_degraded_system_even_off_the_watch_list(pc, monkeypatch):
    """Regression: the run reported "all invariants hold" while systemd was
    degraded, because the failed unit was not on the watch list. An unwatched
    failure is still a failure."""

    def _run(cmd, **kw):
        j = " ".join(cmd)
        if "is-system-running" in j:
            return types.SimpleNamespace(returncode=0, stdout="degraded\n", stderr="")
        if "is-failed" in j:
            return types.SimpleNamespace(returncode=0, stdout="active\n", stderr="")
        if "list-units" in j:
            return types.SimpleNamespace(
                returncode=0, stdout="some-other.service loaded failed\n", stderr=""
            )
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(pc.subprocess, "run", _run)
    pc.check_failed_units()
    assert any("some-other.service" in f for f in pc.failures), pc.failures


# ---------------------------------------------------------------- peer units


def test_peer_unit_failure_is_reported(pc, monkeypatch):
    monkeypatch.setattr(
        pc.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(
            returncode=0, stdout="failed\n", stderr=""
        ),
    )
    pc.check_peer_units()
    assert any("FAILED" in f for f in pc.failures), pc.failures


def test_peer_unreachable_is_a_note_not_a_failure(pc, monkeypatch):
    """An unreachable peer is not evidence of a broken unit, so it must not be
    reported as one — but it must not be silent either."""
    monkeypatch.setattr(
        pc.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(
            returncode=255, stdout="", stderr="ssh: connect"
        ),
    )
    pc.check_peer_units()
    assert pc.failures == []
    assert any("unreachable" in n for n in pc.notes), pc.notes


# ------------------------------------------------------------- admission etc.


def test_admission_policies_flags_a_missing_policy(pc):
    fake_kubectl(pc, {"validatingadmissionpolicy": {"items": []}})
    pc.check_admission_policies()
    assert pc.failures, "a cluster with no admission policies must not pass"


def test_credentials_flags_a_secret_that_is_not_syncing(pc):
    fake_kubectl(
        pc,
        {
            "externalsecret": {
                "items": [
                    {
                        "metadata": {
                            "name": "cloudflare-api-token",
                            "namespace": "cert-manager",
                        },
                        "status": {
                            "conditions": [{"type": "Ready", "status": "False"}]
                        },
                    }
                ]
            }
        },
    )
    pc.check_credentials()
    assert pc.failures, "a non-syncing ExternalSecret must be reported"


# --------------------------------------------------------------- origin lock


def _origin(
    pc, monkeypatch, public_code, direct_code, hostname="hello.example.invalid"
):
    monkeypatch.setattr(
        pc,
        "site",
        types.SimpleNamespace(
            POSTURE=models.PostureConfig(
                public_hostname=hostname, origin_ip="203.0.113.1"
            )
        ),
        raising=False,
    )
    calls = {"n": 0}

    def _run(cmd, **kw):
        joined = " ".join(cmd)
        # The direct hit is the one that pins the origin address via --resolve.
        code = direct_code if "--resolve" in joined else public_code
        calls["n"] += 1
        return types.SimpleNamespace(returncode=0, stdout=code, stderr="")

    monkeypatch.setattr(pc.subprocess, "run", _run)
    return calls


def test_origin_lock_healthy_when_public_serves_and_direct_is_refused(pc, monkeypatch):
    _origin(pc, monkeypatch, public_code="200", direct_code="000")
    pc.check_origin_lock()
    assert pc.failures == [], pc.failures


def test_origin_lock_flags_a_direct_hit_that_succeeds(pc, monkeypatch):
    """The whole point of the allowlist: reaching the origin without going
    through Cloudflare must fail. A 200 here means the lock is off."""
    _origin(pc, monkeypatch, public_code="200", direct_code="200")
    pc.check_origin_lock()
    assert pc.failures, "a reachable origin must be reported"


def test_origin_lock_flags_a_public_site_that_is_down(pc, monkeypatch):
    _origin(pc, monkeypatch, public_code="502", direct_code="000")
    pc.check_origin_lock()
    assert pc.failures, "a non-200 public site must be reported"


def test_origin_lock_skipped_when_no_hostname_is_configured(pc, monkeypatch):
    """site.yml is gitignored, so a fresh clone has no hostname. That must be a
    skip note, not a failure — otherwise the check cries wolf on every new
    machine."""
    monkeypatch.setattr(
        pc, "site", types.SimpleNamespace(POSTURE=models.PostureConfig()), raising=False
    )
    pc.check_origin_lock()
    assert pc.failures == []
    assert any("skipped" in n for n in pc.notes), pc.notes


# -------------------------------------------------------------- find kubectl


def test_find_kubectl_uses_what_is_on_path(pc, monkeypatch):
    monkeypatch.setattr(pc.shutil, "which", lambda name, path=None: "/usr/bin/kubectl")
    assert pc._find_kubectl() == "/usr/bin/kubectl"


def test_find_kubectl_falls_back_to_the_linuxbrew_path(pc, monkeypatch):
    """kubectl lives under linuxbrew here, which is NOT on systemd's default
    PATH. Without the fallback the timer reported "6 invariants BROKEN" every
    morning — a false alarm indistinguishable from a real breach."""

    def which(name, path=None):
        return "/home/linuxbrew/.linuxbrew/bin/kubectl" if path else None

    monkeypatch.setattr(pc.shutil, "which", which)
    assert "linuxbrew" in pc._find_kubectl()


def test_find_kubectl_refuses_to_run_when_absent(pc, monkeypatch):
    """Missing tooling must be reported AS missing tooling, not as broken
    security posture."""
    monkeypatch.setattr(pc.shutil, "which", lambda name, path=None: None)
    with pytest.raises(SystemExit):
        pc._find_kubectl()


# ------------------------------------------------- unreachable-API guard rails


@pytest.mark.parametrize(
    "check",
    [
        "check_pod_security",
        "check_default_deny",
        "check_cluster_admin",
        "check_flux",
        "check_source_verified",
        "check_credentials",
        "check_admission_policies",
    ],
)
def test_a_check_returns_quietly_when_kubectl_fails(pc, check):
    """kubectl() records its OWN failure and returns None; each check then
    returns early. The check must NOT add a second, misleading failure of its
    own — and must not raise, or one unreachable API would hide every other
    invariant behind a traceback."""
    pc.kubectl = lambda *a: None
    getattr(pc, check)()
    assert pc.failures == [], f"{check} invented a failure on an unreachable API"


def test_cluster_admin_notes_a_subject_that_disappeared(pc):
    """Fewer holders than the baseline is not a failure — but it must be visible,
    because it means the baseline is now stale."""
    fake_kubectl(pc, {"clusterrolebinding": {"items": [_crb("cluster-admin", [])]}})
    pc.check_cluster_admin()
    assert pc.failures == []
    assert any("removed since baseline" in n for n in pc.notes), pc.notes


def test_jit_grant_that_has_expired_but_still_exists_is_flagged(pc, monkeypatch):
    """Expired-but-present means the reaper is not working — the window closed
    and the privilege is still bound."""
    import datetime as _dt

    past = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    crb = json.dumps(
        {"metadata": {"annotations": {"jit.bradpenney.io/expires-at": past}}}
    )
    _run_returning(pc, monkeypatch, {"clusterrolebinding": (0, crb)})
    pc.check_no_standing_grant()
    assert pc.failures or any("EXPIRED" in n or "expired" in n for n in pc.notes)


# ----------------------------------------------- the healthy/edge notes paths


def test_default_deny_notes_the_count_when_every_namespace_is_covered(pc):
    fake_kubectl(
        pc,
        {
            "namespaces": {"items": [ns("a"), ns("b")]},
            "networkpolicy": {"items": [_netpol("a"), _netpol("b")]},
        },
    )
    pc.check_default_deny()
    assert pc.failures == []
    assert any("default-deny" in n for n in pc.notes), pc.notes


def test_jit_grant_within_its_window_is_reported_not_failed(pc, monkeypatch):
    """A live, unexpired grant is the system working — visible, but not a
    failure."""
    import datetime as _dt

    future = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=20)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    crb = json.dumps(
        {"metadata": {"annotations": {"jit.bradpenney.io/expires-at": future}}}
    )
    _run_returning(pc, monkeypatch, {"clusterrolebinding": (0, crb)})
    pc.check_no_standing_grant()
    assert any("outstanding" in n for n in pc.notes), pc.notes


def test_credentials_notes_the_count_when_all_are_syncing(pc):
    fake_kubectl(
        pc,
        {
            "externalsecret": {
                "items": [
                    {
                        "metadata": {"name": "a", "namespace": "x"},
                        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
                    }
                ]
            }
        },
    )
    pc.check_credentials()
    assert pc.failures == []
    assert any("external secrets syncing" in n for n in pc.notes), pc.notes


def test_selinux_notes_an_unreachable_peer_rather_than_failing(pc, monkeypatch):
    """A peer that cannot be reached is not evidence that SELinux is off."""
    monkeypatch.setattr(
        pc.subprocess,
        "run",
        lambda cmd, **kw: (
            types.SimpleNamespace(returncode=255, stdout="", stderr="no route")
            if "ssh" in " ".join(cmd)
            else types.SimpleNamespace(returncode=0, stdout="Enforcing\n0\n", stderr="")
        ),
    )
    pc.check_selinux()
    assert pc.failures == []
    assert any("unreachable" in n for n in pc.notes), pc.notes


def test_selinux_tolerates_a_non_numeric_permissive_count(pc, monkeypatch):
    """`semanage` may be absent, in which case the count is not a number. That
    must not crash the check and take every other invariant with it."""
    monkeypatch.setattr(
        pc.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(
            returncode=0, stdout="Enforcing\nnot-a-number\n", stderr=""
        ),
    )
    pc.check_selinux()
    assert not any("raised" in f for f in pc.failures), pc.failures


def test_peer_unit_in_any_other_state_is_noted(pc, monkeypatch):
    """inactive is the normal resting state for a timer-driven unit — reported,
    not failed."""
    monkeypatch.setattr(
        pc.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(
            returncode=1, stdout="inactive\n", stderr=""
        ),
    )
    pc.check_peer_units()
    assert pc.failures == []
    assert any("inactive" in n for n in pc.notes), pc.notes


def test_origin_lock_skips_the_bypass_check_without_an_origin_ip(pc, monkeypatch):
    """The WAN address is gitignored, so a fresh clone can still check that the
    public site serves — it just cannot test the direct path."""
    monkeypatch.setattr(
        pc,
        "site",
        types.SimpleNamespace(
            POSTURE=models.PostureConfig(public_hostname="hello.example.invalid")
        ),
        raising=False,
    )
    monkeypatch.setattr(
        pc.subprocess,
        "run",
        lambda cmd, **kw: types.SimpleNamespace(returncode=0, stdout="200", stderr=""),
    )
    pc.check_origin_lock()
    assert any("skipped" in n for n in pc.notes), pc.notes


def test_cluster_admin_reports_both_new_and_removed_subjects(pc):
    """A baseline that has drifted in both directions must show both."""
    expected = sorted(pc.EXPECTED_CLUSTER_ADMIN)
    kind, name = expected[0].split("/", 1)
    fake_kubectl(
        pc,
        {
            "clusterrolebinding": {
                "items": [_crb("cluster-admin", [(kind, name), ("User", "newcomer")])]
            }
        },
    )
    pc.check_cluster_admin()
    assert any("newcomer" in f for f in pc.failures), pc.failures


# -------------------------------------------------------------------- firewall


def _probe(pc, monkeypatch, results):
    """Stub the TCP probe. `results` maps (prober_substring, port) -> OPEN/CLOSED.

    Anything unlisted answers CLOSED, so a test only has to state the cases it
    cares about.
    """

    def _run(cmd, **_kw):
        joined = " ".join(cmd)
        # The port comes from /dev/tcp/<host>/<port>, NOT from the last slash in
        # the line -- that one belongs to the 2>/dev/null redirect.
        m = re.search(r"/dev/tcp/[0-9.]+/(\d+)", joined)
        port = m.group(1) if m else ""
        for prober, prober_port in results:
            if prober in joined and prober_port == port:
                out = results[(prober, prober_port)]
                if out == "UNREACHABLE":
                    return types.SimpleNamespace(returncode=255, stdout="", stderr="")
                return types.SimpleNamespace(returncode=0, stdout=out + "\n", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="CLOSED\n", stderr="")

    monkeypatch.setattr(pc.subprocess, "run", _run)


def _node_and_peer(pc, monkeypatch):
    """Give the check a coherent world built from the fixture site.

    The suite runs against tests/fixtures/site.yml (conftest), whose hypervisors
    are hvA/hvB — so socket.gethostname() matches neither and _local_address()
    returns "". Without this the check would bail with "site config incomplete"
    and every assertion below would pass against a check that ran nothing.
    """
    me, other = pc.site.HOSTS[0], pc.site.HOSTS[-1]
    monkeypatch.setattr(pc.socket, "gethostname", lambda: me.name)
    peer = other.peer_target or other.ssh_target
    monkeypatch.setattr(pc, "PEER", peer)
    node = [vm.static_ip for h in pc.site.HOSTS for vm in h.vms][0]
    return node, peer


def test_firewall_flags_a_port_reachable_from_a_denied_source(pc, monkeypatch):
    """The defect of 2026-09-02, as a test.

    9100/9428/8428 all answered 200 from hosts that were never allow-listed,
    because the zone opens 1025-65535 and an `accept` on top of that restricts
    nothing. Every rule existed; none of them filtered.
    """
    node, peer = _node_and_peer(pc, monkeypatch)
    peer_host = peer.rpartition("@")[2]
    _probe(pc, monkeypatch, {(peer_host, "8428"): "OPEN", (node, "8428"): "OPEN"})
    pc.check_firewall_restrictions()
    assert any(
        "8428" in f and "NOT allow-listed" in f for f in pc.failures
    ), pc.failures


def test_firewall_quiet_when_denied_is_refused_and_allowed_gets_through(
    pc, monkeypatch
):
    """The good state must be silent, or the check is useless in practice."""
    node, peer = _node_and_peer(pc, monkeypatch)
    _probe(
        pc,
        monkeypatch,
        {
            (node, "8428"): "OPEN",
            (node, "9428"): "OPEN",
            (peer.rpartition("@")[2], "9100"): "OPEN",
        },
    )
    pc.check_firewall_restrictions()
    assert pc.failures == [], pc.failures
    assert any("refuse non-allow-listed" in n for n in pc.notes), pc.notes


def test_firewall_flags_a_port_refused_for_a_source_that_must_reach_it(pc, monkeypatch):
    """A firewall that blocks everything is also broken.

    That direction fails silently in production — it looks like a healthy
    firewall and shows up much later as a scrape target that never came up.
    """
    node, peer = _node_and_peer(pc, monkeypatch)
    _probe(pc, monkeypatch, {(peer.rpartition("@")[2], "9100"): "CLOSED"})
    pc.check_firewall_restrictions()
    assert any("MUST reach it" in f for f in pc.failures), pc.failures


def test_firewall_notes_an_unreachable_prober_rather_than_passing(pc, monkeypatch):
    """An unreachable prober is inconclusive, not evidence of a closed port.

    Scoring it as a pass is how a check degrades into always-passing — the
    failure this whole file exists to prevent.
    """
    node, peer = _node_and_peer(pc, monkeypatch)
    _probe(
        pc,
        monkeypatch,
        {
            (k, p): "UNREACHABLE"
            for k in (node, peer.rpartition("@")[2])
            for p in ("9100", "9428", "8428")
        },
    )
    pc.check_firewall_restrictions()
    assert pc.failures == []
    assert any("not checked" in n for n in pc.notes), pc.notes


def test_firewall_skips_cleanly_when_site_config_is_incomplete(pc, monkeypatch):
    monkeypatch.setattr(pc, "_local_address", lambda: "")
    pc.check_firewall_restrictions()
    assert pc.failures == []
    assert any("site config incomplete" in n for n in pc.notes), pc.notes


def test_port_probe_maps_output_to_a_tri_state(pc, monkeypatch):
    """OPEN / CLOSED / anything else must not collapse into a boolean.

    `None` means "did not find out", and the caller treats it differently from
    "closed". Collapsing the two turns an unreachable prober into a pass.
    """
    for stdout, code, expected in (
        ("OPEN\n", 0, True),
        ("CLOSED\n", 0, False),
        ("", 255, None),
        ("garbage\n", 0, None),
    ):
        monkeypatch.setattr(
            pc.subprocess,
            "run",
            lambda *_a, _s=stdout, _c=code, **_k: types.SimpleNamespace(
                returncode=_c, stdout=_s, stderr=""
            ),
        )
        assert pc._port_reachable_from("u@h", "1.2.3.4", 80) is expected


# ------------------------------------------------------------------- addresses


def test_peer_and_local_addresses_come_from_config_not_literals():
    """These carried a hardcoded LAN address until 2026-09-02.

    site.yml is gitignored so addresses live in one place and substrate can be
    published without them; a convenient default quietly undid that.
    """
    source = (REPO / "posture-check.py").read_text()
    assert (
        'os.environ.get("POSTURE_PEER", "' not in source
    ), "POSTURE_PEER has a hardcoded address default again"


def test_peer_target_picks_the_other_hypervisor(pc, monkeypatch):
    other = [h for h in pc.site.HOSTS][-1]
    monkeypatch.setattr(pc.socket, "gethostname", lambda: pc.site.HOSTS[0].name)
    assert (
        pc._peer_target().rpartition("@")[2]
        == (other.peer_target or other.ssh_target).rpartition("@")[2]
    )


def test_local_address_is_this_hosts_own(pc, monkeypatch):
    me = pc.site.HOSTS[0]
    monkeypatch.setattr(pc.socket, "gethostname", lambda: me.name)
    assert pc._local_address() == (me.peer_target or me.ssh_target).rpartition("@")[2]
