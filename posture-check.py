#!/usr/bin/env python3
"""Assert the cluster's security invariants still hold, and shout if they do not.

WHY THIS EXISTS
Every control built through ADR-058..072 is PREVENTIVE. Not one of them notices
when it stops being true. Pod Security labels were silently stripped for hours
while both Flux Kustomizations reported Ready (ADR-063); the privilege-expiry
reaper failed open on a missing base image while `kubectl get cronjob` looked
healthy (ADR-065). In both cases the fix was easy and the DISCOVERY was luck.

This is the detective half. It re-asserts, from outside, the things the
preventive controls are supposed to guarantee -- including the ones that would
otherwise only surface during an incident.

DESIGNED TO RUN READ-ONLY.
Every check below is a read, so this runs as the scoped `brad` identity and
never needs the break-glass certificate (ADR-071). A monitor that requires
cluster-admin is a monitor that will be run as root forever.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hosts as site

CONTEXT = os.environ.get("POSTURE_CONTEXT", "brad")
# Namespaces exempt from the default-deny requirement, with the reason.
NETPOL_EXEMPT = {
    "hello": "podinfo demo, pending removal from Git",
}
# Subjects legitimately holding cluster-admin. Anything else is an alert.
EXPECTED_CLUSTER_ADMIN = {
    "Group/system:masters",              # the bootstrap certificate itself
    "ServiceAccount/kustomize-controller",
    "ServiceAccount/helm-controller",    # binding remains; the SA is gone
    "ServiceAccount/flux-operator",
    "ServiceAccount/longhorn-support-bundle",
}

failures: list[str] = []
notes: list[str] = []


def _find_kubectl() -> str:
    """Locate kubectl, or refuse to run at all.

    WHY THIS IS NOT JUST `shutil.which` INLINE
    Without it, a missing kubectl makes every check raise and this script
    reports "6 security invariants BROKEN" — a false alarm that looks exactly
    like a real breach of posture. A monitor that cries wolf gets muted, and a
    muted monitor is worse than none.

    Found the hard way: kubectl lives under linuxbrew here, which is not on
    systemd's default PATH, so the timer would have paged every morning.
    """
    found = shutil.which("kubectl") or shutil.which(
        "kubectl", path="/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin")
    if not found:
        sys.exit("posture-check: kubectl not found on PATH. This is a TOOLING "
                 "failure, not a security finding — fix PATH and re-run.")
    return found


def kubectl(*args: str) -> dict | None:
    r = subprocess.run([KUBECTL, f"--context={CONTEXT}", *args, "-o", "json"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode:
        failures.append(f"kubectl {' '.join(args)} failed: {r.stderr.strip()[:160]}")
        return None
    try:
        return json.loads(r.stdout)
    except Exception as e:
        failures.append(f"kubectl {' '.join(args)} returned unparseable JSON: {e}")
        return None


def check_pod_security() -> None:
    """Every namespace must declare an enforcement level (ADR-062/063)."""
    d = kubectl("get", "namespaces")
    if not d:
        return
    missing = [n["metadata"]["name"] for n in d["items"]
               if "pod-security.kubernetes.io/enforce" not in (n["metadata"].get("labels") or {})]
    if missing:
        failures.append(f"namespaces with NO Pod Security enforcement: {', '.join(sorted(missing))}")
    else:
        notes.append(f"pod security: {len(d['items'])}/{len(d['items'])} namespaces enforced")


def check_default_deny() -> None:
    """Every namespace should deny ingress and egress by default (ADR-067)."""
    ns = kubectl("get", "namespaces")
    np = kubectl("get", "networkpolicy", "-A")
    if not ns or not np:
        return
    have = {p["metadata"]["namespace"] for p in np["items"]
            if p["spec"].get("podSelector") == {}
            and set(p["spec"].get("policyTypes") or []) >= {"Ingress", "Egress"}}
    gaps = [n["metadata"]["name"] for n in ns["items"]
            if n["metadata"]["name"] not in have
            and n["metadata"]["name"] not in NETPOL_EXEMPT]
    if gaps:
        failures.append(f"namespaces with NO default-deny NetworkPolicy: {', '.join(sorted(gaps))}")
    else:
        notes.append(f"network policy: {len(have)} namespaces default-deny")


def check_cluster_admin() -> None:
    """cluster-admin must not grow new holders without someone noticing."""
    d = kubectl("get", "clusterrolebinding")
    if not d:
        return
    subs = {f"{s.get('kind')}/{s.get('name')}"
            for b in d["items"] if b["roleRef"]["name"] == "cluster-admin"
            for s in (b.get("subjects") or [])}
    new = subs - EXPECTED_CLUSTER_ADMIN
    if new:
        failures.append(f"UNEXPECTED cluster-admin subjects: {', '.join(sorted(new))}")
    gone = EXPECTED_CLUSTER_ADMIN - subs
    if gone:
        notes.append(f"cluster-admin subjects removed since baseline: {', '.join(sorted(gone))}")
    if not new:
        notes.append(f"cluster-admin: {len(subs)} subjects, all expected")


def check_no_standing_grant() -> None:
    """A JIT grant left outstanding means the reaper is not working (ADR-065)."""
    r = subprocess.run(
        [KUBECTL, f"--context={CONTEXT}", "get", "clusterrolebinding",
         "jit-platform-admin", "-o", "json"],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        notes.append("jit grant: none outstanding")
        return
    try:
        ann = json.loads(r.stdout)["metadata"].get("annotations") or {}
    except Exception:
        ann = {}
    exp = ann.get("jit.bradpenney.io/expires-at")
    if not exp:
        failures.append("a jit-platform-admin grant exists with NO expiry annotation")
        return
    import datetime as dt
    end = dt.datetime.fromisoformat(exp.replace("Z", "+00:00"))
    left = (end - dt.datetime.now(dt.timezone.utc)).total_seconds()
    if left < -300:
        failures.append(
            f"jit grant EXPIRED at {exp} and is still present -- the reaper is not running")
    else:
        notes.append(f"jit grant: outstanding, expires {exp}")


EXPECTED_POLICIES = {"require-pss-labels", "workload-hygiene"}


def check_admission_policies() -> None:
    """The admission policies must still exist AND still be enforcing.

    A binding flipped from Deny to Warn is invisible in `kubectl get` output and
    silently turns a guardrail into a log line (ADR-068).
    """
    pol = kubectl("get", "validatingadmissionpolicy")
    bind = kubectl("get", "validatingadmissionpolicybinding")
    if not pol or not bind:
        return
    have = {p["metadata"]["name"] for p in pol["items"]}
    gone = EXPECTED_POLICIES - have
    if gone:
        failures.append(f"admission policies MISSING: {', '.join(sorted(gone))}")
    denying = {b["spec"]["policyName"] for b in bind["items"]
               if "Deny" in (b["spec"].get("validationActions") or [])}
    if not denying:
        failures.append("no admission policy binding is set to Deny -- "
                        "every guardrail has become advisory")
    elif not gone:
        notes.append(f"admission: {len(have)} policies, {len(denying)} enforcing Deny")


def check_flux() -> None:
    d = kubectl("get", "kustomization", "-n", "flux-system")
    if not d:
        return
    bad = [k["metadata"]["name"] for k in d["items"]
           if not any(c.get("type") == "Ready" and c.get("status") == "True"
                      for c in (k.get("status", {}).get("conditions") or []))]
    if bad:
        failures.append(f"Flux Kustomizations not Ready: {', '.join(bad)}")
    else:
        notes.append(f"flux: {len(d['items'])} kustomizations reconciling")


def check_credentials() -> None:
    """ExternalSecrets must still be SYNCING, not merely have left a Secret behind."""
    d = kubectl("get", "externalsecret", "-A")
    if not d:
        return
    stale = [f"{e['metadata']['namespace']}/{e['metadata']['name']}" for e in d["items"]
             if not any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in (e.get("status", {}).get("conditions") or []))]
    if stale:
        failures.append(f"ExternalSecrets not syncing (the Secret may still look fine): "
                        f"{', '.join(stale)}")
    else:
        notes.append(f"credentials: {len(d['items'])} external secrets syncing")


def check_origin_lock() -> None:
    """The public site must answer through Cloudflare and REFUSE a direct hit.

    The hostname and origin address come from site.yml, which is gitignored —
    `substrate` is a public repository and the WAN address does not belong in it.

    This is the check that would have caught the original exposure, and it is
    the one most likely to regress: the allowlist is a static list of Cloudflare
    ranges (ADR-070) and a stale list fails closed.
    """
    hostname = (site.POSTURE or {}).get("public_hostname")
    origin = (site.POSTURE or {}).get("origin_ip")
    if not hostname:
        notes.append("origin lock: no public_hostname configured, check skipped")
        return

    def curl(*extra: str) -> str:
        r = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-m", "12",
                            "-w", "%{http_code}", *extra,
                            f"https://{hostname}"],
                           capture_output=True, text=True)
        return r.stdout.strip()

    through = curl()
    if through != "200":
        failures.append(f"public site via Cloudflare returned {through}, expected 200")
    else:
        notes.append("public site: 200 through Cloudflare")

    if not origin:
        notes.append("origin lock: no origin_ip configured, bypass check skipped")
        return
    direct = curl("--resolve", f"{hostname}:443:{origin}")
    if direct == "200":
        failures.append(
            "ORIGIN LOCK BROKEN: the ingress answers a direct connection that "
            "bypasses Cloudflare (ADR-070)")
    else:
        notes.append(f"origin lock: direct bypass refused ({direct or 'no response'})")


KUBECTL = ""


def main() -> int:
    global KUBECTL
    KUBECTL = _find_kubectl()
    for check in (check_pod_security, check_default_deny, check_cluster_admin,
                  check_no_standing_grant, check_admission_policies, check_flux,
                  check_credentials,
                  check_origin_lock):
        try:
            check()
        except Exception as e:  # a check that crashes must not hide the others
            failures.append(f"{check.__name__} raised {type(e).__name__}: {e}")

    for n in notes:
        print(f"  [ok  ] {n}")
    for f in failures:
        print(f"  [FAIL] {f}", file=sys.stderr)
    print()
    if failures:
        print(f"{len(failures)} security invariant(s) BROKEN", file=sys.stderr)
        return 1
    print(f"all {len(notes)} security invariants hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
