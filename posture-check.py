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

# Units whose failure means something on this host stopped protecting the
# cluster. Not an inventory of every timer -- only the ones whose silence is
# dangerous.
WATCHED_UNITS = [
    "hypervisor-update.service",
    "nextcloud-backup.service",
    "ddns-cloudflare.service",
    "homelab-update.service",
    # NOT posture-check.service itself. Watching yourself deadlocks: one failure
    # marks the unit failed, the next run then fails BECAUSE it is failed, and it
    # can never clear -- the unit only leaves the failed state by succeeding.
    # Caught by running it while it happened to be in that state.
]


def check_failed_units() -> None:
    """Catch host-side automation that has quietly stopped working.

    WHY THIS EXISTS
    `hypervisor-update.service` failed five nights running -- the host applied
    no updates and never rebooted -- and nobody knew, because that unit had no
    OnFailure= wired. It was found by reading the journal for an unrelated
    reason.

    Two of the units below had broken notification paths at the time this was
    written: one had no OnFailure at all, another had it in the [Service]
    section where systemd silently ignores it. Both are fixed, but the lesson is
    that per-unit alerting is something you can forget to add. This check does
    not depend on remembering.
    """
    r = subprocess.run(["systemctl", "is-system-running"],
                       capture_output=True, text=True)
    for unit in WATCHED_UNITS:
        s = subprocess.run(["systemctl", "is-failed", unit],
                           capture_output=True, text=True).stdout.strip()
        if s == "failed":
            when = subprocess.run(
                ["systemctl", "show", unit, "-p", "ExecMainExitTimestamp",
                 "--value"], capture_output=True, text=True).stdout.strip()
            failures.append(f"systemd unit {unit} is FAILED (since {when or 'unknown'})")
    # A failed unit is a finding, not a footnote. This previously recorded
    # unwatched failures as a NOTE, so the run could print "all invariants hold"
    # while systemd was sitting in a degraded state -- a contradiction that
    # teaches the reader to distrust the summary line.
    deg = r.stdout.strip()
    if deg == "degraded":
        n = subprocess.run(["systemctl", "list-units", "--state=failed",
                            "--no-legend", "--plain"],
                           capture_output=True, text=True).stdout.strip().splitlines()
        others = [l.split()[0] for l in n if l.split() and l.split()[0] not in WATCHED_UNITS]
        if others:
            failures.append("systemd is degraded; failed units not on the watch "
                            f"list: {', '.join(others[:5])}")
    if not any("systemd unit" in f for f in failures):
        notes.append(f"host units: {len(WATCHED_UNITS)} watched, none failed")


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


# The other hypervisor. It runs the same nightly maintenance but has no
# notification path of its own -- no notify.sh, no ntfy topic -- and duplicating
# the topic onto a second host would mean two copies of a secret to rotate.
# Watching it from here keeps ONE alerting path for both machines.
PEER = os.environ.get("POSTURE_PEER", "brad@192.168.2.101")
PEER_UNITS = ["hypervisor-update.service"]


def check_peer_units() -> None:
    """Assert the peer hypervisor's maintenance is not silently failing.

    server2's `hypervisor-update` had been aborting nightly since Aug 25 with a
    stale kubeconfig -- the identical fault as server1, found only because
    someone went looking. It has no OnFailure of its own, so nothing on that host
    could ever have reported it.
    """
    for unit in PEER_UNITS:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", PEER,
             f"systemctl is-failed {unit}"],
            capture_output=True, text=True, timeout=30)
        state = r.stdout.strip()
        if state == "failed":
            failures.append(f"peer {PEER.split('@')[-1]}: {unit} is FAILED")
        elif not state:
            # Unreachable is worth knowing, but it is not a security finding --
            # do not fail the whole check because a host is briefly rebooting.
            notes.append(f"peer {PEER.split('@')[-1]}: unreachable, {unit} not checked")
        else:
            notes.append(f"peer {PEER.split('@')[-1]}: {unit} {state}")


def check_flux() -> None:
    d = kubectl("get", "kustomization", "-n", "flux-system")
    if not d:
        return
    # Ready=False is NOT the same as broken. Flux sets it while a
    # reconciliation is in flight, so a check that fires on Ready!=True reports
    # a failure whenever it happens to run mid-reconcile. That happened on the
    # first run after adding signature verification -- a false alarm, and a
    # daily false alarm is how an alert gets ignored.
    #
    # Treat progressing states as healthy; only a terminal failure counts.
    PROGRESSING = {"Progressing", "ProgressingWithRetry", "DependencyNotReady",
                   "ReconciliationSucceeded", "Unknown"}
    bad = []
    for k in d["items"]:
        conds = k.get("status", {}).get("conditions") or []
        ready = next((c for c in conds if c.get("type") == "Ready"), None)
        if ready is None:
            bad.append(f"{k['metadata']['name']} (no Ready condition)")
        elif ready.get("status") != "True":
            reason = ready.get("reason", "")
            if reason in PROGRESSING or ready.get("status") == "Unknown":
                notes.append(f"flux: {k['metadata']['name']} reconciling ({reason})")
            else:
                bad.append(f"{k['metadata']['name']} ({reason})")
    if bad:
        failures.append(f"Flux Kustomizations not Ready: {', '.join(bad)}")
    else:
        notes.append(f"flux: {len(d['items'])} kustomizations reconciling")


def check_source_verified() -> None:
    """The config artifact's signature must still be verified on every pull.

    `spec.verify` can be removed from the OCIRepository without anything
    breaking -- Flux keeps reconciling perfectly, just without checking who
    produced the artifact. The failure is invisible by construction, which is
    exactly the kind that needs an external assertion.
    """
    d = kubectl("get", "ocirepository", "flux-system", "-n", "flux-system")
    if not d:
        return
    verify = (d.get("spec") or {}).get("verify")
    if not verify:
        failures.append("the config artifact is NO LONGER signature-verified "
                        "(spec.verify removed from the OCIRepository)")
        return
    if not verify.get("matchOIDCIdentity"):
        failures.append("cosign verification has no matchOIDCIdentity — it would "
                        "accept ANY valid Sigstore signature, including an attacker's")
        return
    cond = next((c for c in (d.get("status", {}).get("conditions") or [])
                 if c.get("type") == "SourceVerified"), None)
    if not cond or cond.get("status") != "True":
        failures.append(f"artifact signature NOT verified: "
                        f"{(cond or {}).get('message', 'no SourceVerified condition')}")
    else:
        notes.append("supply chain: artifact signature verified against the pinned identity")


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
                  check_failed_units, check_peer_units, check_source_verified,
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
