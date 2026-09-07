#!/usr/bin/env python3
"""Grant time-boxed platform-admin rights by creating an expiring binding.

THE MODEL (ADR-065)
Read-only access is permanent and unremarkable. Write access is an event: you
ask for it, it is recorded, and it goes away on its own.

Kubernetes has no TTL on a ClusterRoleBinding, so the expiry lives in an
annotation and the `jit-reaper` CronJob in kube-system enforces it every two
minutes. The reaper runs in the cluster on purpose -- the laptop that asked for
elevation is the thing most likely to be asleep when the timer should fire.

The reaper also deletes any grant that has NO expiry annotation, so a binding
made by hand cannot quietly become permanent.

WHAT THIS IS AND IS NOT
It is: a named identity in the audit log, revocable by deleting one object, and
read-only by default.
It is not: a containment boundary. platform-admin can create pods, and anything
that can create a pod can mount a ServiceAccount token. Treat the grant window
as the thing being minimised, not as a sandbox.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import socket
import subprocess
import sys

BINDING = "jit-platform-admin"
ANNOTATION = "jit.bradpenney.io/expires-at"

# Creating the grant means creating a ClusterRoleBinding, which the scoped
# identity deliberately CANNOT do — otherwise the time box would constrain
# nothing, since you could simply re-grant yourself forever.
#
# So issuing a grant is the one action that still needs the break-glass
# certificate, and naming the context here makes that visible rather than
# implicit. The god credential goes from "everything you do all day" to "one
# command, which leaves a record."
BREAK_GLASS_CONTEXT = "break-glass"

# Where the audit trail lives, and why it is not just annotations on the
# binding: annotations disappear when the grant is reaped, which is precisely
# when you most want to know a grant existed. A ConfigMap survives the reap,
# lives in etcd, and therefore inherits the etcd backup that has actually been
# restore-tested (ADR-072).
AUDIT_CONFIGMAP = "jit-admin-audit"
AUDIT_NAMESPACE = "kube-system"
# ConfigMaps cap at ~1 MiB. Each entry is a short JSON line, so this is far
# under the limit while keeping a useful history.
AUDIT_MAX_ENTRIES = 200


def sh(
    args: list[str], check=True, context: str | None = None, **kw
) -> subprocess.CompletedProcess:
    """Run kubectl, exiting with the failing command and its stderr.

    SystemExit rather than an exception: this is a CLI, and whoever is holding a
    break-glass credential should see the command, not a traceback."""
    if context and args and args[0] == "kubectl":
        args = [args[0], f"--context={context}"] + args[1:]
    r = subprocess.run(args, capture_output=True, text=True, **kw, check=False)
    if check and r.returncode:
        sys.exit(f"command failed: {' '.join(args)}\n{r.stderr.strip()}")
    return r


def current() -> dict | None:
    """The outstanding grant as a dict, or None when there is none.

    None is the healthy state: it means no standing privilege exists."""
    r = sh(["kubectl", "get", "clusterrolebinding", BINDING, "-o", "json"], check=False)
    return json.loads(r.stdout) if r.returncode == 0 else None


def cmd_status() -> int:
    """Report whether a grant exists and how long it has left.

    Runs as the CURRENT user, unlike grant and revoke — reading the binding
    needs no privilege, and requiring break-glass just to look would discourage
    looking."""
    crb = current()
    if not crb:
        print("  no outstanding grant - read-only")
        return 0
    exp = crb["metadata"].get("annotations", {}).get(ANNOTATION)
    subs = ", ".join(f"{s['kind']}/{s['name']}" for s in crb.get("subjects", []))
    if not exp:
        print(f"  grant to {subs} has NO expiry - the reaper will remove it within 2m")
        return 0
    end = dt.datetime.fromisoformat(exp.replace("Z", "+00:00"))
    left = (end - dt.datetime.now(dt.timezone.utc)).total_seconds()
    state = f"{int(left // 60)}m remaining" if left > 0 else "EXPIRED, awaiting reaper"
    print(f"  granted to {subs}\n  expires    {exp}  ({state})")
    return 0


def invoker() -> str:
    """Best-effort identity of the human who ran this.

    `SUDO_USER` first: under sudo, `USER` is root and says nothing about who is
    actually at the keyboard. Falls back through the login environment to the
    process owner.

    This is attribution, NOT authentication — anything here can be spoofed by
    whoever can already run the command. Its job is to answer "who did this?"
    on a Tuesday, not to withstand an adversary who already holds the
    break-glass context.
    """
    for var in ("SUDO_USER", "USER", "LOGNAME"):
        value = os.environ.get(var)
        if value:
            return value
    return getpass.getuser()


def attribution(user: str, reason: str, expires: str, granted: str) -> dict[str, str]:
    """Annotations recording who asked for a grant, from where, and why.

    Args:
        user: the Kubernetes user the grant binds to.
        reason: free text from `--reason`, required at the CLI.
        expires: RFC3339 expiry stamp.
        granted: RFC3339 issue stamp.

    Returns:
        The annotation map for the ClusterRoleBinding.

    A grant that records only its expiry — which is what this tool wrote until
    2026-09-06 — cannot answer the one question asked after the fact. An
    unattributed grant appeared on this cluster on 2026-09-05 and neither the
    operator nor the tooling could say who issued it (ADR-136).
    """
    return {
        ANNOTATION: expires,
        "jit.bradpenney.io/granted-at": granted,
        "jit.bradpenney.io/invoker": invoker(),
        "jit.bradpenney.io/source-host": socket.gethostname(),
        "jit.bradpenney.io/reason": reason,
        "jit.bradpenney.io/subject": user,
    }


def audit_line(action: str, user: str, reason: str, when: str) -> str:
    """One JSON line for the audit ConfigMap. Newline-free by construction.

    Args:
        action: "grant" or "revoke".
        user: the Kubernetes user the grant applies to.
        reason: free text, or "" for a revoke.
        when: RFC3339 stamp.

    Returns:
        A single-line JSON record.
    """
    return json.dumps(
        {
            "at": when,
            "action": action,
            "subject": user,
            "invoker": invoker(),
            "host": socket.gethostname(),
            "reason": reason,
        },
        sort_keys=True,
    )


def trimmed_log(existing: str, line: str) -> str:
    """Append `line` to `existing`, keeping only the newest AUDIT_MAX_ENTRIES.

    Args:
        existing: current ConfigMap `log` value, newline-separated.
        line: the new single-line JSON record.

    Returns:
        The new log value, oldest entries dropped first.

    Split out from the IO so the trimming can be tested without a cluster. A
    log that grows without bound eventually exceeds the ~1 MiB ConfigMap limit,
    at which point the audit stops recording — silently, and only once there is
    a lot of history worth keeping.
    """
    entries = [x for x in existing.split("\n") if x]
    entries = entries[-(AUDIT_MAX_ENTRIES - 1) :] if AUDIT_MAX_ENTRIES > 1 else []
    entries.append(line)
    return "\n".join(entries)


def append_audit(line: str) -> None:
    """Append one record to the audit ConfigMap, trimming to the newest entries.

    Args:
        line: a single-line JSON record from `audit_line`.

    A FAILURE HERE WARNS AND DOES NOT BLOCK, deliberately. Break-glass exists
    for the times the cluster is already unwell; refusing to grant admin because
    the audit ConfigMap could not be written would make the control fail closed
    at the exact moment it is needed. The warning is loud, and the grant still
    carries its attribution annotations either way.
    """
    try:
        result = sh(
            [
                "kubectl",
                "-n",
                AUDIT_NAMESPACE,
                "get",
                "configmap",
                AUDIT_CONFIGMAP,
                "-o",
                "json",
            ],
            context=BREAK_GLASS_CONTEXT,
            check=False,
        )
        existing = ""
        if result.returncode == 0:
            existing = json.loads(result.stdout).get("data", {}).get("log", "")
        cm = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": AUDIT_CONFIGMAP, "namespace": AUDIT_NAMESPACE},
            "data": {"log": trimmed_log(existing, line)},
        }
        sh(
            ["kubectl", "apply", "-f", "-"],
            input=json.dumps(cm),
            context=BREAK_GLASS_CONTEXT,
        )
    except Exception as exc:  # noqa: BLE001 - never block break-glass on audit
        print(f"  WARNING: could not write the audit record: {exc}", file=sys.stderr)
        print("  The grant still carries its attribution annotations.", file=sys.stderr)


def cmd_grant(user: str, minutes: int, reason: str) -> int:
    """Bind platform-admin to a user for a fixed window.

    Refuses to stack on an existing grant: a second one would silently extend the
    first, and the time box would constrain nothing."""
    if current():
        sys.exit(
            f"a grant is already outstanding; run `{sys.argv[0]} status` "
            f"or revoke it first"
        )
    issued = dt.datetime.now(dt.timezone.utc)
    now = issued.strftime("%Y-%m-%dT%H:%M:%SZ")
    exp = (issued + dt.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    crb = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {
            "name": BINDING,
            "annotations": attribution(user, reason, exp, now),
            "labels": {"rbac.bradpenney.io/jit": "true"},
        },
        "subjects": [
            {"kind": "User", "name": user, "apiGroup": "rbac.authorization.k8s.io"}
        ],
        "roleRef": {
            "kind": "ClusterRole",
            "name": "platform-admin",
            "apiGroup": "rbac.authorization.k8s.io",
        },
    }
    sh(
        ["kubectl", "apply", "-f", "-"],
        input=json.dumps(crb),
        context=BREAK_GLASS_CONTEXT,
    )
    append_audit(audit_line("grant", user, reason, now))
    print(f"  granted platform-admin to {user} until {exp} ({minutes}m)")
    print(f"  invoker: {invoker()}@{socket.gethostname()}  reason: {reason}")
    print(f"  revoke early: {sys.argv[0]} revoke")
    return 0


def cmd_revoke() -> int:
    """Remove the grant now rather than waiting for the reaper.

    Names the break-glass context explicitly: the scoped identity deliberately
    cannot delete a ClusterRoleBinding."""
    crb = current()
    if not crb:
        print("  no outstanding grant")
        return 0
    subject = (
        crb["metadata"].get("annotations", {}).get("jit.bradpenney.io/subject", "")
    )
    sh(
        ["kubectl", "delete", "clusterrolebinding", BINDING],
        context=BREAK_GLASS_CONTEXT,
    )
    # Record the revoke too. Without it the trail shows a grant and no end, and
    # "was it revoked early or did it run its full window?" is exactly the sort
    # of question this exists to answer.
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    append_audit(audit_line("revoke", subject, "", now))
    print("  revoked")
    return 0


def main() -> int:
    """Dispatch grant, revoke or status.

    grant and revoke are privileged and say so by naming the break-glass
    context; status is not."""
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grant", help="grant platform-admin for a bounded window")
    g.add_argument("user")
    g.add_argument("--minutes", type=int, default=30, help="grant window (default 30)")
    # REQUIRED, not optional. Half the value of an audit trail is that someone
    # had to state a purpose before elevating; an optional field would be left
    # empty exactly when it matters.
    g.add_argument(
        "--reason", required=True, help="why this grant is needed (recorded, required)"
    )
    sub.add_parser("revoke", help="remove the grant now")
    sub.add_parser("status", help="show whether a grant is outstanding")
    a = ap.parse_args()

    if a.cmd == "grant":
        if a.minutes < 1 or a.minutes > 480:
            sys.exit(
                "--minutes must be between 1 and 480; a grant longer than "
                "a working day is a standing privilege wearing a costume"
            )
        return cmd_grant(a.user, a.minutes, a.reason)
    if a.cmd == "revoke":
        return cmd_revoke()
    return cmd_status()


if __name__ == "__main__":
    sys.exit(main())
