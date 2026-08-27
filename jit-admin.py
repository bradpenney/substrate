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
import json
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


def sh(args: list[str], check=True, context: str | None = None, **kw) -> subprocess.CompletedProcess:
    if context and args and args[0] == "kubectl":
        args = [args[0], f"--context={context}"] + args[1:]
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    if check and r.returncode:
        sys.exit(f"command failed: {' '.join(args)}\n{r.stderr.strip()}")
    return r


def current() -> dict | None:
    r = sh(["kubectl", "get", "clusterrolebinding", BINDING, "-o", "json"], check=False)
    return json.loads(r.stdout) if r.returncode == 0 else None


def cmd_status() -> int:
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


def cmd_grant(user: str, minutes: int) -> int:
    if current():
        sys.exit(f"a grant is already outstanding; run `{sys.argv[0]} status` "
                 f"or revoke it first")
    end = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)
    exp = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    crb = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {
            "name": BINDING,
            "annotations": {
                ANNOTATION: exp,
                "jit.bradpenney.io/granted-at":
                    dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "labels": {"rbac.bradpenney.io/jit": "true"},
        },
        "subjects": [{"kind": "User", "name": user,
                      "apiGroup": "rbac.authorization.k8s.io"}],
        "roleRef": {"kind": "ClusterRole", "name": "platform-admin",
                    "apiGroup": "rbac.authorization.k8s.io"},
    }
    sh(["kubectl", "apply", "-f", "-"], input=json.dumps(crb),
       context=BREAK_GLASS_CONTEXT)
    print(f"  granted platform-admin to {user} until {exp} ({minutes}m)")
    print(f"  revoke early: {sys.argv[0]} revoke")
    return 0


def cmd_revoke() -> int:
    if not current():
        print("  no outstanding grant")
        return 0
    sh(["kubectl", "delete", "clusterrolebinding", BINDING],
       context=BREAK_GLASS_CONTEXT)
    print("  revoked")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grant", help="grant platform-admin for a bounded window")
    g.add_argument("user")
    g.add_argument("--minutes", type=int, default=30,
                   help="grant window (default 30)")
    sub.add_parser("revoke", help="remove the grant now")
    sub.add_parser("status", help="show whether a grant is outstanding")
    a = ap.parse_args()

    if a.cmd == "grant":
        if a.minutes < 1 or a.minutes > 480:
            sys.exit("--minutes must be between 1 and 480; a grant longer than "
                     "a working day is a standing privilege wearing a costume")
        return cmd_grant(a.user, a.minutes)
    if a.cmd == "revoke":
        return cmd_revoke()
    return cmd_status()


if __name__ == "__main__":
    sys.exit(main())
