#!/usr/bin/env python3
"""Enforce coverage per module, because one global number is the wrong shape here.

Two kinds of code live in this repo and they are verified differently:

  LOGIC        decisions taken from data — parse a config, compare two
               fingerprints, decide whether a namespace is compliant. A unit test
               is the right tool and 95% is a fair bar.

  ORCHESTRATION  virsh, ssh, scp, install waits, reboot loops. Driving these to
               95% means stubbing a hypervisor, and a test that passes then
               proves the mock matches the author's belief about the code rather
               than that the code is right. These are covered end to end by
               `gate.py rebuild`, which destroys and rebuilds the fleet with BOTH
               bootstrap implementations and compares the resulting clusters.

Reporting them as one number would either understate the testing (a real 36%
while the orchestration is exercised for real, twice) or invite mocking a
hypervisor to move a percentage. So the gate is per-module and the badge reports
the logic figure, named as such.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Verified by unit tests. Raise these; never lower one to make CI pass.
LOGIC_TARGET = 95
LOGIC_MODULES = [
    "siteconfig.py",
    "hosts.py",
    "models.py",
    "posture-check.py",
    "jit-admin.py",
    "create-client-cert.py",
    "deploy-cplb.py",
    "deploy_updates.py",
]

# Verified by the destroy-and-rebuild gate instead. Reported, never gated.
ORCHESTRATION_MODULES = ["gate.py", "provision.py"]


def main() -> int:
    data = json.loads(
        Path(sys.argv[1] if len(sys.argv) > 1 else "coverage.json").read_text()
    )
    files = {Path(k).name: v for k, v in data["files"].items()}

    failures = []
    covered = missing = 0

    print("LOGIC — unit tested, gated at {}%".format(LOGIC_TARGET))
    for name in LOGIC_MODULES:
        f = files.get(name)
        if f is None:
            failures.append(f"{name}: not present in the coverage report")
            continue
        s = f["summary"]
        pct = s["percent_covered"]
        covered += s["covered_lines"]
        missing += s["missing_lines"]
        flag = "ok  " if pct >= LOGIC_TARGET else "FAIL"
        print(f"  [{flag}] {name:<24} {pct:5.1f}%  ({s['missing_lines']} uncovered)")
        if pct < LOGIC_TARGET:
            failures.append(
                f"{name} at {pct:.1f}%, below the {LOGIC_TARGET}% logic bar"
            )

    total = covered + missing
    logic_pct = (covered / total * 100) if total else 0.0
    print(f"  logic total: {logic_pct:.1f}%")

    print("\nORCHESTRATION — covered by `gate.py rebuild`, reported not gated")
    for name in ORCHESTRATION_MODULES:
        f = files.get(name)
        if f:
            s = f["summary"]
            print(
                f"  [    ] {name:<24} {s['percent_covered']:5.1f}%  ({s['missing_lines']} uncovered)"
            )

    Path("logic-coverage.txt").write_text(f"{round(logic_pct)}\n")

    if failures:
        print("\n" + "\n".join(f"FAIL: {f}" for f in failures), file=sys.stderr)
        return 1
    print(f"\nall logic modules at or above {LOGIC_TARGET}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
