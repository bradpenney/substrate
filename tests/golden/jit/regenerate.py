#!/usr/bin/env python3
"""Regenerate the jit-admin goldens from the PYTHON implementation.

READ THE DIFF. This is a deliberate script and not a `--update-snapshots` flag,
for the same reason the cloud-config goldens are: regenerating on failure is how
a port stops being a port and becomes a rewrite that agrees with itself.

WHY GOLDENS RATHER THAN A DIFFERENTIAL
posture-check is read-only, so both implementations can run against the same
cluster and their output diffed. jit-admin WRITES — it grants cluster-admin —
and two write tools cannot be compared by running both, because both would
write. So the pure functions are pinned to files instead, exactly as the
renderer's are.

`invoker` and `source-host` are FIXED here rather than read from the
environment. The Python reads them inside each function; a value that varies by
machine cannot be a golden, which is why the Rust takes them as an argument.
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]))
import jit_admin_shim  # noqa: E402

jit = jit_admin_shim.load()

HERE = pathlib.Path(__file__).resolve().parent

# Fixed attribution, so the goldens describe the FUNCTIONS and not this laptop.
INVOKER = "brad"
HOST = "golden-host"

CASES = {
    "attribution.json": lambda: json.dumps(
        jit.attribution(
            user="brad",
            reason="investigating a failed backup",
            expires="2026-09-10T13:00:00Z",
            granted="2026-09-10T12:30:00Z",
        ),
        indent=2,
        sort_keys=True,
    ),
    "audit_grant.txt": lambda: jit.audit_line(
        "grant", "brad", "investigating a failed backup", "2026-09-10T12:30:00Z"
    ),
    # A revoke carries an EMPTY reason, and that empty string must survive into
    # the record rather than being dropped — the audit answers "who revoked
    # this" as much as "who granted it".
    "audit_revoke.txt": lambda: jit.audit_line(
        "revoke", "brad", "", "2026-09-10T12:45:00Z"
    ),
    # Reason text with a quote and a backslash: the record is JSON, and an
    # unescaped quote would produce a line that cannot be parsed back.
    "audit_awkward_reason.txt": lambda: jit.audit_line(
        "grant", "brad", 'he said "fix it" C:\\temp', "2026-09-10T12:30:00Z"
    ),
}


def main() -> int:
    # Patched ON THE REAL MODULE, so the functions under test are the shipped
    # ones and only their two environment lookups are pinned.
    jit.invoker = lambda: INVOKER
    jit.socket.gethostname = lambda: HOST
    for name, produce in CASES.items():
        (HERE / name).write_text(produce() + "\n")
        print(f"wrote {name}")
    print("\nREAD THE DIFF before committing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
