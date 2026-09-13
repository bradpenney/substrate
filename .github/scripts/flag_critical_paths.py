#!/usr/bin/env python3
"""Comment on a pull request that touches root-executing or supply-chain files.

WHY THIS IS NOT JUST A FAILING CHECK
A red X teaches nothing and gets clicked past. The useful information is WHICH
files and WHY: the risk is not "a file changed", it is "this file becomes a root
shell on both hypervisors tonight". CODEOWNERS requests the reviewer; this
tells them what they are reviewing for.

WHY IT DOES NOT BLOCK
Blocking would make every routine change to a unit file need a ceremony, and a
control that fires constantly gets routed around. This raises the cost of NOT
noticing, which is the actual failure mode — nobody has ever merged a root-shell
change on purpose.
"""

from __future__ import annotations

import os
import subprocess
import sys

# Ordered most-alarming first, so the comment leads with the worst thing.
CRITICAL = [
    (
        "systemd/",
        "runs as root on a hypervisor, on a timer, forever",
    ),
    (
        "versions.yml",
        "pins the CHECKSUMS of every binary installed on nodes and hypervisors "
        "— changing one changes which bytes execute",
    ),
    (
        ".github/workflows/",
        "CI has write access to this repository and signs the artifacts the "
        "cluster trusts",
    ),
    (
        "crates/substrate-core/src/updates.rs",
        "composes the privileged installer that runs under sudo on both hosts",
    ),
    (
        "crates/substrate-core/src/observability/",
        "composes the privileged installer that runs under sudo on both hosts",
    ),
    (
        "crates/substrate-core/src/cplb.rs",
        "composes the privileged installer that runs under sudo on both hosts",
    ),
    (
        "notify.sh",
        "the alerting path every other unit depends on — its silent failure "
        "hides all the others",
    ),
    (
        "crates/substrate-core/src/render.rs",
        "renders the cosign identity the cluster verifies against, and the SSH "
        "key baked into every node",
    ),
    (
        "crates/substrate-core/src/provision.rs",
        "creates VMs, mints join tokens and rewrites the operator's kubeconfig",
    ),
    ("crates/substrate-core/src/config.rs", "defines what a valid site configuration is"),
    (".sh", "shell executed on a hypervisor"),
]


def changed_files(base: str, head: str) -> list[str]:
    """Files the pull request touches."""
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [f for f in out.stdout.splitlines() if f.strip()]


def classify(files: list[str]) -> list[tuple[str, str]]:
    """Pair each critical file with the reason it is critical.

    First match wins, so a file under `systemd/` is reported as a unit rather
    than falling through to the generic shell rule.
    """
    found = []
    for path in sorted(files):
        for marker, why in CRITICAL:
            if marker.endswith("/") and path.startswith(marker):
                found.append((path, why))
                break
            if not marker.endswith("/") and (path == marker or path.endswith(marker)):
                found.append((path, why))
                break
    return found


def comment_body(found: list[tuple[str, str]]) -> str:
    """The review note itself."""
    lines = [
        "### ⚠️ This pull request changes the root-executing surface",
        "",
        "These files run as root on a hypervisor, or decide what does. "
        "`substrate` is public, so opening a pull request is not the same as "
        "being trusted with root on these machines.",
        "",
        "| file | why it matters |",
        "|---|---|",
    ]
    for path, why in found:
        lines.append(f"| `{path}` | {why} |")
    lines += [
        "",
        "**Reviewing this means asking:** would I run this as root on both "
        "hypervisors, tonight, unattended? A change that is correct and a "
        "change that is safe to execute automatically are different questions.",
    ]
    return "\n".join(lines)


def main() -> int:
    """Comment if anything critical changed; say nothing otherwise."""
    base, head, pr = os.environ["BASE"], os.environ["HEAD"], os.environ["PR"]
    found = classify(changed_files(base, head))
    if not found:
        print("no critical paths touched")
        return 0

    print(f"{len(found)} critical path(s) touched")
    subprocess.run(
        ["gh", "pr", "comment", pr, "--body", comment_body(found)],
        check=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
