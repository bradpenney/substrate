#!/bin/sh
"exec" "$(cd $(dirname $0); pwd)/.venv/bin/python3" "-u" "$0" "$@"
"""Render one node's cloud-config to stdout. Read-only, no side effects.

WHY THIS EXISTS AS A SEPARATE CLI
---------------------------------
Rendering was reachable only by importing `provision.py` and calling a function.
That is fine for Python callers and useless for anyone else, which matters for
two reasons that arrived together:

**The golden files need a stable seam.** `tests/test_golden_cloud_config.py`
asserts that the renderer reproduces committed, byte-exact cloud-config. If that
test imported `provision`, replacing the renderer with a Rust binary would mean
rewriting the test. Because it shells out to THIS command instead, the port is a
one-line change to which executable is invoked — the contract is the CLI, not
the Python module (ADR-093).

**`provision.py` has no argparse and its `main()` provisions the fleet.** Adding
a `render` subcommand there would put a read-only operation behind an entry
point whose default behaviour is destructive. A separate command cannot be
mistaken for one.

WHY IT PRINTS RATHER THAN WRITES
--------------------------------
stdout composes: diff it, pipe it, capture it in a test. A `--output` flag would
invite a caller to write over the file the goldens live in.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not mint a join token — `--join-token` takes one as an argument. Minting
requires a running bootstrap node, and a renderer that reaches out to a cluster
is no longer a pure function of its inputs, which is the property the golden
files depend on.

Requires PyYAML and Jinja2: run through the repo venv (`.venv/bin/python3`).
"""

import argparse
import sys

import hosts
import provision


def build_parser() -> argparse.ArgumentParser:
    """Define the CLI.

    Split out from main() so tests can inspect the interface without running
    it — the argument names ARE the contract a Rust reimplementation has to
    honour, so they are worth asserting on directly.
    """
    parser = argparse.ArgumentParser(
        description="Render one node's cloud-config to stdout.",
        epilog=(
            "Reads the site config from $SUBSTRATE_SITE_FILE, or site.yml. "
            "Every value below overrides the fleet defaults for this one node."
        ),
    )
    parser.add_argument("--name", required=True, help="node hostname")
    parser.add_argument("--ip", required=True, help="static address")
    # REQUIRED, like --name and --ip. A node rendered without a failure domain
    # joins the cluster carrying no statement of which machine it sits on, and
    # no scheduling constraint can then express "not both of these on one host".
    # Defaulting it would make that the quiet outcome of forgetting a flag.
    parser.add_argument(
        "--hypervisor",
        required=True,
        help="hypervisor carrying this node — its failure domain",
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="render the bootstrap controller (no join token is used)",
    )
    parser.add_argument("--memory-mib", type=int, help="override the default RAM")
    parser.add_argument("--vcpu", type=int, help="override the default vCPU count")
    parser.add_argument(
        "--storage-disk-gb",
        type=int,
        help="dedicated Longhorn disk in GB (ADR-050); omit for none",
    )
    parser.add_argument(
        "--join-token",
        help="token minted from the bootstrap node; omit for the bootstrap node",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Render and print. Returns a process exit code."""
    args = build_parser().parse_args(argv)

    if args.bootstrap and args.join_token:
        # The bootstrap node comes up alone and joins nothing. Accepting a token
        # here would render a config that silently contradicts itself.
        print(
            "error: --bootstrap and --join-token are mutually exclusive",
            file=sys.stderr,
        )
        return 2

    vm = hosts.VM(
        name=args.name,
        static_ip=args.ip,
        hypervisor=args.hypervisor,
        bootstrap=args.bootstrap,
        memory_mib=args.memory_mib,
        vcpu=args.vcpu,
        storage_disk_gb=args.storage_disk_gb,
    )
    # end="" because render_cloud_config already terminates with a newline;
    # print's default would add a second one and every golden would be off by
    # a byte.
    print(provision.render_cloud_config(vm, args.join_token), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
