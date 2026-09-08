#!/usr/bin/env python3
"""Regenerate the committed golden cloud-config files. Run deliberately.

WHAT A GOLDEN FILE IS FOR
-------------------------
`tests/golden/*.yaml` is the byte-exact cloud-config each node archetype must
receive. The renderer is asserted against it, so any change to the rendered
output shows up as a reviewable diff instead of passing silently.

This replaces the guarantee that `ansible/check_render.py` provided (ADR-020:
Python and Jinja must render byte-identical output) with one that survives
Ansible's removal — and that catches a failure mode the old one could not.
**Two implementations agreeing does not prove either is correct.** They can
agree on a wrong answer, and check_render.py reports "renderers agree" when
they do. A golden pins the actual bytes.

WHY THIS SCRIPT CORROBORATES BEFORE WRITING
-------------------------------------------
A golden captured from one implementation is only as good as that
implementation. So while BOTH still exist, this refuses to write a golden
unless the Python renderer and the Jinja template independently produce the
same bytes. That is the moment there are two witnesses to what is correct, and
it is the reason to capture the goldens now rather than after Ansible goes.

When Ansible is removed, delete the Jinja half of this script. The committed
goldens keep the provenance: every one of them was agreed by two independent
implementations on the day it was written.

WHY REGENERATION IS A SCRIPT AND NOT A TEST FLAG
------------------------------------------------
The forcing function the dual implementation gave us was that a change had to
be made TWICE, deliberately. A `--update-snapshots` flag on the test suite
would replace that with a reflex. Running this is a separate, explicit act, and
the diff it produces is meant to be read.

Usage:
    tests/golden/regenerate.py           # rewrite every golden
    tests/golden/regenerate.py --check   # what the test does, without pytest
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
GOLDEN_DIR = Path(__file__).resolve().parent
FIXTURE = REPO / "tests" / "fixtures" / "site.yml"

# The one SSH key every golden is rendered against. Pinned here rather than
# taken from the environment: the key lands in the rendered output, so a
# developer's real key would otherwise be written into a committed file.
FIXTURE_SSH_KEY = "ssh-ed25519 AAAATESTKEYONLY test@fixture"

# A fixed token. Minting a real one needs a running bootstrap node, and a
# renderer that reaches out to a cluster is not a pure function of its inputs.
FIXTURE_TOKEN = "TESTTOKEN123abc"

# The archetypes are declared ONCE, in archetypes.yaml, and read by both this
# generator and crates/substrate/tests/golden.rs. Declaring them twice would let
# the Python and Rust harnesses drift into testing different things while both
# reported success — the exact failure this directory exists to close.
ARCHETYPES_FILE = GOLDEN_DIR / "archetypes.yaml"


def _load_archetypes() -> list[dict]:
    """Read the shared archetype declaration."""
    import yaml  # imported here so --help works without the venv

    return yaml.safe_load(ARCHETYPES_FILE.read_text())


ARCHETYPES = _load_archetypes()


def site_file_for(archetype: dict, stack: list) -> str:
    """Return the site.yml path to render this archetype against.

    The private-artifact variant is DERIVED from the committed fixture rather
    than being a second committed file. A copy would drift the moment a key is
    added to one and not the other, and the two would then differ in ways the
    archetype was never meant to test.
    """
    if not archetype["private_artifact"]:
        return str(FIXTURE)

    import yaml  # imported here so --help works without the venv

    cfg = yaml.safe_load(FIXTURE.read_text())
    cfg["flux"]["ghcr_token"] = "fake-ghcr-token"
    tmp = tempfile.NamedTemporaryFile(  # pylint: disable=consider-using-with
        "w", suffix=".yml", delete=False
    )
    yaml.safe_dump(cfg, tmp)
    tmp.close()
    stack.append(Path(tmp.name))
    return tmp.name


def env_for(site_file: str) -> dict:
    """Environment that makes rendering deterministic.

    Both variables are set rather than defaulted. `conftest.py` uses
    `setdefault` so the suite can be pointed at a real site.yml, which is right
    for the other tests and wrong here: a golden rendered from the real config
    would commit real addresses and a real key into a public repo.
    """
    env = dict(os.environ)
    env["SUBSTRATE_SITE_FILE"] = site_file
    env["HOMELAB_SSH_PUBLIC_KEY"] = FIXTURE_SSH_KEY
    return env


def render_python(archetype: dict, site_file: str) -> str:
    """Render through the CLI, not by importing provision.

    The CLI is the contract a Rust implementation will honour, so the goldens
    are pinned to it. Swapping the renderer becomes a change to this one line.
    """
    proc = subprocess.run(
        [sys.executable, str(REPO / "render-cloud-config.py"), *archetype["args"]],
        capture_output=True,
        text=True,
        env=env_for(site_file),
        check=True,
    )
    return proc.stdout


def render_jinja(archetype: dict, site_file: str) -> str:
    """Render the same node through Ansible's template, in a subprocess.

    A subprocess because `hosts` and `inventory` read the site config at IMPORT
    time; the private-artifact archetype needs a different config, and an
    already-imported module cannot be pointed at one.
    """
    proc = subprocess.run(
        [sys.executable, str(Path(__file__)), "--emit-jinja", json.dumps(archetype)],
        capture_output=True,
        text=True,
        env=env_for(site_file),
        check=True,
    )
    return proc.stdout


def _emit_jinja(archetype: dict) -> int:
    """Internal: the subprocess half of render_jinja(). Not for direct use."""
    sys.path.insert(0, str(REPO))
    sys.path.insert(0, str(REPO / "ansible"))
    import check_render  # pylint: disable=import-error
    import hosts  # pylint: disable=import-error

    parsed = {}
    args = list(archetype["args"])
    while args:
        key = args.pop(0).lstrip("-").replace("-", "_")
        if key == "bootstrap":
            parsed["bootstrap"] = True
            continue
        parsed[key] = args.pop(0)

    vm = hosts.VM(
        name=parsed["name"],
        static_ip=parsed["ip"],
        hypervisor=parsed["hypervisor"],
        bootstrap=parsed.get("bootstrap", False),
        memory_mib=int(parsed["memory_mib"]) if "memory_mib" in parsed else None,
        vcpu=int(parsed["vcpu"]) if "vcpu" in parsed else None,
        storage_disk_gb=(
            int(parsed["storage_disk_gb"]) if "storage_disk_gb" in parsed else None
        ),
    )
    hostvars = {}
    if vm.storage_disk_gb is not None:
        hostvars["storage_disk_gb"] = vm.storage_disk_gb
    # Per-node, and unconditional: the playbook gets it from the inventory's
    # hostvars, and omitting it here would render an empty label on the Jinja
    # side only — a divergence this corroboration exists to catch.
    hostvars["hypervisor"] = vm.hypervisor
    sys.stdout.write(
        check_render.render_jinja(
            vm.name, vm.static_ip, parsed.get("join_token"), hostvars
        )
    )
    return 0


def build(check_only: bool) -> int:
    """Render every archetype, corroborate, then write or compare."""
    failures = []
    for archetype in ARCHETYPES:
        stack: list[Path] = []
        try:
            site_file = site_file_for(archetype, stack)
            python_out = render_python(archetype, site_file)
            jinja_out = render_jinja(archetype, site_file)

            if python_out != jinja_out:
                # Refuse to capture. A golden written from one implementation
                # while the other disagrees records a guess, not a fact.
                failures.append(
                    f"{archetype['file']}: renderers DISAGREE — refusing to "
                    f"capture. Run ansible/check_render.py for the diff."
                )
                continue

            target = GOLDEN_DIR / archetype["file"]
            if check_only:
                if not target.exists():
                    failures.append(f"{archetype['file']}: missing")
                elif target.read_text() != python_out:
                    failures.append(f"{archetype['file']}: DIFFERS from the renderer")
                else:
                    print(f"  [ok ] {archetype['file']}")
            else:
                changed = not target.exists() or target.read_text() != python_out
                target.write_text(python_out)
                state = "updated" if changed else "unchanged"
                print(f"  [{state:9}] {archetype['file']} — {archetype['why']}")
        finally:
            for path in stack:
                path.unlink(missing_ok=True)

    if failures:
        for line in failures:
            print(f"  [BUG] {line}")
        return 1
    return 0


def main() -> int:
    """Parse arguments and run."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare without writing")
    parser.add_argument("--emit-jinja", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.emit_jinja:
        return _emit_jinja(json.loads(args.emit_jinja))

    if not args.check:
        print(
            "Regenerating goldens. READ THE DIFF — these files are the "
            "definition of a correct node.\n"
        )
    return build(check_only=args.check)


if __name__ == "__main__":
    sys.exit(main())
