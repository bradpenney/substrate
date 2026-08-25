#!/usr/bin/env python3
"""
Assert the Jinja cloud-config template renders BYTE-IDENTICAL output to
provision.py's render_cloud_config().

This is the sharpest correctness check on the Ansible port. The cloud-config is
where every Kairos gotcha lives — `stages` vs `write_files`, unquoted octal
permissions, `Name=` vs `Type=ether` — and all three fail SILENTLY when wrong:
a mis-set permission means the file simply isn't written, and the node comes up
with no network and no error anywhere. A subtle divergence between the two
implementations would produce two different clusters while both runs reported
success, which is exactly what the destroy-and-rebuild gate is supposed to rule
out.

Renders both for a bootstrap node (no token) and a joining node (with token),
and diffs.
"""

from __future__ import annotations

import difflib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from jinja2 import Environment, FileSystemLoader

import hosts as py
import provision
import inventory

TEMPLATE_DIR = Path(__file__).parent / "roles" / "k0s_node" / "templates"


def render_jinja(vm_name: str, static_ip: str, join_token: str | None,
                 hostvars: dict | None = None) -> str:
    # Group vars come from the dynamic inventory — the same source the playbook
    # itself uses, so this compares what Ansible would ACTUALLY render rather
    # than a hand-maintained approximation of it.
    gvars = dict(inventory.build()["all"]["vars"])

    # Ansible's template module defaults to trim_blocks=True. Matching it here
    # is essential — otherwise this test would compare output the playbook
    # never actually produces.
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=False,
        keep_trailing_newline=True,
    )
    template = env.get_template("cloud-config.yaml.j2")
    # Pass the whole group-var set rather than hand-picking names. Cherry-picking
    # meant that adding `admin_user` to the template silently rendered it EMPTY
    # here — the harness looked fine while comparing output the playbook would
    # never produce. Splatting keeps this honest as the template grows.
    return template.render(
        inventory_hostname=vm_name,
        static_ip=static_ip,
        join_token=join_token,
        **gvars,
        # Per-NODE vars, which the playbook gets from the inventory's hostvars.
        # Without these the storage-disk branch renders empty on the Jinja side
        # and the comparison passes by comparing two absences.
        **(hostvars or {}),
    )


def compare(label: str, vm: py.VM, join_token: str | None) -> bool:
    expected = provision.render_cloud_config(vm, join_token)
    hostvars = {}
    if vm.storage_disk_gb is not None:
        hostvars["storage_disk_gb"] = vm.storage_disk_gb
    actual = render_jinja(vm.name, vm.static_ip, join_token, hostvars)
    if expected == actual:
        print(f"  [ok ] {label}: byte-identical ({len(actual)} bytes)")
        return True
    print(f"  [BUG] {label}: OUTPUT DIFFERS")
    for line in difflib.unified_diff(
        expected.splitlines(keepends=True),
        actual.splitlines(keepends=True),
        fromfile="provision.py",
        tofile="cloud-config.yaml.j2",
    ):
        print("    " + line.rstrip("\n"))
    return False


def main() -> int:
    ok = True
    ok &= compare(
        "bootstrap node (no token)",
        py.VM(name="test-boot", static_ip="192.0.2.10", bootstrap=True),
        None,
    )
    ok &= compare(
        "joining node (with token)",
        py.VM(name="test-join", static_ip="192.0.2.11", memory_mib=10240, vcpu=4),
        "TESTTOKEN123abc",
    )
    # Exercise the OPTIONAL branches too. A guard that only covers the default
    # path is half a guard: the pullSecret indentation bug was caught only
    # because the private-artifact path was tested, and the storage-disk branch
    # would otherwise render empty on BOTH sides and "match".
    ok &= compare(
        "node WITH a Longhorn disk (ADR-050)",
        py.VM(name="test-store", static_ip="192.0.2.12", storage_disk_gb=200),
        "TESTTOKEN123abc",
    )
    if not ok:
        print("\nThe two implementations would build DIFFERENT nodes. Fix before running the gate.")
        return 1
    print("cloud-config renderers agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
