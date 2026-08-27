#!/bin/sh
"exec" "$(cd $(dirname $0)/..; pwd)/.venv/bin/python3" "$0" "$@"
"""
Dynamic Ansible inventory, built from ../site.yml.

THE SHEBANG ABOVE IS DELIBERATE AND LOAD-BEARING.
Ansible executes an inventory script as a subprocess, so it runs under the
script's OWN shebang — not under the interpreter running ansible-playbook.
With a plain `#!/usr/bin/env python3` that meant system python, which has no
PyYAML here, so this script died on import... and Ansible's script-inventory
plugin SWALLOWED the error and returned an EMPTY inventory. A playbook then
runs successfully against zero hosts, which looks like everything being
skipped rather than like a failure.

The two lines above are a sh/Python polyglot: sh sees a command that re-execs
this file through the repo venv; Python sees a harmless string literal. That
keeps the script self-contained — no dependency on what the ambient python3
happens to have installed.

WHY DYNAMIC RATHER THAN A STATIC inventory.yml
Everything site-specific — LAN addresses, admin username, storage pool names,
which machine hosts what — lives in `../site.yml`, which is GITIGNORED (the
committed template is `../site.example.yml`). That keeps a publishable repo
from doubling as a map of a private network. A static YAML inventory can't
source those values at parse time, so the inventory is generated instead.

WHY BOTH IMPLEMENTATIONS SHARE site.yml
Reading the same data makes the two fleet definitions impossible to drift
apart, rather than merely checked for drift afterwards. The independence that
matters for the destroy-and-rebuild gate is the BUILD LOGIC — written twice
(provision.py vs these roles) and verified byte-identical by check_render.py.
Sharing the inputs is what isolates the variable actually under test.

NOTE: the k0s nodes are NOT Ansible connection targets. They deliberately have
no SSH-based management path once running. They appear here only so each gets
its own play iteration and host_vars; every task that touches them runs
`delegate_to: {{ hypervisor }}`.

Usage is the standard dynamic-inventory contract:
    ./inventory.py --list
    ./inventory.py --host <name>
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import siteconfig


def _pull_secret_b64(flux: dict) -> str:
    """dockerconfigjson for the private config artifact, or "" if public.

    The ONE irreducible bootstrap credential (ADR-019): Flux needs it to pull
    the config artifact, which happens before External Secrets exists.
    """
    if not flux.get("ghcr_token"):
        return ""
    import base64
    import json
    registry = flux["oci_repository"].split("/")[0]
    auth = base64.b64encode(
        f"{flux['ghcr_username']}:{flux['ghcr_token']}".encode()).decode()
    cfg = json.dumps({"auths": {registry: {"auth": auth}}})
    return base64.b64encode(cfg.encode()).decode()


def build() -> dict:
    cfg = siteconfig.load()
    net = cfg["network"]
    defaults = cfg["defaults"]

    hypervisor_hosts = {}
    for name, hcfg in cfg["hypervisors"].items():
        hvars = {
            "disk_pool": hcfg["disk_pool"],
            "pool_needs_nocow": bool(hcfg.get("pool_needs_nocow", False)),
        }
        target = hcfg.get("ssh_target")
        if target is None:
            # Ansible runs ON this machine — no SSH round-trip to itself.
            hvars["ansible_connection"] = "local"
        else:
            user, _, host = target.partition("@")
            hvars["ansible_host"] = host or user
            if host:
                hvars["ansible_user"] = user
        hypervisor_hosts[name] = hvars

    bootstrap, joiners, node_vars = [], [], {}
    for name, ncfg in cfg["nodes"].items():
        (bootstrap if ncfg.get("bootstrap") else joiners).append(name)
        node_vars[name] = {
            "hypervisor": ncfg["hypervisor"],
            "static_ip": ncfg["ip"],
            "memory_mib": ncfg.get("memory_mib", defaults["memory_mib"]),
            "vcpu": ncfg.get("vcpu", defaults["vcpu"]),
            # ADR-050. Falls back to the fleet default, then to 0 (no disk).
            "storage_disk_gb": ncfg.get(
                "storage_disk_gb", defaults.get("storage_disk_gb", 0) or 0),
        }

    hostvars = {**hypervisor_hosts, **node_vars}

    return {
        "_meta": {"hostvars": hostvars},
        "all": {
            "children": ["hypervisors", "k0s_bootstrap", "k0s_joiners", "k0s_nodes"],
            "vars": {
                "admin_user": cfg["admin_user"],
                "gateway": net["gateway"],
                "dns_servers": list(net["dns_servers"]),
                "network_bridge": net["bridge"],
                # NEVER match the node NIC on Type=ether: that also matches the
                # CNI's veth pairs, so systemd-networkd claims kube-router's pod
                # interfaces and pod networking dies completely.
                "primary_nic": net["primary_nic"],
                # Resolved at runtime from the environment or
                # ~/.ssh/id_ed25519.pub — never stored, so the repo carries
                # nobody's identity. hosts.py resolves the same three sources
                # in the same order.
                "ssh_public_key": siteconfig.resolve_ssh_public_key(),
                "kairos_iso_url": cfg["kairos"]["iso_url"],
                "kairos_iso_sha256": cfg["kairos"]["iso_sha256"],
                "k0s_args": list(cfg["k0s"]["args"]),
            # Empty string when no LB is configured — Jinja tests truthiness.
            "control_plane_vip": (cfg.get("control_plane") or {}).get("vip") or "",
                "k0s_token_expiry": cfg["k0s"]["token_expiry"],
                "vm_memory_mib": defaults["memory_mib"],
                "vm_vcpu": defaults["vcpu"],
                "vm_disk_gb": defaults["disk_gb"],
            # ADR-050: dedicated Longhorn disk. 0 = do not attach one.
            "vm_storage_disk_gb": int(cfg["defaults"].get("storage_disk_gb", 0) or 0),
                "iso_pool": cfg["libvirt"]["iso_pool"],
                "iso_pool_path": cfg["libvirt"]["iso_pool_path"],
                # GitOps bootstrap (ADR-018). The pull secret is pre-rendered
                # here rather than in Jinja: base64-of-JSON-of-base64 is
                # unreadable as a template expression, and getting it subtly
                # wrong would fail at node boot rather than in CI.
                "flux": cfg["flux"],
                "flux_pull_secret_b64": _pull_secret_b64(cfg["flux"]),
                # External Secrets bootstrap credential (ADR-055). Absent from
                # the Ansible path until 2026-08-26, which check_render.py
                # caught: an Ansible-built cluster came up with no Infisical
                # credentials, so cert-manager could not solve DNS-01 and the
                # PV backups had no remote — the exact silent failure the
                # bootstrap manifest exists to prevent.
                "external_secrets": cfg.get("external_secrets") or {},
                # API server hardening: secrets-at-rest encryption key and
                # audit log settings (ADR-066).
                "api_hardening": cfg.get("api_hardening") or {},
                # Lifecycle timeouts (seconds).
                "install_wait_timeout": 900,
                "ssh_wait_timeout": 300,
                "poll_interval": 10,
                "node_ready_timeout": 600,
                "create_retries": 3,
            },
        },
        "hypervisors": {"hosts": sorted(hypervisor_hosts)},
        # Exactly one bootstrap node — siteconfig.load() enforces this. It comes
        # up first and alone; every other node joins with a token minted from
        # it. Matters only for the initial build.
        "k0s_bootstrap": {"hosts": bootstrap},
        "k0s_joiners": {"hosts": joiners},
        "k0s_nodes": {"children": ["k0s_bootstrap", "k0s_joiners"]},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--host")
    args = parser.parse_args()

    data = build()
    if args.host:
        print(json.dumps(data["_meta"]["hostvars"].get(args.host, {}), indent=2))
    else:
        print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
