#!/usr/bin/env python3
"""
Assert that hosts.py and ansible/inventory.py INTERPRET site.yml identically.

WHAT THIS CHECKS, AND WHY IT CHANGED
Originally the two implementations each declared the fleet separately, and this
script caught them disagreeing. They now both read `../site.yml`, so the raw
data can no longer drift — that class of bug is gone by construction, which is
strictly better than detecting it after the fact.

What remains checkable, and still genuinely worth checking, is INTERPRETATION.
Each side independently decides how to apply defaults, how to split nodes into
bootstrap vs joiners, and how to turn an `ssh_target` into connection settings.
Those are separate code paths that can disagree while reading identical input —
and if they do, the destroy-and-rebuild gate would compare two runs that built
materially different clusters while reporting both succeeded.

Run by site.yml before anything is built. Exits non-zero listing every
difference.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import hosts as py
import inventory as ans


def from_python() -> dict:
    """The fleet as hosts.py interprets it."""
    vms = {}
    for host in py.HOSTS:
        for vm in host.vms:
            vms[vm.name] = {
                "hypervisor": host.name,
                "static_ip": vm.static_ip,
                "bootstrap": vm.bootstrap,
                # Defaults applied here, independently of the Ansible side.
                "memory_mib": vm.memory_mib or py.VM_MEMORY_MIB,
                "vcpu": vm.vcpu or py.VM_VCPU,
            }
    return {
        "vms": vms,
        "hypervisors": {
            h.name: {
                "disk_pool": h.disk_pool,
                "pool_needs_nocow": h.pool_needs_nocow,
                "local": h.ssh_target is None,
            }
            for h in py.HOSTS
        },
        "settings": {
            "admin_user": py.ADMIN_USER,
            "gateway": py.GATEWAY,
            "dns_servers": list(py.DNS_SERVERS),
            "network_bridge": py.NETWORK_BRIDGE,
            "primary_nic": py.PRIMARY_NIC,
            "ssh_public_key": py.SSH_PUBLIC_KEY,
            "kairos_iso_url": py.KAIROS_ISO_URL,
            "kairos_iso_sha256": py.KAIROS_ISO_SHA256,
            "k0s_args": list(py.K0S_ARGS),
            "k0s_token_expiry": py.K0S_TOKEN_EXPIRY,
            "vm_disk_gb": py.VM_DISK_GB,
            "iso_pool": py.ISO_POOL,
            "iso_pool_path": py.ISO_POOL_PATH,
        },
    }


def from_ansible() -> dict:
    """The fleet as the dynamic inventory interprets it."""
    data = ans.build()
    hostvars = data["_meta"]["hostvars"]
    gvars = data["all"]["vars"]
    bootstrap = set(data["k0s_bootstrap"]["hosts"])

    vms = {}
    for name in data["k0s_bootstrap"]["hosts"] + data["k0s_joiners"]["hosts"]:
        hv = hostvars[name]
        vms[name] = {
            "hypervisor": hv["hypervisor"],
            "static_ip": hv["static_ip"],
            "bootstrap": name in bootstrap,
            "memory_mib": hv["memory_mib"],
            "vcpu": hv["vcpu"],
        }

    return {
        "vms": vms,
        "hypervisors": {
            name: {
                "disk_pool": hostvars[name]["disk_pool"],
                "pool_needs_nocow": hostvars[name]["pool_needs_nocow"],
                "local": hostvars[name].get("ansible_connection") == "local",
            }
            for name in data["hypervisors"]["hosts"]
        },
        "settings": {
            "admin_user": gvars["admin_user"],
            "gateway": gvars["gateway"],
            "dns_servers": list(gvars["dns_servers"]),
            "network_bridge": gvars["network_bridge"],
            "primary_nic": gvars["primary_nic"],
            "ssh_public_key": gvars["ssh_public_key"],
            "kairos_iso_url": gvars["kairos_iso_url"],
            "kairos_iso_sha256": gvars["kairos_iso_sha256"],
            "k0s_args": list(gvars["k0s_args"]),
            "k0s_token_expiry": gvars["k0s_token_expiry"],
            "vm_disk_gb": gvars["vm_disk_gb"],
            "iso_pool": gvars["iso_pool"],
            "iso_pool_path": gvars["iso_pool_path"],
        },
    }


def diff(a: dict, b: dict, path: str = "") -> list[str]:
    """Every leaf-level disagreement, reported with a readable path."""
    problems = []
    for key in sorted(set(a) | set(b)):
        where = f"{path}.{key}" if path else key
        if key not in a:
            problems.append(f"  {where}: absent in hosts.py (inventory has {b[key]!r})")
        elif key not in b:
            problems.append(f"  {where}: absent in inventory.py (hosts.py has {a[key]!r})")
        elif isinstance(a[key], dict) and isinstance(b[key], dict):
            problems.extend(diff(a[key], b[key], where))
        elif a[key] != b[key]:
            problems.append(f"  {where}: hosts.py={a[key]!r} vs inventory.py={b[key]!r}")
    return problems


def main() -> int:
    problems = diff(from_python(), from_ansible())
    if problems:
        print("INTERPRETATION DRIFT — hosts.py and inventory.py read site.yml differently:")
        print("\n".join(problems))
        print("\nBoth read the same site.yml, so this is a logic difference, not a")
        print("data one. Left unfixed, the two bootstrap methods would build")
        print("different clusters and the gate would compare them as if identical.")
        return 1
    n = len(from_python()["vms"])
    print(f"both implementations interpret site.yml identically ({n} VMs, all settings match)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
