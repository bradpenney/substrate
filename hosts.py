"""
The k0s VM fleet, as provision.py sees it.

This module used to hold the fleet definition literally. It no longer does:
every site-specific value — addresses, admin username, storage pool names,
which machine hosts what — now lives in `site.yml`, which is GITIGNORED. What
you're reading is the generic shape; `site.example.yml` is the committed
template.

That split exists so this repo can be published without shipping a map of a
private network alongside a detailed description of how to build machines on
it. None of it was ever a credential; it's a "don't hand anyone the blueprint"
measure.

`ansible/inventory.yml` reads the same site.yml, so the two bootstrap
implementations cannot describe different fleets. What stays independent is the
BUILD LOGIC — written twice, and verified byte-identical by
ansible/check_render.py. That's the part the destroy-and-rebuild gate is
actually testing.

Requires PyYAML: run tooling through the repo venv (`.venv/bin/python3`).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import siteconfig

_CFG = siteconfig.load()


@dataclass
class VM:
    name: str
    static_ip: str
    # Exactly one VM in the whole fleet must be the bootstrap controller.
    # It comes up first and alone; every other node joins it using a token
    # generated from it. This only affects the INITIAL build — once the
    # cluster is formed all nodes are equal controllers, and losing the
    # bootstrap node is no different from losing any other.
    bootstrap: bool = False
    # Per-VM sizing overrides. None => fall back to the VM_* defaults below.
    # Hosts commonly have very different capacity, so uniform sizing would
    # waste one and starve the other.
    memory_mib: int | None = None
    vcpu: int | None = None
    # Dedicated SECOND disk for Longhorn (ADR-050), in GB. 0/None = none.
    #
    # Deliberately separate from the root disk. Longhorn sharing a filesystem
    # with etcd means a volume that fills the disk can stall the control plane —
    # storage pressure should degrade storage, not consensus. It also survives
    # the node lifecycle better: nodes are destroyed and rebuilt on every Kairos
    # release, and a data disk can be reattached rather than rebuilt.
    storage_disk_gb: int | None = None


@dataclass
class Host:
    name: str
    # None means "run locally" (this script executes ON that host).
    # A string is an SSH target ("user@host") the script connects to.
    ssh_target: str | None
    vms: list[VM] = field(default_factory=list)
    # libvirt storage pool for VM disks. Genuinely differs per host — an LVM
    # pool of raw LVs on one machine, the stock dir pool on another that has
    # no LVM at all. Making this DATA rather than a code branch is what lets
    # one code path drive genuinely heterogeneous hardware.
    disk_pool: str = "vmpool"
    # How ANOTHER hypervisor reaches this one. Can't be derived from
    # ssh_target: that's written from the controller's point of view and is
    # None for the machine the tooling runs on, which from a peer's
    # perspective is a perfectly ordinary remote host.
    peer_target: str | None = None
    # True when the pool's backing filesystem is btrfs. VM images on a
    # copy-on-write filesystem fragment badly, so the pool directory needs
    # `chattr +C` set BEFORE any image is created (it only affects new files).
    pool_needs_nocow: bool = False


def _build_hosts() -> list[Host]:
    """Turn site.yml's node list into per-hypervisor Host objects.

    Node order within a host follows site.yml. The bootstrap node is provisioned
    first regardless of where it appears — see provision.py's find_bootstrap().
    """
    hosts: dict[str, Host] = {}
    for name, cfg in _CFG["hypervisors"].items():
        hosts[name] = Host(
            name=name,
            ssh_target=cfg.get("ssh_target"),
            peer_target=cfg.get("peer_target") or cfg.get("ssh_target"),
            disk_pool=cfg["disk_pool"],
            pool_needs_nocow=bool(cfg.get("pool_needs_nocow", False)),
        )
    for name, cfg in _CFG["nodes"].items():
        hosts[cfg["hypervisor"]].vms.append(
            VM(
                name=name,
                static_ip=cfg["ip"],
                bootstrap=bool(cfg.get("bootstrap", False)),
                memory_mib=cfg.get("memory_mib"),
                vcpu=cfg.get("vcpu"),
                storage_disk_gb=cfg.get("storage_disk_gb"),
            )
        )
    return list(hosts.values())


HOSTS = _build_hosts()

# ---- cluster-wide settings, all sourced from site.yml ----

ADMIN_USER = _CFG["admin_user"]
GATEWAY = _CFG["network"]["gateway"]
DNS_SERVERS = list(_CFG["network"]["dns_servers"])
NETWORK_BRIDGE = _CFG["network"]["bridge"]

# The VM's real NIC, matched by NAME in the static network config.
#
# Do NOT match on `Type=ether` instead: that also matches the CNI's veth
# pairs, so systemd-networkd claims kube-router's pod interfaces and applies
# host network settings to them. Pod networking then breaks completely —
# every kubelet probe to a pod IP fails with "connect: no route to host",
# which cascades into CoreDNS/konnectivity/metrics-server crash-looping and
# looks like a broken cluster rather than a networking config bug.
# `networkctl list` on a node shows whether networkd has wrongly claimed any
# veth* interfaces.
PRIMARY_NIC = _CFG["network"]["primary_nic"]

# Resolved at runtime from the environment or ~/.ssh/id_ed25519.pub, never
# stored — so the repo carries nobody's identity and anyone cloning it
# provisions nodes trusting THEIR key.
SSH_PUBLIC_KEY = siteconfig.resolve_ssh_public_key()

# Pinned to a specific release, not "latest", so a re-run months from now
# still builds identical nodes. The checksum is what actually guarantees it.
KAIROS_ISO_URL = _CFG["kairos"]["iso_url"]
KAIROS_ISO_SHA256 = _CFG["kairos"]["iso_sha256"]

K0S_ARGS = list(_CFG["k0s"]["args"])
# Empty string when no load balancer is configured, so provision.py can
# simply test truthiness rather than branching on presence.
CONTROL_PLANE_VIP = (_CFG.get("control_plane") or {}).get("vip") or ""
# ADR-055. Empty client_id/client_secret disables ESO bootstrap entirely.
EXTERNAL_SECRETS = dict(_CFG.get("external_secrets") or {})

# API server hardening: secrets-at-rest encryption and audit logging (ADR-066).
API_HARDENING = dict(_CFG.get("api_hardening") or {})

# Public endpoint the daily posture check verifies (ADR-073).
POSTURE = dict(_CFG.get("posture") or {})

# Join tokens are generated fresh on each provisioning run and baked into
# each joining node's seed ISO, so nodes join on first boot with no
# post-provisioning SSH step. Long enough for a full fleet build in one
# session, short enough that a stale token in an old ISO fails loudly
# instead of silently working months later.
K0S_TOKEN_EXPIRY = _CFG["k0s"]["token_expiry"]

VM_MEMORY_MIB = _CFG["defaults"]["memory_mib"]
VM_VCPU = _CFG["defaults"]["vcpu"]
VM_DISK_GB = _CFG["defaults"]["disk_gb"]
# Default size of the dedicated Longhorn disk. 0 = do not attach one,
# which keeps the change inert until storage is actually rolled out.
VM_STORAGE_DISK_GB = int(_CFG["defaults"].get("storage_disk_gb", 0) or 0)

ISO_POOL = _CFG["libvirt"]["iso_pool"]
ISO_POOL_PATH = _CFG["libvirt"]["iso_pool_path"]

# GitOps bootstrap settings (ADR-018): pinned operator version+checksum come
# from the committed versions.yml; repository/tag/credential from site.yml.
FLUX = _CFG["flux"]
