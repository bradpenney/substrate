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

# Typed (ADR-089), not a dict. Attribute access means a renamed or misspelled
# field is an error where it is READ rather than a KeyError three minutes
# into a provisioning run, and the sub-models below are handed on to callers
# as-is so the typing does not stop at this module's edge.
_CFG = siteconfig.load_model()


@dataclass
class VM:
    """One k0s node: a libvirt domain with a fixed address.

    Every field beyond name/ip is an override; None means "use the VM_* default".
    Hosts commonly differ a lot in capacity, so uniform sizing would waste one
    machine and starve the other.
    """

    name: str
    static_ip: str
    # Which hypervisor carries this VM. Denormalised from site.yml's node list
    # onto the VM itself because render_cloud_config() receives a VM and nothing
    # else, and the node's FAILURE DOMAIN has to reach the cloud-config — see
    # HYPERVISOR_LABEL below. Defaulting to "" rather than requiring it keeps
    # hand-built VM() fixtures (check_render.py) constructible, but an empty
    # value renders a label with no value, which k0s rejects at install: the
    # node fails loudly instead of joining with no failure domain.
    hypervisor: str = ""
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
    """One hypervisor and the VMs it carries.

    Making the differences between machines DATA rather than a code branch is
    what lets a single code path drive genuinely heterogeneous hardware -- an
    LVM pool on one, the stock dir pool on another with no LVM at all.
    """

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
    # See HypervisorConfig.failure_prone. A host that may not come back on its
    # own must not carry the majority of the platform — the same reasoning
    # that keeps the etcd majority off it.
    failure_prone: bool = False


def _build_hosts() -> list[Host]:
    """Turn site.yml's node list into per-hypervisor Host objects.

    Node order within a host follows site.yml. The bootstrap node is provisioned
    first regardless of where it appears — see provision.py's find_bootstrap().
    """
    hosts: dict[str, Host] = {}
    for name, hv in _CFG.hypervisors.items():
        hosts[name] = Host(
            name=name,
            ssh_target=hv.ssh_target,
            peer_target=hv.peer_target or hv.ssh_target,
            disk_pool=hv.disk_pool,
            pool_needs_nocow=hv.pool_needs_nocow,
            failure_prone=hv.failure_prone,
        )
    for name, node in _CFG.nodes.items():
        hosts[node.hypervisor].vms.append(
            VM(
                name=name,
                static_ip=node.ip,
                hypervisor=node.hypervisor,
                bootstrap=node.bootstrap,
                memory_mib=node.memory_mib,
                vcpu=node.vcpu,
                storage_disk_gb=node.storage_disk_gb,
            )
        )
    return list(hosts.values())


HOSTS = _build_hosts()

# ---- cluster-wide settings, all sourced from site.yml ----

ADMIN_USER = _CFG.admin_user
GATEWAY = _CFG.network.gateway
DNS_SERVERS = list(_CFG.network.dns_servers)
NETWORK_BRIDGE = _CFG.network.bridge

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
PRIMARY_NIC = _CFG.network.primary_nic

# Resolved at runtime from the environment or ~/.ssh/id_ed25519.pub, never
# stored — so the repo carries nobody's identity and anyone cloning it
# provisions nodes trusting THEIR key.
#
# LAZY, via module __getattr__ (PEP 562). Resolving it at import time made
# EVERY consumer of the topology require an admin SSH key, including tools that
# never render a cloud-config — deploy-observability.py failed on a missing
# /root/.ssh/id_ed25519.pub while installing metrics agents, which have nothing
# to do with node identity. An import-time side effect is a dependency whether
# or not the value is used.
#
# `from hosts import SSH_PUBLIC_KEY` still works and still resolves eagerly for
# the callers that genuinely need it (provision.py renders it into every node).


def __getattr__(name: str) -> str:
    """Resolve SSH_PUBLIC_KEY on first access, not on import."""
    if name == "SSH_PUBLIC_KEY":
        return siteconfig.resolve_ssh_public_key()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Pinned to a specific release, not "latest", so a re-run months from now
# still builds identical nodes. The checksum is what actually guarantees it.
KAIROS_ISO_URL = _CFG.kairos.iso_url
KAIROS_ISO_SHA256 = _CFG.kairos.iso_sha256

K0S_ARGS = list(_CFG.k0s.args)

# --- the hypervisor failure-domain label (ADR-139 follow-up) ---
#
# The fleet has TWO failure domains and, until this existed, no label saying so.
# `kubernetes.io/hostname` is the only topology label a stock k0s node carries,
# and spreading on it does NOT mean spreading across hypervisors: s2-vm1 and
# s2-vm2 are different hostnames on the SAME machine, which is exactly the
# domain being guarded. Nothing schedulable could express "put these two pods
# on different physical hosts", so every spread so far has been manual and
# every one has been undone by the next reboot.
#
# Applied as a kubelet `--labels` argument, so a REBUILT node carries it
# without anyone remembering to run kubectl. Two consequences worth knowing:
#
#   1. kubelet applies --labels at node REGISTRATION ONLY. Restarting kubelet,
#      or adding this to a node that already joined, does nothing. Nodes that
#      predate this change need a one-time `kubectl label node`, which needs an
#      admin kubeconfig. A rebuild picks it up automatically; a reboot does not.
#   2. NodeRestriction lets a kubelet self-assign labels outside the
#      kubernetes.io/ and k8s.io/ namespaces, which is why this is a custom
#      domain and NOT, say, `topology.kubernetes.io/zone` — the kubelet would
#      be refused that one and the node would join unlabelled.
#
# ⚠️ RENAME BLAST RADIUS: this string is also written into substrate_config
# (the bindy spread policy) and, once labelled, into every live node's metadata.
# It is a constant in exactly one place per implementation so that the pending
# platform rename is a one-line change here plus a re-label — not a search.
HYPERVISOR_LABEL = "invariant-platform.io/hypervisor"
# Empty string when no load balancer is configured, so provision.py can
# simply test truthiness rather than branching on presence.
CONTROL_PLANE_VIP = _CFG.control_plane.vip or ""
# ADR-055. Empty client_id/client_secret disables ESO bootstrap entirely.
EXTERNAL_SECRETS = _CFG.external_secrets

# API server hardening: secrets-at-rest encryption and audit logging (ADR-066).
API_HARDENING = _CFG.api_hardening

# Public endpoint the daily posture check verifies (ADR-073).
POSTURE = _CFG.posture

# Join tokens are generated fresh on each provisioning run and baked into
# each joining node's seed ISO, so nodes join on first boot with no
# post-provisioning SSH step. Long enough for a full fleet build in one
# session, short enough that a stale token in an old ISO fails loudly
# instead of silently working months later.
K0S_TOKEN_EXPIRY = _CFG.k0s.token_expiry

VM_MEMORY_MIB = _CFG.defaults.memory_mib
VM_VCPU = _CFG.defaults.vcpu
VM_DISK_GB = _CFG.defaults.disk_gb
# Default size of the dedicated Longhorn disk. 0 = do not attach one,
# which keeps the change inert until storage is actually rolled out.
VM_STORAGE_DISK_GB = _CFG.defaults.storage_disk_gb

ISO_POOL = _CFG.libvirt.iso_pool
ISO_POOL_PATH = _CFG.libvirt.iso_pool_path

# GitOps bootstrap settings (ADR-018): pinned operator version+checksum come
# from the committed versions.yml; repository/tag/credential from site.yml.
FLUX = _CFG.flux
