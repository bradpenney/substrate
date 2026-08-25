"""
Load site-specific configuration from site.yml.

WHY THIS EXISTS
This repo is meant to be publishable. Everything that identifies a particular
installation — LAN addresses, admin username, storage pool names, which
machine hosts what — lives in `site.yml`, which is gitignored. What gets
committed is generic code plus `site.example.yml`, using RFC 5737
documentation addresses.

The point isn't secrecy in the cryptographic sense (none of it is a
credential). It's not handing a reader a map of a private network alongside a
detailed description of how to build machines on it.

BOTH implementations read this same file — provision.py through here, and
ansible/inventory.yml directly. That's deliberate. Sharing the DATA makes the
two fleet definitions impossible to drift apart, rather than merely checked
for drift. What stays genuinely independent is the part the destroy-and-rebuild
gate is actually testing: the BUILD LOGIC, written twice, and verified by
check_render.py to produce byte-identical node configuration.

Requires PyYAML — run tooling through the repo venv (.venv/bin/python3).
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    raise SystemExit(
        "PyYAML is required. Use the repo venv:\n"
        "  python3 -m venv .venv && .venv/bin/pip install ansible-core\n"
        "  .venv/bin/python3 provision.py"
    )

REPO_ROOT = Path(__file__).resolve().parent
# site.yml normally lives beside the code, but a DEPLOYED copy (the auto-roll
# clone on a hypervisor) cannot have it — it is gitignored, so a fresh clone
# never contains it. $SUBSTRATE_SITE_FILE lets the installer point at a system
# location (/etc/substrate/site.yml, mode 0600) instead of copying secrets into
# a git working tree.
# NOTE: test the STRING, not Path(...) — Path("") evaluates to Path(".") which
# is truthy, so `Path(env) or default` silently returns the current directory.
_SITE_OVERRIDE = os.environ.get("SUBSTRATE_SITE_FILE", "").strip()
SITE_FILE = Path(_SITE_OVERRIDE) if _SITE_OVERRIDE else REPO_ROOT / "site.yml"
VERSIONS_FILE = REPO_ROOT / "versions.yml"
EXAMPLE_FILE = REPO_ROOT / "site.example.yml"


def load_versions() -> dict:
    """Pinned upstream versions, from the COMMITTED versions.yml.

    Deliberately separate from site.yml: an upstream version is a project-wide
    choice, not a site-specific one — and site.yml is gitignored, so a pin
    living there would be invisible to the update bots in .github/workflows.
    That mistake was made twice (flux-operator, then Kairos) before the
    distinction was drawn.
    """
    if not VERSIONS_FILE.is_file():
        raise SystemExit(f"Missing {VERSIONS_FILE} — pinned versions live there, not in site.yml")
    return yaml.safe_load(VERSIONS_FILE.read_text())


def load() -> dict:
    """Read and validate site.yml, merged with the pinned versions."""
    if not SITE_FILE.is_file():
        raise SystemExit(
            f"No site configuration found at {SITE_FILE}.\n"
            f"  Copy the template and edit it:\n"
            f"    cp {EXAMPLE_FILE.name} {SITE_FILE.name}\n"
            f"  It holds your addresses and usernames, and is gitignored."
        )

    cfg = yaml.safe_load(SITE_FILE.read_text())
    versions = load_versions()

    # Pinned versions are merged in so callers see one config object, but they
    # come from a different (committed) file — see load_versions().
    cfg["kairos"] = versions["kairos"]
    cfg.setdefault("flux", {}).update({
        "operator_version": versions["flux_operator"]["version"],
        "operator_sha256": versions["flux_operator"]["sha256"],
        "operator_url": versions["flux_operator"]["url"].format(
            version=versions["flux_operator"]["version"]),
        "distribution_version": versions["flux_distribution"]["version"],
    })

    _validate(cfg)
    return cfg


def _validate(cfg: dict) -> None:
    """Fail early and specifically, rather than with a KeyError mid-build.

    A malformed site.yml that only surfaces after the ISO has downloaded and
    two VMs exist is a genuinely annoying failure mode, so the shape is checked
    up front.
    """
    for key in ("admin_user", "network", "hypervisors", "nodes", "defaults",
                "k0s", "libvirt"):
        if key not in cfg:
            raise SystemExit(f"site.yml is missing the top-level '{key}' section")

    # A hypervisor the tooling runs ON has no ssh_target, so nothing else
    # carries an address its PEER could use — and the nightly-update health
    # check needs exactly that. Catch it here rather than at 03:00.
    for name, h in cfg["hypervisors"].items():
        if not h.get("ssh_target") and not h.get("peer_target"):
            raise SystemExit(
                f"site.yml: hypervisor '{name}' has `ssh_target: null` (runs "
                f"locally) but no `peer_target`.\n"
                f"  Set peer_target to how the OTHER hypervisor reaches it, "
                f"e.g. user@10.0.0.5"
            )

    # The control-plane VIP must not collide with any node address.
    #
    # Caught during the ADR-046 retopology: renumbering the nodes silently put
    # a node on the VIP. Nothing would have failed at provisioning time — the
    # VM would boot fine and keepalived would later ARP for an address a live
    # host already answers for, producing intermittent, extremely confusing
    # control-plane failures. Cheap to check, miserable to debug.
    cp = cfg.get("control_plane") or {}
    vip = cp.get("vip")
    if vip:
        clash = [n for n, c in cfg["nodes"].items() if c.get("ip") == vip]
        if clash:
            raise SystemExit(
                f"site.yml: control_plane.vip {vip} is also assigned to "
                f"node(s) {', '.join(clash)}.\n"
                f"  The VIP floats between hypervisors and must not be a node "
                f"address."
            )
        for h, hc in cfg["hypervisors"].items():
            for field in ("ssh_target", "peer_target"):
                t = hc.get(field) or ""
                if vip in t:
                    raise SystemExit(
                        f"site.yml: control_plane.vip {vip} appears in "
                        f"hypervisor '{h}' {field}."
                    )

    bootstraps = [n for n, c in cfg["nodes"].items() if c.get("bootstrap")]
    if len(bootstraps) != 1:
        raise SystemExit(
            f"site.yml must mark exactly ONE node as `bootstrap: true`, found "
            f"{len(bootstraps)}: {bootstraps or 'none'}.\n"
            f"  The bootstrap node comes up first and alone; every other node "
            f"joins using a token minted from it."
        )

    # An even node count is a real, quiet foot-gun: etcd needs a majority, so 6
    # nodes tolerate the same 2 failures as 5 while adding split-brain risk.
    # Warn rather than fail — it's the operator's cluster.
    count = len(cfg["nodes"])
    if count % 2 == 0:
        print(f"site.yml WARNING: {count} nodes is an EVEN count. etcd wants an "
              f"odd number for clean quorum — consider {count - 1} or {count + 1}.")

    for name, node in cfg["nodes"].items():
        hv = node.get("hypervisor")
        if hv not in cfg["hypervisors"]:
            raise SystemExit(
                f"site.yml: node '{name}' references unknown hypervisor '{hv}'. "
                f"Known: {', '.join(cfg['hypervisors'])}"
            )
        if not node.get("ip"):
            raise SystemExit(f"site.yml: node '{name}' has no `ip`")

    ips = [n["ip"] for n in cfg["nodes"].values()]
    dupes = {ip for ip in ips if ips.count(ip) > 1}
    if dupes:
        raise SystemExit(f"site.yml: duplicate node IPs: {', '.join(sorted(dupes))}")


# ---------------------------------------------------------------- ssh key

SSH_PUBLIC_KEY_ENV = "HOMELAB_SSH_PUBLIC_KEY"
SSH_PUBLIC_KEY_FILE_ENV = "HOMELAB_SSH_PUBLIC_KEY_FILE"
DEFAULT_SSH_PUBLIC_KEY_FILE = "~/.ssh/id_ed25519.pub"


def resolve_ssh_public_key() -> str:
    """The public key authorised on every node.

    Resolved at runtime rather than stored, so the repo carries nobody's
    identity and anyone cloning it provisions nodes trusting THEIR key.
    ansible/inventory.yml resolves the same three sources in the same order.

    Order: $HOMELAB_SSH_PUBLIC_KEY -> $HOMELAB_SSH_PUBLIC_KEY_FILE ->
           ~/.ssh/id_ed25519.pub
    """
    inline = os.environ.get(SSH_PUBLIC_KEY_ENV, "").strip()
    if inline:
        return inline

    path = Path(
        os.environ.get(SSH_PUBLIC_KEY_FILE_ENV, "").strip()
        or DEFAULT_SSH_PUBLIC_KEY_FILE
    ).expanduser()
    if not path.is_file():
        raise SystemExit(
            f"No SSH public key found at {path}.\n"
            f"  Set ${SSH_PUBLIC_KEY_ENV} to the key itself, or\n"
            f"  set ${SSH_PUBLIC_KEY_FILE_ENV} to a different .pub file, or\n"
            f"  generate one: ssh-keygen -t ed25519"
        )
    key = path.read_text().strip()
    # Fail loudly rather than baking a private key or junk into every node's
    # authorized_keys, where it surfaces much later as "SSH just doesn't work"
    # on a freshly built cluster.
    if not key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-",
                           "sk-ssh-", "sk-ecdsa-")):
        raise SystemExit(f"{path} does not look like an SSH public key: {key[:40]!r}")
    return key
