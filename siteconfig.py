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

from pydantic import ValidationError

import models

try:
    import yaml
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        "PyYAML is required. Use the repo venv:\n"
        "  python3 -m venv .venv && .venv/bin/pip install ansible-core\n"
        "  .venv/bin/python3 provision.py"
    ) from e

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


class _StrictLoader(yaml.SafeLoader):
    """A YAML loader that REFUSES duplicate keys.

    PyYAML silently accepts them and keeps the last, which is how the real
    site.yml carried `storage_disk_gb` twice on three nodes for an unknown
    length of time (ADR-095). Both values happened to be equal, so nothing
    broke — but editing one and not the other would have silently discarded
    the change with no error anywhere.

    Found by the Rust renderer, whose YAML parser rejects duplicates by
    default. This closes the gap in the direction that matters: the two
    implementations must agree on what a VALID config is, not only on how to
    render a valid one.
    """


def _no_duplicate_keys(loader, node, deep=False):
    """Construct a mapping, failing on any repeated key."""
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise SystemExit(
                f"{SITE_FILE}: duplicate key '{key}' at line "
                f"{key_node.start_mark.line + 1}.\n"
                f"  YAML keeps the LAST one silently, so an edit to the first "
                f"is discarded with no error. Remove the duplicate."
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys
)


def load_versions() -> dict:
    """Pinned upstream versions, from the COMMITTED versions.yml.

    Deliberately separate from site.yml: an upstream version is a project-wide
    choice, not a site-specific one — and site.yml is gitignored, so a pin
    living there would be invisible to the update bots in .github/workflows.
    That mistake was made twice (flux-operator, then Kairos) before the
    distinction was drawn.
    """
    if not VERSIONS_FILE.is_file():
        raise SystemExit(
            f"Missing {VERSIONS_FILE} — pinned versions live there, not in site.yml"
        )
    return yaml.load(VERSIONS_FILE.read_text(), Loader=_StrictLoader)


def load() -> dict:
    """Load and validate site.yml.

    Validation happens here rather than at first use so a malformed config
    fails immediately, not after the ISO has downloaded and two VMs exist."""
    if not SITE_FILE.is_file():
        raise SystemExit(
            f"No site configuration found at {SITE_FILE}.\n"
            f"  Copy the template and edit it:\n"
            f"    cp {EXAMPLE_FILE.name} {SITE_FILE.name}\n"
            f"  It holds your addresses and usernames, and is gitignored."
        )

    cfg = yaml.load(SITE_FILE.read_text(encoding="utf-8"), Loader=_StrictLoader)
    versions = load_versions()

    # Pinned versions are merged in so callers see one config object, but they
    # come from a different (committed) file — see load_versions().
    cfg["kairos"] = versions["kairos"]
    cfg.setdefault("flux", {}).update(
        {
            "operator_version": versions["flux_operator"]["version"],
            "operator_sha256": versions["flux_operator"]["sha256"],
            "operator_url": versions["flux_operator"]["url"].format(
                version=versions["flux_operator"]["version"]
            ),
            "distribution_version": versions["flux_distribution"]["version"],
        }
    )

    _validate_shape(cfg)
    _validate(cfg)
    return cfg


def load_model() -> "models.SiteConfig":
    """The same configuration, as a typed object rather than a dict.

    New code should prefer this: `cfg.network.gateway` fails at load with the
    field named, where `cfg["network"]["gateway"]` fails at the moment of use
    with a KeyError and no indication of what was expected.

    `load()` remains for the existing callers, which index by string throughout.
    Both run the same validation, so they cannot disagree about what is valid.
    """
    return models.SiteConfig(**load())


def _validate_shape(cfg: dict) -> None:
    """Check field names and types against the models, before the cross-field rules.

    Pydantic catches what a hand-written validator does not bother to: a
    misspelled key (the models forbid extras, so `gatway:` is an error rather
    than a silently ignored line that leaves the default in place), and a value
    of the wrong type arriving from hand-edited YAML.

    The error is reformatted rather than raised as a ValidationError, because
    pydantic reports a field path and this file's other messages explain what to
    do about the problem. Whoever hits this is usually mid-provision.
    """
    try:
        models.SiteConfig(**cfg)
    except ValidationError as exc:
        lines = [f"{SITE_FILE} does not match the expected schema:"]
        for err in exc.errors():
            where = ".".join(str(p) for p in err["loc"]) or "(root)"
            lines.append(f"  {where}: {err['msg']}")
        raise SystemExit("\n".join(lines)) from exc


def _validate(cfg: dict) -> None:
    """Fail early and specifically, rather than with a KeyError mid-build.

    A malformed site.yml that only surfaces after the ISO has downloaded and
    two VMs exist is a genuinely annoying failure mode, so the shape is checked
    up front.
    """
    for key in (
        "admin_user",
        "network",
        "hypervisors",
        "nodes",
        "defaults",
        "k0s",
        "libvirt",
    ):
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

    # Flux will only reconcile an artifact signed by this exact identity
    # (ADR-069). It was HARDCODED in both renderers until ADR-094 — so a public
    # repo named a private one, and anyone else cloning substrate would have
    # built a cluster pinned to somebody else's workflow, which fails as an
    # opaque registry error rather than as "you are trusting the wrong person".
    #
    # No default, and no skipping the block when absent. `provider: cosign`
    # alone accepts ANY valid Sigstore signature, including one an attacker
    # produced with their own GitHub account; the subject pin is the whole
    # control. Silently rendering without it would be a downgrade that looks
    # like success.
    flux = cfg.get("flux") or {}
    if flux and not flux.get("cosign_subject"):
        raise SystemExit(
            "site.yml: flux.cosign_subject is not set.\n"
            "  Flux verifies the config artifact's signature against this "
            "identity, and `provider: cosign` without it accepts any valid\n"
            "  Sigstore signature — including an attacker's. Set it to the "
            "workflow that publishes your artifact, escaped as it must\n"
            "  appear in the rendered yaml, e.g.\n"
            "    cosign_subject: '^https://github\\\\.com/ORG/REPO/"
            "\\\\.github/workflows/publish\\\\.yaml@refs/heads/main$'"
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
        print(
            f"site.yml WARNING: {count} nodes is an EVEN count. etcd wants an "
            f"odd number for clean quorum — consider {count - 1} or {count + 1}."
        )

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

    _validate_failure_domains(cfg)


def _validate_failure_domains(cfg: dict) -> None:
    """Keep the two statements of "which host is unreliable" in agreement.

    `failure_prone` and `control_plane.priorities` encode the same judgement:
    server1 is the office workstation, so it neither holds the VRRP VIP by
    default nor should carry the platform. Two encodings of one fact drift —
    this project has been caught by that repeatedly — so a config that sets the
    failure-prone host as the VRRP-preferred one is rejected rather than
    silently believed.
    """
    prone = {
        name
        for name, hv in cfg["hypervisors"].items()
        if (hv or {}).get("failure_prone")
    }
    if not prone:
        return
    if len(prone) == len(cfg["hypervisors"]):
        raise SystemExit(
            "site.yml: every hypervisor is marked failure_prone. There is then "
            "nowhere safe to place anything, and the flag means nothing."
        )

    priorities = (cfg.get("control_plane") or {}).get("priorities") or {}
    if not priorities:
        return
    preferred = max(priorities, key=priorities.get)
    if preferred in prone:
        raise SystemExit(
            f"site.yml: '{preferred}' has the highest VRRP priority "
            f"({priorities[preferred]}) but is marked failure_prone. Those are "
            "the same judgement stated twice and they disagree — the VIP would "
            "prefer the machine expected to go away."
        )


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
    key = path.read_text(encoding="utf-8").strip()
    # Fail loudly rather than baking a private key or junk into every node's
    # authorized_keys, where it surfaces much later as "SSH just doesn't work"
    # on a freshly built cluster.
    if not key.startswith(
        ("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")
    ):
        raise SystemExit(f"{path} does not look like an SSH public key: {key[:40]!r}")
    return key
