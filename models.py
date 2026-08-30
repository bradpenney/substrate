"""Typed models for site.yml.

WHY THESE EXIST
---------------
`site.yml` describes the whole fleet — addresses, sizing, credentials, the
pinned image — and until now it was a bare dict validated by an imperative
`_validate()`. That worked, but every consumer indexed it by string
(`cfg["network"]["gateway"]`), so a typo was a KeyError at the moment of use
rather than an error at load, and nothing described the schema except the
validator itself.

These models make the shape declarative: what fields exist, which are optional,
and what type each holds. A malformed config now fails at parse time with the
offending field named, and editors and type-checkers can see the structure.

WHY PYDANTIC RATHER THAN PLAIN DATACLASSES
------------------------------------------
Dataclasses describe shape but do not enforce it — a `str` annotation does not
stop an int arriving from YAML. Pydantic coerces and validates at construction,
which is the property wanted here: `site.yml` is hand-edited, and the cost of a
wrong type is discovering it three minutes into a provisioning run.

RELATIONSHIP TO THE RUST PORT (ADR-088)
---------------------------------------
These map almost one-to-one onto `serde` structs. Doing the typing in Python
first means a later port is a translation rather than a redesign, and it makes
the schema explicit while the reasoning is still fresh.

CROSS-FIELD RULES LIVE IN siteconfig._validate, NOT HERE
--------------------------------------------------------
Rules that span sections — a node sitting on the control-plane VIP, exactly one
bootstrap node, a local hypervisor with no `peer_target` — stay in
`siteconfig._validate()`, because their error messages explain *why* the rule
exists and what to do about it. Pydantic's ValidationError would replace those
with a field path, which is a worse thing to read at 03:00.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    """Base for every model here: unknown keys are an error, not a shrug.

    `extra="forbid"` is the point. A misspelled key in site.yml would otherwise
    be silently ignored and the default used instead — the same class of failure
    as a misspelled field in a Kubernetes manifest, which is exactly what
    kubeconform was added to catch on the other side of the estate.
    """

    model_config = ConfigDict(extra="forbid")


class NetworkConfig(_Strict):
    """The LAN every node sits on.

    `primary_nic` is the interface name INSIDE the guest, not on the hypervisor:
    the static network file written into the cloud-config matches on it, and
    matching on the wrong thing produces a node with no address and nothing in
    any log.
    """

    gateway: str
    dns_servers: list[str]
    bridge: str
    primary_nic: str


class HypervisorConfig(_Strict):
    """One physical machine that carries VMs.

    `ssh_target: null` means "the tooling runs on this host". `peer_target` is
    how the OTHER hypervisor reaches it, which cannot be derived from
    `ssh_target` — that is written from the controller's point of view and is
    None for the local machine, which from a peer's perspective is an ordinary
    remote.
    """

    ssh_target: str | None = None
    peer_target: str | None = None
    disk_pool: str = "vmpool"
    pool_needs_nocow: bool = False


class NodeConfig(_Strict):
    """One k0s node.

    Sizing fields are overrides; when omitted the corresponding `defaults` value
    applies. Hosts commonly differ a lot in capacity, so uniform sizing would
    waste one machine and starve the other.
    """

    hypervisor: str
    ip: str
    bootstrap: bool = False
    memory_mib: int | None = None
    vcpu: int | None = None
    storage_disk_gb: int | None = None


class DefaultsConfig(_Strict):
    """Fallback sizing for any node that does not override it."""

    memory_mib: int
    vcpu: int
    disk_gb: int
    storage_disk_gb: int = 0


class KairosConfig(_Strict):
    """The pinned node image.

    `iso_sha256` is what actually makes a rebuild months from now install the
    same bytes; the URL only makes it readable. The asset name encodes flavour
    AND k0s version, so a bump can change more of the URL than the tag.
    """

    iso_url: str
    iso_sha256: str
    version: str | None = None


class K0sConfig(_Strict):
    """Arguments passed to k0s on every node, and the join-token lifetime."""

    args: list[str] = Field(default_factory=list)
    token_expiry: str = "24h"


class ControlPlaneConfig(_Strict):
    """The VRRP virtual IP fronting the API server.

    `priorities` decides which hypervisor holds the VIP. Identical values on
    both would leave them contesting it.
    """

    vip: str | None = None
    vrrp_router_id: int | None = None
    auth_pass: str | None = None
    priorities: dict[str, int] = Field(default_factory=dict)


class ExternalSecretsConfig(_Strict):
    """The one irreducible bootstrap credential (ADR-019).

    External Secrets cannot fetch the credential that lets it fetch credentials,
    so this pair is baked into the node at provisioning time.
    """

    host: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    project_slug: str | None = None
    environment_slug: str | None = None


class ApiHardeningConfig(_Strict):
    """kube-apiserver flags that are not on by default.

    Secrets encryption applies on WRITE only, so enabling it on an existing
    cluster requires rewriting every secret; on a fresh build every secret is
    encrypted from the first one.
    """

    secrets_encryption_key: str | None = None
    audit_log_path: str | None = None
    audit_log_maxage: str | None = None


class PostureConfig(_Strict):
    """What posture-check asserts about the public path.

    Kept in site.yml because `substrate` is a public repository and the WAN
    address does not belong in it.
    """

    public_hostname: str | None = None
    origin_ip: str | None = None


class LibvirtConfig(_Strict):
    """Where seed ISOs live on each hypervisor."""

    iso_pool: str
    iso_pool_path: str


class FluxConfig(_Strict):
    """The OCI artifact Flux reconciles, and the credential to pull it."""

    oci_repository: str
    oci_tag: str = "main"
    ghcr_username: str | None = None
    ghcr_token: str | None = None

    # Merged in from the COMMITTED versions.yml by siteconfig.load(), so callers
    # see one config object. They are modelled here because this is the shape
    # consumers actually receive — describing only the raw file would document
    # something nobody uses.
    operator_version: str | None = None
    operator_sha256: str | None = None
    operator_url: str | None = None
    distribution_version: str | None = None


class DnsConfig(_Strict):
    """The public zone and which records are proxied."""

    domain: str | None = None
    proxied: list[str] = Field(default_factory=list)
    vercel_team: str | None = None


class SiteConfig(_Strict):
    """The whole of site.yml, validated.

    Optional sections are genuinely optional: a fleet with no control-plane load
    balancer, no External Secrets and no public site is a valid — if smaller —
    deployment, and the tooling degrades to skipping those checks rather than
    refusing to run.
    """

    admin_user: str
    network: NetworkConfig
    hypervisors: dict[str, HypervisorConfig]
    nodes: dict[str, NodeConfig]
    defaults: DefaultsConfig
    kairos: KairosConfig
    k0s: K0sConfig
    libvirt: LibvirtConfig
    flux: FluxConfig
    control_plane: ControlPlaneConfig = Field(default_factory=ControlPlaneConfig)
    external_secrets: ExternalSecretsConfig = Field(
        default_factory=ExternalSecretsConfig
    )
    api_hardening: ApiHardeningConfig = Field(default_factory=ApiHardeningConfig)
    posture: PostureConfig = Field(default_factory=PostureConfig)
    dns: DnsConfig = Field(default_factory=DnsConfig)
