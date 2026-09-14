//! Typed `site.yml`, the serde half of what `models.py` declares in pydantic.
//!
//! The Python models were written first (ADR-089) precisely so this would be a
//! translation rather than a redesign, and the mapping is one-to-one. Two
//! properties are carried across deliberately:
//!
//! * `deny_unknown_fields` is `extra="forbid"`. A misspelled key must be an
//!   error, not a silently ignored line that leaves the default in place.
//! * Optional sections stay optional. A fleet with no control-plane load
//!   balancer, no External Secrets and no public site is a smaller but valid
//!   deployment.
//!
//! Cross-field rules do NOT live here, for the same reason they do not live in
//! `models.py`: their error messages explain *why* a rule exists, and a field
//! path is a worse thing to read mid-provision.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The LAN every node sits on.
///
/// `primary_nic` is the interface name INSIDE the guest. The static network
/// file written into the cloud-config matches on it, and matching on the wrong
/// thing produces a node with no address and nothing in any log.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub gateway: String,
    pub dns_servers: Vec<String>,
    pub bridge: String,
    pub primary_nic: String,
}

/// One physical machine that carries VMs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypervisorConfig {
    #[serde(default)]
    pub ssh_target: Option<String>,
    #[serde(default)]
    pub peer_target: Option<String>,
    #[serde(default = "default_disk_pool")]
    pub disk_pool: String,
    #[serde(default)]
    pub pool_needs_nocow: bool,
    /// True for a host less likely to come back unattended after an outage.
    ///
    /// The renderer does not USE this — cloud-config is identical either way,
    /// and the goldens prove it. It is declared so the strict schema accepts a
    /// site.yml the Python side already understands: `deny_unknown_fields`
    /// means every field must be known to BOTH implementations or the fleet
    /// has two disagreeing definitions of its own configuration.
    #[serde(default)]
    pub failure_prone: bool,
}

fn default_disk_pool() -> String {
    "vmpool".to_string()
}

/// One k0s node. Sizing fields are overrides; omitted means "use `defaults`".
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub hypervisor: String,
    pub ip: String,
    #[serde(default)]
    pub bootstrap: bool,
    #[serde(default)]
    pub memory_mib: Option<u32>,
    #[serde(default)]
    pub vcpu: Option<u32>,
    #[serde(default)]
    pub storage_disk_gb: Option<u32>,
}

/// Fallback sizing for any node that does not override it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultsConfig {
    pub memory_mib: u32,
    pub vcpu: u32,
    pub disk_gb: u32,
    #[serde(default)]
    pub storage_disk_gb: u32,
}

/// The pinned node image. Replaced wholesale from `versions.yml` at load time.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KairosConfig {
    #[serde(default)]
    pub iso_url: String,
    #[serde(default)]
    pub iso_sha256: String,
    #[serde(default)]
    pub version: Option<String>,
}

/// Arguments passed to k0s on every node, and the join-token lifetime.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct K0sConfig {
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_token_expiry")]
    pub token_expiry: String,
}

fn default_token_expiry() -> String {
    "24h".to_string()
}

/// The VRRP virtual IP fronting the API server.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneConfig {
    #[serde(default)]
    pub vip: Option<String>,
    #[serde(default)]
    pub vrrp_router_id: Option<u32>,
    #[serde(default)]
    pub auth_pass: Option<String>,
    #[serde(default)]
    pub priorities: BTreeMap<String, i32>,
}

/// The one irreducible bootstrap credential (ADR-019/055).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExternalSecretsConfig {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub project_slug: Option<String>,
    #[serde(default)]
    pub environment_slug: Option<String>,
}

/// kube-apiserver flags that are not on by default (ADR-066).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ApiHardeningConfig {
    #[serde(default)]
    pub secrets_encryption_key: Option<String>,
    #[serde(default)]
    pub audit_log_path: Option<String>,
    #[serde(default)]
    pub audit_log_maxage: Option<String>,
}

/// What posture-check asserts about the public path (ADR-073).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PostureConfig {
    #[serde(default)]
    pub public_hostname: Option<String>,
    #[serde(default)]
    pub origin_ip: Option<String>,
}

/// Where the host-tier observability stack runs (ADR-098).
///
/// `host` names a hypervisor from the `hypervisors` map. Configuration rather
/// than a constant because this repository is going public: a hardcoded name
/// would ship one estate's topology to everyone who clones it — the mistake
/// ADR-094 caught in the cosign identity.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub host: Option<String>,
    /// The public name Grafana answers on. Sets Grafana's `root_url`; without
    /// it Grafana emits redirects to its bind address and login fails in a way
    /// that looks like a proxy fault.
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default = "default_retention_months")]
    pub retention_months: u32,
    /// GitHub org allowed to log in to Grafana. Unused by the renderer —
    /// declared so the strict schema accepts the real site.yml, which the
    /// Python side has understood since the field was added.
    #[serde(default)]
    pub github_org: Option<String>,
}

fn default_retention_months() -> u32 {
    6
}

/// Where seed ISOs live on each hypervisor.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibvirtConfig {
    pub iso_pool: String,
    pub iso_pool_path: String,
}

/// The OCI artifact Flux reconciles, and who must have signed it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FluxConfig {
    pub oci_repository: String,
    #[serde(default = "default_oci_tag")]
    pub oci_tag: String,
    #[serde(default)]
    pub ghcr_username: Option<String>,
    #[serde(default)]
    pub ghcr_token: Option<String>,

    /// Who is allowed to have signed the artifact (ADR-069, ADR-094).
    ///
    /// `cosign_subject` has no default on purpose: `provider: cosign` alone
    /// accepts any valid Sigstore signature, including one an attacker made
    /// with their own GitHub account. A default would be a silent downgrade.
    /// Stored exactly as it must appear in the rendered yaml, backslashes and
    /// all, and interpolated verbatim — escaping at render time would need
    /// identical logic in every implementation, which is where renderers drift.
    #[serde(default = "default_cosign_issuer")]
    pub cosign_issuer: String,
    #[serde(default)]
    pub cosign_subject: Option<String>,

    // Merged in from the committed versions.yml, so callers see one config
    // object. Modelled here because this is the shape consumers receive.
    #[serde(default)]
    pub operator_version: Option<String>,
    #[serde(default)]
    pub operator_sha256: Option<String>,
    #[serde(default)]
    pub operator_url: Option<String>,
    #[serde(default)]
    pub distribution_version: Option<String>,
}

fn default_oci_tag() -> String {
    "main".to_string()
}

fn default_cosign_issuer() -> String {
    r"^https://token\\.actions\\.githubusercontent\\.com$".to_string()
}

/// The estate's zone, and how the LAN resolves it (ADR-182).
///
/// `domain` is the zone the authoritative pair in the cluster serves for the
/// LAN. `forwarders` are the pair's addresses — every address the pair could
/// hold, since they float inside a MetalLB pool rather than being pinned.
/// `upstreams` are the public resolvers everything else goes to, over TLS,
/// in unbound's `addr@port#authname` form.
///
/// `proxied` and `vercel_team` fed the retired Cloudflare migration script
/// and are read by nothing; they stay accepted so an older site.yml parses.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub proxied: Vec<String>,
    #[serde(default)]
    pub vercel_team: Option<String>,
    #[serde(default)]
    pub forwarders: Vec<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
}

/// The whole of `site.yml`, validated.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    pub admin_user: String,
    pub network: NetworkConfig,
    pub hypervisors: BTreeMap<String, HypervisorConfig>,
    pub nodes: BTreeMap<String, NodeConfig>,
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub kairos: KairosConfig,
    pub k0s: K0sConfig,
    pub libvirt: LibvirtConfig,
    pub flux: FluxConfig,
    #[serde(default)]
    pub control_plane: ControlPlaneConfig,
    #[serde(default)]
    pub external_secrets: ExternalSecretsConfig,
    #[serde(default)]
    pub api_hardening: ApiHardeningConfig,
    #[serde(default)]
    pub posture: PostureConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub dns: DnsConfig,
}
