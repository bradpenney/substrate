//! substrate's shared core: typed site configuration and cloud-config rendering.
//!
//! This is Wave 0 of the Rust port (ADR-088). It exists to be proven against
//! the golden files before anything destructive is ported — a renderer can be
//! checked byte-for-byte against a committed artefact, which is not true of
//! `virsh` calls or a boot wait.

pub mod config;
pub mod render;
pub mod versions;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Resolve which `site.yml` to read.
///
/// `$SUBSTRATE_SITE_FILE` wins so the test suite and the golden generator can
/// point at the synthetic fixture. Matching `siteconfig.py` exactly matters:
/// two implementations reading different files would compare nothing.
pub fn site_file(repo_root: &Path) -> PathBuf {
    std::env::var_os("SUBSTRATE_SITE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("site.yml"))
}

/// Load `site.yml`, merge the pinned versions, and validate.
///
/// The merge is not cosmetic: `versions.yml` is COMMITTED and `site.yml` is
/// gitignored, so an upstream pin living in the latter would be invisible to
/// the update bots. That mistake was made twice before the split was drawn,
/// and both files have to be read here for a caller to see one config.
pub fn load(repo_root: &Path) -> Result<config::SiteConfig> {
    let path = site_file(repo_root);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("no site configuration at {}", path.display()))?;

    let mut value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text)
        .with_context(|| format!("{} is not valid yaml", path.display()))?;

    versions::merge(repo_root, &mut value)?;

    let cfg: config::SiteConfig = serde_yaml_ng::from_value(value)
        .with_context(|| format!("{} does not match the expected schema", path.display()))?;

    validate(&cfg)?;
    Ok(cfg)
}

/// Cross-field rules, kept out of the type definitions on purpose.
///
/// These messages explain *why* a rule exists and what to do about it. A serde
/// field path would replace that with a location, which is a worse thing to
/// read mid-provision — the same split `siteconfig.py` makes.
pub fn validate(cfg: &config::SiteConfig) -> Result<()> {
    // Flux will only reconcile an artifact signed by this identity (ADR-069).
    // No default and no skipping the block when absent: `provider: cosign`
    // alone accepts ANY valid Sigstore signature, including one an attacker
    // produced with their own GitHub account, so rendering without it is a
    // downgrade that looks like success (ADR-094).
    if cfg.flux.cosign_subject.as_deref().unwrap_or("").is_empty() {
        anyhow::bail!(
            "site.yml: flux.cosign_subject is not set.\n  \
             Flux verifies the config artifact's signature against this identity, \
             and `provider: cosign` without it accepts any valid\n  \
             Sigstore signature — including an attacker's."
        );
    }

    // A hypervisor the tooling runs ON has no ssh_target, so nothing else
    // carries an address its PEER could use — and the nightly-update health
    // check needs exactly that. Catch it here rather than at 03:00.
    for (name, hv) in &cfg.hypervisors {
        if hv.ssh_target.is_none() && hv.peer_target.is_none() {
            anyhow::bail!(
                "site.yml: hypervisor '{name}' has `ssh_target: null` (runs locally) \
                 but no `peer_target`.\n  \
                 Set peer_target to how the OTHER hypervisor reaches it, e.g. user@10.0.0.5"
            );
        }
    }

    // The control-plane VIP must not collide with any node address. A VM would
    // boot fine and keepalived would later ARP for an address a live host
    // already answers for — intermittent, extremely confusing control-plane
    // failures. Cheap to check, miserable to debug.
    if let Some(vip) = cfg.control_plane.vip.as_deref() {
        let clash: Vec<&str> = cfg
            .nodes
            .iter()
            .filter(|(_, n)| n.ip == vip)
            .map(|(name, _)| name.as_str())
            .collect();
        if !clash.is_empty() {
            anyhow::bail!(
                "site.yml: control_plane.vip {vip} is also assigned to node(s) {}.\n  \
                 The VIP floats between hypervisors and must not be a node address.",
                clash.join(", ")
            );
        }
    }

    // Exactly one bootstrap node. It comes up first and alone; every other node
    // joins using a token minted from it. Zero means nothing can be built; more
    // than one means two clusters that each think they are the cluster.
    let bootstraps: Vec<&str> = cfg
        .nodes
        .iter()
        .filter(|(_, n)| n.bootstrap)
        .map(|(name, _)| name.as_str())
        .collect();
    if bootstraps.len() != 1 {
        anyhow::bail!(
            "site.yml: exactly one node must have `bootstrap: true`, found {} ({}).",
            bootstraps.len(),
            if bootstraps.is_empty() {
                "none".to_string()
            } else {
                bootstraps.join(", ")
            }
        );
    }

    Ok(())
}
