//! The pinned upstream versions, from the COMMITTED `versions.yml`.
//!
//! Deliberately separate from `site.yml`: an upstream version is a project-wide
//! choice, not a site-specific one, and `site.yml` is gitignored — a pin living
//! there would be invisible to the update bots in `.github/workflows`.

use anyhow::{Context, Result};
use serde_yaml_ng::Value;
use std::path::Path;

/// Merge `versions.yml` into a raw `site.yml` value, in place.
///
/// Mirrors `siteconfig.load()` exactly, including the fact that `kairos` is
/// REPLACED wholesale rather than merged. Any divergence here would produce two
/// implementations that agree on the config file and disagree on the config.
pub fn merge(repo_root: &Path, site: &mut Value) -> Result<()> {
    let path = repo_root.join("versions.yml");
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "Missing {} — pinned versions live there, not in site.yml",
            path.display()
        )
    })?;
    let versions: Value = serde_yaml_ng::from_str(&text)
        .with_context(|| format!("{} is not valid yaml", path.display()))?;

    let get = |section: &str, key: &str| -> Result<String> {
        versions
            .get(section)
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .with_context(|| format!("versions.yml: missing {section}.{key}"))
    };

    let operator_version = get("flux_operator", "version")?;
    let operator_url = get("flux_operator", "url")?.replace("{version}", &operator_version);

    let map = site.as_mapping_mut().context("site.yml is not a mapping")?;

    map.insert(
        Value::from("kairos"),
        versions
            .get("kairos")
            .cloned()
            .context("versions.yml: missing kairos")?,
    );

    let flux = map
        .entry(Value::from("flux"))
        .or_insert_with(|| Value::Mapping(Default::default()))
        .as_mapping_mut()
        .context("site.yml: flux is not a mapping")?;

    flux.insert(
        Value::from("operator_version"),
        Value::from(operator_version),
    );
    flux.insert(
        Value::from("operator_sha256"),
        Value::from(get("flux_operator", "sha256")?),
    );
    flux.insert(Value::from("operator_url"), Value::from(operator_url));
    flux.insert(
        Value::from("distribution_version"),
        Value::from(get("flux_distribution", "version")?),
    );

    // Host tools, pinned the same way. `{version}` in the URL is substituted
    // here so the installer receives a literal address it can only fetch.
    let cosign_version = get("cosign", "version")?;
    let mut cosign = serde_yaml_ng::Mapping::new();
    cosign.insert(Value::from("version"), Value::from(cosign_version.clone()));
    cosign.insert(Value::from("sha256"), Value::from(get("cosign", "sha256")?));
    cosign.insert(
        Value::from("url"),
        Value::from(get("cosign", "url")?.replace("{version}", &cosign_version)),
    );
    let mut tools = serde_yaml_ng::Mapping::new();
    tools.insert(Value::from("cosign"), Value::Mapping(cosign));
    map.insert(Value::from("host_tools"), Value::Mapping(tools));

    Ok(())
}
