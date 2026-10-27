//! The pinned upstream versions, from the COMMITTED `versions.yml`.
//!
//! Deliberately separate from `site.yml`: an upstream version is a project-wide
//! choice, not a site-specific one, and `site.yml` is gitignored — a pin living
//! there would be invisible to the update bots in `.github/workflows`.

use crate::yaml::{self, Mapping, Value};
use anyhow::{Context, Result};
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
    let versions: Value =
        yaml::from_str(&text).with_context(|| format!("{} is not valid yaml", path.display()))?;

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

    let map = site.as_object_mut().context("site.yml is not a mapping")?;

    map.insert(
        "kairos".into(),
        versions
            .get("kairos")
            .cloned()
            .context("versions.yml: missing kairos")?,
    );

    let flux = map
        .entry("flux")
        .or_insert_with(|| Value::Object(Mapping::new()))
        .as_object_mut()
        .context("site.yml: flux is not a mapping")?;

    flux.insert("operator_version".into(), Value::from(operator_version));
    flux.insert(
        "operator_sha256".into(),
        Value::from(get("flux_operator", "sha256")?),
    );
    flux.insert("operator_url".into(), Value::from(operator_url));
    flux.insert(
        "distribution_version".into(),
        Value::from(get("flux_distribution", "version")?),
    );

    // Host tools, pinned the same way. `{version}` in the URL is substituted
    // here so the installer receives a literal address it can only fetch.
    let cosign_version = get("cosign", "version")?;
    let mut cosign = Mapping::new();
    cosign.insert("version".into(), Value::from(cosign_version.clone()));
    cosign.insert("sha256".into(), Value::from(get("cosign", "sha256")?));
    cosign.insert(
        "url".into(),
        Value::from(get("cosign", "url")?.replace("{version}", &cosign_version)),
    );
    let mut tools = Mapping::new();
    tools.insert("cosign".into(), Value::Object(cosign));
    map.insert("host_tools".into(), Value::Object(tools));

    Ok(())
}
