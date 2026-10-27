//! Install a substrate release on EVERY hypervisor, in order, from one place.
//!
//! WHY. `install.sh` installs on the machine it runs on and nowhere else, while
//! every `deploy-*` reaches all hosts from one. Twice in four days that
//! difference left server2 a release behind while both hosts were believed
//! upgraded (bug-209): v0.2.8 under v0.2.10's config, then v0.2.10 under
//! v0.2.11. Brad: "I thought I could just run ./install.sh and it would do
//! both?" `substrate install-fleet` makes that true.
//!
//! What stays the same is the trust model. Each host downloads the release
//! itself and verifies it with its OWN cosign against the release workflow's
//! identity, through the same `install.sh` — now carried in the signed binary
//! instead of fetched from raw GitHub (assessment item #3). Nothing is trusted
//! because server1 vouched for it.
//!
//! **Never skip a release** (Brad's rule) is enforced here rather than
//! remembered: a host two releases behind installs the one in between first.
//! A release in that path with no binary refuses the whole host, because
//! installing around it would be the skip.

use anyhow::{Result, bail};

/// The release asset `install.sh` installs.
pub const ASSET: &str = "substrate-x86_64-unknown-linux-musl";

/// One published release, as the GitHub API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    /// The release carries the binary. v0.2.11 was once published without it.
    pub has_binary: bool,
}

/// `vX.Y.Z` → (X, Y, Z). Anything else (a pre-release, a dirty stamp) is None.
pub fn semver(tag: &str) -> Option<(u64, u64, u64)> {
    let mut it = tag.strip_prefix('v')?.split('.');
    let v = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    it.next().is_none().then_some(v)
}

/// Published, non-draft, non-pre-release releases from a `releases` API page.
pub fn parse_releases(api_json: &serde_json::Value) -> Vec<Release> {
    api_json
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or_default()
        .iter()
        .filter(|r| !r["draft"].as_bool().unwrap_or(true))
        .filter(|r| !r["prerelease"].as_bool().unwrap_or(true))
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?.to_string();
            semver(&tag)?;
            let has_binary = r["assets"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x["name"] == ASSET));
            Some(Release { tag, has_binary })
        })
        .collect()
}

/// The releases a host on `current` must install, in order, to reach `target`.
///
/// Empty when it is already there. A host with no substrate installed gets the
/// target alone — there is no earlier release on it to skip past. Refuses a
/// downgrade, a target that is not a published release with a binary, and a
/// path through a release with no binary.
pub fn install_path(
    current: Option<&str>,
    target: &str,
    releases: &[Release],
) -> Result<Vec<String>> {
    let Some(want) = semver(target) else {
        bail!("{target} is not a release tag (vX.Y.Z)");
    };
    match releases.iter().find(|r| r.tag == target) {
        None => bail!("{target} is not a published release"),
        Some(r) if !r.has_binary => bail!("{target} is published but carries no binary"),
        Some(_) => {}
    }
    let Some(cur) = current.and_then(semver) else {
        return Ok(vec![target.to_string()]);
    };
    if cur == want {
        return Ok(vec![]);
    }
    if cur > want {
        bail!(
            "refusing to downgrade from {} to {target}",
            current.unwrap_or_default()
        );
    }
    let mut path: Vec<&Release> = releases
        .iter()
        .filter(|r| semver(&r.tag).is_some_and(|v| v > cur && v <= want))
        .collect();
    path.sort_by_key(|r| semver(&r.tag));
    if let Some(gap) = path.iter().find(|r| !r.has_binary) {
        bail!(
            "{} is between {} and {target} and carries no binary — installing around it would skip a release",
            gap.tag,
            current.unwrap_or_default()
        );
    }
    Ok(path.into_iter().map(|r| r.tag.clone()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(tag: &str) -> Release {
        Release {
            tag: tag.into(),
            has_binary: true,
        }
    }
    fn fleet() -> Vec<Release> {
        ["v0.2.12", "v0.2.11", "v0.2.10", "v0.2.9"]
            .map(rel)
            .to_vec()
    }

    /// server2 on 2026-10-27: two behind installs the one in between first.
    #[test]
    fn a_host_two_releases_behind_installs_both_in_order() {
        assert_eq!(
            install_path(Some("v0.2.10"), "v0.2.12", &fleet()).unwrap(),
            vec!["v0.2.11", "v0.2.12"]
        );
    }

    #[test]
    fn a_host_already_there_installs_nothing() {
        assert!(
            install_path(Some("v0.2.12"), "v0.2.12", &fleet())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_fresh_host_gets_the_target_alone() {
        assert_eq!(
            install_path(None, "v0.2.12", &fleet()).unwrap(),
            vec!["v0.2.12"]
        );
    }

    #[test]
    fn a_downgrade_is_refused() {
        assert!(install_path(Some("v0.2.12"), "v0.2.11", &fleet()).is_err());
    }

    /// v0.2.11 as first published: no binary. Installing around it is a skip.
    #[test]
    fn a_release_with_no_binary_in_the_path_refuses_the_host() {
        let mut r = fleet();
        r[1].has_binary = false;
        let err = install_path(Some("v0.2.10"), "v0.2.12", &r)
            .unwrap_err()
            .to_string();
        assert!(err.contains("v0.2.11") && err.contains("skip"), "{err}");
    }

    #[test]
    fn an_unpublished_or_empty_target_is_refused() {
        assert!(install_path(Some("v0.2.10"), "v0.2.99", &fleet()).is_err());
        let mut r = fleet();
        r[0].has_binary = false;
        assert!(install_path(Some("v0.2.10"), "v0.2.12", &r).is_err());
        assert!(install_path(Some("v0.2.10"), "latest", &fleet()).is_err());
    }

    #[test]
    fn versions_compare_numerically_not_as_text() {
        let r = ["v0.2.10", "v0.2.9", "v0.2.11"].map(rel).to_vec();
        assert_eq!(
            install_path(Some("v0.2.8"), "v0.2.11", &r).unwrap(),
            vec!["v0.2.9", "v0.2.10", "v0.2.11"]
        );
    }

    #[test]
    fn drafts_prereleases_and_odd_tags_are_not_releases() {
        let j = serde_json::json!([
            {"tag_name": "v0.2.12", "draft": false, "prerelease": false, "assets": [{"name": ASSET}]},
            {"tag_name": "v0.2.13", "draft": true,  "prerelease": false, "assets": [{"name": ASSET}]},
            {"tag_name": "v0.3.0-rc1", "draft": false, "prerelease": true, "assets": [{"name": ASSET}]},
            {"tag_name": "v0.2.11", "draft": false, "prerelease": false, "assets": []},
        ]);
        assert_eq!(
            parse_releases(&j),
            vec![
                rel("v0.2.12"),
                Release {
                    tag: "v0.2.11".into(),
                    has_binary: false
                }
            ]
        );
    }
}
