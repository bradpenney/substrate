//! Every host a deploy reaches runs the same substrate release as the deploy.
//!
//! WHY (bug-209). On 2026-10-23 `deploy-posture --apply` ran from server1 on
//! v0.2.10 and fanned a v0.2.10-shaped `site.yml` out to server2, which was
//! still on v0.2.8 — the install there had never happened. v0.2.8 could not
//! parse the new config, and (bug-208) its posture-check then published
//! "10 of 10, no findings" for three days. Nothing compared versions, so a newer
//! configuration reached an older binary that did not understand it.
//!
//! A deploy now asks each host what it runs before writing anything, and
//! refuses unless every one reports the deploying binary's own release tag. A
//! host that cannot be asked is a refusal too: an unknown version is not a
//! matching one. The fix is always the same — install the missing release on
//! that host, in order, never skipping one.

/// The release tag in a version line: `substrate 0.2.10 (v0.2.10)` → `v0.2.10`.
///
/// Also accepts the bare build stamp the binary embeds (`0.2.10 (v0.2.10)`).
/// None when there is no parenthesised tag, e.g. a development build's stamp
/// with a dirty suffix still yields its tag, but garbage yields nothing.
pub fn release_tag(version_line: &str) -> Option<&str> {
    let open = version_line.rfind('(')?;
    let close = version_line[open..].find(')')? + open;
    let tag = version_line[open + 1..close].trim();
    (!tag.is_empty()).then_some(tag)
}

/// One line per host whose substrate is not `ours`, naming what it reported.
///
/// `reported` pairs a host name with its `substrate --version` output, or None
/// when it could not be asked. Empty when every host matches.
pub fn skew(ours: &str, reported: &[(String, Option<String>)]) -> Vec<String> {
    let mut out = Vec::new();
    for (host, line) in reported {
        match line.as_deref().map(str::trim) {
            None | Some("") => out.push(format!(
                "{host}: could not be asked which substrate it runs — an unknown version is not {ours}"
            )),
            Some(l) => match release_tag(l) {
                Some(tag) if tag == ours => {}
                Some(tag) => out.push(format!("{host}: runs {tag}, this deploy is {ours}")),
                None => out.push(format!("{host}: reported {l:?}, which names no release")),
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_tag_from_a_version_line_and_from_the_bare_stamp() {
        assert_eq!(release_tag("substrate 0.2.10 (v0.2.10)"), Some("v0.2.10"));
        assert_eq!(release_tag("0.2.12 (v0.2.12)"), Some("v0.2.12"));
        assert_eq!(release_tag("bash: substrate: command not found"), None);
    }

    #[test]
    fn a_matching_fleet_is_silent() {
        let r = vec![
            (
                "server1".to_string(),
                Some("substrate 0.2.12 (v0.2.12)".to_string()),
            ),
            (
                "server2".to_string(),
                Some("substrate 0.2.12 (v0.2.12)\n".to_string()),
            ),
        ];
        assert!(skew("v0.2.12", &r).is_empty());
    }

    /// bug-209, as found.
    #[test]
    fn a_host_on_an_older_release_is_named() {
        let r = vec![
            (
                "server1".to_string(),
                Some("substrate 0.2.10 (v0.2.10)".to_string()),
            ),
            (
                "server2".to_string(),
                Some("substrate 0.2.8 (v0.2.8)".to_string()),
            ),
        ];
        assert_eq!(
            skew("v0.2.10", &r),
            vec!["server2: runs v0.2.8, this deploy is v0.2.10"]
        );
    }

    #[test]
    fn a_host_that_cannot_be_asked_is_a_refusal_not_a_pass() {
        let r = vec![("server2".to_string(), None)];
        assert_eq!(skew("v0.2.12", &r).len(), 1);
        let r = vec![("server2".to_string(), Some("command not found".to_string()))];
        assert_eq!(skew("v0.2.12", &r).len(), 1);
    }
}
