//! The published posture document (ADR-194): what the public site's status
//! strip and hero terminal are filled from.
//!
//! posture-check RECORDS a document after every run, pass or fail, and
//! `publish-status` PUTs it to a Cloudflare KV namespace the site's Worker
//! reads. Two commands, one file between them, so a publish failure is a
//! publish failure and never looks like a broken invariant — and so the
//! document can be inspected on disk before anything leaves the host.
//!
//! THE CONTRACT IS THE JSON. The Worker never invents a number: a missing or
//! stale document renders as "no run recorded" / "stale", never as a default
//! that looks real. Field names here are the field names in `src/worker.ts`.
//!
//! Everything that decides is pure and tested; the two effects — writing the
//! file and calling curl — live in the binary.

use crate::posture::Report;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One line of the run, as the terminal on the site shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Line {
    /// `ok` or `FAIL` — the two states posture-check prints.
    pub status: String,
    pub text: String,
}

/// The document. `held`/`invariants` feed the strip, `lines` the terminal,
/// `findings` both. `ran_at` is RFC 3339 UTC; the Worker localises it.
///
/// NO HOSTNAME. The first document carried `host: "server1"` and the Worker
/// printed it under the hero terminal — Brad: "that is not a great leak".
/// The site needs to know that a host ran the check, never which one; the
/// journal on the machine already knows. What is published is what is
/// public, and a machine name is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    pub ran_at: String,
    pub provisioner: String,
    pub invariants: usize,
    pub held: usize,
    pub findings: Vec<String>,
    pub lines: Vec<Line>,
}

/// Private (RFC 1918) addresses in a line become `lan-peer` before anything
/// is published. posture-check names its peer by address ("selinux:
/// 192.168.2.101 enforcing"), which is right in a journal and wrong on a
/// public page: a published document that maps a private network is a gift
/// to the wrong reader (the same rule the architecture views are checked
/// against). Public addresses, such as the edge that served the site check,
/// are left alone.
pub fn redact(text: &str) -> String {
    text.split(' ')
        .map(|word| {
            let trimmed = word.trim_matches(|c: char| !c.is_ascii_digit());
            match trimmed.parse::<std::net::Ipv4Addr>() {
                Ok(ip) if ip.is_private() => word.replacen(trimmed, "lan-peer", 1),
                _ => word.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl Document {
    /// Build the document from a finished report. `ran_at` is passed in so the
    /// shape is testable without a clock; the binary passes now. Every line
    /// passes through `redact` on the way in — the document is public.
    pub fn from_report(r: &Report, ran_at: &str, provisioner: &str) -> Self {
        let mut lines: Vec<Line> = r
            .notes
            .iter()
            .map(|t| Line {
                status: "ok".into(),
                text: redact(t),
            })
            .collect();
        lines.extend(r.failures.iter().map(|t| Line {
            status: "FAIL".into(),
            text: redact(t),
        }));
        Document {
            ran_at: ran_at.to_string(),
            provisioner: provisioner.to_string(),
            invariants: r.notes.len() + r.failures.len(),
            held: r.notes.len(),
            findings: r.failures.iter().map(|f| redact(f)).collect(),
            lines,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("posture document serialises")
    }

    pub fn from_json(text: &str) -> Result<Self> {
        serde_json::from_str(text).context("posture document is not the expected JSON")
    }

    /// One line for the journal: what is about to be, or was, published.
    pub fn summary(&self) -> String {
        format!(
            "{} — {} of {} invariants hold, {} finding(s), provisioner {}",
            self.ran_at,
            self.held,
            self.invariants,
            self.findings.len(),
            self.provisioner
        )
    }
}

/// The current time as the document's `ran_at`: RFC 3339, UTC, whole seconds.
pub fn now_rfc3339() -> Result<String> {
    Ok(time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)?
        .format(&time::format_description::well_known::Rfc3339)?)
}

/// Where the document goes. Read from the environment by the binary — the
/// token comes from a root-owned EnvironmentFile the service user cannot read
/// (the same pattern as auto-roll.env), and is never printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub account_id: String,
    pub namespace_id: String,
    pub key: String,
}

impl Target {
    pub fn url(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}",
            self.account_id, self.namespace_id, self.key
        )
    }
}

/// Read the target from `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_KV_NAMESPACE_ID`
/// (and `CLOUDFLARE_KV_KEY`, default `posture`). A missing variable is named,
/// because "curl: URL rejected" would not be.
pub fn target_from_env(get: impl Fn(&str) -> Option<String>) -> Result<Target> {
    let need = |k: &str| {
        get(k).filter(|v| !v.trim().is_empty()).with_context(|| {
            format!(
                "{k} is not set — publish-status needs it (see /etc/substrate/publish-status.env)"
            )
        })
    };
    Ok(Target {
        account_id: need("CLOUDFLARE_ACCOUNT_ID")?,
        namespace_id: need("CLOUDFLARE_KV_NAMESPACE_ID")?,
        key: get("CLOUDFLARE_KV_KEY").unwrap_or_else(|| "posture".into()),
    })
}

/// The curl invocation, minus the token. The token is passed through a header
/// file (`-H @file`) so it never appears in /proc/<pid>/cmdline, for the same
/// reason a join token is never a `--join-token` argument.
pub fn curl_args(target: &Target, body_path: &str, header_path: &str) -> Vec<String> {
    vec![
        "-sS".into(),
        "--fail-with-body".into(),
        "-X".into(),
        "PUT".into(),
        target.url(),
        "-H".into(),
        format!("@{header_path}"),
        "-H".into(),
        "Content-Type: application/json".into(),
        "--data-binary".into(),
        format!("@{body_path}"),
    ]
}

/// Cloudflare answers `{"success": true|false, "errors": [...]}` with a 200
/// even on some failures, so the body is the verdict, not the status code.
pub fn publish_succeeded(response_body: &str) -> Result<()> {
    let v: serde_json::Value =
        serde_json::from_str(response_body).context("KV response is not JSON")?;
    if v.get("success").and_then(|s| s.as_bool()) == Some(true) {
        return Ok(());
    }
    anyhow::bail!(
        "KV refused the write: {}",
        v.get("errors")
            .map(|e| e.to_string())
            .unwrap_or_else(|| response_body.trim().to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        let mut r = Report::default();
        r.note("pod security: 19/19 namespaces enforced");
        r.note("flux: 5 kustomizations reconciling");
        r.fail("systemd is degraded; failed units not on the watch list: x.service");
        r
    }

    #[test]
    fn the_document_counts_every_line_and_keeps_failures_as_findings() {
        let d = Document::from_report(&report(), "2026-09-15T23:55:34Z", "0.2.4");
        assert_eq!(d.invariants, 3);
        assert_eq!(d.held, 2);
        assert_eq!(
            d.findings,
            vec!["systemd is degraded; failed units not on the watch list: x.service"]
        );
        assert_eq!(d.lines.len(), 3);
        assert_eq!(d.lines[0].status, "ok");
        assert_eq!(d.lines[2].status, "FAIL");
        assert_eq!(d.lines[2].text, d.findings[0]);
    }

    #[test]
    fn private_addresses_never_reach_the_document() {
        assert_eq!(
            redact("selinux: 192.168.2.101 enforcing, no permissive domains"),
            "selinux: lan-peer enforcing, no permissive domains"
        );
        assert_eq!(
            redact("peer 10.0.0.7: hypervisor-update.service inactive"),
            "peer lan-peer: hypervisor-update.service inactive"
        );
        // a public address is information the reader could get anyway
        assert_eq!(
            redact("public site: 200 through Cloudflare (edge 172.67.222.31)"),
            "public site: 200 through Cloudflare (edge 172.67.222.31)"
        );
        // and a number that is not an address is untouched
        assert_eq!(
            redact("pod security: 19/19 namespaces enforced"),
            "pod security: 19/19 namespaces enforced"
        );

        let mut r = Report::default();
        r.note("selinux: 192.168.2.101 enforcing");
        r.fail("peer 192.168.2.101: hypervisor-update.service active");
        let d = Document::from_report(&r, "t", "v");
        assert!(!d.to_json().unwrap().contains("192.168."));
    }

    #[test]
    fn a_clean_run_has_no_findings_and_held_equals_invariants() {
        let mut r = Report::default();
        r.note("a");
        r.note("b");
        let d = Document::from_report(&r, "t", "v");
        assert_eq!((d.held, d.invariants), (2, 2));
        assert!(d.findings.is_empty());
    }

    #[test]
    fn the_json_round_trips_and_carries_the_worker_field_names() {
        let d = Document::from_report(&report(), "2026-09-15T23:55:34Z", "0.2.4");
        let text = d.to_json().unwrap();
        for field in [
            "ran_at",
            "invariants",
            "held",
            "findings",
            "provisioner",
            "lines",
        ] {
            assert!(text.contains(&format!("\"{field}\"")), "{field} missing");
        }
        assert!(
            !text.contains("host"),
            "a machine name must never be in the document"
        );
        assert_eq!(Document::from_json(&text).unwrap(), d);
    }

    #[test]
    fn the_target_names_the_missing_variable() {
        let err = target_from_env(|_| None).unwrap_err().to_string();
        assert!(err.contains("CLOUDFLARE_ACCOUNT_ID"), "{err}");
        let err = target_from_env(|k| (k == "CLOUDFLARE_ACCOUNT_ID").then(|| "acc".into()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("CLOUDFLARE_KV_NAMESPACE_ID"), "{err}");
    }

    #[test]
    fn the_key_defaults_to_posture() {
        let t = target_from_env(|k| match k {
            "CLOUDFLARE_ACCOUNT_ID" => Some("acc".into()),
            "CLOUDFLARE_KV_NAMESPACE_ID" => Some("ns".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(t.key, "posture");
        assert_eq!(
            t.url(),
            "https://api.cloudflare.com/client/v4/accounts/acc/storage/kv/namespaces/ns/values/posture"
        );
    }

    #[test]
    fn curl_never_sees_the_token_on_its_command_line() {
        let t = Target {
            account_id: "acc".into(),
            namespace_id: "ns".into(),
            key: "posture".into(),
        };
        let args = curl_args(&t, "/tmp/body.json", "/tmp/hdr");
        assert!(args.iter().any(|a| a == "@/tmp/hdr"));
        assert!(args.iter().any(|a| a == "@/tmp/body.json"));
        assert!(!args.iter().any(|a| a.contains("Bearer")));
        assert!(args.contains(&"--fail-with-body".to_string()));
    }

    #[test]
    fn success_is_read_from_the_body_not_assumed() {
        assert!(publish_succeeded(r#"{"success":true,"errors":[]}"#).is_ok());
        let err = publish_succeeded(
            r#"{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Authentication error"), "{err}");
        assert!(publish_succeeded("<html>502</html>").is_err());
    }
}
