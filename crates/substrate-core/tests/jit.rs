//! The ported jit-admin functions must reproduce the Python byte for byte.
//!
//! WHY GOLDENS AND NOT A DIFFERENTIAL
//! `posture-check` is read-only, so both implementations could be run against
//! the same cluster and their output compared. `jit-admin` WRITES — it grants
//! cluster-admin — and two write tools cannot be proven equivalent by running
//! both, because both would write.
//!
//! So these are pinned to files generated from the Python by
//! `tests/golden/jit/regenerate.py`. Regeneration is a deliberate script that
//! prints "READ THE DIFF", never a `--update-snapshots` flag: regenerating on
//! failure is how a port stops being a port and becomes a rewrite that agrees
//! with itself.
#![allow(non_snake_case)]

use std::path::PathBuf;
use substrate_core::jit::*;

fn golden(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/jit")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("golden {} unreadable: {e}", p.display()))
}

/// The fixed identity the goldens were generated with. A value that varied by
/// machine could not be pinned, which is why the Rust takes it as an argument
/// where the Python reads it from the environment.
fn who() -> Attribution {
    Attribution {
        invoker: "brad".into(),
        host: "golden-host".into(),
    }
}

#[test]
fn the_attribution_map_reproduces_its_golden() {
    let m = attribution(
        "brad",
        "investigating a failed backup",
        "2026-09-10T13:00:00Z",
        "2026-09-10T12:30:00Z",
        &who(),
    );
    let rendered = serde_json::to_string_pretty(&m).unwrap() + "\n";
    assert_eq!(rendered, golden("attribution.json"));
}

#[test]
fn every_annotation_the_ADR_136_incident_demanded_is_present() {
    // A grant recording only its expiry — what this tool wrote until
    // 2026-09-06 — cannot answer the one question asked after the fact. An
    // unattributed grant appeared on 2026-09-05 and neither the operator nor
    // the tooling could say who issued it.
    let m = attribution("u", "r", "e", "g", &who());
    for key in [
        "jit.bradpenney.io/expires-at",
        "jit.bradpenney.io/granted-at",
        "jit.bradpenney.io/invoker",
        "jit.bradpenney.io/source-host",
        "jit.bradpenney.io/reason",
        "jit.bradpenney.io/subject",
    ] {
        assert!(m.contains_key(key), "missing annotation {key}");
    }
}

#[test]
fn the_grant_audit_line_reproduces_its_golden_INCLUDING_whitespace() {
    // ⚠️ THE POINT OF THIS TEST. `json.dumps` separates with ", " and ": ";
    // serde_json writes neither by default. An audit record differing only in
    // whitespace is still a record the two tools do not agree on, and it would
    // show as a spurious diff in the ConfigMap forever after.
    let line = audit_line(
        "grant",
        "brad",
        "investigating a failed backup",
        "2026-09-10T12:30:00Z",
        &who(),
    );
    assert_eq!(line + "\n", golden("audit_grant.txt"));
}

#[test]
fn a_revoke_keeps_its_EMPTY_reason_rather_than_dropping_the_key() {
    // The audit answers "who revoked this" as much as "who granted it". A
    // dropped key would make the two record shapes differ.
    let line = audit_line("revoke", "brad", "", "2026-09-10T12:45:00Z", &who());
    assert_eq!(line + "\n", golden("audit_revoke.txt"));
}

#[test]
fn a_reason_containing_quotes_and_backslashes_stays_parseable() {
    // The record is JSON. An unescaped quote produces a line that cannot be
    // read back — and the audit log is only worth keeping if it can be.
    let line = audit_line(
        "grant",
        "brad",
        r#"he said "fix it" C:\temp"#,
        "2026-09-10T12:30:00Z",
        &who(),
    );
    assert_eq!(line.clone() + "\n", golden("audit_awkward_reason.txt"));
    serde_json::from_str::<serde_json::Value>(&line).expect("must parse back");
}

#[test]
fn the_audit_line_contains_no_newline_by_construction() {
    // The ConfigMap value is newline-separated records. One embedded newline
    // turns a single record into two malformed ones.
    let line = audit_line("grant", "u", "a\nb", "t", &who());
    assert!(!line.contains('\n'), "got {line:?}");
}

// ──────────────────────────────────────────────────────────── trimming

#[test]
fn trimming_keeps_the_newest_entries_and_drops_the_oldest() {
    // A log that grows without bound eventually exceeds the ~1 MiB ConfigMap
    // limit, at which point the audit stops recording — silently, and only once
    // there is a lot of history worth keeping.
    let existing = (1..=250)
        .map(|i| format!("e{i}"))
        .collect::<Vec<_>>()
        .join("\n");
    let out = trimmed_log(&existing, "newest");
    let lines: Vec<&str> = out.split('\n').collect();
    assert_eq!(lines.len(), AUDIT_MAX_ENTRIES);
    assert_eq!(*lines.last().unwrap(), "newest");
    assert_eq!(lines[0], "e52", "oldest entries drop first");
}

#[test]
fn trimming_an_empty_log_yields_just_the_new_line() {
    assert_eq!(trimmed_log("", "first"), "first");
}

#[test]
fn blank_lines_in_the_existing_log_are_not_counted_as_entries() {
    assert_eq!(trimmed_log("a\n\nb\n", "c"), "a\nb\nc");
}

// ─────────────────────────────────────────────────────── grant window

#[test]
fn a_grant_longer_than_a_working_day_is_refused() {
    // Not time-boxed in any meaningful sense.
    assert!(validate_minutes(481).is_err());
    assert!(validate_minutes(0).is_err());
    assert!(validate_minutes(-5).is_err());
}

#[test]
fn the_boundaries_of_the_grant_window_are_inclusive() {
    assert_eq!(validate_minutes(1), Ok(1));
    assert_eq!(validate_minutes(480), Ok(480));
}
