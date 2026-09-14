//! The ported checks must reach the SAME verdict as the Python, and say it in
//! the same words.
//!
//! WHY THE EXACT STRINGS ARE ASSERTED
//! posture-check's output is its interface: a systemd unit runs it, and
//! `OnFailure` fires on the exit code while a human reads the lines. The
//! differential harness compares the two implementations' text, so a message
//! that is merely EQUIVALENT is a port that cannot be proven. Rewording a
//! finding is a deliberate act that should break these tests.
//!
//! Fixtures are inline rather than captured from the live cluster on purpose:
//! a test that needs a cluster only runs where there is one, and the failure
//! paths below — a namespace with no PSS label, an unexpected cluster-admin —
//! are states the real cluster had better never be in.

// Capitals in test names are deliberate emphasis on the thing that must not
// regress — the same convention the Python suite uses
// (`test_activity_ids_are_compared_as_STRINGS_not_ints`). A test name is read
// in a failure report, where "Deny" carries more than "deny".
#![allow(non_snake_case)]

use serde_json::json;
use substrate_core::posture::*;

// ───────────────────────────────────────────────────────── pod security

#[test]
fn pod_security_passes_when_every_namespace_carries_an_enforce_label() {
    let ns = json!({"items": [
        {"metadata": {"name": "kube-system",
                      "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}},
        {"metadata": {"name": "wanderer",
                      "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}},
    ]});
    let mut r = Report::default();
    check_pod_security(&ns, &mut r);
    assert_eq!(r.failures, Vec::<String>::new());
    assert_eq!(r.notes, vec!["pod security: 2/2 namespaces enforced"]);
}

#[test]
fn pod_security_does_not_care_WHICH_level_is_enforced() {
    // privileged is legitimate for kube-system and k0s-autopilot. The check
    // asserts the label EXISTS; a check that demanded `restricted` everywhere
    // would fail permanently and teach everyone to ignore it.
    let ns = json!({"items": [
        {"metadata": {"name": "kube-system",
                      "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}},
    ]});
    let mut r = Report::default();
    check_pod_security(&ns, &mut r);
    assert!(r.failures.is_empty(), "privileged must not be a finding");
}

#[test]
fn pod_security_fails_and_names_the_namespaces_with_no_label_at_all() {
    // The default for a NEW namespace. This is the state the check exists for.
    let ns = json!({"items": [
        {"metadata": {"name": "zeta", "labels": {}}},
        {"metadata": {"name": "alpha"}},
        {"metadata": {"name": "ok",
                      "labels": {"pod-security.kubernetes.io/enforce": "baseline"}}},
    ]});
    let mut r = Report::default();
    check_pod_security(&ns, &mut r);
    assert_eq!(
        r.failures,
        vec!["namespaces with NO Pod Security enforcement: alpha, zeta"],
        "names must be sorted, and a missing labels map counts as missing"
    );
    assert!(r.notes.is_empty());
}

// ───────────────────────────────────────────────────────── default deny

#[test]
fn a_policy_counts_only_with_an_empty_selector_and_BOTH_directions() {
    // The whole point of the check. An ingress-only policy leaves egress wide
    // open, which is the half that matters for exfiltration; a policy with a
    // podSelector catches some pods and not others.
    let ns = json!({"items": [
        {"metadata": {"name": "good"}},
        {"metadata": {"name": "ingress-only"}},
        {"metadata": {"name": "selective"}},
    ]});
    let np = json!({"items": [
        {"metadata": {"namespace": "good"},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
        {"metadata": {"namespace": "ingress-only"},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}},
        {"metadata": {"namespace": "selective"},
         "spec": {"podSelector": {"matchLabels": {"app": "x"}},
                  "policyTypes": ["Ingress", "Egress"]}},
    ]});
    let mut r = Report::default();
    check_default_deny(&ns, &np, &mut r);
    assert_eq!(
        r.failures,
        vec!["namespaces with NO default-deny NetworkPolicy: ingress-only, selective"]
    );
}

#[test]
fn the_exempt_namespace_is_not_reported_as_a_gap() {
    let ns = json!({"items": [{"metadata": {"name": "hello"}}]});
    let np = json!({"items": []});
    let mut r = Report::default();
    check_default_deny(&ns, &np, &mut r);
    assert!(
        r.failures.is_empty(),
        "hello is exempt with a recorded reason"
    );
    assert_eq!(r.notes, vec!["network policy: 0 namespaces default-deny"]);
}

// ───────────────────────────────────────────────────────── cluster-admin

#[test]
fn a_new_cluster_admin_subject_is_a_failure() {
    let b = json!({"items": [
        {"roleRef": {"name": "cluster-admin"},
         "subjects": [{"kind": "Group", "name": "system:masters"},
                      {"kind": "User", "name": "mallory"}]},
    ]});
    let mut r = Report::default();
    check_cluster_admin(&b, &mut r);
    assert_eq!(
        r.failures,
        vec!["UNEXPECTED cluster-admin subjects: User/mallory"]
    );
}

#[test]
fn a_subject_that_disappeared_is_a_NOTE_not_a_failure() {
    // It means the baseline is stale, not that the cluster is unsafe. Reporting
    // it as a failure would make the monitor cry wolf every time something was
    // legitimately removed.
    let b = json!({"items": [
        {"roleRef": {"name": "cluster-admin"},
         "subjects": [{"kind": "Group", "name": "system:masters"}]},
    ]});
    let mut r = Report::default();
    check_cluster_admin(&b, &mut r);
    assert!(r.failures.is_empty());
    assert!(
        r.notes
            .iter()
            .any(|n| n.starts_with("cluster-admin subjects removed since baseline: ")),
        "got {:?}",
        r.notes
    );
}

#[test]
fn bindings_to_other_roles_are_ignored_entirely() {
    let b = json!({"items": [
        {"roleRef": {"name": "view"},
         "subjects": [{"kind": "User", "name": "someone"}]},
    ]});
    let mut r = Report::default();
    check_cluster_admin(&b, &mut r);
    assert!(
        r.failures.is_empty(),
        "a `view` binding is not a cluster-admin finding"
    );
}

// ───────────────────────────────────────────────── admission policies

#[test]
fn a_binding_downgraded_from_Deny_to_Warn_is_caught() {
    // ADR-068: invisible in `kubectl get`, and silently turns a guardrail into
    // a log line. This is the entire reason the check inspects
    // validationActions rather than just counting policies.
    let pol = json!({"items": [
        {"metadata": {"name": "require-pss-labels"}},
        {"metadata": {"name": "workload-hygiene"}},
    ]});
    let bind = json!({"items": [
        {"spec": {"policyName": "require-pss-labels", "validationActions": ["Warn"]}},
        {"spec": {"policyName": "workload-hygiene", "validationActions": ["Warn"]}},
    ]});
    let mut r = Report::default();
    check_admission_policies(&pol, &bind, &mut r);
    assert_eq!(
        r.failures,
        vec!["no admission policy binding is set to Deny -- every guardrail has become advisory"]
    );
}

#[test]
fn a_missing_policy_is_named() {
    let pol = json!({"items": [{"metadata": {"name": "require-pss-labels"}}]});
    let bind = json!({"items": [
        {"spec": {"policyName": "require-pss-labels", "validationActions": ["Deny"]}},
    ]});
    let mut r = Report::default();
    check_admission_policies(&pol, &bind, &mut r);
    assert_eq!(
        r.failures,
        vec!["admission policies MISSING: workload-hygiene"]
    );
    assert!(
        r.notes.is_empty(),
        "with a policy missing, the reassuring note must be withheld"
    );
}

#[test]
fn all_present_and_denying_produces_the_note() {
    let pol = json!({"items": [
        {"metadata": {"name": "require-pss-labels"}},
        {"metadata": {"name": "workload-hygiene"}},
    ]});
    let bind = json!({"items": [
        {"spec": {"policyName": "require-pss-labels", "validationActions": ["Deny"]}},
        {"spec": {"policyName": "workload-hygiene", "validationActions": ["Deny", "Audit"]}},
    ]});
    let mut r = Report::default();
    check_admission_policies(&pol, &bind, &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(r.notes, vec!["admission: 2 policies, 2 enforcing Deny"]);
}

// ───────────────────────────────────────────────────────── robustness

#[test]
fn a_response_with_no_items_yields_nothing_rather_than_panicking() {
    // A check that crashes must not hide the others — the reason the Python
    // wraps every call in try/except. Here it is structural instead.
    let empty = json!({});
    let mut r = Report::default();
    check_pod_security(&empty, &mut r);
    check_cluster_admin(&empty, &mut r);
    check_admission_policies(&empty, &empty, &mut r);
    check_default_deny(&empty, &empty, &mut r);
    // No panic is the assertion. Findings are whatever empty input implies.
}

// ───────────────────────────────────────────────────────────────── flux

#[test]
fn a_kustomization_merely_reconciling_is_a_NOTE_not_a_failure() {
    // Directly earned: a check that fired on Ready!=True reported a failure
    // whenever it ran mid-reconcile, which is normal operation. A daily false
    // alarm is how an alert gets ignored.
    let k = json!({"items": [
        {"metadata": {"name": "apps"},
         "status": {"conditions": [
            {"type": "Ready", "status": "False", "reason": "Progressing"}]}},
    ]});
    let mut r = Report::default();
    check_flux(&k, &mut r);
    assert!(r.failures.is_empty(), "progressing is not broken");
    // BOTH lines, and that is the Python's actual contract rather than an
    // oversight: the per-item note explains WHICH one is mid-flight, and the
    // summary still fires because nothing landed in `bad`. This assertion was
    // written expecting only the first, and the test caught the difference
    // between what I assumed and what the reference implementation does —
    // which is the entire job of a differential port.
    assert_eq!(
        r.notes,
        vec![
            "flux: apps reconciling (Progressing)",
            "flux: 1 kustomizations reconciling"
        ]
    );
}

#[test]
fn DependencyNotReady_is_tolerated_because_it_is_ordinary_ordering() {
    // Seen for real: `apps` waits on `infrastructure-config` every reconcile.
    let k = json!({"items": [
        {"metadata": {"name": "apps"},
         "status": {"conditions": [
            {"type": "Ready", "status": "False", "reason": "DependencyNotReady"}]}},
    ]});
    let mut r = Report::default();
    check_flux(&k, &mut r);
    assert!(r.failures.is_empty());
}

#[test]
fn a_terminal_flux_failure_IS_reported() {
    let k = json!({"items": [
        {"metadata": {"name": "apps"},
         "status": {"conditions": [
            {"type": "Ready", "status": "False", "reason": "ReconciliationFailed"}]}},
    ]});
    let mut r = Report::default();
    check_flux(&k, &mut r);
    assert_eq!(
        r.failures,
        vec!["Flux Kustomizations not Ready: apps (ReconciliationFailed)"]
    );
}

#[test]
fn a_MISSING_Ready_condition_is_a_failure_because_absent_is_not_healthy() {
    // The distinction the docstring insists on. A Kustomization that never
    // started has no Ready condition at all, and treating that as fine is
    // exactly how it stays unnoticed.
    let k = json!({"items": [{"metadata": {"name": "apps"}, "status": {}}]});
    let mut r = Report::default();
    check_flux(&k, &mut r);
    assert_eq!(
        r.failures,
        vec!["Flux Kustomizations not Ready: apps (no Ready condition)"]
    );
}

// ────────────────────────────────────────────────────────── credentials

#[test]
fn an_externalsecret_that_stopped_syncing_is_named() {
    // It keeps working until the value is rotated, so the failure is invisible
    // right up until it is urgent.
    let e = json!({"items": [
        {"metadata": {"namespace": "wanderer", "name": "ok"},
         "status": {"conditions": [{"type": "Ready", "status": "True"}]}},
        {"metadata": {"namespace": "wanderer", "name": "stale"},
         "status": {"conditions": [{"type": "Ready", "status": "False"}]}},
    ]});
    let mut r = Report::default();
    check_credentials(&e, &mut r);
    assert_eq!(
        r.failures,
        vec!["ExternalSecrets not syncing (the Secret may still look fine): wanderer/stale"]
    );
}

#[test]
fn an_externalsecret_with_no_conditions_at_all_counts_as_stale() {
    let e = json!({"items": [{"metadata": {"namespace": "ns", "name": "new"}}]});
    let mut r = Report::default();
    check_credentials(&e, &mut r);
    assert_eq!(
        r.failures.len(),
        1,
        "no conditions is not the same as Ready"
    );
}

// ──────────────────────────────────────────────────────────── jit grant

/// 2026-09-10T12:00:00Z as a unix timestamp — the "now" every case below uses.
///
/// COMPUTED, not typed from memory. The first version of this line was
/// 1_788_004_800, which is 2026-08-29 — twelve days out, and it put every
/// "expired" fixture in the FUTURE. Only one test caught it. Verify with:
///   python3 -c "import datetime as dt; \
///     print(int(dt.datetime.fromisoformat('2026-09-10T12:00:00+00:00').timestamp()))"
const NOW: i64 = 1_789_041_600;

#[test]
fn no_binding_at_all_is_the_healthy_ordinary_case() {
    // kubectl exits non-zero for "not found", which is why this check cannot
    // use the shared query helper: that would record a kubectl failure for the
    // most common and most desirable state.
    let mut r = Report::default();
    check_no_standing_grant(None, NOW, &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(r.notes, vec!["jit grant: none outstanding"]);
}

#[test]
fn a_grant_with_NO_expiry_annotation_is_standing_cluster_admin() {
    // The entire point of the check. A binding without an expiry is permanent
    // privilege wearing the name of a temporary one.
    let b = json!({"metadata": {"name": "jit-platform-admin", "annotations": {}}});
    let mut r = Report::default();
    check_no_standing_grant(Some(&b), NOW, &mut r);
    assert_eq!(
        r.failures,
        vec!["a jit-platform-admin grant exists with NO expiry annotation"]
    );
}

#[test]
fn a_live_grant_is_reported_as_a_note_with_its_expiry() {
    let b = json!({"metadata": {"annotations":
        {"jit.bradpenney.io/expires-at": "2026-09-10T13:00:00Z"}}});
    let mut r = Report::default();
    check_no_standing_grant(Some(&b), NOW, &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["jit grant: outstanding, expires 2026-09-10T13:00:00Z"]
    );
}

#[test]
fn a_grant_just_past_expiry_is_tolerated_because_the_reaper_is_a_cronjob() {
    // 4 minutes over. The reaper runs on a schedule, so there is always a gap
    // between expiry and removal; firing on it would page for normal operation.
    let b = json!({"metadata": {"annotations":
        {"jit.bradpenney.io/expires-at": "2026-09-10T11:56:00Z"}}});
    let mut r = Report::default();
    check_no_standing_grant(Some(&b), NOW, &mut r);
    assert!(r.failures.is_empty(), "4 minutes over must not page");
}

#[test]
fn a_grant_well_past_expiry_means_the_reaper_is_NOT_running() {
    // 10 minutes over, past the 5-minute grace.
    let b = json!({"metadata": {"annotations":
        {"jit.bradpenney.io/expires-at": "2026-09-10T11:50:00Z"}}});
    let mut r = Report::default();
    check_no_standing_grant(Some(&b), NOW, &mut r);
    assert_eq!(
        r.failures,
        vec![
            "jit grant EXPIRED at 2026-09-10T11:50:00Z and is still present -- the reaper is not running"
        ]
    );
}

#[test]
fn an_unparseable_expiry_is_never_treated_as_healthy() {
    // The Python reaches this as an unhandled exception caught by main()'s
    // wrapper — a different message, same refusal. Calling an expiry we cannot
    // read "fine" is the one outcome neither implementation permits.
    let b = json!({"metadata": {"annotations":
        {"jit.bradpenney.io/expires-at": "not-a-timestamp"}}});
    let mut r = Report::default();
    check_no_standing_grant(Some(&b), NOW, &mut r);
    assert_eq!(r.failures.len(), 1);
    assert!(r.notes.is_empty());
}

// ─────────────────────────────────────────────────────── host units

use substrate_core::posture::SystemdState;

#[test]
fn a_failed_watched_unit_is_named_with_when_it_failed() {
    let st = SystemdState {
        system_status: "degraded".into(),
        failed_watched: vec![(
            "hypervisor-update.service".into(),
            "Thu 2026-09-10 03:40:10 ADT".into(),
        )],
        all_failed: vec!["hypervisor-update.service".into()],
    };
    let mut r = Report::default();
    check_failed_units(&st, &mut r);
    assert_eq!(
        r.failures,
        vec![
            "systemd unit hypervisor-update.service is FAILED (since Thu 2026-09-10 03:40:10 ADT)"
        ]
    );
    assert!(
        r.notes.is_empty(),
        "the reassuring note must be withheld when a watched unit is failed"
    );
}

#[test]
fn a_missing_timestamp_says_unknown_rather_than_printing_nothing() {
    let st = SystemdState {
        system_status: "running".into(),
        failed_watched: vec![("auto-roll.service".into(), String::new())],
        all_failed: vec![],
    };
    let mut r = Report::default();
    check_failed_units(&st, &mut r);
    assert_eq!(
        r.failures,
        vec!["systemd unit auto-roll.service is FAILED (since unknown)"]
    );
}

#[test]
fn a_degraded_system_reports_UNWATCHED_failures_as_a_failure_not_a_note() {
    // This previously recorded them as a note, so a run could print "all
    // invariants hold" while systemd sat degraded — a contradiction that
    // teaches the reader to distrust the summary line.
    let st = SystemdState {
        system_status: "degraded".into(),
        failed_watched: vec![],
        all_failed: vec!["something-else.service".into()],
    };
    let mut r = Report::default();
    check_failed_units(&st, &mut r);
    assert_eq!(
        r.failures,
        vec!["systemd is degraded; failed units not on the watch list: something-else.service"]
    );
}

#[test]
fn posture_check_itself_is_NOT_watched_because_watching_yourself_deadlocks() {
    // One failure marks the unit failed; the next run then fails BECAUSE it is
    // failed, and it can never clear — a unit only leaves the failed state by
    // succeeding. Found by running it while it was in exactly that state.
    assert!(
        !WATCHED_UNITS.contains(&"posture-check.service"),
        "adding posture-check.service to the watch list creates a deadlock"
    );
}

#[test]
fn a_healthy_host_produces_the_summary_note() {
    let st = SystemdState {
        system_status: "running".into(),
        failed_watched: vec![],
        all_failed: vec![],
    };
    let mut r = Report::default();
    check_failed_units(&st, &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(r.notes, vec!["host units: 8 watched, none failed"]);
}

#[test]
fn only_the_first_five_unwatched_failures_are_listed() {
    // An unbounded list turns one bad boot into a wall of text that buries
    // every other finding.
    let st = SystemdState {
        system_status: "degraded".into(),
        failed_watched: vec![],
        all_failed: (1..=9).map(|i| format!("u{i}.service")).collect(),
    };
    let mut r = Report::default();
    check_failed_units(&st, &mut r);
    assert_eq!(r.failures.len(), 1);
    assert_eq!(
        r.failures[0].matches(".service").count(),
        5,
        "the list must be truncated to five"
    );
}

// ────────────────────────────────────────────────────────────── selinux

use substrate_core::posture::SelinuxProbe;

fn probe(label: &str, out: Option<&str>) -> SelinuxProbe {
    SelinuxProbe {
        label: label.into(),
        output: out.map(str::to_string),
    }
}

#[test]
fn enforcing_with_zero_permissive_domains_is_the_healthy_answer() {
    let mut r = Report::default();
    check_selinux(&[probe("this host", Some("Enforcing\n0\n"))], &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["selinux: this host enforcing, no permissive domains"]
    );
}

#[test]
fn permissive_MODE_is_a_failure() {
    let mut r = Report::default();
    check_selinux(&[probe("this host", Some("Permissive\n0\n"))], &mut r);
    assert_eq!(
        r.failures,
        vec!["selinux: this host is Permissive, expected Enforcing"]
    );
}

#[test]
fn enforcing_with_a_permissive_DOMAIN_is_still_a_failure() {
    // The property is not the mode. A host can report Enforcing while a
    // `semanage permissive -a` added to work around one awkward denial quietly
    // opts that domain out of the entire control — which is precisely the drift
    // this check exists to catch, and which the mode alone cannot see.
    let mut r = Report::default();
    check_selinux(&[probe("this host", Some("Enforcing\n2\n"))], &mut r);
    assert_eq!(r.failures.len(), 1);
    assert!(
        r.failures[0].contains("2 domain(s) are permissive"),
        "got {:?}",
        r.failures
    );
    assert!(r.notes.is_empty());
}

#[test]
fn an_unreachable_host_is_a_NOTE_saying_it_was_not_checked() {
    // Unreachable is not evidence the control is broken — but it is not
    // evidence it holds either, and the wording keeps those apart. Reporting it
    // as a failure would page on a transient ssh blip.
    let mut r = Report::default();
    check_selinux(&[probe("192.168.2.101", None)], &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["selinux: 192.168.2.101 unreachable, not checked"]
    );
}

#[test]
fn empty_output_counts_as_unreachable_not_as_a_mode_of_question_mark() {
    // A host that answers with nothing must not be reported as
    // `is ?, expected Enforcing` — that reads as a real finding about SELinux
    // when it is actually a broken probe.
    let mut r = Report::default();
    check_selinux(&[probe("peer", Some("   \n"))], &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(r.notes, vec!["selinux: peer unreachable, not checked"]);
}

#[test]
fn a_non_numeric_permissive_count_does_not_manufacture_a_failure() {
    let mut r = Report::default();
    check_selinux(&[probe("this host", Some("Enforcing\nnope\n"))], &mut r);
    assert!(r.failures.is_empty(), "an unparseable count reads as zero");
}

#[test]
fn both_hosts_are_reported_independently() {
    let mut r = Report::default();
    check_selinux(
        &[
            probe("this host", Some("Enforcing\n0")),
            probe("192.168.2.101", Some("Permissive\n0")),
        ],
        &mut r,
    );
    assert_eq!(r.notes.len(), 1);
    assert_eq!(
        r.failures.len(),
        1,
        "one healthy host must not mask the other"
    );
}

// ──────────────────────────────────────────────────────── peer units

use substrate_core::posture::PeerUnitState;

fn peer(state: Option<&str>) -> PeerUnitState {
    PeerUnitState {
        label: "192.168.2.101".into(),
        unit: "hypervisor-update.service".into(),
        state: state.map(str::to_string),
    }
}

#[test]
fn a_failed_peer_unit_is_a_failure() {
    // The fault this exists for: server2's hypervisor-update aborted nightly
    // for days with nothing on that host able to report it.
    let mut r = Report::default();
    check_peer_units(&[peer(Some("failed"))], &mut r);
    assert_eq!(
        r.failures,
        vec!["peer 192.168.2.101: hypervisor-update.service is FAILED"]
    );
}

#[test]
fn an_unreachable_peer_is_a_note_not_a_failure() {
    // Do not fail the whole check because a host is briefly rebooting — which
    // is a state the nightly maintenance puts it in ON PURPOSE.
    let mut r = Report::default();
    check_peer_units(&[peer(None)], &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["peer 192.168.2.101: unreachable, hypervisor-update.service not checked"]
    );
}

#[test]
fn an_empty_answer_is_treated_as_unreachable_not_as_healthy() {
    let mut r = Report::default();
    check_peer_units(&[peer(Some("  \n"))], &mut r);
    assert!(r.failures.is_empty());
    assert!(r.notes[0].contains("unreachable"), "got {:?}", r.notes);
}

#[test]
fn any_other_state_is_reported_verbatim() {
    // `inactive` is the healthy resting state for a oneshot unit between runs.
    let mut r = Report::default();
    check_peer_units(&[peer(Some("inactive"))], &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["peer 192.168.2.101: hypervisor-update.service inactive"]
    );
}

// ─────────────────────────────────────────────────────── origin lock

use substrate_core::posture::OriginProbe;

#[test]
fn a_direct_connection_that_ANSWERS_is_the_lock_being_broken() {
    // The single most consequential finding in the file: someone can reach the
    // ingress without passing the edge allowlist. 200 here is the failure.
    let p = OriginProbe {
        hostname_configured: true,
        edge: Some("203.0.113.10".into()),
        through: "200".into(),
        direct: Some("200".into()),
    };
    let mut r = Report::default();
    check_origin_lock(&p, &mut r);
    assert_eq!(r.failures.len(), 1);
    assert!(
        r.failures[0].starts_with("ORIGIN LOCK BROKEN"),
        "got {:?}",
        r.failures
    );
}

#[test]
fn a_refused_direct_connection_is_the_HEALTHY_answer() {
    // 000 means the connection never completed. Inverted from every other
    // check in this file, and the reason the probe records a raw status rather
    // than a boolean someone could read the wrong way round.
    let p = OriginProbe {
        hostname_configured: true,
        edge: Some("203.0.113.10".into()),
        through: "200".into(),
        direct: Some("000".into()),
    };
    let mut r = Report::default();
    check_origin_lock(&p, &mut r);
    assert!(r.failures.is_empty());
    assert!(
        r.notes
            .contains(&"origin lock: direct bypass refused (000)".to_string())
    );
}

#[test]
fn the_public_site_not_returning_200_is_a_failure() {
    let p = OriginProbe {
        hostname_configured: true,
        edge: Some("203.0.113.10".into()),
        through: "503".into(),
        direct: Some("000".into()),
    };
    let mut r = Report::default();
    check_origin_lock(&p, &mut r);
    assert!(
        r.failures
            .iter()
            .any(|f| f.contains("returned 503, expected 200"))
    );
}

#[test]
fn an_unconfigured_hostname_SKIPS_rather_than_failing() {
    // A repo cloned without a site.yml must not report a broken origin lock —
    // that is a configuration absence, not a security finding, and conflating
    // them would make the check useless to anyone else.
    let p = OriginProbe::default();
    let mut r = Report::default();
    check_origin_lock(&p, &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["origin lock: no public_hostname configured, check skipped"]
    );
}

#[test]
fn a_configured_hostname_with_no_origin_still_checks_the_public_side() {
    let p = OriginProbe {
        hostname_configured: true,
        edge: Some("203.0.113.10".into()),
        through: "200".into(),
        direct: None,
    };
    let mut r = Report::default();
    check_origin_lock(&p, &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(r.notes.len(), 2, "the public 200 AND the skip note");
}

#[test]
fn no_public_answer_means_the_cloudflare_path_was_not_probed_and_that_FAILS() {
    // The host's own resolver answers the ingress's LAN address under
    // split-horizon (ADR-187); a probe that used it would pass without ever
    // touching Cloudflare. So the probe pins to a public answer, and having
    // none is a check that could not see — which must fail, not pass.
    let p = OriginProbe {
        hostname_configured: true,
        edge: None,
        through: String::new(),
        direct: Some("000".into()),
    };
    let mut r = Report::default();
    check_origin_lock(&p, &mut r);
    assert_eq!(r.failures.len(), 1);
    assert!(r.failures[0].contains("NOT probed"), "got {:?}", r.failures);
}

#[test]
fn an_empty_direct_status_reads_as_no_response_not_as_blank() {
    let p = OriginProbe {
        hostname_configured: true,
        edge: Some("203.0.113.10".into()),
        through: "200".into(),
        direct: Some(String::new()),
    };
    let mut r = Report::default();
    check_origin_lock(&p, &mut r);
    assert!(
        r.notes.iter().any(|n| n.contains("(no response)")),
        "got {:?}",
        r.notes
    );
}

// ───────────────────────────────────────────────────── supply chain

#[test]
fn removing_spec_verify_entirely_is_the_loudest_finding() {
    // Flux keeps reconciling perfectly without it — the failure is invisible by
    // construction, which is why an external assertion exists at all.
    let o = json!({"spec": {}, "status": {"conditions": []}});
    let mut r = Report::default();
    check_source_verified(&o, &mut r);
    assert_eq!(r.failures.len(), 1);
    assert!(r.failures[0].contains("NO LONGER signature-verified"));
}

#[test]
fn verification_without_matchOIDCIdentity_would_accept_anyones_signature() {
    // Weaker than it looks, and it reads as "verification: on" in every UI.
    // cosign with no identity match accepts any valid Sigstore signature.
    let o = json!({"spec": {"verify": {"provider": "cosign"}},
                   "status": {"conditions": [
                       {"type": "SourceVerified", "status": "True"}]}});
    let mut r = Report::default();
    check_source_verified(&o, &mut r);
    assert_eq!(r.failures.len(), 1);
    assert!(
        r.failures[0].contains("matchOIDCIdentity"),
        "got {:?}",
        r.failures
    );
    assert!(
        r.notes.is_empty(),
        "a passing SourceVerified must not excuse a missing identity match"
    );
}

#[test]
fn an_empty_matchOIDCIdentity_list_counts_as_absent() {
    // `matchOIDCIdentity: []` satisfies a key-exists check while constraining
    // nothing — the shape of a control that is present and matches everyone.
    let o = json!({"spec": {"verify": {"matchOIDCIdentity": []}},
                   "status": {"conditions": [
                       {"type": "SourceVerified", "status": "True"}]}});
    let mut r = Report::default();
    check_source_verified(&o, &mut r);
    assert_eq!(r.failures.len(), 1);
    assert!(r.failures[0].contains("matchOIDCIdentity"));
}

#[test]
fn a_configured_but_FAILING_verification_reports_its_message() {
    let o = json!({"spec": {"verify": {"matchOIDCIdentity": [{"issuer": "x"}]}},
                   "status": {"conditions": [
                       {"type": "SourceVerified", "status": "False",
                        "message": "no matching signatures"}]}});
    let mut r = Report::default();
    check_source_verified(&o, &mut r);
    assert_eq!(
        r.failures,
        vec!["artifact signature NOT verified: no matching signatures"]
    );
}

#[test]
fn a_missing_SourceVerified_condition_is_not_treated_as_healthy() {
    let o = json!({"spec": {"verify": {"matchOIDCIdentity": [{"issuer": "x"}]}},
                   "status": {"conditions": []}});
    let mut r = Report::default();
    check_source_verified(&o, &mut r);
    assert_eq!(
        r.failures,
        vec!["artifact signature NOT verified: no SourceVerified condition"]
    );
}

#[test]
fn fully_configured_and_passing_produces_the_note() {
    let o = json!({"spec": {"verify": {"matchOIDCIdentity": [{"issuer": "x"}]}},
                   "status": {"conditions": [
                       {"type": "SourceVerified", "status": "True"}]}});
    let mut r = Report::default();
    check_source_verified(&o, &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["supply chain: artifact signature verified against the pinned identity"]
    );
}

// ──────────────────────────────────────────────────────────── firewall

use substrate_core::posture::FirewallProbe;

fn fw(leaked: Option<bool>, permitted: Option<bool>) -> FirewallProbe {
    FirewallProbe {
        port: 9100,
        what: "node_exporter".into(),
        allowed_label: "brad@10.0.0.5".into(),
        denied_label: "brad@10.0.0.9".into(),
        leaked,
        permitted,
    }
}

#[test]
fn a_port_reachable_from_a_NON_allowlisted_source_is_the_finding() {
    // The defect that earned this check: `accept` rich rules layered on top of
    // an already-open 1025-65535 range restricted nothing, and every other
    // check passed throughout because none of them asked whether a refusal
    // actually refuses.
    let mut r = Report::default();
    check_firewall_restrictions(Some(&[fw(Some(true), None)]), &mut r);
    assert_eq!(r.failures.len(), 1);
    assert!(
        r.failures[0].contains("is NOT allow-listed"),
        "got {:?}",
        r.failures
    );
    assert!(
        r.notes.is_empty(),
        "a leaking port must not be counted as checked"
    );
}

#[test]
fn a_port_REFUSED_for_a_source_that_must_reach_it_is_also_a_failure() {
    // Both directions. A firewall that blocks everything is not correct — it is
    // broken where nobody looks until a scrape quietly stops arriving.
    let mut r = Report::default();
    check_firewall_restrictions(Some(&[fw(Some(false), Some(false))]), &mut r);
    assert_eq!(r.failures.len(), 1);
    assert!(
        r.failures[0].contains("MUST reach it"),
        "got {:?}",
        r.failures
    );
}

#[test]
fn correctly_denied_and_correctly_permitted_counts_as_checked() {
    let mut r = Report::default();
    check_firewall_restrictions(Some(&[fw(Some(false), Some(true))]), &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["firewall: 1 port(s) refuse non-allow-listed sources"]
    );
}

#[test]
fn an_INCONCLUSIVE_probe_is_never_counted_as_a_pass() {
    // None means the prober could not be reached, so nothing was learned. The
    // dangerous reading is treating "no answer" as "correctly refused" — that
    // would report the control as verified on the strength of a broken probe.
    let mut r = Report::default();
    check_firewall_restrictions(Some(&[fw(None, None)]), &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["firewall: 9100 not checked (brad@10.0.0.9 unreachable)"],
        "and crucially NOT a 'ports refuse' summary"
    );
}

#[test]
fn an_unprobed_permitted_side_does_not_manufacture_a_failure() {
    // permitted == None is "not probed", distinct from Some(false).
    let mut r = Report::default();
    check_firewall_restrictions(Some(&[fw(Some(false), None)]), &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(r.notes.len(), 1);
}

#[test]
fn incomplete_site_config_skips_rather_than_failing() {
    let mut r = Report::default();
    check_firewall_restrictions(None, &mut r);
    assert!(r.failures.is_empty());
    assert_eq!(
        r.notes,
        vec!["firewall: site config incomplete, not checked"]
    );
}

#[test]
fn a_mix_reports_each_port_on_its_own_merits() {
    let probes = vec![
        fw(Some(false), Some(true)),
        FirewallProbe {
            port: 9428,
            what: "log ingest".into(),
            ..fw(Some(true), None)
        },
    ];
    let mut r = Report::default();
    check_firewall_restrictions(Some(&probes), &mut r);
    assert_eq!(r.failures.len(), 1, "the leak");
    assert_eq!(
        r.notes,
        vec!["firewall: 1 port(s) refuse non-allow-listed sources"],
        "the summary counts only the port that actually verified"
    );
}
