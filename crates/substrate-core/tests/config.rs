//! The cross-field rules, in both directions.
//!
//! Every rule here is asserted to FIRE on the bad config and to stay quiet on
//! the good one. A test that only proves a check can pass is what let the
//! readiness gate ship while it was silently always-true (ADR-080), and these
//! rules guard configurations that fail in ways nobody notices: a cluster that
//! trusts the wrong signer, a VIP that collides with a live host, a fleet with
//! two nodes each believing they are the cluster.

use std::path::Path;
use substrate_core::config::SiteConfig;

/// Load the committed fixture and let a caller break one thing about it.
///
/// Starting from a KNOWN-GOOD config is the point: a hand-built minimal config
/// would drift from the real schema, and a rule could then pass here while
/// being unreachable in practice.
fn fixture_with(edit: impl FnOnce(&mut serde_yaml_ng::Value)) -> SiteConfig {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(repo.join("tests/fixtures/site.yml")).expect("fixture");
    let mut value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text).expect("fixture parses");
    substrate_core::versions::merge(&repo, &mut value).expect("versions merge");
    edit(&mut value);
    serde_yaml_ng::from_value(value).expect("still matches the schema")
}

fn set(value: &mut serde_yaml_ng::Value, section: &str, key: &str, to: serde_yaml_ng::Value) {
    value
        .get_mut(section)
        .and_then(|s| s.as_mapping_mut())
        .expect("section is a mapping")
        .insert(serde_yaml_ng::Value::from(key), to);
}

#[test]
fn the_committed_fixture_is_valid() {
    // If this fails every other test in the file is meaningless — they all
    // start from it and change one thing.
    substrate_core::validate(&fixture_with(|_| {})).expect("fixture must be valid");
}

#[test]
fn a_missing_cosign_subject_is_refused() {
    // `provider: cosign` alone accepts ANY valid Sigstore signature, including
    // one an attacker produced with their own GitHub account. Rendering without
    // a subject pin is a downgrade that looks like success (ADR-094).
    let cfg = fixture_with(|v| set(v, "flux", "cosign_subject", serde_yaml_ng::Value::Null));
    let err = substrate_core::validate(&cfg).expect_err("must refuse");
    assert!(err.to_string().contains("cosign_subject"), "{err}");
}

#[test]
fn an_empty_cosign_subject_is_refused_too() {
    // Present-but-blank is the more likely mistake: a key left in place while
    // its value was cut. It must not read as "configured".
    let cfg = fixture_with(|v| set(v, "flux", "cosign_subject", serde_yaml_ng::Value::from("")));
    assert!(substrate_core::validate(&cfg).is_err());
}

#[test]
fn a_node_sitting_on_the_control_plane_vip_is_refused() {
    // Nothing fails at provisioning time: the VM boots fine, and keepalived
    // later ARPs for an address a live host already answers for. Intermittent,
    // extremely confusing control-plane failures. Cheap to check here.
    let cfg = fixture_with(|v| {
        let vip = v["control_plane"]["vip"].clone();
        v.get_mut("nodes")
            .and_then(|n| n.as_mapping_mut())
            .expect("nodes")
            .get_mut(serde_yaml_ng::Value::from("b-vm2"))
            .and_then(|n| n.as_mapping_mut())
            .expect("b-vm2")
            .insert(serde_yaml_ng::Value::from("ip"), vip);
    });
    let err = substrate_core::validate(&cfg).expect_err("must refuse");
    assert!(err.to_string().contains("also assigned to node"), "{err}");
}

#[test]
fn a_local_hypervisor_without_a_peer_target_is_refused() {
    // `ssh_target: null` means "runs locally", so nothing else carries an
    // address the OTHER hypervisor could use — and the nightly-update health
    // check needs exactly that. Catch it here rather than at 03:00.
    let cfg = fixture_with(|v| {
        v.get_mut("hypervisors")
            .and_then(|h| h.as_mapping_mut())
            .expect("hypervisors")
            .get_mut(serde_yaml_ng::Value::from("hvA"))
            .and_then(|h| h.as_mapping_mut())
            .expect("hvA")
            .insert(
                serde_yaml_ng::Value::from("peer_target"),
                serde_yaml_ng::Value::Null,
            );
    });
    let err = substrate_core::validate(&cfg).expect_err("must refuse");
    assert!(err.to_string().contains("peer_target"), "{err}");
}

#[test]
fn exactly_one_bootstrap_node_is_required() {
    // Zero means nothing can be built. Two means two clusters, each believing
    // it is the cluster — and both runs report success.
    let two = fixture_with(|v| {
        v.get_mut("nodes")
            .and_then(|n| n.as_mapping_mut())
            .expect("nodes")
            .get_mut(serde_yaml_ng::Value::from("b-vm2"))
            .and_then(|n| n.as_mapping_mut())
            .expect("b-vm2")
            .insert(
                serde_yaml_ng::Value::from("bootstrap"),
                serde_yaml_ng::Value::from(true),
            );
    });
    assert!(substrate_core::validate(&two).is_err());

    let none = fixture_with(|v| {
        v.get_mut("nodes")
            .and_then(|n| n.as_mapping_mut())
            .expect("nodes")
            .get_mut(serde_yaml_ng::Value::from("b-vm1"))
            .and_then(|n| n.as_mapping_mut())
            .expect("b-vm1")
            .insert(
                serde_yaml_ng::Value::from("bootstrap"),
                serde_yaml_ng::Value::from(false),
            );
    });
    assert!(substrate_core::validate(&none).is_err());
}

#[test]
fn an_unknown_key_is_an_error_not_a_shrug() {
    // `deny_unknown_fields` is pydantic's `extra="forbid"`. A misspelled key
    // must not be silently ignored with the default left in place — the same
    // class of failure kubeconform was added to catch on the manifests side.
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(repo.join("tests/fixtures/site.yml")).expect("fixture");
    let mut value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text).expect("parses");
    substrate_core::versions::merge(&repo, &mut value).expect("versions merge");
    set(
        &mut value,
        "network",
        "gatway",
        serde_yaml_ng::Value::from("10.99.0.1"),
    );

    let parsed: Result<SiteConfig, _> = serde_yaml_ng::from_value(value);
    let err = parsed.expect_err("a misspelled key must not parse");
    assert!(err.to_string().contains("gatway"), "{err}");
}

#[test]
fn duplicate_keys_are_refused() {
    // PyYAML silently keeps the last, which is how the production site.yml
    // carried storage_disk_gb twice on three nodes (ADR-095). serde refuses,
    // and siteconfig.py now does too — the two implementations must agree on
    // what a VALID config is, not only on how to render a valid one.
    let parsed: Result<serde_yaml_ng::Value, _> = serde_yaml_ng::from_str("a:\n  x: 1\n  x: 2\n");
    assert!(parsed.is_err(), "duplicate keys must not parse");
}
