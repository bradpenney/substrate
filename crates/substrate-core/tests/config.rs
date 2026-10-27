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
fn fixture_with(edit: impl FnOnce(&mut substrate_core::yaml::Value)) -> SiteConfig {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(repo.join("tests/fixtures/site.yml")).expect("fixture");
    let mut value: substrate_core::yaml::Value =
        substrate_core::yaml::from_str(&text).expect("fixture parses");
    substrate_core::versions::merge(&repo, &mut value).expect("versions merge");
    edit(&mut value);
    substrate_core::yaml::from_value(value).expect("still matches the schema")
}

fn set(
    value: &mut substrate_core::yaml::Value,
    section: &str,
    key: &str,
    to: substrate_core::yaml::Value,
) {
    value
        .get_mut(section)
        .and_then(|s| s.as_object_mut())
        .expect("section is a mapping")
        .insert(key.to_string(), to);
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
    let cfg = fixture_with(|v| {
        set(
            v,
            "flux",
            "cosign_subject",
            substrate_core::yaml::Value::Null,
        )
    });
    let err = substrate_core::validate(&cfg).expect_err("must refuse");
    assert!(err.to_string().contains("cosign_subject"), "{err}");
}

#[test]
fn an_empty_cosign_subject_is_refused_too() {
    // Present-but-blank is the more likely mistake: a key left in place while
    // its value was cut. It must not read as "configured".
    let cfg = fixture_with(|v| {
        set(
            v,
            "flux",
            "cosign_subject",
            substrate_core::yaml::Value::from(""),
        )
    });
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
            .and_then(|n| n.as_object_mut())
            .expect("nodes")
            .get_mut("b-vm2")
            .and_then(|n| n.as_object_mut())
            .expect("b-vm2")
            .insert("ip".into(), vip);
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
            .and_then(|h| h.as_object_mut())
            .expect("hypervisors")
            .get_mut("hvA")
            .and_then(|h| h.as_object_mut())
            .expect("hvA")
            .insert("peer_target".into(), substrate_core::yaml::Value::Null);
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
            .and_then(|n| n.as_object_mut())
            .expect("nodes")
            .get_mut("b-vm2")
            .and_then(|n| n.as_object_mut())
            .expect("b-vm2")
            .insert("bootstrap".into(), substrate_core::yaml::Value::from(true));
    });
    assert!(substrate_core::validate(&two).is_err());

    let none = fixture_with(|v| {
        v.get_mut("nodes")
            .and_then(|n| n.as_object_mut())
            .expect("nodes")
            .get_mut("b-vm1")
            .and_then(|n| n.as_object_mut())
            .expect("b-vm1")
            .insert("bootstrap".into(), substrate_core::yaml::Value::from(false));
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
    let mut value: substrate_core::yaml::Value =
        substrate_core::yaml::from_str(&text).expect("parses");
    substrate_core::versions::merge(&repo, &mut value).expect("versions merge");
    set(
        &mut value,
        "network",
        "gatway",
        substrate_core::yaml::Value::from("10.99.0.1"),
    );

    let parsed: Result<SiteConfig, _> = substrate_core::yaml::from_value(value);
    let err = parsed.expect_err("a misspelled key must not parse");
    assert!(err.to_string().contains("gatway"), "{err}");
}

#[test]
fn duplicate_keys_are_refused() {
    // PyYAML silently keeps the last, which is how the production site.yml
    // carried storage_disk_gb twice on three nodes (ADR-095). serde refuses,
    // and siteconfig.py now does too — the two implementations must agree on
    // what a VALID config is, not only on how to render a valid one.
    let parsed: Result<substrate_core::yaml::Value, _> =
        substrate_core::yaml::from_str("a:\n  x: 1\n  x: 2\n");
    assert!(parsed.is_err(), "duplicate keys must not parse");
}

// ─────────────────────────────────────────── operator keys on every node (bug-210)

const KEY_S1: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIserver1key brad@server1";
const KEY_S2: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIserver2key brad@server2";

fn declare_keys(v: &mut substrate_core::yaml::Value, a: Option<&str>, b: Option<&str>) {
    for (hv, key) in [("hvA", a), ("hvB", b)] {
        if let Some(k) = key {
            v["hypervisors"][hv]["ssh_public_key"] = substrate_core::yaml::Value::from(k);
        }
    }
}

/// A site that declares no keys keeps the old behaviour exactly.
#[test]
fn with_no_keys_declared_the_runners_key_is_the_set() {
    let cfg = fixture_with(|_| {});
    assert_eq!(
        substrate_core::render::authorized_keys(&cfg, KEY_S1).unwrap(),
        vec![KEY_S1.to_string()]
    );
}

/// The bug-210 fix: a roll from server1 authorizes server2's key too.
#[test]
fn every_declared_key_is_authorized_whoever_runs_the_roll() {
    let cfg = fixture_with(|v| declare_keys(v, Some(KEY_S1), Some(KEY_S2)));
    let keys = substrate_core::render::authorized_keys(&cfg, KEY_S1).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&KEY_S2.to_string()), "{keys:?}");
}

/// Key material is compared, not the trailing comment.
#[test]
fn the_runner_matches_on_key_material_not_comment() {
    let cfg = fixture_with(|v| declare_keys(v, Some(KEY_S1), Some(KEY_S2)));
    let same_key_other_label = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIserver1key someone@laptop";
    assert!(substrate_core::render::authorized_keys(&cfg, same_key_other_label).is_ok());
}

/// Declared keys that leave out the runner would build a node the runner
/// cannot reach — refused, and the callers check this before destroying.
#[test]
fn a_runner_outside_the_declared_set_is_refused() {
    let cfg = fixture_with(|v| declare_keys(v, Some(KEY_S2), None));
    assert!(substrate_core::render::authorized_keys(&cfg, KEY_S1).is_err());
}

/// End to end through the real renderer: both declared keys land in the
/// node's cloud-config as authorized keys for the admin user.
#[test]
fn a_rendered_node_authorizes_every_declared_key() {
    let cfg = fixture_with(|v| declare_keys(v, Some(KEY_S1), Some(KEY_S2)));
    let keys = substrate_core::render::authorized_keys(&cfg, KEY_S1).unwrap();
    let (name, node) = cfg.nodes.iter().next().expect("fixture has a node");
    let vm = substrate_core::render::Vm {
        name: name.clone(),
        static_ip: node.ip.clone(),
        hypervisor: node.hypervisor.clone(),
        bootstrap: node.bootstrap,
        memory_mib: None,
        vcpu: None,
        storage_disk_gb: None,
    };
    let rendered = substrate_core::render::cloud_config(&cfg, &vm, None, &keys);
    let doc: substrate_core::yaml::Value =
        substrate_core::yaml::from_str(&rendered).expect("cloud-config parses");
    let authorized = doc["users"][0]["ssh_authorized_keys"]
        .as_array()
        .expect("a key list");
    assert_eq!(authorized.len(), 2);
    assert!(
        authorized.iter().any(|k| k == KEY_S2),
        "server2's key must be on the node"
    );
}
