//! The fleet is not two hosts (ADR-199 and its amendment).
//!
//! `tests/fixtures/site-one-host.yml` is a stranger with one server;
//! `tests/fixtures/site-three-hosts.yml` is N. Everything here that passes
//! today is a shape the tooling already handles; everything marked
//! `#[ignore]` names the bug that the "peers are a list" work (Phase A.2)
//! removes, and is un-ignored in the same change. A shape that is only ever
//! rendered for two hosts is a shape that silently assumes two.

use std::path::{Path, PathBuf};
use substrate_core::config::SiteConfig;
use substrate_core::provision::Fleet;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> SiteConfig {
    let text = std::fs::read_to_string(repo().join("tests/fixtures").join(name)).expect("fixture");
    let mut value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text).expect("parses");
    substrate_core::versions::merge(&repo().join("tests/fixtures"), &mut value)
        .expect("frozen versions merge");
    serde_yaml_ng::from_value(value).expect("matches the schema")
}

// ------------------------------------------------------------ one host ---

#[test]
fn one_host_is_a_valid_site() {
    let cfg = fixture("site-one-host.yml");
    assert_eq!(cfg.hypervisors.len(), 1);
    substrate_core::validate(&cfg).expect("a one-host site needs no peer_target");
}

#[test]
fn one_host_fleet_has_three_nodes_and_one_bootstrap() {
    let fleet = Fleet::from_config(&fixture("site-one-host.yml"));
    assert_eq!(fleet.hosts.len(), 1);
    assert_eq!(fleet.all_vms().count(), 3);
    let (host, boot) = fleet.find_bootstrap().expect("exactly one bootstrap");
    assert_eq!(host.name, "hvA");
    assert_eq!(boot.name, "a-vm1");
}

#[test]
fn one_host_holds_the_vip_alone() {
    let cfg = fixture("site-one-host.yml");
    let cplb = substrate_core::cplb::Cplb::new(&cfg).expect("cplb config");
    assert_eq!(cplb.controllers().len(), 3);
    let ka = cplb.keepalived_cfg("hvA");
    assert!(
        ka.contains("state MASTER"),
        "the only host must be MASTER:\n{ka}"
    );
    assert!(cplb.haproxy_cfg().contains("10.99.0.22"));
}

#[test]
fn two_hosts_still_require_a_peer_target_for_the_local_one() {
    // The rule is relaxed for ONE host, not removed.
    let mut cfg = fixture("site.yml");
    cfg.hypervisors.get_mut("hvA").expect("hvA").peer_target = None;
    let err = substrate_core::validate(&cfg).expect_err("two hosts, no peer_target: refused");
    assert!(err.to_string().contains("peer_target"), "{err}");
}

// ---------------------------------------------------------- three hosts ---

#[test]
fn three_hosts_is_a_valid_site() {
    let cfg = fixture("site-three-hosts.yml");
    assert_eq!(cfg.hypervisors.len(), 3);
    substrate_core::validate(&cfg).expect("valid");
    let fleet = Fleet::from_config(&cfg);
    assert_eq!(fleet.hosts.len(), 3);
    assert_eq!(fleet.all_vms().count(), 5);
}

#[test]
fn three_hosts_get_three_posture_slots() {
    // deploy-posture staggers the timers 30 minutes apart by host index.
    assert_eq!(substrate_core::deploy_posture::slot(0), "07:30");
    assert_eq!(substrate_core::deploy_posture::slot(1), "08:00");
    assert_eq!(substrate_core::deploy_posture::slot(2), "08:30");
}

#[test]
fn three_hosts_elect_exactly_one_vrrp_master() {
    let cfg = fixture("site-three-hosts.yml");
    let cplb = substrate_core::cplb::Cplb::new(&cfg).expect("cplb config");
    let masters: Vec<&str> = ["hvA", "hvB", "hvC"]
        .into_iter()
        .filter(|h| cplb.keepalived_cfg(h).contains("state MASTER"))
        .collect();
    assert_eq!(masters, vec!["hvB"], "highest priority is the one MASTER");
    assert_eq!(cplb.controllers().len(), 5);
}

#[test]
fn survivability_is_checked_for_the_loss_of_each_of_three_hosts() {
    use serde_json::json;
    use std::collections::BTreeMap;
    use substrate_core::gate::logic::survivability_failures;
    let node_hv: BTreeMap<String, String> = [
        ("b-vm1", "hvB"),
        ("b-vm2", "hvB"),
        ("a-vm1", "hvA"),
        ("a-vm2", "hvA"),
        ("c-vm1", "hvC"),
    ]
    .into_iter()
    .map(|(n, h)| (n.to_string(), h.to_string()))
    .collect();
    let alloc: BTreeMap<String, i64> = node_hv.keys().map(|n| (n.clone(), 4096)).collect();
    // 5 × 4 GiB. One 13000 MiB pod fits the 3 nodes left after losing a
    // two-node host (12288 MiB) — no; the 4 left after losing one-node hvC
    // (16384 MiB) — yes. The check must name hvA and hvB, and not hvC: the
    // loss of EACH host is budgeted, not "the peer".
    let pods = json!({"items": [{
        "metadata": {"namespace": "apps", "name": "big", "ownerReferences": [{"kind": "ReplicaSet"}]},
        "spec": {"nodeName": "a-vm1", "containers": [{"resources": {"requests": {"memory": "13000Mi"}}}]},
        "status": {"phase": "Running"}
    }]});
    let failures = survivability_failures(&pods, &alloc, &node_hv);
    assert_eq!(failures.len(), 2, "{failures:?}");
    assert!(failures[0].starts_with("losing hvA"), "{failures:?}");
    assert!(failures[1].starts_with("losing hvB"), "{failures:?}");
    assert!(!failures.iter().any(|f| f.contains("hvC")), "{failures:?}");
}

// ------------------------------------- the peer is a LIST (Phase A.2) ---

#[test]
fn peers_of_is_every_other_host() {
    use substrate_core::exec::Host;
    for (name, want) in [
        ("site-one-host.yml", 0usize),
        ("site.yml", 1),
        ("site-three-hosts.yml", 2),
    ] {
        let cfg = fixture(name);
        let hosts: Vec<Host> = cfg
            .hypervisors
            .iter()
            .map(|(n, hv)| Host::from_config(n, hv))
            .collect();
        for host in &hosts {
            let peers = substrate_core::updates::peers_of(&hosts, host);
            assert_eq!(
                peers.len(),
                want,
                "{name}: {} has {want} peer(s)",
                host.name
            );
            assert!(peers.iter().all(|p| p.name != host.name));
        }
    }
}

#[test]
fn the_update_env_names_every_peer() {
    // bug-173: one PEER_HOST per host let hvB and hvC both gate on hvA.
    use substrate_core::exec::Host;
    let cfg = fixture("site-three-hosts.yml");
    let hosts: Vec<Host> = cfg
        .hypervisors
        .iter()
        .map(|(n, hv)| Host::from_config(n, hv))
        .collect();
    let env_for = |name: &str| -> String {
        let host = hosts.iter().find(|h| h.name == name).expect(name);
        let peers = substrate_core::updates::peers_of(&hosts, host);
        substrate_core::updates::peer_hosts_value(host, &peers).expect("every peer reachable")
    };
    assert_eq!(env_for("hvA"), "operator@10.99.0.12 operator@10.99.0.13");
    // hvA runs locally, so its peers reach it by peer_target.
    assert_eq!(env_for("hvB"), "operator@10.99.0.11 operator@10.99.0.13");
    assert_eq!(env_for("hvC"), "operator@10.99.0.11 operator@10.99.0.12");
}

#[test]
fn a_one_host_site_gets_an_empty_peer_list_not_a_skip() {
    use substrate_core::exec::Host;
    let cfg = fixture("site-one-host.yml");
    let hosts: Vec<Host> = cfg
        .hypervisors
        .iter()
        .map(|(n, hv)| Host::from_config(n, hv))
        .collect();
    let peers = substrate_core::updates::peers_of(&hosts, &hosts[0]);
    assert!(peers.is_empty());
    assert_eq!(
        substrate_core::updates::peer_hosts_value(&hosts[0], &peers).unwrap(),
        ""
    );
    let files =
        substrate_core::updates::plan(&repo(), &cfg, &hosts[0], &peers, "fake: kubeconfig", None)
            .expect("a one-host site still gets its update units");
    let env = files
        .iter()
        .find(|f| f.remote.ends_with("update.env"))
        .map(|f| String::from_utf8_lossy(&f.data).into_owned())
        .expect("env planned");
    assert!(env.starts_with("PEER_HOSTS=\n"), "{env}");
}
