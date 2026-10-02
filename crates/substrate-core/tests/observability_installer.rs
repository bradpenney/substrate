//! The installer's restart passes, exercised as shell rather than read as text.
//!
//! bug-198 shipped because nothing here existed. `deploy-observability` replaced
//! the VictoriaMetrics and VictoriaLogs binaries, printed "active" for both, and
//! left two stale processes serving — a patched binary on disk and an unpatched
//! process answering, from two SECURITY releases. The installer already restarted
//! a unit whose FILE changed and one whose startup-only CONFIG changed; the
//! EXECUTABLE was the one layer with no cover.
//!
//! These tests RUN the mapping function out of the rendered script instead of
//! grepping for it. A test that asserts the comment is present would have passed
//! against the broken installer too.

use std::path::Path;
use std::process::Command;
use substrate_core::config::SiteConfig;
use substrate_core::observability::{components_for, files_for, render_installer};

/// The component the Grafana PLUGIN path owns. `PLUGIN_INSTALLED` restarts
/// grafana.service for it and explains why in its own message, so it is
/// deliberately absent from `unit_for_component`.
const OWNED_BY_PLUGIN_PATH: &str = "victoria_logs_datasource";

fn repo() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture() -> (std::path::PathBuf, SiteConfig) {
    let repo = repo();
    let text = std::fs::read_to_string(repo.join("tests/fixtures/site.yml")).expect("fixture");
    let mut value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text).expect("fixture parses");
    substrate_core::versions::merge(&repo, &mut value).expect("versions merge");
    let cfg: SiteConfig = serde_yaml_ng::from_value(value).expect("matches the schema");
    (repo, cfg)
}

fn rendered(host: &str) -> String {
    let (repo, cfg) = fixture();
    let files = files_for(&repo, &cfg, host, None).expect("plan the files");
    render_installer(&repo, &cfg, host, &files).expect("render the installer")
}

/// Ask the rendered script itself what unit a component's restart belongs to.
///
/// The function is sourced out of the real installer and called, so the answer
/// is the one a host would get.
fn unit_for_component(script: &str, component: &str) -> String {
    let body = script
        .split_once("unit_for_component() {")
        .map(|(_, rest)| rest.split_once("\n}").expect("function closes").0)
        .expect("the installer defines unit_for_component");
    let program = format!("unit_for_component() {{{body}\n}}\nunit_for_component \"$1\"\n");
    let out = Command::new("bash")
        .arg("-c")
        .arg(&program)
        .arg("bash")
        .arg(component)
        .output()
        .expect("run bash");
    assert!(
        out.status.success(),
        "unit_for_component({component}) exited {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Every component this host installs has somewhere to send a restart.
///
/// This is the bug-198 invariant. A component whose binary can be replaced and
/// whose unit nothing knows about is a component that upgrades on disk and never
/// in the process — so adding one without a mapping has to fail here.
#[test]
fn every_installed_component_has_a_restart_target() {
    let (_, cfg) = fixture();
    for host in ["hvA", "hvB"] {
        let script = rendered(host);
        let components = components_for(&cfg, host);
        assert!(
            !components.is_empty(),
            "{host} installs nothing — the fixture stopped exercising this"
        );
        for c in components {
            if c == OWNED_BY_PLUGIN_PATH {
                continue;
            }
            let unit = unit_for_component(&script, c);
            assert!(
                unit.ends_with(".service"),
                "{host} installs {c} but unit_for_component gives {unit:?}: a replaced \
                 binary would never reach the running process (bug-198)"
            );
        }
    }
}

/// The plugin component stays out of the mapping, so the two restart paths
/// cannot both fire for it.
#[test]
fn the_plugin_component_is_left_to_the_plugin_path() {
    let script = rendered("hvA");
    assert_eq!(
        unit_for_component(&script, OWNED_BY_PLUGIN_PATH),
        "",
        "the plugin path already restarts grafana.service and says why; a second \
         mapping would restart it twice"
    );
}

/// An unknown component yields nothing rather than guessing a unit.
#[test]
fn an_unknown_component_maps_to_nothing() {
    let script = rendered("hvA");
    assert_eq!(unit_for_component(&script, "not_a_component"), "");
}

/// Both install shapes that place an executable record it for the restart pass.
///
/// `install_plugin` is excluded on purpose: it has owned its own restart since it
/// was written, through `PLUGIN_INSTALLED`.
#[test]
fn the_install_shapes_record_what_they_replaced() {
    let script = rendered("hvA");
    for shape in ["install_binary() {", "install_tree() {"] {
        let body = script
            .split_once(shape)
            .map(|(_, rest)| rest.split_once("\n}").expect("function closes").0)
            .unwrap_or_else(|| panic!("the installer defines {shape}"));
        assert!(
            body.contains("CHANGED_BINARIES="),
            "{shape} installs an executable without recording it, so the restart \
             pass cannot see it (bug-198)"
        );
    }
}
