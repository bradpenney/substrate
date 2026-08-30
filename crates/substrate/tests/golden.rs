//! The Rust renderer must reproduce every golden cloud-config, byte for byte.
//!
//! This is the acceptance criterion for Wave 0 of the port (ADR-095), and it is
//! deliberately Rust-native: `cargo test` is the gate, with no Python in the
//! loop. A port whose only proof of correctness runs in the language being
//! replaced is not finished.
//!
//! WHAT IS COMPARED
//! The full contents, and nothing else. An earlier version of this check also
//! asserted the output was over 1000 bytes, on the theory that comparing two
//! empty outputs is how a check quietly stops checking. That reasoning is
//! right, but it does not apply here: the comparison is against a COMMITTED
//! artefact, and empty output is not equal to a golden. The size test was a
//! proxy for a check the comparison already performs, with a magic number
//! attached. It is gone.
//!
//! The guard that does matter is the exit status. A renderer that fails and
//! prints nothing must be reported as a failed renderer, not as a diff.
//!
//! WHERE THE ARCHETYPES COME FROM
//! `tests/golden/archetypes.yaml`, the same file `regenerate.py` reads.
//! Declaring them separately would let the two harnesses drift into testing
//! different things while both reported success.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One archetype, as declared in `tests/golden/archetypes.yaml`.
#[derive(Debug, Deserialize)]
struct Archetype {
    file: String,
    #[allow(dead_code)] // documentation for a human reading the yaml
    why: String,
    private_artifact: bool,
    args: Vec<String>,
}

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn golden_dir() -> PathBuf {
    repo_root().join("tests/golden")
}

fn archetypes() -> Vec<Archetype> {
    let text = std::fs::read_to_string(golden_dir().join("archetypes.yaml"))
        .expect("archetypes.yaml is readable");
    serde_yaml_ng::from_str(&text).expect("archetypes.yaml parses")
}

/// The site config to render an archetype against.
///
/// The private-artifact variant is DERIVED from the committed fixture rather
/// than being a second committed file: a copy would drift the moment a key was
/// added to one and not the other, and the two would then differ in ways the
/// archetype was never meant to test.
fn site_file(archetype: &Archetype, tmp: &tempfile::TempDir) -> PathBuf {
    let fixture = repo_root().join("tests/fixtures/site.yml");
    if !archetype.private_artifact {
        return fixture;
    }
    let text = std::fs::read_to_string(&fixture).expect("fixture is readable");
    let mut value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text).expect("fixture parses");
    value
        .get_mut("flux")
        .and_then(|f| f.as_mapping_mut())
        .expect("fixture has a flux mapping")
        .insert(
            serde_yaml_ng::Value::from("ghcr_token"),
            serde_yaml_ng::Value::from("fake-ghcr-token"),
        );
    let path = tmp.path().join("site.yml");
    std::fs::write(
        &path,
        serde_yaml_ng::to_string(&value).expect("re-serialises"),
    )
    .expect("temp site.yml is writable");
    path
}

/// Render one archetype through the built binary.
///
/// Both variables are SET rather than defaulted. A golden rendered from a real
/// `site.yml` would bake real addresses and a real key into a committed file,
/// so this must never inherit an operator's environment.
fn render(archetype: &Archetype, site: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_substrate"))
        .arg("render")
        .args(&archetype.args)
        .arg("--repo")
        .arg(repo_root())
        .env("SUBSTRATE_SITE_FILE", site)
        .env(
            "HOMELAB_SSH_PUBLIC_KEY",
            "ssh-ed25519 AAAATESTKEYONLY test@fixture",
        )
        .output()
        .expect("the substrate binary runs");

    assert!(
        output.status.success(),
        "renderer failed for {}: {}",
        archetype.file,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("output is utf-8")
}

#[test]
fn every_archetype_reproduces_its_golden() {
    let archetypes = archetypes();
    assert!(
        !archetypes.is_empty(),
        "archetypes.yaml declared nothing — a test that checks an empty list \
         passes while checking nothing"
    );

    let tmp = tempfile::tempdir().expect("temp dir");
    let mut failures = Vec::new();

    for archetype in &archetypes {
        let rendered = render(archetype, &site_file(archetype, &tmp));
        let golden_path = golden_dir().join(&archetype.file);
        let golden = std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|_| panic!("{} is missing", archetype.file));

        if rendered != golden {
            failures.push(describe_difference(&archetype.file, &golden, &rendered));
        }
    }

    assert!(
        failures.is_empty(),
        "the Rust renderer no longer reproduces the goldens.\n\n{}\n\
         The port REPRODUCES; it does not redefine. Do not regenerate a golden \
         to make this pass.",
        failures.join("\n\n")
    );
}

/// First differing line, with context — a byte count says nothing useful.
fn describe_difference(name: &str, golden: &str, rendered: &str) -> String {
    let mut lines = vec![format!("--- {name}")];
    let golden_lines: Vec<&str> = golden.lines().collect();
    let rendered_lines: Vec<&str> = rendered.lines().collect();

    for (i, (want, got)) in golden_lines.iter().zip(rendered_lines.iter()).enumerate() {
        if want != got {
            lines.push(format!("  line {}:", i + 1));
            lines.push(format!("    golden: {want}"));
            lines.push(format!("    rust:   {got}"));
            return lines.join("\n");
        }
    }
    // No differing line means one output is a prefix of the other, which a
    // line-by-line walk cannot show.
    lines.push(format!(
        "  identical for {} lines, then the files differ in length \
         (golden {} lines, rust {} lines)",
        golden_lines.len().min(rendered_lines.len()),
        golden_lines.len(),
        rendered_lines.len()
    ));
    lines.join("\n")
}

#[test]
fn the_private_artifact_archetype_actually_renders_a_pull_secret() {
    // Guard the guard. If the derived fixture silently stopped overriding
    // ghcr_token, that archetype would become a duplicate of `joiner` and the
    // 16-space pullSecret indent bug would be covered by nothing, while the
    // suite stayed green.
    let tmp = tempfile::tempdir().expect("temp dir");
    let all = archetypes();
    let private = all
        .iter()
        .find(|a| a.private_artifact)
        .expect("one archetype must exercise the private-artifact path");
    let plain = all
        .iter()
        .find(|a| !a.private_artifact)
        .expect("at least one archetype must not");

    assert!(render(private, &site_file(private, &tmp)).contains("pullSecret: ghcr-auth"));
    assert!(!render(plain, &site_file(plain, &tmp)).contains("pullSecret: ghcr-auth"));
}

#[test]
fn a_bootstrap_node_may_not_also_carry_a_join_token() {
    // The bootstrap node comes up alone and joins nothing. Accepting both would
    // render a config that silently contradicts itself, and the node would come
    // up looking fine.
    let output = Command::new(env!("CARGO_BIN_EXE_substrate"))
        .args(["render", "--name", "x", "--ip", "192.0.2.1", "--bootstrap"])
        .args(["--join-token", "nope", "--repo"])
        .arg(repo_root())
        .env(
            "SUBSTRATE_SITE_FILE",
            repo_root().join("tests/fixtures/site.yml"),
        )
        .env(
            "HOMELAB_SSH_PUBLIC_KEY",
            "ssh-ed25519 AAAATESTKEYONLY test@fixture",
        )
        .output()
        .expect("the substrate binary runs");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("mutually exclusive"));
}
