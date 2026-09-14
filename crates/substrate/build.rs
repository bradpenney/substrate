//! Stamp the binary with what it was built from.
//!
//! `substrate --version` printed `0.1.0` through a weekend of changes, two
//! rebuilds and a roll; nothing recorded which build did which (ADR-192).
//! The stamp is `git describe --tags --always --dirty` — a released build
//! reads `v0.2.0`, a build between releases `v0.2.0-3-gabc1234`, and a build
//! from an uncommitted tree carries `-dirty`, which the writers refuse to
//! act on. Outside a git checkout (a source tarball) the stamp is `unknown`,
//! which the writers also refuse: an artifact of unknown provenance does not
//! get to destroy a cluster.

use std::process::Command;

fn main() {
    let describe = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty=-dirty"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SUBSTRATE_BUILD={describe}");
    // Rebuild the stamp when HEAD or the index moves; a stale stamp would be
    // the exact lie this exists to prevent.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-changed=../../.git/refs/tags");
}
