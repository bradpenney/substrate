//! Everything a `deploy-*` command puts on a host, embedded at build time
//! (ADR-200). The release artifact IS the payload: a script or unit that the
//! signed binary does not carry cannot reach a hypervisor, and `--repo`
//! supplies configuration only — `site.yml` and `versions.yml`.
//!
//! WHY EMBEDDED, NOT READ. ADR-192 made the provisioner a signed release and
//! made every writer refuse to run from a build that is not one. That guard
//! covered the binary while the payload was read at run time from whatever
//! `--repo` pointed at: any commit, any branch, a hand-edited working tree.
//! Brad: "deploy-updates should pull from a released version!" It does now,
//! because the released version is the only place the payload exists.
//!
//! THE LIST IS EXPLICIT. No build script walks a directory: a walk would
//! embed whatever happened to be on disk, which is the failure this module
//! exists to close. Instead the test below walks the repository and fails
//! when a shipped file is not listed here or a listed file is gone, so
//! adding a unit to `systemd/` without adding it here does not compile a
//! release that silently lacks it.

/// A shipped file: its path in the repository, and its bytes.
pub struct Shipped {
    pub path: &'static str,
    pub bytes: &'static [u8],
}

macro_rules! ship {
    ($p:literal) => {
        Shipped {
            path: $p,
            bytes: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../", $p)),
        }
    };
}

/// Every file a planner may deploy, keyed by repository path.
pub const FILES: &[Shipped] = &[
    // deploy-updates (nightly maintenance on every hypervisor)
    ship!("hypervisor-update.sh"),
    ship!("hypervisor-uncordon.sh"),
    ship!("notify.sh"),
    ship!("systemd/hypervisor-update.service"),
    ship!("systemd/hypervisor-update.timer"),
    ship!("systemd/hypervisor-uncordon.service"),
    ship!("systemd/hypervisor-update-notify.service"),
    // deploy-posture (ADR-196)
    ship!("systemd/posture-check.service"),
    ship!("systemd/posture-check.timer"),
    ship!("systemd/posture-check-notify.service"),
    ship!("systemd/publish-status.service"),
    // deploy-observability (ADR-098)
    ship!("grafana-health.sh"),
    ship!("substrate-reconcile.sh"),
    ship!("systemd/observability/grafana-health.service"),
    ship!("systemd/observability/grafana-health.timer"),
    ship!("systemd/observability/grafana.service"),
    ship!("systemd/observability/node-exporter.service"),
    ship!("systemd/observability/observability-notify@.service"),
    ship!("systemd/observability/substrate-reconcile.service"),
    ship!("systemd/observability/substrate-reconcile.timer"),
    ship!("systemd/observability/victoria-logs.service"),
    ship!("systemd/observability/victoria-metrics.service"),
    ship!("observability-host/grafana.ini.template"),
    ship!("observability-host/traefik/observe.yml.template"),
    ship!("observability-host/provisioning/datasources/victoria.yaml"),
    ship!("observability-host/provisioning/dashboards/repository.yaml"),
    ship!("observability-host/dashboards/app-health.json"),
    ship!("observability-host/dashboards/fleet-overview.json"),
    ship!("observability-host/dashboards/k8s-state.json"),
];

/// The bytes of a shipped file, by repository path.
pub fn bytes(path: &str) -> anyhow::Result<&'static [u8]> {
    FILES
        .iter()
        .find(|f| f.path == path)
        .map(|f| f.bytes)
        .ok_or_else(|| {
            anyhow::anyhow!("{path} is not part of this release's payload (payload.rs, ADR-200)")
        })
}

/// A shipped text file, by repository path.
pub fn text(path: &str) -> anyhow::Result<&'static str> {
    std::str::from_utf8(bytes(path)?).map_err(|e| anyhow::anyhow!("{path} is not UTF-8: {e}"))
}

/// Every shipped file under a repository directory, sorted by path — how the
/// dashboards are enumerated, so a new dashboard is a new list entry, not a
/// directory walk at deploy time.
pub fn under(dir: &str) -> Vec<&'static Shipped> {
    let prefix = format!("{}/", dir.trim_end_matches('/'));
    let mut v: Vec<&Shipped> = FILES
        .iter()
        .filter(|f| f.path.starts_with(&prefix))
        .collect();
    v.sort_by_key(|f| f.path);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Path;

    fn repo() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// Walk the directories a planner ships from and return every file in
    /// them as a repository-relative path.
    fn on_disk() -> BTreeSet<String> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(root, &p, out);
                } else {
                    out.insert(
                        p.strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
        }
        let root = repo();
        let mut out = BTreeSet::new();
        for dir in ["systemd", "observability-host"] {
            walk(&root, &root.join(dir), &mut out);
        }
        out
    }

    #[test]
    fn every_shipped_directory_file_is_embedded() {
        // Units the planners never ship are listed here ON PURPOSE, with the
        // reason: adding to this list is a decision, not an oversight.
        let deliberately_unshipped: BTreeSet<&str> = [
            // ADR-186: present, disabled by design — a host timer must not
            // pull from git. deploy-auto-roll.sh is archived with them.
            "systemd/auto-roll.service",
            "systemd/auto-roll.timer",
            "systemd/auto-roll-notify.service",
        ]
        .into_iter()
        .collect();
        let embedded: BTreeSet<&str> = FILES.iter().map(|f| f.path).collect();
        let disk = on_disk();
        let missing: Vec<&String> = disk
            .iter()
            .filter(|p| {
                !embedded.contains(p.as_str()) && !deliberately_unshipped.contains(p.as_str())
            })
            .collect();
        assert!(
            missing.is_empty(),
            "on disk but not in the release payload — add to payload.rs FILES or to \
             deliberately_unshipped with a reason: {missing:?}"
        );
        let gone: Vec<&str> = embedded
            .iter()
            .copied()
            .filter(|p| !repo().join(p).is_file())
            .collect();
        assert!(gone.is_empty(), "embedded but gone from disk: {gone:?}");
    }

    #[test]
    fn embedded_bytes_are_the_committed_bytes() {
        for f in FILES {
            let disk = std::fs::read(repo().join(f.path)).unwrap();
            assert_eq!(f.bytes, disk.as_slice(), "{} drifted from the tree", f.path);
        }
    }

    #[test]
    fn lookups_are_by_repository_path() {
        assert!(
            text("hypervisor-update.sh")
                .unwrap()
                .starts_with("#!/usr/bin/env bash")
        );
        assert!(bytes("systemd/posture-check.service").is_ok());
        let err = bytes("systemd/does-not-exist.service")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not part of this release's payload"), "{err}");
        let boards: Vec<&str> = under("observability-host/dashboards")
            .iter()
            .map(|f| f.path)
            .collect();
        assert_eq!(
            boards,
            [
                "observability-host/dashboards/app-health.json",
                "observability-host/dashboards/fleet-overview.json",
                "observability-host/dashboards/k8s-state.json",
            ]
        );
    }

    #[test]
    fn no_shipped_file_is_empty() {
        for f in FILES {
            assert!(!f.bytes.is_empty(), "{} is empty", f.path);
        }
    }
}
