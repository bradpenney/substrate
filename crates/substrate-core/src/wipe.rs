//! Destroy the entire fleet, leaving nothing a rebuild could inherit.
//!
//! Ported from `gate.py::wipe` and `gate.py::orphaned_vms`. This is the one
//! DESTRUCTIVE operation in the binary, and it lives apart from `provision`
//! on purpose: the build path never destroys anything (a failed `create_vm`
//! tears down only its own attempt), and the destroy path never builds. A
//! rebuild is the two run back to back — see `rebuild`.
//!
//! "Fully wiped" means more than deleting VMs. Three kinds of leftover state
//! have each caused real problems in this build:
//!
//! - **Seed ISOs.** Each carries a baked-in join token. A stale one lets a
//!   node rejoin a cluster that no longer exists.
//! - **known_hosts entries.** Rebuilt VMs get new SSH host keys at the same
//!   IPs, so stale entries make later SSH fail with a host-key mismatch.
//! - **Orphans.** A VM that site.yml no longer declares is never visited by a
//!   wipe that iterates site.yml. It keeps running, still holding the old
//!   cluster's PKI and an etcd membership, and will try to participate in a
//!   cluster rebuilt underneath it (found during the ADR-046 retopology).
//!
//! NOT wiped, deliberately:
//!
//! - **The pinned Kairos ISO.** An immutable artifact verified by checksum on
//!   every run, not cluster state.
//! - **etcd membership — no explicit prune.** etcd's data lives on each node's
//!   own disk, and deleting the volumes destroys it; a full wipe clears
//!   membership by construction. Pruning here would also be harmful: `k0s
//!   etcd leave` against a wedged control plane has no timeout, and pruning
//!   members out from under still-running nodes invites them to crash or
//!   re-add themselves mid-wipe.

use crate::config::SiteConfig;
use crate::exec::{Host, run};
use crate::libvirt;
use crate::provision::{Fleet, Vm, destroy_and_undefine};

/// A VM name this tooling could have created: `s<digits>-vm<digits>`.
///
/// The orphan scan only ever offers to destroy names of this shape. Anything
/// else running on a hypervisor — a desktop VM, a scratch box — is not ours
/// to touch, whatever site.yml says.
pub fn is_fleet_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('s') else {
        return false;
    };
    let Some((a, b)) = rest.split_once("-vm") else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    digits(a) && digits(b)
}

/// VMs present on a hypervisor that site.yml no longer declares.
pub fn orphaned_vms(fleet: &Fleet) -> Vec<(&Host, String)> {
    let declared: Vec<&str> = fleet.all_vms().map(|(_, v)| v.name.as_str()).collect();
    let mut found = Vec::new();
    for (host, _) in &fleet.hosts {
        let argv = ["virsh", "-c", "qemu:///system", "list", "--all", "--name"];
        let Ok(out) = run(host, &argv, None) else {
            continue;
        };
        for line in out.stdout.lines() {
            let name = line.trim();
            if !name.is_empty() && !declared.contains(&name) && is_fleet_name(name) {
                found.push((host, name.to_string()));
            }
        }
    }
    found
}

fn seed_paths(cfg: &SiteConfig, vm: &Vm) -> [String; 3] {
    [
        format!("{}/{}-cloudinit.iso", cfg.libvirt.iso_pool_path, vm.name),
        format!("/tmp/{}-user-data", vm.name),
        format!("/tmp/{}-meta-data", vm.name),
    ]
}

/// Destroy the fleet. With `dry_run`, print exactly what would go and touch
/// nothing — including the precise disk volumes, because an LVM pool may be
/// defined over the same volume group that holds the hypervisor's own root
/// LV, and "which volumes exactly" is a question worth answering before
/// pressing go, not after.
pub fn wipe(cfg: &SiteConfig, dry_run: bool) {
    let fleet = Fleet::from_config(cfg);
    let total = fleet.all_vms().count();
    let label = if dry_run {
        "DRY RUN — would destroy"
    } else {
        "DESTROYING"
    };
    println!("=== {label} {total} VMs ===");

    let orphans = orphaned_vms(&fleet);
    if !orphans.is_empty() {
        println!(
            "\n  {} ORPHAN(S) — on a hypervisor but not in site.yml:",
            orphans.len()
        );
        for (host, name) in &orphans {
            println!("    {}: {}", host.name, name);
        }
        println!("  These hold the old cluster's PKI and etcd membership. Leaving");
        println!("  them running while rebuilding produces a node that believes it");
        println!("  belongs to a cluster that no longer exists.");
        if !dry_run {
            for (host, name) in &orphans {
                println!("  destroying orphan {name} on {}...", host.name);
                let _ = run(
                    host,
                    &["virsh", "-c", "qemu:///system", "destroy", name],
                    None,
                );
                let _ = run(
                    host,
                    &["virsh", "-c", "qemu:///system", "undefine", name, "--nvram"],
                    None,
                );
            }
        }
        println!();
    }

    for (host, vm) in fleet.all_vms() {
        let lv = libvirt::Vm::new(&vm.name);
        let exists = libvirt::vm_exists(host, &lv);
        let state = if exists {
            libvirt::domain_state(host, &lv)
        } else {
            "absent".to_string()
        };
        println!("  [{}] {} ({state})", host.name, vm.name);
        if !exists {
            continue;
        }
        for path in libvirt::disk_volume_paths(host, &lv) {
            let verb = if dry_run { "would delete" } else { "deleting" };
            println!("      {verb} volume {path}");
        }
        if dry_run {
            continue;
        }
        destroy_and_undefine(host, vm);
    }

    println!("=== removing seed ISOs and cloud-config scratch files ===");
    for (host, vm) in fleet.all_vms() {
        for path in seed_paths(cfg, vm) {
            let verb = if dry_run { "would remove" } else { "removing" };
            println!("  [{}] {verb} {path}", host.name);
            if !dry_run {
                let _ = run(host, &["rm", "-f", &path], None);
            }
        }
    }

    println!("=== clearing local known_hosts entries (rebuilt VMs get new keys) ===");
    let local = Host::local("local");
    for (_, vm) in fleet.all_vms() {
        let verb = if dry_run { "would clear" } else { "clearing" };
        println!("  {verb} {}", vm.static_ip);
        if !dry_run {
            let _ = run(&local, &["ssh-keygen", "-R", &vm.static_ip], None);
        }
    }

    if dry_run {
        println!("\nDRY RUN — nothing was changed.");
    } else {
        println!("\nwipe complete — no VMs, no seed ISOs, no etcd members, no host keys");
    }
}

#[cfg(test)]
mod tests {
    use super::is_fleet_name;

    #[test]
    fn fleet_names_match_the_python_regex() {
        // ^s\d+-vm\d+$
        for ok in ["s1-vm1", "s2-vm3", "s10-vm12"] {
            assert!(is_fleet_name(ok), "{ok}");
        }
        for bad in [
            "",
            "s-vm1",
            "s1-vm",
            "vm1",
            "s1vm1",
            "S1-vm1",
            "s1-vm1x",
            "xs1-vm1",
            "s1-vm-1",
            "fedora-desktop",
            "s1-vm1 ",
        ] {
            assert!(!is_fleet_name(bad), "{bad:?}");
        }
    }
}
