//! Provisioning the fleet: host preparation, VM lifecycle, cluster join.
//!
//! Ported from `provision.py`. The goal is not a Rust program that builds *a*
//! cluster — it is one that builds the SAME cluster, so behaviour is
//! reproduced as written even where the Python is surprising. Where the Python
//! is wrong, that is recorded rather than silently corrected: a fix smuggled
//! into a port cannot be reviewed as a fix.

use crate::config::SiteConfig;
use crate::exec::{Host, run, run_checked};
use anyhow::{Result, bail};

/// Tools a hypervisor must have before anything is attempted.
pub const REQUIRED_TOOLS: &[&str] = &[
    "virsh",
    "virt-install",
    "virt-xml",
    "mkisofs",
    "curl",
    "sha256sum",
];

fn virsh(args: &[&str]) -> Vec<String> {
    let mut v = vec!["virsh".to_string(), "-c".into(), "qemu:///system".into()];
    v.extend(args.iter().map(|a| a.to_string()));
    v
}

/// Fail fast, with a useful message, if a host is missing tooling.
///
/// Learned the hard way: server1 had `virsh` and `qemu-kvm` (from desktop and
/// Docker use) but never `virt-install`, because it had never been a
/// hypervisor. Without this check that surfaces ~2 minutes into a run as a bare
/// missing-executable error, AFTER the ISO has already been downloaded.
pub fn preflight(host: &Host) -> Result<()> {
    let mut missing = Vec::new();
    for tool in REQUIRED_TOOLS {
        let argv = vec!["sh", "-c", &format!("command -v {tool} >/dev/null")]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        if !run(host, &argv, None).map(|o| o.ok()).unwrap_or(false) {
            missing.push(*tool);
        }
    }
    if !missing.is_empty() {
        bail!(
            "[{}] missing required tools: {}\n  install with: sudo dnf install -y \
             virt-install libvirt-client genisoimage",
            host.name,
            missing.join(", ")
        );
    }
    Ok(())
}

/// Make sure the VM-disk pool exists and is fit for VM images.
///
/// The pool must already exist — this refuses rather than creating one, because
/// its backing (LVM volume group vs plain directory) is a host-level storage
/// decision that provisioning must not make on someone's behalf.
pub fn ensure_disk_pool(host: &Host) -> Result<()> {
    if !run(host, &virsh(&["pool-info", &host.disk_pool]), None)
        .map(|o| o.ok())
        .unwrap_or(false)
    {
        bail!(
            "[{}] disk pool {:?} does not exist — create it before provisioning",
            host.name,
            host.disk_pool
        );
    }
    if !host.pool_needs_nocow {
        return Ok(());
    }

    // btrfs is copy-on-write; VM images on CoW fragment badly and slow to a
    // crawl. `chattr +C` only affects files created AFTER it is set, so this
    // has to happen before the first disk is provisioned.
    let dump = format!(
        "virsh -c qemu:///system pool-dumpxml {} | sed -n 's:.*<path>\\(.*\\)</path>.*:\\1:p'",
        host.disk_pool
    );
    let path = run(host, &["sh".to_string(), "-c".into(), dump], None)
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default();
    if path.is_empty() {
        println!(
            "[{}] WARNING: could not determine pool path; skipping no-CoW setup",
            host.name
        );
        return Ok(());
    }

    // `sudo` is required for BOTH the check and the change: the pool dir is
    // root-owned 0711, so an unprivileged `lsattr` returns "Permission denied"
    // rather than the flags. Without sudo the check silently never matches and
    // chattr is re-run on every single provisioning pass.
    let probe = format!("sudo lsattr -d {path} 2>/dev/null | cut -d' ' -f1");
    let already = run(host, &["sh".to_string(), "-c".into(), probe], None)
        .map(|o| o.stdout)
        .unwrap_or_default();
    if already.contains('C') {
        println!("[{}] {path} already no-CoW", host.name);
        return Ok(());
    }
    println!(
        "[{}] setting no-CoW (chattr +C) on {path} — btrfs pool",
        host.name
    );
    let argv = vec![
        "sudo".to_string(),
        "chattr".into(),
        "+C".into(),
        path.clone(),
    ];
    match run(host, &argv, None) {
        Ok(o) if o.ok() => {}
        // Not fatal — VMs still work, just with CoW fragmentation — but it must
        // be visible rather than swallowed.
        Ok(o) => println!(
            "[{}] WARNING: chattr +C failed on {path}: {}",
            host.name,
            o.stderr.trim()
        ),
        Err(e) => println!("[{}] WARNING: chattr +C failed on {path}: {e}", host.name),
    }
    Ok(())
}

/// Make sure the ISO pool exists and is started.
///
/// Separate from the disk pool because the two differ per host — the disk pool
/// may be LVM or a directory, while ISOs are always a plain directory that qemu
/// must be able to read.
pub fn ensure_iso_pool(host: &Host, cfg: &SiteConfig) -> Result<()> {
    let pool = &cfg.libvirt.iso_pool;
    if run(host, &virsh(&["pool-info", pool]), None)
        .map(|o| o.ok())
        .unwrap_or(false)
    {
        return Ok(());
    }
    println!("[{}] defining ISO pool {pool:?}...", host.name);
    run_checked(
        host,
        &virsh(&[
            "pool-define-as",
            pool,
            "dir",
            "--target",
            &cfg.libvirt.iso_pool_path,
        ]),
        None,
    )?;
    for step in ["pool-build", "pool-start", "pool-autostart"] {
        run_checked(host, &virsh(&[step, pool]), None)?;
    }
    Ok(())
}

/// Download the pinned Kairos ISO if absent, and verify its checksum.
///
/// The tag makes it readable; the CHECKSUM is what makes a rebuild months from
/// now install the same bytes.
pub fn ensure_kairos_iso(host: &Host, cfg: &SiteConfig) -> Result<()> {
    let dest = format!("{}/kairos-hadron-k0s.iso", cfg.libvirt.iso_pool_path);
    let want = &cfg.kairos.iso_sha256;

    if let Ok(o) = run(host, &["sha256sum".to_string(), dest.clone()], None)
        && o.ok()
        && o.stdout.split_whitespace().next() == Some(want.as_str())
    {
        println!("[{}] Kairos ISO already present and verified", host.name);
        return Ok(());
    }
    println!("[{}] downloading Kairos ISO (~500MB)...", host.name);

    // Download to a TEMP name, verify, then rename into place. Two reasons:
    //
    // 1. PERMISSIONS. libvirt chowns an attached ISO to `qemu:qemu`, so the
    //    admin user cannot overwrite it in place — `curl -o` fails with
    //    "Permission denied" even though the pool directory is group-writable.
    //    Creating a new file and renaming needs only DIRECTORY write.
    // 2. ATOMICITY. Writing straight to the canonical path leaves a truncated
    //    ISO there if the download dies partway — and a half-downloaded image
    //    that merely *exists* is exactly what a later run treats as "present".
    //    Verify first, publish second.
    let tmp = format!("{dest}.tmp");
    let _ = run(host, &["rm".to_string(), "-f".into(), tmp.clone()], None);
    run_checked(
        host,
        &[
            "curl".to_string(),
            "-fL".into(),
            "-o".into(),
            tmp.clone(),
            cfg.kairos.iso_url.clone(),
        ],
        None,
    )?;
    let out = run_checked(host, &["sha256sum".to_string(), tmp.clone()], None)?;
    let actual = out
        .stdout
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    if &actual != want {
        let _ = run(host, &["rm".to_string(), "-f".into(), tmp.clone()], None);
        bail!(
            "[{}] Kairos ISO checksum mismatch: expected {want}, got {actual}",
            host.name
        );
    }
    // Unlinking needs write on the DIRECTORY, not the file — so this works even
    // though the old ISO is owned by qemu.
    let _ = run(host, &["rm".to_string(), "-f".into(), dest.clone()], None);
    run_checked(host, &["mv".to_string(), tmp, dest.clone()], None)?;
    // Non-fatal: libvirt chowns attached ISOs to qemu, so a pre-existing file
    // may not be ours to chmod. mkisofs/curl already create it readable.
    let _ = run(host, &["chmod".to_string(), "0644".into(), dest], None);
    Ok(())
}

// --- timing and retry policy, from provision.py ---------------------------

pub const CREATE_RETRIES: u32 = 3;
pub const SSH_WAIT_TIMEOUT: u64 = 300;
/// Install plus self-reboot takes materially longer than a plain boot.
pub const INSTALL_WAIT_TIMEOUT: u64 = 900;
pub const SSH_WAIT_INTERVAL: u64 = 10;
pub const NODE_READY_TIMEOUT: u64 = 600;

/// One VM as the provisioner sizes it. Per-VM values override fleet defaults.
#[derive(Debug, Clone)]
pub struct Vm {
    pub name: String,
    pub static_ip: String,
    pub hypervisor: String,
    pub bootstrap: bool,
    pub memory_mib: Option<u32>,
    pub vcpu: Option<u32>,
    pub storage_disk_gb: Option<u32>,
}

/// Render the cloud-config and build the seed ISO for one VM.
///
/// The ISO is the ONLY channel into a Kairos node: the installed system has no
/// SSH management path by design (ADR-025), so anything the node needs to know
/// has to be on this disk before it first boots.
pub fn build_seed_iso(
    host: &Host,
    vm: &Vm,
    cfg: &SiteConfig,
    join_token: Option<&str>,
    ssh_key: &str,
) -> Result<()> {
    let rvm = crate::render::Vm {
        name: vm.name.clone(),
        static_ip: vm.static_ip.clone(),
        hypervisor: vm.hypervisor.clone(),
        bootstrap: vm.bootstrap,
        memory_mib: vm.memory_mib,
        vcpu: vm.vcpu,
        storage_disk_gb: vm.storage_disk_gb,
    };
    let user_data = crate::render::cloud_config(cfg, &rvm, join_token, ssh_key);
    crate::exec::write_file(host, &format!("/tmp/{}-user-data", vm.name), &user_data)?;
    crate::exec::write_file(host, &format!("/tmp/{}-meta-data", vm.name), "")?;

    let iso = format!("{}/{}-cloudinit.iso", cfg.libvirt.iso_pool_path, vm.name);
    run_checked(
        host,
        &[
            "mkisofs".to_string(),
            "-output".into(),
            iso.clone(),
            "-volid".into(),
            "cidata".into(),
            "-joliet".into(),
            "-rock".into(),
            "-graft-points".into(),
            format!("user-data=/tmp/{}-user-data", vm.name),
            format!("meta-data=/tmp/{}-meta-data", vm.name),
        ],
        None,
    )?;
    let _ = run(host, &["chmod".to_string(), "0644".into(), iso], None);
    Ok(())
}

/// Block until the installed system is up on `ip`.
///
/// Kairos POWERS OFF when the install completes; it does not reboot. Waiting
/// for a reboot that never comes is a hang with no error.
pub fn wait_for_install(admin_user: &str, ip: &str, timeout: u64, interval: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    while std::time::Instant::now() < deadline {
        if crate::libvirt::booted_from_disk(admin_user, ip) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
    false
}

/// Wait for the Kairos installer to finish, which it signals by POWERING THE VM
/// OFF — not by rebooting into the installed system.
///
/// With CD-first boot order (correct during install), Kairos detects that
/// rebooting would land it right back in the installer, so it deliberately
/// powers off instead of looping. The domain goes to `shut off` and stays
/// there. Waiting on SSH or IP here would hang forever.
pub fn wait_for_installer_finish(host: &Host, vm: &Vm, timeout: u64, interval: u64) -> bool {
    let lv = crate::libvirt::Vm::new(&vm.name);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    while std::time::Instant::now() < deadline {
        if crate::libvirt::domain_state(host, &lv) == "shut off" {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
    false
}

/// Switch to disk-first boot and start the installed system.
///
/// Called only once the installer has finished and powered the VM off, so there
/// is genuinely something bootable on the disk. The domain is already off at
/// that point (that is how Kairos signals completion), so no power cycle is
/// needed — virt-xml's edits apply to the powered-off definition.
pub fn set_boot_disk_first(host: &Host, vm: &Vm, admin_user: &str) -> Result<()> {
    println!(
        "[{}] setting {} to boot from disk first (post-install)...",
        host.name, vm.name
    );
    run_checked(
        host,
        &[
            "virt-xml".to_string(),
            "-c".into(),
            "qemu:///system".into(),
            vm.name.clone(),
            "--edit".into(),
            "--boot".into(),
            "hd,cdrom,menu=off".into(),
        ],
        None,
    )?;
    // Survive a hypervisor reboot. Without this a host restart (including the
    // nightly-update reboots) silently leaves the cluster down — libvirtd comes
    // back but the domains do not.
    run_checked(host, &virsh(&["autostart", &vm.name]), None)?;
    run_checked(host, &virsh(&["start", &vm.name]), None)?;
    if !wait_for_install(
        admin_user,
        &vm.static_ip,
        SSH_WAIT_TIMEOUT,
        SSH_WAIT_INTERVAL,
    ) {
        bail!(
            "[{}] {} did not come up from disk after boot-order change",
            host.name,
            vm.name
        );
    }
    println!(
        "[{}] {} booted into the installed system",
        host.name, vm.name
    );
    Ok(())
}

/// Tear down one VM and delete its own disk — nothing else.
///
/// Deliberately NOT `undefine --remove-all-storage`. That flag deletes every
/// *pool-managed* volume attached to the domain, and read-only CDROMs are not
/// exempt — verified experimentally, not assumed. Since the seed ISOs and the
/// Kairos ISO all live in the `isos` POOL, its blast radius includes the SHARED
/// Kairos ISO whenever that is still attached.
///
/// In practice that was a real latent bug on the retry path: virt-install
/// detaches install media from a *successfully* installed domain, so a normal
/// teardown looked safe — but a FAILED install still has the Kairos ISO
/// attached, so retrying would delete the shared ISO out from under every
/// subsequent VM. It self-healed via `ensure_kairos_iso`'s checksum
/// re-download, which is exactly why it went unnoticed: a silent 500MB
/// re-download per retry.
///
/// ⚠️ NEVER delete pool-wide. An LVM pool may be defined over the SAME volume
/// group that holds the hypervisor's own root LV, in which case `vol-list`
/// lists the HOST'S ROOT FILESYSTEM alongside the VM disks. Only ever delete
/// volumes resolved from a specific domain's disk list, as done here.
pub fn destroy_and_undefine(host: &Host, vm: &Vm) {
    let lv = crate::libvirt::Vm::new(&vm.name);
    // Read the disk list BEFORE undefining — once the domain is gone there is
    // nothing left to ask which volumes were its own.
    let disks = crate::libvirt::disk_volume_paths(host, &lv);
    let _ = run(host, &virsh(&["destroy", &vm.name]), None);
    let _ = run(host, &virsh(&["undefine", &vm.name]), None);
    for path in disks {
        let _ = run(
            host,
            &virsh(&["vol-delete", "--pool", &host.disk_pool, &path]),
            None,
        );
    }
}

/// Bring an already-existing VM back to the desired state.
///
/// Idempotent re-runs should not merely skip existing VMs — they should correct
/// drift. Two things matter for a cluster that must survive host reboots:
/// autostart being set, and the VM actually running.
pub fn reconcile_existing(host: &Host, vm: &Vm, admin_user: &str) {
    let lv = crate::libvirt::Vm::new(&vm.name);
    let info = run(host, &virsh(&["dominfo", &vm.name]), None)
        .map(|o| o.stdout)
        .unwrap_or_default();
    let autostart_disabled = info
        .split("Autostart:")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .map(|line| line.contains("disable"))
        .unwrap_or(false);
    if autostart_disabled {
        println!(
            "[{}] {}: enabling autostart (was disabled)",
            host.name, vm.name
        );
        let _ = run(host, &virsh(&["autostart", &vm.name]), None);
    }

    let state = crate::libvirt::domain_state(host, &lv);
    if state != "running" {
        println!(
            "[{}] {}: state is {state:?} — starting it",
            host.name, vm.name
        );
        let _ = run(host, &virsh(&["start", &vm.name]), None);
        if wait_for_install(
            admin_user,
            &vm.static_ip,
            SSH_WAIT_TIMEOUT,
            SSH_WAIT_INTERVAL,
        ) {
            println!("[{}] {} is up", host.name, vm.name);
        } else {
            println!(
                "[{}] WARNING: {} started but did not become reachable",
                host.name, vm.name
            );
        }
    } else {
        println!("[{}] {} already running", host.name, vm.name);
    }
}

// --- talking to a node -----------------------------------------------------

/// SSH to a cluster NODE (not a hypervisor), with the options every such call
/// in `provision.py` uses.
///
/// Host-key checking is off deliberately and only here: these calls race
/// machines that are installing or reinstalling, so their host keys
/// legitimately change underneath us. Scoping it to node access keeps it out of
/// hypervisor SSH, which does verify.
pub fn node_ssh(
    admin_user: &str,
    ip: &str,
    connect_timeout: u32,
    cmd: &str,
) -> Result<crate::exec::Output> {
    let out = std::process::Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            &format!("ConnectTimeout={connect_timeout}"),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            &format!("{admin_user}@{ip}"),
            cmd,
        ])
        .output()?;
    Ok(crate::exec::Output {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Remove a dead node's etcd member entry from the cluster.
///
/// LOAD-BEARING for retries. A joining node registers itself in etcd early,
/// potentially BEFORE it finishes coming up. If it is then destroyed (a failed
/// attempt, a rebuild), its member entry survives as a ghost. With 2 members
/// and one a ghost, etcd can never reach a majority — the survivor loops
/// elections forever, the API server wedges, and etcd cannot even remove the
/// ghost because *removal itself requires quorum*. That deadlock bricked the
/// cluster once during this build and needed a full wipe to recover.
///
/// So: always prune before recreating a node. Best-effort — if the cluster is
/// healthy and has no such member, this is a harmless no-op.
pub fn etcd_prune(admin_user: &str, bootstrap_host: &Host, bootstrap_ip: &str, dead: &Vm) {
    let listed = match node_ssh(admin_user, bootstrap_ip, 10, "sudo k0s etcd member-list") {
        Ok(o) if o.ok() => o.stdout,
        _ => return,
    };
    if !listed.contains(&dead.static_ip) {
        return;
    }
    println!(
        "[{}] pruning stale etcd member for {}...",
        bootstrap_host.name, dead.name
    );
    let _ = node_ssh(
        admin_user,
        bootstrap_ip,
        10,
        &format!("sudo k0s etcd leave --peer-address {}", dead.static_ip),
    );
}

/// Remove the destroyed node's Kubernetes Node object, and with it Longhorn's
/// record of the node.
///
/// A replacement joins under the SAME name. Left in place, the old Node
/// object is simply re-adopted by the new kubelet — and Longhorn's node CR
/// hanging off it still carries the OLD disk's UUID, so the fresh disk is
/// refused ("record diskUUID doesn't match the one on the disk"), the node
/// never takes a replica again, and every volume that had one there stays
/// degraded (bug-154, found on the first real roll). Longhorn deletes its
/// node CR itself when the Kubernetes Node goes away, and creates a fresh
/// one when the replacement registers; this is the only clean path — its
/// webhook refuses to delete the CR of a node it still thinks is Ready.
///
/// Also evicts the dead node's pods immediately instead of after the
/// five-minute tolerations, which is why the app comes back sooner.
pub fn forget_node(admin_user: &str, donor_host: &Host, donor_ip: &str, dead: &Vm) {
    println!(
        "[{}] removing the Node object for {} (and Longhorn's record of it)...",
        donor_host.name, dead.name
    );
    let _ = node_ssh(
        admin_user,
        donor_ip,
        90,
        &format!(
            "sudo k0s kubectl delete node {} --ignore-not-found --timeout=60s",
            dead.name
        ),
    );
    let has_longhorn = node_ssh(
        admin_user,
        donor_ip,
        10,
        "sudo k0s kubectl get crd nodes.longhorn.io",
    )
    .map(|o| o.ok())
    .unwrap_or(false);
    if !has_longhorn {
        return;
    }
    for i in 0..24 {
        let gone = node_ssh(
            admin_user,
            donor_ip,
            10,
            &format!(
                "sudo k0s kubectl -n longhorn-system get nodes.longhorn.io {}",
                dead.name
            ),
        )
        .map(|o| !o.ok())
        .unwrap_or(false);
        if gone {
            println!("    longhorn forgot {}", dead.name);
            return;
        }
        println!(
            "    waiting for longhorn to forget {} ({}s)...",
            dead.name,
            i * 5
        );
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    println!(
        "    WARNING: longhorn still records {} — its disk will show DiskNotReady after the join; remove and re-add the disk by hand (bug-154)",
        dead.name
    );
}

/// Map node name -> Ready, as the cluster currently sees it.
///
/// Queried through `k0s kubectl` on the bootstrap node rather than a local
/// kubectl, deliberately: after a full teardown there is no local kubeconfig
/// (and a stale one points at a node that no longer exists), so depending on
/// one would make this fail for reasons unrelated to cluster health.
///
/// `None` if the API server cannot be reached or its answer cannot be parsed —
/// a transient state during a rebuild, not an error. Callers keep polling.
pub fn node_ready_states(
    admin_user: &str,
    bootstrap_ip: &str,
) -> Option<std::collections::BTreeMap<String, bool>> {
    let out = node_ssh(
        admin_user,
        bootstrap_ip,
        10,
        "sudo k0s kubectl get nodes -o json",
    )
    .ok()?;
    if !out.ok() {
        return None;
    }
    let payload: serde_json::Value = serde_json::from_str(&out.stdout).ok()?;
    let mut states = std::collections::BTreeMap::new();
    for node in payload.get("items")?.as_array()? {
        let Some(name) = node.pointer("/metadata/name").and_then(|v| v.as_str()) else {
            continue;
        };
        let ready = node
            .pointer("/status/conditions")
            .and_then(|c| c.as_array())
            .map(|cs| {
                cs.iter().any(|c| {
                    c.get("type").and_then(|v| v.as_str()) == Some("Ready")
                        && c.get("status").and_then(|v| v.as_str()) == Some("True")
                })
            })
            .unwrap_or(false);
        states.insert(name.to_string(), ready);
    }
    Some(states)
}

/// Block until every expected node is registered AND Ready.
///
/// `create_vm` returns as soon as a VM is running its installed system, but k0s
/// then takes roughly another 45-60s to register that node with the API server.
/// Without this poll the run exits while the cluster is still converging, so an
/// immediate `kubectl get nodes` shows fewer nodes than were built — which
/// looks exactly like a failed build. The destroy-and-rebuild gate has to
/// distinguish "still coming up" from "genuinely broken", and only a poll can.
///
/// Errors on timeout, naming what was missing or NotReady, so an unattended run
/// fails loudly instead of reporting a false success.
pub fn wait_for_nodes_ready(
    admin_user: &str,
    bootstrap_ip: &str,
    expected: &[String],
    timeout: u64,
    interval: u64,
) -> Result<()> {
    println!("=== waiting for {} nodes to be Ready ===", expected.len());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    let mut last_report: Option<(Vec<String>, Vec<String>)> = None;
    while std::time::Instant::now() < deadline {
        if let Some(states) = node_ready_states(admin_user, bootstrap_ip) {
            let missing: Vec<String> = expected
                .iter()
                .filter(|n| !states.contains_key(*n))
                .cloned()
                .collect();
            let not_ready: Vec<String> = expected
                .iter()
                .filter(|n| states.get(*n) == Some(&false))
                .cloned()
                .collect();
            if missing.is_empty() && not_ready.is_empty() {
                println!("all {} nodes Ready", expected.len());
                return Ok(());
            }
            // Only print when the picture changes, so a long wait does not bury
            // the real output in identical status lines.
            let report = (missing.clone(), not_ready.clone());
            if last_report.as_ref() != Some(&report) {
                let mut pending: Vec<String> = missing
                    .iter()
                    .map(|n| format!("{n} (unregistered)"))
                    .collect();
                pending.extend(not_ready.iter().map(|n| format!("{n} (NotReady)")));
                println!("  waiting on: {}", pending.join(", "));
                last_report = Some(report);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
    let states = node_ready_states(admin_user, bootstrap_ip).unwrap_or_default();
    let missing: Vec<&String> = expected
        .iter()
        .filter(|n| !states.contains_key(*n))
        .collect();
    let not_ready: Vec<&String> = expected
        .iter()
        .filter(|n| states.get(*n) == Some(&false))
        .collect();
    bail!(
        "nodes did not all become Ready within {timeout}s — unregistered: {:?}, NotReady: {:?}",
        missing,
        not_ready
    );
}

/// Wait until k0s on the bootstrap node can actually serve requests.
///
/// `COS_ACTIVE` in /proc/cmdline proves the INSTALLED OS is running. It says
/// nothing about k0s, which takes appreciably longer — so minting a join token
/// immediately after the bootstrap VM boots is a race:
///
/// ```text
/// Error: failed to get k0s status: ... dial unix /run/k0s/status.sock:
/// connect: no such file or directory
/// ```
///
/// "The OS is up" is not "the service is up" — the same class of mistake as
/// treating SSH reachability as proof the install had finished.
pub fn wait_for_k0s_ready(admin_user: &str, ip: &str, timeout: u64, interval: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    while std::time::Instant::now() < deadline {
        if node_ssh(admin_user, ip, 5, "sudo k0s status")
            .map(|o| o.ok())
            .unwrap_or(false)
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
    false
}

/// The Pod Security labels k0s-autopilot must carry: privileged/baseline,
/// mirroring kube-system (autopilot updates node binaries and needs host
/// access). Public so the verifier can assert the same set it enforces.
pub const AUTOPILOT_POD_SECURITY_LABELS: &[(&str, &str)] = &[
    ("pod-security.kubernetes.io/enforce", "privileged"),
    ("pod-security.kubernetes.io/enforce-version", "latest"),
    ("pod-security.kubernetes.io/warn", "baseline"),
    ("pod-security.kubernetes.io/audit", "baseline"),
];

/// Label the k0s-autopilot namespace AFTER the cluster is up.
///
/// THIS IS THE ONLY OWNER OF THESE LABELS. There used to be a rendered
/// manifest stack, `/var/lib/k0s/manifests/namespace-labels/`, declaring the
/// same Namespace with the labels. Two owners of one object: autopilot's own
/// stack applies the Namespace without them, its three-way merge therefore
/// stripped them, the `require-pss-labels` admission policy denied that, and
/// the whole autopilot stack failed and retried every 30 seconds — with k0s's
/// applier re-annotating its in-memory resources on every retry until the
/// leader's supervisor process ran out of memory (bug-150, ADR-191: nodes
/// hung one after another for a night and a morning). The stack is gone.
///
/// Labels set with `kubectl label` live only in the object, not in any
/// stack's last-applied record, so neither applier's patch touches them and
/// the admission policy stays satisfied. Applied once every node is Ready and
/// autopilot has finished starting; `--overwrite` makes it idempotent; the
/// read-back turns a silently ignored label into a failed build rather than a
/// finding the next morning.
pub fn enforce_autopilot_pod_security(admin_user: &str, bootstrap_ip: &str) -> Result<()> {
    println!("=== k0s-autopilot: Pod Security labels ===");
    let pairs: Vec<String> = AUTOPILOT_POD_SECURITY_LABELS
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let cmd = format!(
        "sudo k0s kubectl label namespace k0s-autopilot --overwrite {}",
        pairs.join(" ")
    );
    let out = node_ssh(admin_user, bootstrap_ip, 10, &cmd)?;
    if !out.ok() {
        bail!("labelling k0s-autopilot failed: {}", out.stderr.trim());
    }
    let check = node_ssh(
        admin_user,
        bootstrap_ip,
        10,
        "sudo k0s kubectl get namespace k0s-autopilot -o jsonpath='{.metadata.labels}'",
    )?;
    for (k, v) in AUTOPILOT_POD_SECURITY_LABELS {
        let want = format!("\"{k}\":\"{v}\"");
        if !check.stdout.contains(&want) {
            bail!(
                "k0s-autopilot is missing {k}={v} after labelling: {}",
                check.stdout.trim()
            );
        }
    }
    println!(
        "k0s-autopilot: {} labels asserted",
        AUTOPILOT_POD_SECURITY_LABELS.len()
    );
    Ok(())
}

/// Generate a CONTROLLER-role join token on the bootstrap node.
///
/// Every node in this cluster is a controller (all-controllers design), so
/// `--role controller`, not the more commonly documented worker role.
pub fn generate_join_token(admin_user: &str, host: &Host, vm: &Vm, expiry: &str) -> Result<String> {
    println!(
        "[{}] generating controller join token on {}...",
        host.name, vm.name
    );
    let out = node_ssh(
        admin_user,
        &vm.static_ip,
        10,
        &format!("sudo k0s token create --role controller --expiry {expiry}"),
    )?;
    if !out.ok() {
        bail!(
            "failed to generate join token on {}: {}",
            vm.name,
            out.stderr
        );
    }
    let token = out
        .stdout
        .trim()
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .to_string();
    if token.is_empty() {
        bail!("got an empty join token from {}", vm.name);
    }
    Ok(token)
}

/// Create, install and boot one VM, retrying a failed install.
///
/// Retries because the Kairos installer is not perfectly reliable — a failed
/// attempt leaves a defined domain and its disks behind, so each retry cleans
/// up first. Boot order is flipped to disk-first only AFTER something is
/// installed, or the node would boot the installer again forever.
#[allow(clippy::too_many_arguments)]
pub fn create_vm(
    host: &Host,
    vm: &Vm,
    cfg: &SiteConfig,
    join_token: Option<&str>,
    ssh_key: &str,
    admin_user: &str,
    bootstrap_pair: Option<(&Host, &str)>,
) -> Result<()> {
    let lv = crate::libvirt::Vm::new(&vm.name);
    if crate::libvirt::vm_exists(host, &lv) {
        reconcile_existing(host, vm, admin_user);
        return Ok(());
    }

    // Per-VM override, else the fleet default. 0 means no second disk at all.
    let storage_gb = vm.storage_disk_gb.unwrap_or(cfg.defaults.storage_disk_gb);

    for attempt in 1..=CREATE_RETRIES {
        let extra = if storage_gb > 0 {
            format!(" with a {storage_gb}GB storage disk")
        } else {
            String::new()
        };
        println!(
            "[{}] creating {} (attempt {attempt}/{CREATE_RETRIES}){extra}...",
            host.name, vm.name
        );
        build_seed_iso(host, vm, cfg, join_token, ssh_key)?;

        let mut argv: Vec<String> = vec![
            "virt-install".into(),
            "--connect".into(),
            "qemu:///system".into(),
            "--name".into(),
            vm.name.clone(),
            "--memory".into(),
            vm.memory_mib.unwrap_or(cfg.defaults.memory_mib).to_string(),
            "--vcpus".into(),
            vm.vcpu.unwrap_or(cfg.defaults.vcpu).to_string(),
            "--cpu".into(),
            "host-passthrough".into(),
            "--disk".into(),
            format!(
                "pool={},size={},bus=virtio",
                host.disk_pool, cfg.defaults.disk_gb
            ),
        ];
        // Dedicated Longhorn disk (ADR-050), attached as vdb when sized.
        // Omitted entirely when 0, so a node built without it is not silently
        // different — Longhorn simply finds no disk to claim.
        if storage_gb > 0 {
            argv.push("--disk".into());
            argv.push(format!(
                "pool={},size={storage_gb},bus=virtio",
                host.disk_pool
            ));
        }
        argv.extend([
            "--cdrom".to_string(),
            format!("{}/kairos-hadron-k0s.iso", cfg.libvirt.iso_pool_path),
            "--disk".into(),
            format!(
                "device=cdrom,bus=sata,path={}/{}-cloudinit.iso",
                cfg.libvirt.iso_pool_path, vm.name
            ),
            "--network".into(),
            format!("bridge={},model=virtio", cfg.network.bridge),
            "--os-variant".into(),
            "generic".into(),
            "--graphics".into(),
            "none".into(),
            "--console".into(),
            "pty,target_type=serial".into(),
            "--noautoconsole".into(),
        ]);
        run_checked(host, &argv, None)?;

        // Boot order is deliberately NOT touched here. virt-install already
        // sets the correct order for a FRESH install (CD bootindex=1, disk
        // bootindex=2), and the disk at this point is blank and never written.
        // Forcing "hd first" before anything is installed makes SeaBIOS try to
        // boot an empty disk and halt outright (observed as a frozen vCPU at
        // EIP=0xb78c, HLT=1) rather than falling through to the CD. That
        // misplaced "fix" — correct in itself, but applied at the wrong point
        // in the VM lifecycle — was the real cause of what looked for a long
        // time like intermittent, tool-specific flakiness.
        println!(
            "[{}] waiting for {} installer to finish (VM powers itself off)...",
            host.name, vm.name
        );
        if wait_for_installer_finish(host, vm, INSTALL_WAIT_TIMEOUT, SSH_WAIT_INTERVAL) {
            println!("[{}] {} install complete", host.name, vm.name);
            set_boot_disk_first(host, vm, admin_user)?;
            return Ok(());
        }

        println!(
            "[{}] {} install did not complete within {INSTALL_WAIT_TIMEOUT}s — destroying and retrying",
            host.name, vm.name
        );
        destroy_and_undefine(host, vm);
        // A failed joining node may already have registered itself in etcd
        // before dying. Left behind, that ghost member permanently breaks
        // quorum — see etcd_prune.
        if let Some((bhost, bip)) = bootstrap_pair {
            etcd_prune(admin_user, bhost, bip, vm);
        }
    }
    bail!(
        "[{}] {} failed to come up after {CREATE_RETRIES} attempts",
        host.name,
        vm.name
    )
}

/// Make the OPERATOR'S OWN tooling work again after a rebuild.
///
/// A rebuild leaves two pieces of stale client-side state, and both bit
/// repeatedly before this was automated:
///
/// 1. **known_hosts** — rebuilt VMs present new SSH host keys at the same IPs,
///    so any later `ssh` fails with a host-key mismatch. The provisioner's own
///    probes pass `StrictHostKeyChecking=no`, so they never notice; it is the
///    human who hits it afterwards.
/// 2. **kubeconfig** — the new cluster has a new CA at the same IP, so an
///    existing `~/.kube/config` fails with
///    `x509: certificate signed by unknown authority ... "kubernetes-ca"`.
///
/// Neither is cluster state, which is exactly why they kept getting forgotten:
/// the cluster is genuinely fine and only the workstation is wrong. But
/// "reproducible" has to mean the environment works after a rebuild, not just
/// that the pods are Running.
pub fn refresh_client_access(
    admin_user: &str,
    bootstrap_ip: &str,
    node_ips: &[String],
) -> Result<()> {
    println!("=== refreshing client access (known_hosts + kubeconfig) ===");
    let home = std::env::var("HOME").unwrap_or_default();

    for ip in node_ips {
        let _ = std::process::Command::new("ssh-keygen")
            .args(["-R", ip])
            .output();
        if let Ok(scan) = std::process::Command::new("ssh-keyscan")
            .args(["-t", "ed25519", ip])
            .output()
        {
            let text = String::from_utf8_lossy(&scan.stdout);
            if scan.status.success() && !text.trim().is_empty() {
                let dir = std::path::Path::new(&home).join(".ssh");
                let _ = std::fs::create_dir_all(&dir);
                if let Ok(mut fh) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dir.join("known_hosts"))
                {
                    use std::io::Write;
                    let _ = fh.write_all(text.as_bytes());
                }
            }
        }
    }
    println!("  known_hosts refreshed for {} nodes", node_ips.len());

    let out = node_ssh(admin_user, bootstrap_ip, 10, "sudo k0s kubeconfig admin")?;
    // Validate before overwriting: clobbering a working kubeconfig with an
    // error message would turn a transient fetch failure into a broken
    // workstation.
    if !out.ok() || !out.stdout.contains("client-certificate-data") {
        println!("  WARNING: could not fetch a valid kubeconfig — leaving the existing one alone");
        println!(
            "  fix manually: ssh {admin_user}@{bootstrap_ip} 'sudo k0s kubeconfig admin' > ~/.kube/config"
        );
        return Ok(());
    }

    let kube_dir = std::path::Path::new(&home).join(".kube");
    std::fs::create_dir_all(&kube_dir)?;
    let kube_config = kube_dir.join("config");
    if kube_config.exists() {
        let stamp = std::process::Command::new("date")
            .arg("+%Y%m%d-%H%M%S")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let backup = kube_dir.join(format!("config.bak.{stamp}"));
        let _ = std::fs::copy(&kube_config, &backup);
    }
    std::fs::write(&kube_config, &out.stdout)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&kube_config, std::fs::Permissions::from_mode(0o600));
    }
    println!("  kubeconfig refreshed: {}", kube_config.display());

    // Prove it actually works rather than assuming. A kubeconfig that parses
    // but cannot authenticate looks identical to a good one on disk.
    match std::process::Command::new("kubectl")
        .args(["get", "nodes", "--no-headers"])
        .output()
    {
        Ok(c) if c.status.success() => println!(
            "  kubectl verified: {} nodes visible",
            String::from_utf8_lossy(&c.stdout).trim().lines().count()
        ),
        Ok(c) => println!(
            "  WARNING: kubectl still failing: {}",
            String::from_utf8_lossy(&c.stderr)
                .trim()
                .chars()
                .take(200)
                .collect::<String>()
        ),
        Err(e) => println!("  WARNING: kubectl still failing: {e}"),
    }
    Ok(())
}

/// The fleet, grouped by hypervisor, in site.yml order.
pub struct Fleet {
    pub hosts: Vec<(Host, Vec<Vm>)>,
}

impl Fleet {
    /// Build from site.yml, matching `hosts.py::_build_hosts`.
    pub fn from_config(cfg: &SiteConfig) -> Self {
        let mut hosts: Vec<(Host, Vec<Vm>)> = cfg
            .hypervisors
            .iter()
            .map(|(name, hv)| (Host::from_config(name, hv), Vec::new()))
            .collect();
        for (name, node) in &cfg.nodes {
            if let Some(entry) = hosts.iter_mut().find(|(h, _)| h.name == node.hypervisor) {
                entry.1.push(Vm {
                    name: name.clone(),
                    static_ip: node.ip.clone(),
                    hypervisor: node.hypervisor.clone(),
                    bootstrap: node.bootstrap,
                    memory_mib: node.memory_mib,
                    vcpu: node.vcpu,
                    storage_disk_gb: node.storage_disk_gb,
                });
            }
        }
        Self { hosts }
    }

    pub fn all_vms(&self) -> impl Iterator<Item = (&Host, &Vm)> {
        self.hosts
            .iter()
            .flat_map(|(h, vms)| vms.iter().map(move |v| (h, v)))
    }

    /// The bootstrap VM and the host carrying it.
    ///
    /// site.yml must mark exactly one; the config validator checks that up
    /// front, because discovering it here would mean failing after the ISO has
    /// downloaded.
    pub fn find_bootstrap(&self) -> Result<(&Host, &Vm)> {
        let matches: Vec<(&Host, &Vm)> = self.all_vms().filter(|(_, v)| v.bootstrap).collect();
        if matches.len() != 1 {
            bail!(
                "exactly one VM must have bootstrap: true, found {} — check site.yml",
                matches.len()
            );
        }
        Ok(matches[0])
    }
}

/// Print what a provision WOULD build, and touch nothing.
///
/// Every destructive action in this module is downstream of the same two facts:
/// which VM is the bootstrap, and what the fleet looks like. Printing those is
/// a faithful preview rather than a summary of one.
pub fn plan(cfg: &SiteConfig) -> Result<()> {
    let fleet = Fleet::from_config(cfg);
    // Called for its VALIDATION: it errors if the fleet declares zero or
    // several bootstrap nodes, and a dry run that stayed silent about that
    // would preview a plan that cannot actually be executed.
    let (_bhost, bvm) = fleet.find_bootstrap()?;
    let total: usize = fleet.hosts.iter().map(|(_, v)| v.len()).sum();
    println!("=== DRY RUN — would provision {total} VM(s) ===");
    for (host, vms) in &fleet.hosts {
        println!(
            "  {} ({})",
            host.name,
            host.ssh_target.as_deref().unwrap_or("local")
        );
        for vm in vms {
            let role = if vm.name == bvm.name {
                "BOOTSTRAP"
            } else {
                "joiner"
            };
            let state = if crate::libvirt::vm_exists(host, &crate::libvirt::Vm::new(&vm.name)) {
                "EXISTS, would reconcile"
            } else {
                "would CREATE"
            };
            let disk = match vm.storage_disk_gb {
                Some(g) if g > 0 => format!(", {g}G longhorn"),
                _ => String::new(),
            };
            println!(
                "    {:<8} {:<9} {:<15} {}MiB / {} vCPU{disk}  [{state}]",
                vm.name,
                role,
                vm.static_ip,
                vm.memory_mib.unwrap_or(cfg.defaults.memory_mib),
                vm.vcpu.unwrap_or(cfg.defaults.vcpu),
            );
        }
    }
    println!("\nDRY RUN — nothing was created, started, joined, or written.");
    Ok(())
}

/// Provision the whole fleet: bootstrap first, then every joining node.
///
/// Strictly ordered. The joining nodes need a token minted from the bootstrap
/// node, so parallelising this would only race for something that does not
/// exist yet.
pub fn provision_fleet(cfg: &SiteConfig, ssh_key: &str) -> Result<()> {
    let fleet = Fleet::from_config(cfg);
    let (bootstrap_host, bootstrap_vm) = fleet.find_bootstrap()?;
    let admin = &cfg.admin_user;

    // Phase 1: the bootstrap controller must be fully up BEFORE any other node
    // is created, because their join tokens are generated from it and baked
    // into their seed ISOs. This ordering applies only to the initial build —
    // once formed, every node is an equal controller and the bootstrap node
    // holds no special status.
    println!(
        "=== bootstrap: {} on {} ===",
        bootstrap_vm.name, bootstrap_host.name
    );
    preflight(bootstrap_host)?;
    ensure_disk_pool(bootstrap_host)?;
    ensure_iso_pool(bootstrap_host, cfg)?;
    ensure_kairos_iso(bootstrap_host, cfg)?;
    create_vm(
        bootstrap_host,
        bootstrap_vm,
        cfg,
        None,
        ssh_key,
        admin,
        None,
    )?;

    // The bootstrap VM booting is NOT the same as k0s being ready to mint join
    // tokens. Without this, the first joiner races the control plane's startup.
    println!(
        "[{}] waiting for k0s to be ready on {}...",
        bootstrap_host.name, bootstrap_vm.name
    );
    if !wait_for_k0s_ready(
        admin,
        &bootstrap_vm.static_ip,
        SSH_WAIT_TIMEOUT,
        SSH_WAIT_INTERVAL,
    ) {
        bail!(
            "k0s did not become ready on {} within {SSH_WAIT_TIMEOUT}s",
            bootstrap_vm.name
        );
    }

    // Node names are the VM names (cloud-config sets `hostname: {vm.name}`), so
    // the fleet definition is also the list of nodes the cluster must end up
    // with.
    let expected: Vec<String> = fleet.all_vms().map(|(_, v)| v.name.clone()).collect();
    let all_ips: Vec<String> = fleet.all_vms().map(|(_, v)| v.static_ip.clone()).collect();

    let joining: Vec<(&Host, &Vm)> = fleet.all_vms().filter(|(_, v)| !v.bootstrap).collect();
    if joining.is_empty() {
        println!("no joining nodes defined — cluster is a single bootstrap node");
        wait_for_nodes_ready(
            admin,
            &bootstrap_vm.static_ip,
            &expected,
            NODE_READY_TIMEOUT,
            SSH_WAIT_INTERVAL,
        )?;
        enforce_autopilot_pod_security(admin, &bootstrap_vm.static_ip)?;
        return refresh_client_access(admin, &bootstrap_vm.static_ip, &all_ips);
    }

    // Phase 2: one token per joining node, minted fresh from the running
    // bootstrap controller.
    println!("=== joining nodes ({}) ===", joining.len());
    for (host, vm) in &joining {
        // Existing VMs get reconciled (autostart, running state) rather than
        // skipped — and crucially we do NOT mint a join token for them, since
        // generating one is pointless work for a node that is already a member.
        if crate::libvirt::vm_exists(host, &crate::libvirt::Vm::new(&vm.name)) {
            reconcile_existing(host, vm, admin);
            continue;
        }
        preflight(host)?;
        ensure_disk_pool(host)?;
        ensure_iso_pool(host, cfg)?;
        ensure_kairos_iso(host, cfg)?;
        let token =
            generate_join_token(admin, bootstrap_host, bootstrap_vm, &cfg.k0s.token_expiry)?;
        create_vm(
            host,
            vm,
            cfg,
            Some(&token),
            ssh_key,
            admin,
            Some((bootstrap_host, &bootstrap_vm.static_ip)),
        )?;
    }

    // Phase 3: do not exit until the cluster actually reflects what was built.
    // create_vm returns when a VM is running, which is ~45-60s before its node
    // registers — so without this, a successful exit does not mean a usable
    // cluster.
    wait_for_nodes_ready(
        admin,
        &bootstrap_vm.static_ip,
        &expected,
        NODE_READY_TIMEOUT,
        SSH_WAIT_INTERVAL,
    )?;

    // Phase 3b: what the cluster cannot declare for itself. k0s owns the
    // k0s-autopilot namespace (ADR-063: Flux must not), and its own manifest
    // stack loses the race to autopilot — see enforce_autopilot_pod_security.
    enforce_autopilot_pod_security(admin, &bootstrap_vm.static_ip)?;

    // Phase 4: leave the OPERATOR'S environment working too. A rebuild that
    // produces a healthy cluster you cannot talk to is not reproducible in any
    // useful sense.
    refresh_client_access(admin, &bootstrap_vm.static_ip, &all_ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(name: &str, hv: &str, bootstrap: bool) -> Vm {
        Vm {
            name: name.into(),
            static_ip: "192.0.2.1".into(),
            hypervisor: hv.into(),
            bootstrap,
            memory_mib: None,
            vcpu: None,
            storage_disk_gb: None,
        }
    }

    fn fleet(vms: Vec<Vm>) -> Fleet {
        Fleet {
            hosts: vec![(Host::local("hvA"), vms)],
        }
    }

    #[test]
    fn exactly_one_bootstrap_is_required() {
        let f = fleet(vec![vm("a", "hvA", true), vm("b", "hvA", false)]);
        assert_eq!(f.find_bootstrap().unwrap().1.name, "a");
    }

    #[test]
    fn zero_bootstraps_is_an_error_not_a_default() {
        // Picking "the first node" would build a cluster whose control plane
        // nobody declared, and the mistake would only surface as a fleet that
        // never forms a quorum.
        let f = fleet(vec![vm("a", "hvA", false)]);
        assert!(f.find_bootstrap().is_err());
    }

    #[test]
    fn two_bootstraps_is_an_error() {
        // Two nodes each coming up alone form TWO one-node clusters that can
        // never merge. Failing here costs nothing; failing later costs a wipe.
        let f = fleet(vec![vm("a", "hvA", true), vm("b", "hvA", true)]);
        assert!(f.find_bootstrap().is_err());
    }

    #[test]
    fn a_host_with_no_ssh_target_is_local() {
        let h = Host::local("hvA");
        assert!(h.ssh_target.is_none());
    }

    #[test]
    fn peer_target_falls_back_to_ssh_target() {
        // hosts.py: `peer_target=hv.peer_target or hv.ssh_target`. Dropping the
        // fallback leaves the peer unreachable from the other hypervisor, which
        // only shows up during a cross-host operation.
        let hv = crate::config::HypervisorConfig {
            ssh_target: Some("brad@host".into()),
            peer_target: None,
            disk_pool: "vmpool".into(),
            pool_needs_nocow: false,
            failure_prone: false,
        };
        let h = Host::from_config("hvA", &hv);
        assert_eq!(h.peer_target.as_deref(), Some("brad@host"));
    }

    #[test]
    fn an_explicit_peer_target_is_not_overridden() {
        let hv = crate::config::HypervisorConfig {
            ssh_target: Some("brad@via-controller".into()),
            peer_target: Some("brad@via-peer".into()),
            disk_pool: "vmpool".into(),
            pool_needs_nocow: false,
            failure_prone: false,
        };
        let h = Host::from_config("hvA", &hv);
        assert_eq!(h.peer_target.as_deref(), Some("brad@via-peer"));
    }
}
