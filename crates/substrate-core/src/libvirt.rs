//! Reading libvirt's view of a hypervisor. Everything here is READ-ONLY.
//!
//! Ported from `provision.py`. Split from the destructive lifecycle operations
//! deliberately: these four can be run against the live fleet to verify the
//! port without changing anything, which is the only way to check them short of
//! a rebuild.
//!
//! Every call names `-c qemu:///system` explicitly. Omitting it picks up the
//! caller's session URI, and a session-scoped libvirt sees NONE of the system
//! domains — so a query would cheerfully report "no such VM" about a running
//! node and a create would build a second one alongside it.

use crate::exec::{Host, run};

/// One virtual machine, as the provisioner refers to it.
#[derive(Debug, Clone)]
pub struct Vm {
    pub name: String,
}

impl Vm {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

fn virsh(args: &[&str]) -> Vec<String> {
    let mut v = vec!["virsh".to_string(), "-c".into(), "qemu:///system".into()];
    v.extend(args.iter().map(|a| a.to_string()));
    v
}

/// Whether libvirt already knows about this domain.
///
/// Distinct from "is it running": a defined-but-off domain still owns its name
/// and disks, so creating over it fails in a confusing way.
pub fn vm_exists(host: &Host, vm: &Vm) -> bool {
    matches!(run(host, &virsh(&["dominfo", &vm.name]), None), Ok(o) if o.ok())
}

/// libvirt's state string for a domain, or empty if it does not exist.
///
/// Empty rather than an error: callers use this to decide whether to create,
/// and "not there" is the normal case on a fresh build.
pub fn domain_state(host: &Host, vm: &Vm) -> String {
    match run(host, &virsh(&["domstate", &vm.name]), None) {
        Ok(o) => o.stdout.trim().to_string(),
        Err(_) => String::new(),
    }
}

/// Source paths of the domain's real disks — CDROMs deliberately excluded.
///
/// `virsh domblklist --details` output looks like:
///
/// ```text
/// Type    Device   Target   Source
/// block   disk     vda      /dev/<vg>/<node>
/// file    cdrom    hda      -
/// file    cdrom    sda      /var/lib/libvirt/isos/<node>-cloudinit.iso
/// ```
///
/// Only `disk` rows are the VM's own storage. The cdrom rows are shared or
/// separately-managed media and must never be deleted as part of tearing down
/// one VM — which is what this list is used for.
pub fn disk_volume_paths(host: &Host, vm: &Vm) -> Vec<String> {
    let out = match run(host, &virsh(&["domblklist", &vm.name, "--details"]), None) {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    out.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            (f.len() >= 4 && f[1] == "disk" && f[3] != "-").then(|| f[3].to_string())
        })
        .collect()
}

/// True only if the VM is running the INSTALLED system, not live media.
///
/// SSH reachability alone is NOT a valid "install finished" signal: Kairos's
/// live installer brings up networking and sshd (it applies the cloud-config's
/// network/user stages early), so the VM answers on port 22 while the install
/// is still running and the disk is still blank. Acting on SSH-alone caused a
/// real bug here — the post-install boot-order change got applied to a VM that
/// had not finished installing, leaving it pointed at an unbootable disk and
/// halting SeaBIOS.
///
/// The reliable discriminator is the kernel command line:
///   live media : `root=live:CDLABEL=COS_LIVE`
///   installed  : `root=LABEL=COS_ACTIVE`
///
/// Host-key checking is disabled on purpose: this races a machine that is
/// reinstalling, so its host key legitimately changes underneath us. That is
/// why it is scoped to this one probe rather than set globally.
pub fn booted_from_disk(admin_user: &str, ip: &str) -> bool {
    let out = std::process::Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            &format!("{admin_user}@{ip}"),
            "cat /proc/cmdline",
        ])
        .output();
    match out {
        Ok(o) => o.status.success() && String::from_utf8_lossy(&o.stdout).contains("COS_ACTIVE"),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_disk_rows_are_returned_never_cdroms() {
        // The exact shape `virsh domblklist --details` emits. A parser that
        // took every non-"-" Source would return the cloudinit ISO, and the
        // teardown path would delete shared media as if it were the VM's own.
        let sample = "\
 Type    Device   Target   Source
------------------------------------------------
 block   disk     vda      /dev/vg0/s1-vm1
 file    cdrom    hda      -
 file    cdrom    sda      /var/lib/libvirt/isos/s1-vm1-cloudinit.iso
 block   disk     vdb      /dev/vg0/s1-vm1-longhorn
";
        let rows: Vec<String> = sample
            .lines()
            .filter_map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                (f.len() >= 4 && f[1] == "disk" && f[3] != "-").then(|| f[3].to_string())
            })
            .collect();
        assert_eq!(rows, vec!["/dev/vg0/s1-vm1", "/dev/vg0/s1-vm1-longhorn"]);
    }

    #[test]
    fn every_virsh_invocation_pins_the_system_uri() {
        // A session-scoped libvirt sees none of the system domains, so an
        // unpinned query reports "no such VM" about a running node.
        let argv = virsh(&["dominfo", "s1-vm1"]);
        assert_eq!(argv[..3], ["virsh", "-c", "qemu:///system"]);
    }
}
