//! Manual live check of the read-only libvirt port. Reads site.yml; hardcodes
//! nothing. Run: cargo run --example live_libvirt_diff
fn main() -> anyhow::Result<()> {
    use substrate_core::exec::Host;
    use substrate_core::libvirt::{Vm, disk_volume_paths, domain_state, vm_exists};

    let cfg = substrate_core::load(std::path::Path::new("."))?;
    for (hname, h) in &cfg.hypervisors {
        let host = match &h.ssh_target {
            Some(t) => Host::remote(hname, t),
            None => Host::local(hname),
        };
        println!("--- {hname} ---");
        for (vname, node) in &cfg.nodes {
            if &node.hypervisor != hname {
                continue;
            }
            let vm = Vm::new(vname);
            println!(
                "  {vname:8} exists={:5} state={:10} disks={}",
                vm_exists(&host, &vm),
                domain_state(&host, &vm),
                disk_volume_paths(&host, &vm).join(",")
            );
        }
    }
    Ok(())
}
