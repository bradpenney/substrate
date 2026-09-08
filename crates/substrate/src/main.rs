//! The substrate binary.
//!
//! One subcommand so far: `render`, which reproduces `render-cloud-config.py`.
//! It is deliberately the first thing ported (ADR-093) because a renderer can
//! be proven byte-for-byte against a committed artefact, which is not true of
//! anything that drives libvirt or waits for a machine to boot.
//!
//! The Python CLI's argument names are the contract, so they are reproduced
//! exactly rather than improved: the goldens are pinned to them, and a rename
//! would make this a different tool that happens to render the same bytes.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "substrate",
    version,
    about = "Provision and operate the k0s fleet."
)]
struct Cli {
    /// Repository root; where site.yml and versions.yml are looked for.
    #[arg(long, global = true, default_value = ".")]
    repo: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Render one node's cloud-config to stdout. Read-only.
    Render(RenderArgs),
}

#[derive(clap::Args)]
struct RenderArgs {
    /// Node hostname.
    #[arg(long)]
    name: String,
    /// Static address.
    #[arg(long)]
    ip: String,
    /// Hypervisor carrying this node — its failure domain. REQUIRED: a node
    /// rendered without one joins with no failure domain, which no scheduling
    /// constraint can then express.
    #[arg(long)]
    hypervisor: String,
    /// Render the bootstrap controller (no join token is used).
    #[arg(long)]
    bootstrap: bool,
    /// Override the default RAM.
    #[arg(long)]
    memory_mib: Option<u32>,
    /// Override the default vCPU count.
    #[arg(long)]
    vcpu: Option<u32>,
    /// Dedicated Longhorn disk in GB (ADR-050); omit for none.
    #[arg(long)]
    storage_disk_gb: Option<u32>,
    /// Token minted from the bootstrap node; omit for the bootstrap node.
    #[arg(long)]
    join_token: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Render(args) => render(&cli.repo, args),
    }
}

fn render(repo: &std::path::Path, args: RenderArgs) -> Result<()> {
    // The bootstrap node comes up alone and joins nothing. Accepting both would
    // render a config that silently contradicts itself, and the node would come
    // up looking fine.
    if args.bootstrap && args.join_token.is_some() {
        eprintln!("error: --bootstrap and --join-token are mutually exclusive");
        std::process::exit(2);
    }

    // Read from the environment here rather than inside the renderer: the key
    // lands in the output, so a renderer that reaches for ambient state is not
    // a pure function of its inputs — which is what the goldens rely on.
    //
    // Refuses to guess. Rendering with the wrong key produces a node nobody can
    // log into, discovered after it has been built.
    let ssh_key = ssh_public_key().context(
        "no admin SSH key found. Set $HOMELAB_SSH_PUBLIC_KEY or create ~/.ssh/id_ed25519.pub",
    )?;

    let cfg = substrate_core::load(repo)?;
    let vm = substrate_core::render::Vm {
        name: args.name,
        static_ip: args.ip,
        hypervisor: args.hypervisor,
        bootstrap: args.bootstrap,
        memory_mib: args.memory_mib,
        vcpu: args.vcpu,
        storage_disk_gb: args.storage_disk_gb,
    };

    let out = substrate_core::render::cloud_config(&cfg, &vm, args.join_token.as_deref(), &ssh_key);
    // Write the bytes as they are. `println!` would add a newline the renderer
    // already emitted and put every golden one byte out.
    std::io::stdout().write_all(out.as_bytes())?;
    Ok(())
}

/// Resolve the admin SSH public key, never storing it in the repo.
///
/// Same order as `siteconfig.resolve_ssh_public_key()`: the environment first,
/// then the conventional key path. Anyone cloning this provisions nodes that
/// trust THEIR key, and the repo carries nobody's identity.
fn ssh_public_key() -> Option<String> {
    if let Some(key) = std::env::var_os("HOMELAB_SSH_PUBLIC_KEY") {
        let key = key.to_string_lossy().trim().to_string();
        if !key.is_empty() {
            return Some(key);
        }
    }
    let home = std::env::var_os("HOME")?;
    let path = PathBuf::from(home).join(".ssh/id_ed25519.pub");
    let text = std::fs::read_to_string(path).ok()?;
    let key = text.trim().to_string();
    (!key.is_empty()).then_some(key)
}
