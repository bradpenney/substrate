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
    /// Re-assert the cluster's security invariants. Read-only.
    ///
    /// Wave 1 of the Rust port. Covers ALL THIRTEEN of the Python's
    /// thirteen checks — see `posture-check --list` for exactly which, and
    /// `posture-differential.sh` for the harness that proves the two
    /// agree. Until all thirteen are ported, posture-check.py remains the
    /// one that runs on the timer.
    PostureCheck,
    /// Provision the k0s VM fleet. Idempotent. WRITES — see --apply.
    Provision(ProvisionArgs),
    /// DESTROY the whole fleet: VMs, disks, seed ISOs, host keys. See --yes.
    Wipe(WipeArgs),
    /// DESTROY the fleet and provision it again from nothing. See --yes.
    Rebuild(WipeArgs),
    /// Assert the 10 rebuild-gate criteria against the live cluster. Read-only.
    Verify,
    /// Print the cluster's comparable end state (JSON). Read-only.
    Fingerprint(FingerprintArgs),
    /// Compare two saved fingerprints — the actual rebuild proof. Read-only.
    Compare(CompareArgs),
    /// DESTRUCTIVE (one node at a time): rebuild nodes onto the pinned image.
    Roll(RollArgs),
    /// Architecture: check conformance and render diagrams. Read-only.
    Architecture(ArchArgs),
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
        Command::PostureCheck => posture_check(&cli.repo),
        Command::Provision(args) => provision(&cli.repo, args),
        Command::Wipe(args) => wipe(&cli.repo, args),
        Command::Rebuild(args) => rebuild(&cli.repo, args),
        Command::Verify => verify(&cli.repo),
        Command::Fingerprint(args) => fingerprint(&cli.repo, args),
        Command::Compare(args) => compare(&cli.repo, args),
        Command::Roll(args) => roll(&cli.repo, args),
        Command::Architecture(args) => architecture(args),
    }
}

/// Run the ported invariants and print them in the Python's exact format.
///
/// THE OUTPUT IS THE INTERFACE. A systemd unit runs this and `OnFailure` fires
/// on the exit code, while a human reads the lines. The two-space indent, the
/// `[ok  ]` padding and the stdout/stderr split are all reproduced rather than
/// improved, because the differential harness compares this text against the
/// Python's.
fn posture_check(repo: &std::path::Path) -> Result<()> {
    use substrate_core::posture::{
        Report, check_admission_policies, check_cluster_admin, check_credentials,
        check_default_deny, check_failed_units, check_firewall_restrictions, check_flux,
        check_no_standing_grant, check_origin_lock, check_peer_units, check_pod_security,
        check_selinux, check_source_verified,
    };

    let context = std::env::var("POSTURE_CONTEXT").unwrap_or_else(|_| "brad".into());
    let mut r = Report::default();

    // Each query records its OWN failure and yields None, so a caller that
    // returns early has still reported something rather than passing silently.
    let mut get = |args: &[&str]| -> Option<serde_json::Value> {
        match kubectl_json(&context, args) {
            Ok(v) => Some(v),
            Err(e) => {
                r.fail(format!("kubectl {} failed: {}", args.join(" "), e));
                None
            }
        }
    };

    let namespaces = get(&["get", "namespaces"]);
    let netpols = get(&["get", "networkpolicy", "-A"]);
    let crbs = get(&["get", "clusterrolebinding"]);
    let vaps = get(&["get", "validatingadmissionpolicy"]);
    let vapbs = get(&["get", "validatingadmissionpolicybinding"]);
    let flux = get(&["get", "kustomization", "-n", "flux-system"]);
    let ocirepo = get(&["get", "ocirepository", "flux-system", "-n", "flux-system"]);
    let esecrets = get(&["get", "externalsecret", "-A"]);

    if let Some(ns) = &namespaces {
        check_pod_security(ns, &mut r);
    }
    if let (Some(ns), Some(np)) = (&namespaces, &netpols) {
        check_default_deny(ns, np, &mut r);
    }
    if let Some(b) = &crbs {
        check_cluster_admin(b, &mut r);
    }
    if let (Some(p), Some(b)) = (&vaps, &vapbs) {
        check_admission_policies(p, b, &mut r);
    }
    if let Some(f) = &flux {
        check_flux(f, &mut r);
    }
    if let Some(e) = &esecrets {
        check_credentials(e, &mut r);
    }
    // Queried on its own, NOT through `get`. kubectl exits non-zero when the
    // binding does not exist, and that is the healthy, ordinary state — routing
    // it through the shared helper would record a kubectl failure every time
    // nobody holds a JIT grant, which is almost always.
    let jit = kubectl_json(
        &context,
        &["get", "clusterrolebinding", "jit-platform-admin"],
    )
    .ok();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    check_no_standing_grant(jit.as_ref(), now, &mut r);
    check_failed_units(&gather_systemd(), &mut r);
    check_selinux(&gather_selinux(repo), &mut r);
    check_peer_units(&gather_peer_units(repo), &mut r);
    check_origin_lock(&gather_origin(repo), &mut r);
    if let Some(o) = &ocirepo {
        check_source_verified(o, &mut r);
    }
    let fw = gather_firewall(repo);
    check_firewall_restrictions(fw.as_deref(), &mut r);

    for n in &r.notes {
        println!("  [ok  ] {n}");
    }
    for f in &r.failures {
        eprintln!("  [FAIL] {f}");
    }
    println!();
    if r.failures.is_empty() {
        println!("all {} security invariants hold", r.notes.len());
        Ok(())
    } else {
        eprintln!("{} security invariant(s) BROKEN", r.failures.len());
        std::process::exit(1);
    }
}

/// Query the cluster as JSON.
///
/// Shells out to kubectl rather than using kube-rs, deliberately and for now:
/// the pilot's contract is identical output to the Python, and that means
/// identical queries and identical credential resolution. Swapping the
/// transport is a later step that must be proven on its own.
fn kubectl_json(context: &str, args: &[&str]) -> Result<serde_json::Value> {
    // Without this, a missing kubectl makes every check fail and the tool
    // reports invariants BROKEN — a false alarm that looks exactly like a real
    // breach. kubectl lives under linuxbrew here, which is not on systemd's
    // default PATH; that already paged once.
    let exe = which_kubectl().ok_or_else(|| {
        anyhow::anyhow!(
            "kubectl not found on PATH. This is a TOOLING failure, not a \
             security finding -- fix PATH and re-run."
        )
    })?;
    let out = std::process::Command::new(exe)
        .arg(format!("--context={context}"))
        .args(args)
        .args(["-o", "json"])
        .output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let trimmed = err.trim();
        anyhow::bail!("{}", &trimmed[..trimmed.len().min(160)]);
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

fn which_kubectl() -> Option<std::path::PathBuf> {
    let extra = "/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin";
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in format!("{path}:{extra}")
        .split(':')
        .filter(|d| !d.is_empty())
    {
        let p = std::path::Path::new(dir).join("kubectl");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn render(repo: &std::path::Path, args: RenderArgs) -> Result<()> {
    // The bootstrap node comes up alone and joins nothing. Accepting both would
    // render a config that silently contradicts itself, and the node would come
    // up looking fine.
    if args.bootstrap && args.join_token.is_some() {
        eprintln!("error: --bootstrap and --join-token are mutually exclusive");
        std::process::exit(2);
    }

    // $SUBSTRATE_JOIN_TOKEN is the way a CALLER should pass a REAL token.
    //
    // A join token grants cluster membership. Passed as `--join-token`, it
    // lands in /proc/<pid>/cmdline, which is world-readable — so every local
    // user on the provisioning host can read it for as long as the process
    // lives, and it reaches the shell history and any process listing. The
    // flag is kept because the goldens and the archetypes use a dummy token
    // and argv is clearer there, but automation must not use it.
    //
    // Read here, not in the renderer: same reason as the SSH key below — the
    // renderer stays a pure function of its inputs, which is what the goldens
    // depend on.
    //
    // The flag wins if both are set, so an explicit argument is never silently
    // overridden by a stale exported variable.
    let join_token = args.join_token.clone().or_else(|| {
        std::env::var("SUBSTRATE_JOIN_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
    });
    if args.bootstrap && join_token.is_some() {
        eprintln!(
            "error: --bootstrap was given but $SUBSTRATE_JOIN_TOKEN is set. \
             The bootstrap node joins nothing; unset it or drop --bootstrap."
        );
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

    let out = substrate_core::render::cloud_config(&cfg, &vm, join_token.as_deref(), &ssh_key);
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

/// Ask systemd what is failing, before anything decides what that means.
///
/// Every call here is `check=false` in spirit: systemctl exits non-zero for
/// perfectly ordinary answers — `is-failed` returns 1 when a unit is HEALTHY,
/// and `is-system-running` returns 1 when the system is degraded. Treating
/// those exits as errors would invert the check.
fn gather_systemd() -> substrate_core::posture::SystemdState {
    use substrate_core::posture::{SystemdState, WATCHED_UNITS};

    let run = |args: &[&str]| -> String {
        std::process::Command::new("systemctl")
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };

    let mut failed_watched = Vec::new();
    for unit in WATCHED_UNITS {
        if run(&["is-failed", unit]) == "failed" {
            let when = run(&["show", unit, "-p", "ExecMainExitTimestamp", "--value"]);
            failed_watched.push(((*unit).to_string(), when));
        }
    }

    // `--no-legend --plain` so the first whitespace-separated field is the unit
    // name and nothing else. Without --plain, systemd prefixes a bullet
    // character on failed units and the name parses as "●".
    let all_failed = run(&["list-units", "--state=failed", "--no-legend", "--plain"])
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect();

    SystemdState {
        system_status: run(&["is-system-running"]),
        failed_watched,
        all_failed,
    }
}

/// The other hypervisor, derived from typed config rather than a literal.
///
/// This default used to be a hardcoded LAN address in a repository that is on
/// its way to being public. site.yml is gitignored precisely so addresses live
/// in exactly one place; a "convenient" default quietly undid that.
///
/// Returns an empty string when the peer cannot be determined, which
/// `gather_selinux` reports as "unreachable, not checked" rather than
/// inventing a host to blame.
fn peer_target(repo: &std::path::Path) -> String {
    // An empty POSTURE_PEER is treated as unset, matching the Python's
    // `os.environ.get(...) or _peer_target()` — an exported-but-blank variable
    // must fall through to the config, not silently disable the peer check.
    if let Some(p) = std::env::var("POSTURE_PEER").ok().filter(|p| !p.is_empty()) {
        return p;
    }
    let me = hostname();
    let Ok(cfg) = substrate_core::load(repo) else {
        return String::new();
    };
    cfg.hypervisors
        .iter()
        .find(|(name, _)| **name != me)
        .and_then(|(_, h)| h.peer_target.clone().or_else(|| h.ssh_target.clone()))
        .unwrap_or_default()
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Ask both hypervisors about SELinux, without judging the answers here.
///
/// The same one-liner runs locally and over ssh so the two hosts are asked
/// EXACTLY the same question — a probe that differs per host cannot support a
/// comparison between them.
fn gather_selinux(repo: &std::path::Path) -> Vec<substrate_core::posture::SelinuxProbe> {
    use substrate_core::posture::SelinuxProbe;

    // getenforce, then the count of permissive DOMAINS. The mode alone is not
    // the property being asserted.
    const SCRIPT: &str =
        "getenforce; semanage permissive -l 2>/dev/null | grep -c '^[a-z]' || echo 0";

    let capture = |mut cmd: std::process::Command| -> Option<String> {
        let out = cmd.output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).to_string();
        (!s.trim().is_empty()).then_some(s)
    };

    let mut local = std::process::Command::new("bash");
    local.args(["-c", SCRIPT]);
    let mut probes = vec![SelinuxProbe {
        label: "this host".into(),
        output: capture(local),
    }];

    let peer = peer_target(repo);
    if !peer.is_empty() {
        // The label is the ADDRESS without any user@ prefix, matching the
        // Python — the finding names a host, not a login.
        let label = peer.rsplit('@').next().unwrap_or(&peer).to_string();
        let mut ssh = std::process::Command::new("ssh");
        ssh.args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            &peer,
            SCRIPT,
        ]);
        probes.push(SelinuxProbe {
            label,
            output: capture(ssh),
        });
    }
    probes
}

/// Ask the peer about the units this host watches on its behalf.
fn gather_peer_units(repo: &std::path::Path) -> Vec<substrate_core::posture::PeerUnitState> {
    use substrate_core::posture::{PEER_UNITS, PeerUnitState};

    let peer = peer_target(repo);
    let label = peer.rsplit('@').next().unwrap_or(&peer).to_string();
    PEER_UNITS
        .iter()
        .map(|unit| {
            // An empty peer target yields None, which the check reports as
            // "unreachable, not checked" — the honest answer when there is no
            // peer configured to ask.
            let state = (!peer.is_empty())
                .then(|| {
                    std::process::Command::new("ssh")
                        .args([
                            "-o",
                            "BatchMode=yes",
                            "-o",
                            "ConnectTimeout=8",
                            &peer,
                            &format!("systemctl is-failed {unit}"),
                        ])
                        .output()
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                })
                .flatten();
            PeerUnitState {
                label: label.clone(),
                unit: (*unit).to_string(),
                state,
            }
        })
        .collect()
}

/// Probe the public path twice: through Cloudflare, and around it.
///
/// `-k` because the direct-to-origin probe deliberately bypasses the proxy and
/// will present a certificate for the wrong name; the status code is the answer
/// being sought, not the TLS chain. `000` means the connection never completed,
/// which is the DESIRED result for the bypass attempt.
fn gather_origin(repo: &std::path::Path) -> substrate_core::posture::OriginProbe {
    use substrate_core::posture::OriginProbe;

    let Ok(cfg) = substrate_core::load(repo) else {
        return OriginProbe::default();
    };
    let Some(hostname) = cfg.posture.public_hostname.filter(|h| !h.is_empty()) else {
        return OriginProbe::default();
    };

    let curl = |extra: &[&str]| -> String {
        let mut c = std::process::Command::new("curl");
        c.args(["-sk", "-o", "/dev/null", "-m", "12", "-w", "%{http_code}"])
            .args(extra)
            .arg(format!("https://{hostname}"));
        c.output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };

    let through = curl(&[]);
    let direct = cfg
        .posture
        .origin_ip
        .filter(|ip| !ip.is_empty())
        .map(|ip| curl(&["--resolve", &format!("{hostname}:443:{ip}")]));

    OriginProbe {
        hostname_configured: true,
        through,
        direct,
    }
}

/// Probe each restricted port from a source that must be denied, and — only if
/// that came back denied — from one that must be allowed.
///
/// The second probe is skipped when the first leaks or is inconclusive, exactly
/// as the Python does: there is nothing to learn from confirming an allowed
/// source can reach a port that everyone can reach.
///
/// Returns None when the site config lacks what the matrix needs, which the
/// check reports as "not checked" rather than inventing a verdict.
fn gather_firewall(repo: &std::path::Path) -> Option<Vec<substrate_core::posture::FirewallProbe>> {
    use substrate_core::posture::FirewallProbe;

    let cfg = substrate_core::load(repo).ok()?;
    let peer = peer_target(repo);
    let me = hostname();
    // This hypervisor's own LAN address, as its peers reach it — the target of
    // every probe below.
    let local = cfg
        .hypervisors
        .get(&me)
        .and_then(|h| h.peer_target.clone().or_else(|| h.ssh_target.clone()))
        .map(|t| t.rsplit('@').next().unwrap_or_default().to_string())
        .unwrap_or_default();
    let first_node = cfg.nodes.values().next().map(|n| n.ip.clone())?;
    if local.is_empty() || peer.is_empty() {
        return None;
    }
    let a_node = format!("{}@{}", cfg.admin_user, first_node);

    // port, what it is, who MUST reach it, who MUST NOT
    let matrix: [(u16, &str, &str, &str); 3] = [
        (9100, "node_exporter", &peer, &a_node),
        (9428, "log ingest", &a_node, &peer),
        (8428, "metrics write + query + delete", &a_node, &peer),
    ];

    Some(
        matrix
            .iter()
            .map(|(port, what, allowed, denied)| {
                let leaked = port_reachable_from(denied, &local, *port);
                // Only probe the allowed side once the denied side is confirmed
                // denied — see the doc comment.
                let permitted = (leaked == Some(false))
                    .then(|| port_reachable_from(allowed, &local, *port))
                    .flatten();
                FirewallProbe {
                    port: *port,
                    what: (*what).to_string(),
                    allowed_label: (*allowed).to_string(),
                    denied_label: (*denied).to_string(),
                    leaked,
                    permitted,
                }
            })
            .collect(),
    )
}

/// Can `prober` open a TCP connection to host:port? None = inconclusive.
///
/// A bare TCP connect, not an HTTP request: the question is whether the packet
/// is allowed through, and a service that answers 403 is still reachable.
fn port_reachable_from(prober: &str, host: &str, port: u16) -> Option<bool> {
    let probe = format!(
        "timeout 4 bash -c 'exec 3<>/dev/tcp/{host}/{port}' 2>/dev/null && echo OPEN || echo CLOSED"
    );
    let out = std::process::Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            prober,
            &probe,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "OPEN" => Some(true),
        "CLOSED" => Some(false),
        // Anything else means the probe itself misbehaved. Inconclusive, never
        // a verdict — reading an unexpected answer as "closed" would report the
        // firewall as verified on the strength of a broken probe.
        _ => None,
    }
}

#[derive(clap::Args, Debug)]
struct ProvisionArgs {
    /// Actually build. Without it, print the plan and touch nothing.
    ///
    /// Safe by DEFAULT, the same shape as deploy-cplb.py: this creates VMs,
    /// mints join tokens and rewrites the operator's kubeconfig, so the
    /// dangerous thing is the one you have to ask for. `provision.py` chose the
    /// opposite default (`--dry-run` opts OUT of building) — kept there for
    /// compatibility with muscle memory and scripts, corrected here because
    /// this is a new entry point with no callers to break.
    #[arg(long)]
    apply: bool,
}

/// Refuse to run privileged, with the REASON rather than the symptom.
///
/// Ported from `siteconfig.refuse_if_root`. Every tool here stages as the
/// ordinary user over SSH and escalates exactly once, for an installer
/// (ADR-078). Run whole under `sudo` it resolves $HOME to /root, finds no admin
/// SSH key and no ssh-agent, and fails with `Permission denied (publickey)` —
/// which names the symptom, not the cause, and only after the first connection
/// attempt.
fn refuse_if_root(tool: &str) {
    // SAFETY: geteuid is always safe; it reads a process property and cannot
    // fail. Avoiding a `nix`/`libc` dependency keeps the static-musl build the
    // installer depends on unchanged.
    let euid = unsafe { libc_geteuid() };
    if euid != 0 {
        return;
    }
    eprintln!(
        "Do not run this under sudo.\n  \
         It stages as YOU over SSH and escalates once, for the installer\n  \
         alone (ADR-078). As root it SSHes as root, which has no key here,\n  \
         and fails with 'Permission denied (publickey)'.\n  \
         Run:  {tool}\n  \
         It will prompt for sudo itself, at most once per host."
    );
    std::process::exit(2);
}

unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

fn provision(repo: &std::path::Path, args: ProvisionArgs) -> Result<()> {
    refuse_if_root("substrate provision --apply");
    let cfg = substrate_core::load(repo)?;
    if !args.apply {
        return substrate_core::provision::plan(&cfg);
    }
    // Same refusal as `render`: a provisioner that guesses the admin key builds
    // a fleet nobody can log into, discovered after it exists.
    let ssh_key = ssh_public_key().context(
        "no admin SSH key found. Set $HOMELAB_SSH_PUBLIC_KEY or create ~/.ssh/id_ed25519.pub",
    )?;
    substrate_core::provision::provision_fleet(&cfg, &ssh_key)
}

#[derive(clap::Args, Debug)]
struct WipeArgs {
    /// Actually destroy. Without it, print exactly what would go — every VM,
    /// every disk volume by path, every seed ISO — and touch nothing.
    ///
    /// Same shape as `provision --apply`: the dangerous thing is the one you
    /// have to ask for. Named `--yes` rather than `--apply` because "apply a
    /// wipe" reads as a euphemism, and this is the one command in the binary
    /// whose whole job is to destroy.
    #[arg(long)]
    yes: bool,
}

fn wipe(repo: &std::path::Path, args: WipeArgs) -> Result<()> {
    refuse_if_root("substrate wipe --yes");
    let cfg = substrate_core::load(repo)?;
    substrate_core::wipe::wipe(&cfg, !args.yes);
    Ok(())
}

/// Wipe, then provision — the whole rebuild in one binary.
///
/// This is the command the rebuild gate exercises. The two halves are kept as
/// separate modules (the build path never destroys, the destroy path never
/// builds) and composed only here, so that neither can be reached through the
/// other by accident. Verification of the result is a separate, read-only
/// step (`gate.py verify` until that is ported).
fn rebuild(repo: &std::path::Path, args: WipeArgs) -> Result<()> {
    refuse_if_root("substrate rebuild --yes");
    let cfg = substrate_core::load(repo)?;
    if !args.yes {
        substrate_core::wipe::wipe(&cfg, true);
        println!();
        substrate_core::provision::plan(&cfg)?;
        // `plan` reads LIVE state, so on an existing fleet it says
        // "would reconcile". After the wipe above there is nothing to
        // reconcile; say so rather than let the preview contradict itself.
        println!("(after the wipe, every VM above is CREATED — none is reconciled)");
        return Ok(());
    }
    // Resolve the key BEFORE destroying anything: a rebuild that wipes the
    // fleet and then discovers it has no admin key to build with has turned a
    // configuration error into an outage.
    let ssh_key = ssh_public_key().context(
        "no admin SSH key found. Set $HOMELAB_SSH_PUBLIC_KEY or create ~/.ssh/id_ed25519.pub",
    )?;
    substrate_core::wipe::wipe(&cfg, false);
    println!(
        "
=== rebuilding ==="
    );
    substrate_core::provision::provision_fleet(&cfg, &ssh_key)
}

#[derive(clap::Args, Debug)]
struct FingerprintArgs {
    /// Also write it to .fingerprints/<METHOD>.json for `compare`.
    #[arg(long, value_name = "METHOD")]
    save: Option<String>,
}

#[derive(clap::Args, Debug)]
struct CompareArgs {
    /// Name of a saved fingerprint (e.g. python, ansible, rust).
    a: String,
    b: String,
}

#[derive(clap::Args, Debug)]
struct RollArgs {
    /// Actually replace nodes. Without it, list what would be rolled.
    #[arg(long)]
    yes: bool,
    /// Roll only this node (default: the whole fleet, one at a time).
    #[arg(long)]
    node: Option<String>,
}

/// Where fingerprints live: beside site.yml, as `gate.py` kept them, so the
/// python/ansible ones already saved there remain comparable.
fn fingerprint_dir(repo: &std::path::Path) -> PathBuf {
    repo.join(".fingerprints")
}

fn exit_with(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { std::process::exit(1) }
}

/// The verifying half of the rebuild gate. Read-only: it reaches the cluster
/// through the bootstrap node's `k0s kubectl` and never creates or destroys
/// anything but its own DNS probe pod. Exit 0 means every criterion held.
fn verify(repo: &std::path::Path) -> Result<()> {
    let cfg = substrate_core::load(repo)?;
    let gate = substrate_core::gate::Gate::new(&cfg)?;
    exit_with(gate.verify())
}

fn fingerprint(repo: &std::path::Path, args: FingerprintArgs) -> Result<()> {
    let cfg = substrate_core::load(repo)?;
    let gate = substrate_core::gate::Gate::new(&cfg)?;
    if let Some(method) = args.save {
        gate.save_fingerprint(&fingerprint_dir(repo), &method)?;
    }
    print!(
        "{}",
        substrate_core::gate::fingerprint_json(&gate.fingerprint()?)
    );
    Ok(())
}

fn compare(repo: &std::path::Path, args: CompareArgs) -> Result<()> {
    exit_with(substrate_core::gate::compare_saved(
        &fingerprint_dir(repo),
        &args.a,
        &args.b,
    ))
}

fn roll(repo: &std::path::Path, args: RollArgs) -> Result<()> {
    refuse_if_root("substrate roll --yes");
    let cfg = substrate_core::load(repo)?;
    let gate = substrate_core::gate::Gate::new(&cfg)?;
    if !args.yes {
        let fleet = substrate_core::provision::Fleet::from_config(&cfg);
        let targets: Vec<_> = fleet
            .all_vms()
            .filter(|(_, v)| args.node.as_deref().is_none_or(|t| t == v.name))
            .collect();
        if targets.is_empty() {
            anyhow::bail!("no such node: {}", args.node.unwrap_or_default());
        }
        println!(
            "DRY RUN — would roll {} node(s) onto image {}..., one at a time:",
            targets.len(),
            &cfg.kairos.iso_sha256[..12]
        );
        for (h, v) in targets {
            println!("  {} on {}", v.name, h.name);
        }
        println!(
            "
DRY RUN — nothing was replaced. Add --yes to roll."
        );
        return Ok(());
    }
    let ssh_key = ssh_public_key().context(
        "no admin SSH key found. Set $HOMELAB_SSH_PUBLIC_KEY or create ~/.ssh/id_ed25519.pub",
    )?;
    exit_with(gate.roll(args.node.as_deref(), &ssh_key))
}

#[derive(clap::Args, Debug)]
struct ArchArgs {
    /// Path to the CALM architecture document.
    #[arg(
        long,
        default_value = "../substrate_config/architecture/homelab.arch.json"
    )]
    model: std::path::PathBuf,
    /// Root of the GitOps configuration repository to check against.
    #[arg(long, default_value = "../substrate_config")]
    config: std::path::PathBuf,
    /// Write D2 view sources to this directory.
    #[arg(long)]
    render: Option<std::path::PathBuf>,
}

/// Architecture Driven Design: the model is checked, and the diagrams come from
/// the model. Read-only in every mode.
fn architecture(args: ArchArgs) -> Result<()> {
    use substrate_core::architecture as arch;
    let model = arch::Architecture::load(&args.model)?;
    println!(
        "  model: {} nodes, {} relationships, {} flows",
        model.nodes.len(),
        model.relationships.len(),
        model.flows.len()
    );

    if let Some(dir) = &args.render {
        std::fs::create_dir_all(dir)?;
        for view in arch::VIEWS {
            let path = dir.join(format!("{}.d2", view.id));
            std::fs::write(&path, model.render_d2(view))?;
            println!("  rendered {}", path.display());
        }
    }

    let surface = arch::deployed_surface(&args.config)?;
    let c = arch::check_conformance(&model, &surface);
    println!(
        "  configuration declares {} deployable component(s)",
        surface.components.len()
    );
    if !c.planned.is_empty() {
        println!(
            "  planned (described, not yet deployed — allowed): {}",
            c.planned.join(", ")
        );
    }
    for v in &c.privacy_violations {
        println!("  PRIVACY: {v}");
    }
    for u in &c.undescribed {
        println!("  UNDESCRIBED: '{u}' is deployed but this architecture does not describe it");
    }
    if !c.privacy_violations.is_empty() {
        eprintln!(
            "\nPUBLISHABILITY VIOLATION\n  \
             This model is rendered onto a public website. Addresses, internal\n  \
             hostnames and credentials must never reach it — a published\n  \
             architecture that maps a private network is worth more to an\n  \
             attacker than it is to a reader.\n  \
             Describe the SHAPE of the topology, never its coordinates."
        );
    }
    if !c.undescribed.is_empty() {
        eprintln!(
            "\nARCHITECTURE DRIVEN DESIGN VIOLATION\n  \
             Architecture may lead reality. Reality may never lead architecture.\n  \
             Add the component to homelab.arch.json FIRST, then deploy it."
        );
    }
    if !c.ok() {
        std::process::exit(1);
    }
    println!("  configuration conforms to the architecture");
    Ok(())
}
