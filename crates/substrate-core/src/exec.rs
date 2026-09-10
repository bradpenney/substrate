//! Running commands, locally or over SSH — the primitive every provisioning
//! step is built from.
//!
//! Ported from `provision.py`'s `run()` / `write_file()`. The contract it
//! keeps, quoted from that docstring, is the reason this module exists at all:
//!
//! > Building commands as argv lists (not shell strings) and using
//! > shlex.join() only at the SSH boundary avoids the exact class of
//! > quoting/heredoc bugs hit repeatedly earlier in this build with both HCL
//! > and Ansible YAML.
//!
//! So `Vec<String>` everywhere, and exactly one place — [`shell_join`] — where
//! an argv becomes a string, because `ssh host cmd` gives the remote shell a
//! string and there is no argv-preserving alternative.

use std::io::Write;
use std::process::{Command, Stdio};

/// A machine to run commands on. `ssh_target` of `None` means locally.
#[derive(Debug, Clone)]
pub struct Host {
    pub name: String,
    pub ssh_target: Option<String>,
    /// libvirt storage pool for VM disks. Genuinely differs per host — an LVM
    /// pool of raw LVs on one machine, the stock dir pool on another with no
    /// LVM at all. DATA rather than a code branch, which is what lets one code
    /// path drive genuinely heterogeneous hardware.
    pub disk_pool: String,
    /// True when the pool's backing filesystem is btrfs. VM images on a
    /// copy-on-write filesystem fragment badly, so the pool directory needs
    /// `chattr +C` BEFORE any image is created — it only affects new files, so
    /// it cannot be applied as an afterthought.
    pub pool_needs_nocow: bool,
    /// How ANOTHER hypervisor reaches this one. Cannot be derived from
    /// `ssh_target`: that is written from the controller's point of view and is
    /// `None` for the machine the tooling runs on, which from a peer's
    /// perspective is a perfectly ordinary remote host.
    pub peer_target: Option<String>,
}

impl Host {
    pub fn local(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ssh_target: None,
            disk_pool: "vmpool".into(),
            pool_needs_nocow: false,
            peer_target: None,
        }
    }
    pub fn remote(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            ssh_target: Some(target.into()),
            ..Self::local(name)
        }
    }
    /// Build from site.yml, matching `hosts.py::_build_hosts`.
    pub fn from_config(name: &str, hv: &crate::config::HypervisorConfig) -> Self {
        Self {
            name: name.to_string(),
            ssh_target: hv.ssh_target.clone(),
            disk_pool: hv.disk_pool.clone(),
            pool_needs_nocow: hv.pool_needs_nocow,
            // `peer_target or ssh_target` — the Python fallback, kept.
            peer_target: hv.peer_target.clone().or_else(|| hv.ssh_target.clone()),
        }
    }
}

/// What a command produced. Mirrors `subprocess.CompletedProcess`.
#[derive(Debug, Clone)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

/// Quote one argument for a POSIX shell, byte-for-byte as Python's
/// `shlex.quote` does.
///
/// This is not "a" quoting function; it must be THAT one. The Rust and Python
/// provisioners have to send identical strings to identical remote shells, and
/// a difference here is invisible until some argument contains a space, a
/// quote, or a newline — which is precisely when it matters and precisely when
/// nobody is watching.
///
/// Python's rule, from `shlex`: empty becomes `''`; a string of only
/// `[a-zA-Z0-9_@%+=:,./-]` is returned unchanged; anything else is wrapped in
/// single quotes with each `'` replaced by `'"'"'`.
pub fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let safe = s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-')
    });
    if safe {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Join an argv into one shell-safe string. Python's `shlex.join`.
pub fn shell_join<S: AsRef<str>>(argv: &[S]) -> String {
    argv.iter()
        .map(|a| shell_quote(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Execute `argv` on `host`. Never uses a shell locally; only the SSH boundary
/// stringifies, and only through [`shell_join`].
///
/// Returns the [`Output`] whatever the exit status — the caller decides whether
/// a non-zero status is fatal, exactly as `check=False` does in the Python.
/// `run_checked` is the `check=True` half.
pub fn run<S: AsRef<str>>(host: &Host, argv: &[S], input: Option<&str>) -> std::io::Result<Output> {
    let mut cmd = match &host.ssh_target {
        None => {
            let mut c = Command::new(argv[0].as_ref());
            for a in &argv[1..] {
                c.arg(a.as_ref());
            }
            c
        }
        Some(target) => {
            let mut c = Command::new("ssh");
            // BatchMode: never prompt. A provisioner that blocks on a password
            // prompt inside a timed wait loop looks like a hung cluster.
            c.arg("-o")
                .arg("BatchMode=yes")
                .arg(target)
                .arg(shell_join(argv));
            c
        }
    };
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    if let Some(text) = input {
        child
            .stdin
            .as_mut()
            .expect("stdin piped above")
            .write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    Ok(Output {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// [`run`], but a non-zero exit is an error carrying both streams — the Python
/// `check=True` path. The message shape is kept because these strings end up in
/// a failed rebuild's scrollback and are the only diagnostic there is.
pub fn run_checked<S: AsRef<str>>(
    host: &Host,
    argv: &[S],
    input: Option<&str>,
) -> anyhow::Result<Output> {
    let out = run(host, argv, input)?;
    if !out.ok() {
        let shown: Vec<&str> = argv.iter().map(|a| a.as_ref()).collect();
        anyhow::bail!(
            "[{}] command failed: {:?}\nstdout: {}\nstderr: {}",
            host.name,
            shown,
            out.stdout,
            out.stderr
        );
    }
    Ok(out)
}

/// Write text to `path` on `host`.
///
/// ⚠️ DOES NOT create parent directories. `provision.py`'s docstring says
/// "creating parent directories" and neither of its branches does so — the
/// local branch is a plain `open(path, "w")` and the remote is `cat > path`,
/// both of which fail if the parent is missing. The behaviour is ported as
/// WRITTEN, not as DOCUMENTED: this port's contract is to build a
/// byte-identical cluster, and quietly adding `mkdir -p` here would be a
/// behaviour change smuggled in under a bug fix. If the directories should be
/// created, that is a change to make in both implementations, deliberately.
///
/// Deliberately NOT routed through [`shell_join`]: that function makes argv
/// survive as LITERAL characters, so it would escape `>` into a plain `>`
/// rather than a redirect. Only the path is quoted, and the redirect is built
/// into the command string — matching the Python exactly, and for the reason
/// its comment gives.
pub fn write_file(host: &Host, path: &str, content: &str) -> anyhow::Result<()> {
    if host.ssh_target.is_none() {
        std::fs::write(path, content)?;
        return Ok(());
    }
    let target = host.ssh_target.as_deref().expect("checked above");
    let remote_cmd = format!("cat > {}", shell_quote(path));

    let mut child = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(target)
        .arg(&remote_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .expect("stdin piped above")
        .write_all(content.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "[{}] write_file failed for {}\nstderr: {}",
            host.name,
            path,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}
