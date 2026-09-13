//! Deploy the control-plane load balancer to both hypervisors (ADR-045).
//!
//! Ported from `deploy-cplb.py`.
//!
//! WHY BOTH HAPROXY AND KEEPALIVED, WHEN A VIP LOOKS LIKE ENOUGH. They solve
//! different halves: HAProxy DISTRIBUTES connections across every controller;
//! keepalived floats one address so HAProxy has a stable home. The
//! distributing half is the one that fixes konnectivity — agents dial the same
//! address repeatedly expecting to reach every server, and a VRRP VIP held by
//! ONE node returns the same server every time (k0s issue #5503). A VIP gives
//! failover; this needs distribution.
//!
//! WHY ON THE HYPERVISORS AND NOT IN THE CLUSTER. The thing that makes the
//! control plane reachable must not depend on the control plane.

use crate::config::SiteConfig;
use anyhow::{Context, Result};

/// 6443 API · 8132 konnectivity · 9443 controller join API. All three must
/// be balanced: a VIP that only fronts 6443 leaves joins pinned to one
/// controller as well.
pub const PORTS: &[(&str, u16)] = &[
    ("k8s-api", 6443),
    ("konnectivity", 8132),
    ("k0s-join", 9443),
];

pub struct Cplb<'a> {
    cfg: &'a SiteConfig,
    vip: &'a str,
    router_id: u32,
    auth_pass: &'a str,
}

impl<'a> Cplb<'a> {
    pub fn new(cfg: &'a SiteConfig) -> Result<Self> {
        let cp = &cfg.control_plane;
        Ok(Self {
            cfg,
            vip: cp
                .vip
                .as_deref()
                .context("site.yml control_plane.vip is required")?,
            router_id: cp
                .vrrp_router_id
                .context("site.yml control_plane.vrrp_router_id is required")?,
            auth_pass: cp
                .auth_pass
                .as_deref()
                .context("site.yml control_plane.auth_pass is required")?,
        })
    }

    /// Every controller as (name, ip), sorted by ADDRESS so the rendered config
    /// is stable across runs — a real change must be distinguishable from
    /// reordering in a diff.
    pub fn controllers(&self) -> Vec<(&str, &str)> {
        let mut v: Vec<(&str, &str)> = self
            .cfg
            .nodes
            .iter()
            .map(|(n, c)| (n.as_str(), c.ip.as_str()))
            .collect();
        v.sort_by(|a, b| a.1.cmp(b.1));
        v
    }

    fn priority(&self, host: &str) -> i32 {
        self.cfg
            .control_plane
            .priorities
            .get(host)
            .copied()
            .unwrap_or(100)
    }

    fn max_priority(&self) -> i32 {
        self.cfg
            .control_plane
            .priorities
            .values()
            .copied()
            .max()
            .unwrap_or(100)
    }

    /// haproxy.cfg: one backend entry per controller. Round-robin, NOT
    /// source-hash — source-hash would pin each agent to one controller and
    /// reproduce the exact bug this exists to fix.
    pub fn haproxy_cfg(&self) -> String {
        let mut out: Vec<String> = vec![
            "# Managed by substrate deploy-cplb.py — do not edit by hand.".into(),
            "global".into(),
            // `warning` drops the per-request access log while keeping every
            // state change; "Server X is DOWN" (alert) still logs.
            "    log /dev/log local0 warning".into(),
            "    maxconn 4096".into(),
            "    daemon".into(),
            "".into(),
            "defaults".into(),
            "    mode tcp".into(),
            "    log global".into(),
            "    option tcplog".into(),
            "    timeout connect 5s".into(),
            // Long client/server timeouts are REQUIRED: konnectivity holds
            // persistent gRPC tunnels and kubectl watches are long-lived.
            "    timeout client  4h".into(),
            "    timeout server  4h".into(),
            "    retries 2".into(),
            "".into(),
        ];
        for (name, port) in PORTS {
            out.push(format!("frontend {name}"));
            out.push(format!("    bind {}:{port}", self.vip));
            out.push(format!("    default_backend {name}-be"));
            out.push(String::new());
            out.push(format!("backend {name}-be"));
            out.push("    balance roundrobin".into());
            out.push("    option tcp-check".into());
            out.push(String::new());
            for (node, ip) in self.controllers() {
                out.push(format!(
                    "    server {node} {ip}:{port} check inter 3s fall 3 rise 2"
                ));
            }
            out.push(String::new());
        }
        out.join("\n")
    }

    /// keepalived.conf for ONE hypervisor: the priority decides who holds the
    /// VIP, so identical config on both would leave them contesting it.
    pub fn keepalived_cfg(&self, host: &str) -> String {
        let prio = self.priority(host);
        let state = if prio == self.max_priority() {
            "MASTER"
        } else {
            "BACKUP"
        };
        format!(
            "# Managed by substrate deploy-cplb.py — do not edit by hand.
global_defs {{
    enable_script_security
    script_user root
}}

# Release the VIP if HAProxy is not actually serving.
#
# Without this, keepalived happily holds the address while the thing that
# answers on it is dead — a VIP that points at nothing is worse than failing
# over, because it looks healthy.
vrrp_script chk_haproxy {{
    script \"/usr/bin/killall -0 haproxy\"
    interval 2
    weight -40
    fall 2
    rise 2
}}

vrrp_instance CPLB {{
    state {state}
    interface {bridge}
    virtual_router_id {router_id}
    priority {prio}
    advert_int 1
    authentication {{
        auth_type PASS
        auth_pass {auth_pass}
    }}
    virtual_ipaddress {{
        {vip}/24
    }}
    track_script {{
        chk_haproxy
    }}
}}
",
            bridge = self.cfg.network.bridge,
            router_id = self.router_id,
            auth_pass = self.auth_pass,
            vip = self.vip,
        )
    }

    /// The full installer for one host, both configs embedded, so the whole
    /// install is one stdin stream: no temp files, nothing left behind if it
    /// fails midway.
    pub fn install_script(&self, host: &str) -> String {
        let hc = self.haproxy_cfg().replace('\'', "'\\''");
        let kc = self.keepalived_cfg(host).replace('\'', "'\\''");
        // The Python source shows `|| \` + newline here, but inside its
        // triple-quoted f-string that is a PYTHON line continuation — the
        // shipped script has one line with three spaces. Reproduced as shipped.
        format!(
            "set -euo pipefail
dnf install -y haproxy keepalived psmisc >/dev/null 2>&1 ||   apt-get install -y haproxy keepalived psmisc >/dev/null 2>&1

# HAProxy binds the VIP on BOTH hypervisors, but only one holds it at a time.
# Without this sysctl the backup node cannot bind an address it does not own
# and haproxy fails to start there — so failover would arrive at a host with
# no proxy running.
echo 'net.ipv4.ip_nonlocal_bind = 1' > /etc/sysctl.d/99-cplb.conf
sysctl -q -w net.ipv4.ip_nonlocal_bind=1

printf '%s\\n' '{hc}' > /etc/haproxy/haproxy.cfg
printf '%s\\n' '{kc}' > /etc/keepalived/keepalived.conf

if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  for p in 6443 8132 9443; do firewall-cmd --quiet --permanent --add-port=$p/tcp || true; done
  # VRRP is IP protocol 112 and multicast — keepalived peers cannot see each
  # other without it, and both hosts then believe they are MASTER.
  firewall-cmd --quiet --permanent --add-protocol=vrrp || true
  firewall-cmd --quiet --reload || true
fi

setsebool -P haproxy_connect_any 1 2>/dev/null || true

systemctl enable --now haproxy keepalived
# reload, not restart: haproxy reloads config without dropping established
# connections. Restarting the load balancer that cluster nodes are joining
# through is a self-inflicted outage.
systemctl reload haproxy 2>/dev/null || systemctl restart haproxy
systemctl reload-or-restart keepalived
sleep 2
systemctl is-active haproxy keepalived
"
        )
    }

    /// The plan, as `deploy-cplb.py` prints it before either mode.
    pub fn print_plan(&self) {
        println!("=== control-plane load balancer ===\n");
        println!(
            "  VIP        : {}  on {}",
            self.vip, self.cfg.network.bridge
        );
        println!(
            "  balanced   : {}",
            PORTS
                .iter()
                .map(|(n, p)| format!("{n}/{p}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("  backends   :");
        for (node, ip) in self.controllers() {
            println!("      {node:<8} {ip}");
        }
        println!("  hypervisors:");
        let max = self.max_priority();
        for h in self.cfg.hypervisors.keys() {
            let prio = self.priority(h);
            let holds = if prio == max {
                "   <- holds the VIP by default"
            } else {
                ""
            };
            println!("      {h:<8} priority {prio}{holds}");
        }
    }

    /// Install on every hypervisor. Escalation happens REMOTELY (`ssh … sudo`),
    /// never locally. Returns the process exit code the Python returned.
    pub fn apply(&self) -> i32 {
        let mut rc = 0;
        for (h, hv) in &self.cfg.hypervisors {
            println!("\n=== installing on {h} ===");
            let r = run_installer(hv.ssh_target.as_deref(), &self.install_script(h));
            if r != 0 {
                eprintln!("  FAILED on {h} (exit {r})");
                rc = 1;
            }
        }
        rc
    }
}

/// `ssh -o BatchMode=yes -o StrictHostKeyChecking=no <target> sudo bash -s`
/// (or `sudo bash -s` locally) with the script on stdin; output inherits the
/// terminal, exactly as the Python's un-captured subprocess did.
pub fn run_installer(ssh_target: Option<&str>, script: &str) -> i32 {
    use std::io::Write as _;
    let mut cmd = match ssh_target {
        Some(t) => {
            let mut c = std::process::Command::new("ssh");
            c.args([
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                t,
                "sudo",
                "bash",
                "-s",
            ]);
            c
        }
        None => {
            let mut c = std::process::Command::new("sudo");
            c.args(["bash", "-s"]);
            c
        }
    };
    cmd.stdin(std::process::Stdio::piped());
    let Ok(mut child) = cmd.spawn() else {
        return 127;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes());
    }
    child.wait().map_or(1, |s| s.code().unwrap_or(1))
}
