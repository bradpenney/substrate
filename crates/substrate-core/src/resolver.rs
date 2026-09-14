//! Deploy the LAN's recursive resolvers to both hypervisors (ADR-182).
//!
//! WHY THIS EXISTS. The 2026-09-11 wipe took the house offline: the router's
//! resolvers were the authoritative pair IN the cluster, so destroying the
//! cluster removed the resolvers every device used — and the resolvers the
//! hypervisors needed to pull the images that would rebuild the pair. That is
//! the cluster in its own bootstrap dependency chain.
//!
//! AUTHORITATIVE AND RECURSIVE ARE DIFFERENT JOBS, and only one of them may
//! live on the cluster. The pair stays where it is, authoritative for the
//! estate's zone. Recursion moves BELOW the cluster: `unbound` on each
//! hypervisor, which is up by definition while the cluster is being rebuilt.
//! The estate's zone is forwarded to the pair with `forward-first`, so when
//! the pair is absent the zone degrades to its public answers instead of to no
//! answers; everything else goes to public resolvers over TLS.
//!
//! WHAT THE INSTALLER PROVES BEFORE IT TOUCHES THE HOST'S OWN RESOLVER. The
//! zone is answered by the pair (the SOA matches), a public name resolves over
//! TLS, and — the property the whole thing exists for — a forwarder that never
//! answers falls back to public answers. Only then does the hypervisor's own
//! resolver list switch to the hypervisors. A resolver that failed any of
//! those would otherwise be adopted by the machine you are typing on.
//!
//! WHY THE HOST'S OWN LIST IS `network.dns_servers`. The nodes resolve through
//! that list (it is rendered into every node's network file), and after this
//! is deployed it names the hypervisors. One list, three consumers — nodes,
//! hypervisors, and the router's DHCP clients — and no second copy to drift.

use crate::config::SiteConfig;
use anyhow::{Context, Result, bail};

/// Everything the renderer needs, pulled out of `site.yml` and validated once.
pub struct Resolver<'a> {
    pub zone: &'a str,
    pub forwarders: &'a [String],
    pub upstreams: &'a [String],
    pub bridge: &'a str,
    /// The list every hypervisor adopts as its own resolvers.
    pub resolvers: &'a [String],
    pub hypervisors: Vec<(&'a str, Option<&'a str>)>,
}

/// An upstream must carry the name to verify its certificate against. TLS to
/// a bare address is plaintext with extra steps.
pub fn check_upstream(u: &str) -> Result<()> {
    let (addr, auth) = u
        .split_once('#')
        .with_context(|| format!("dns.upstreams entry {u:?} is not addr@port#authname"))?;
    if !addr.contains('@') || auth.is_empty() {
        bail!("dns.upstreams entry {u:?} is not addr@port#authname");
    }
    Ok(())
}

impl<'a> Resolver<'a> {
    pub fn from_site(cfg: &'a SiteConfig) -> Result<Self> {
        let zone = cfg
            .dns
            .domain
            .as_deref()
            .context("site.yml dns.domain is required")?;
        if cfg.dns.forwarders.is_empty() {
            bail!("site.yml dns.forwarders is required: the authoritative pair's addresses");
        }
        if cfg.dns.upstreams.is_empty() {
            bail!("site.yml dns.upstreams is required: public resolvers as addr@853#authname");
        }
        for u in &cfg.dns.upstreams {
            check_upstream(u)?;
        }
        Ok(Self {
            zone,
            forwarders: &cfg.dns.forwarders,
            upstreams: &cfg.dns.upstreams,
            bridge: &cfg.network.bridge,
            resolvers: &cfg.network.dns_servers,
            hypervisors: cfg
                .hypervisors
                .iter()
                .map(|(n, h)| (n.as_str(), h.ssh_target.as_deref()))
                .collect(),
        })
    }

    /// The `server:` drop-in. `__IP__` and `__LAN__` are filled in ON the host
    /// from the bridge's address, so one rendering serves both hypervisors and
    /// no hypervisor address has to be declared twice.
    pub fn server_conf(&self) -> String {
        format!(
            "# Managed by substrate deploy-resolver — do not edit by hand.
# Listens on loopback and on the bridge the nodes sit on. Naming an interface
# replaces unbound's loopback-only default, so loopback is named too.
interface: 127.0.0.1
interface: __IP__
access-control: 127.0.0.0/8 allow
access-control: __LAN__ allow
# The estate's zone answers with LAN addresses; both settings keep those
# answers from being treated as a rebinding attack or a DNSSEC failure should
# the public zone ever be signed.
private-domain: \"{zone}\"
domain-insecure: \"{zone}\"
# Verifies the public resolvers' certificates for DNS over TLS.
tls-cert-bundle: \"/etc/pki/tls/certs/ca-bundle.crt\"
# This LAN has no IPv6 route. Left on, iterative fallback tries unreachable
# v6 transports first and the fallback this exists for gets slow.
do-ip6: no
# A SERVFAIL is the symptom of the forwarders being gone; log it.
log-servfail: yes
",
            zone = self.zone
        )
    }

    /// The forward zones. The estate's zone goes to the pair, forward-first;
    /// everything else to the public resolvers over TLS.
    pub fn forward_conf(&self) -> String {
        let mut s = String::from(
            "# Managed by substrate deploy-resolver — do not edit by hand.
# The estate's zone: the authoritative pair in the cluster. forward-first is
# the property this file exists for — when the pair is gone, unbound recurses
# publicly for the zone instead of failing, so the household keeps DNS while
# the cluster is rebuilt.
forward-zone:
",
        );
        s.push_str(&format!("    name: \"{}\"\n", self.zone));
        for f in self.forwarders {
            s.push_str(&format!("    forward-addr: {f}\n"));
        }
        s.push_str("    forward-first: yes\n");
        s.push_str(
            "
# Everything else: public resolvers, over TLS, certificate verified against
# the name after '#'.
forward-zone:
    name: \".\"
    forward-tls-upstream: yes
",
        );
        for u in self.upstreams {
            s.push_str(&format!("    forward-addr: {u}\n"));
        }
        s
    }

    /// The whole installer for one host as a single stdin stream, like
    /// deploy-cplb: nothing staged, nothing left behind if it fails midway.
    ///
    /// Order matters and is the point: install, configure, start, PROVE, and
    /// only then adopt. Every proof exits non-zero before `nmcli` runs.
    pub fn install_script(&self) -> String {
        let sc = self.server_conf().replace('\'', "'\\''");
        let fc = self.forward_conf().replace('\'', "'\\''");
        let forwarders = self.forwarders.join(" ");
        let resolvers = self.resolvers.join(" ");
        let zone = self.zone;
        let bridge = self.bridge;
        format!(
            "set -euo pipefail
dnf install -y unbound bind-utils >/dev/null

# Fedora's unbound.conf includes two drop-in directories; this relies on both
# and refuses to guess if the packaging changes.
CONF=/etc/unbound/unbound.conf
grep -qE '^[[:space:]]*include:[[:space:]]*\"?/etc/unbound/local\\.d/\\*\\.conf' \"$CONF\" || {{ echo \"  $CONF does not include local.d/ — refusing to guess\"; exit 1; }}
grep -qE '^[[:space:]]*include:[[:space:]]*\"?/etc/unbound/conf\\.d/\\*\\.conf' \"$CONF\"  || {{ echo \"  $CONF does not include conf.d/ — refusing to guess\"; exit 1; }}

# This host's address on the bridge, and the LAN it implies. Computed here so
# one rendering serves both hypervisors. Pure bash: not every host has ipcalc.
BRIDGE='{bridge}'
CIDR=$(ip -4 -o addr show dev \"$BRIDGE\" scope global | awk '{{print $4}}' | head -n1)
[ -n \"$CIDR\" ] || {{ echo \"  no IPv4 address on $BRIDGE\"; exit 1; }}
IP=${{CIDR%/*}}; PREFIX=${{CIDR#*/}}
IFS=. read -r a b c d <<<\"$IP\"
n=$(( (a<<24)|(b<<16)|(c<<8)|d )); m=$(( (0xFFFFFFFF << (32-PREFIX)) & 0xFFFFFFFF )); net=$(( n & m ))
LAN=\"$(( net>>24 )).$(( (net>>16)&255 )).$(( (net>>8)&255 )).$(( net&255 ))/$PREFIX\"

printf '%s' '{sc}' | sed \"s|__IP__|$IP|; s|__LAN__|$LAN|\" > /etc/unbound/local.d/substrate.conf
printf '%s' '{fc}' > /etc/unbound/conf.d/substrate.conf
rm -f /etc/unbound/conf.d/substrate-drill.conf
unbound-checkconf >/dev/null

if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  ZONE=$(firewall-cmd --get-zone-of-interface \"$BRIDGE\" 2>/dev/null || firewall-cmd --get-default-zone)
  firewall-cmd --quiet --permanent --zone=\"$ZONE\" --add-service=dns || true
  firewall-cmd --quiet --reload || true
fi

systemctl enable --now unbound >/dev/null
systemctl restart unbound
sleep 1
echo \"  unbound:   $(systemctl is-active unbound) on $IP for $LAN\"

# --- proofs, all before this host's own resolver is touched ---------------
probe() {{ dig +short +time=5 +tries=1 @127.0.0.1 \"$@\"; }}

# 1. The zone is answered by the pair: the SOA we serve is the one they serve.
ours=$(probe SOA '{zone}' | awk '{{print $1}}')
theirs=''
for f in {forwarders}; do
  theirs=$(dig +short +time=2 +tries=1 @\"$f\" SOA '{zone}' | awk '{{print $1}}')
  [ -n \"$theirs\" ] && break
done
[ -n \"$theirs\" ] || {{ echo \"  no forwarder answered for {zone} — is the pair up?\"; exit 1; }}
[ \"$ours\" = \"$theirs\" ] || {{ echo \"  zone is not coming from the pair: resolver SOA '$ours' vs pair SOA '$theirs'\"; exit 1; }}
echo \"  zone:      {zone} answered by the pair ($theirs)\"

# 2. A public name resolves over TLS.
[ -n \"$(probe A github.com)\" ] || {{ echo \"  public resolution over TLS failed\"; exit 1; }}
echo \"  public:    github.com resolves over TLS\"

# 3. THE DRILL. A forwarder that never answers must degrade to public answers.
#    TEST-NET-1 is unroutable, so this is the slowest case: timeouts, not a
#    refusal. If this fails, forward-first is not doing what ADR-182 needs.
cat > /etc/unbound/conf.d/substrate-drill.conf <<'DRILL'
forward-zone:
    name: \"example.com\"
    forward-addr: 192.0.2.1
    forward-first: yes
DRILL
systemctl reload unbound
t0=$(date +%s)
ans=$(dig +short +time=25 +tries=1 @127.0.0.1 A example.com || true)
t1=$(date +%s)
rm -f /etc/unbound/conf.d/substrate-drill.conf
systemctl reload unbound
[ -n \"$ans\" ] || {{ echo \"  DRILL FAILED: forward-first did not fall back to public answers\"; exit 1; }}
echo \"  drill:     dead forwarder fell back to public answers in $((t1-t0))s\"

# --- adopt: this host resolves through the same list the nodes will --------
# Persistent in the profile; immediate via resolved. Deliberately NOT a device
# reapply: the control-plane VIP sits on this bridge as an externally added
# address, and NetworkManager refuses to reapply a device modified behind its back.
CON=$(nmcli -g GENERAL.CONNECTION device show \"$BRIDGE\")
nmcli con mod \"$CON\" ipv4.dns '{resolvers}' ipv4.ignore-auto-dns yes
resolvectl dns \"$BRIDGE\" {resolvers}
resolvectl flush-caches
resolvectl query github.com >/dev/null || {{ echo \"  host cannot resolve through the new list — check resolvectl status\"; exit 1; }}
echo \"  host:      resolves via $(resolvectl status \"$BRIDGE\" | awk '/DNS Servers/{{sub(/.*: /,\"\"); print}}')\"
"
        )
    }

    pub fn print_plan(&self) {
        println!("=== recursive resolvers (ADR-182) ===\n");
        println!("  zone       : {}  -> forwarded, forward-first", self.zone);
        for f in self.forwarders {
            println!("      {f}");
        }
        println!("  upstreams  : everything else, over TLS");
        for u in self.upstreams {
            println!("      {u}");
        }
        println!(
            "  listens on : loopback + the {} address of each hypervisor",
            self.bridge
        );
        println!("  adopts     : {}", self.resolvers.join(", "));
        println!("  hypervisors:");
        for (h, _) in &self.hypervisors {
            println!("      {h}");
        }
    }

    /// Install on every hypervisor. Escalation happens REMOTELY (`ssh … sudo`),
    /// never locally.
    pub fn apply(&self) -> i32 {
        let mut rc = 0;
        for (h, target) in &self.hypervisors {
            println!("\n=== installing on {h} ===");
            let r = crate::cplb::run_installer(*target, &self.install_script());
            if r != 0 {
                eprintln!("  FAILED on {h} (exit {r})");
                rc = 1;
            }
        }
        rc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver<'a>(
        forwarders: &'a [String],
        upstreams: &'a [String],
        resolvers: &'a [String],
    ) -> Resolver<'a> {
        Resolver {
            zone: "example.com",
            forwarders,
            upstreams,
            bridge: "br0",
            resolvers,
            hypervisors: vec![("hvA", None), ("hvB", Some("user@hvb"))],
        }
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn estate_zone_is_forward_first_and_the_rest_is_tls() {
        let f = strings(&["198.51.100.7", "198.51.100.8"]);
        let u = strings(&["1.1.1.1@853#cloudflare-dns.com"]);
        let r = strings(&["198.51.100.1"]);
        let conf = resolver(&f, &u, &r).forward_conf();
        let zone_block = conf.split("forward-zone:").nth(1).unwrap();
        assert!(zone_block.contains("name: \"example.com\""));
        assert!(zone_block.contains("forward-addr: 198.51.100.7"));
        assert!(zone_block.contains("forward-addr: 198.51.100.8"));
        assert!(
            zone_block.contains("forward-first: yes"),
            "without forward-first the pair's absence is an outage again"
        );
        let root_block = conf.split("forward-zone:").nth(2).unwrap();
        assert!(root_block.contains("name: \".\""));
        assert!(root_block.contains("forward-tls-upstream: yes"));
        assert!(root_block.contains("1.1.1.1@853#cloudflare-dns.com"));
        assert!(
            !root_block.contains("forward-first"),
            "public resolution must not silently fall back to plaintext"
        );
    }

    #[test]
    fn server_conf_names_loopback_and_leaves_the_host_address_to_the_host() {
        let f = strings(&["198.51.100.7"]);
        let u = strings(&["1.1.1.1@853#cloudflare-dns.com"]);
        let r = strings(&["198.51.100.1"]);
        let conf = resolver(&f, &u, &r).server_conf();
        assert!(
            conf.contains("interface: 127.0.0.1"),
            "naming an interface drops the loopback default"
        );
        assert!(conf.contains("interface: __IP__"));
        assert!(conf.contains("access-control: __LAN__ allow"));
        assert!(conf.contains("private-domain: \"example.com\""));
        assert!(conf.contains("tls-cert-bundle:"));
    }

    #[test]
    fn installer_proves_before_it_adopts() {
        let f = strings(&["198.51.100.7"]);
        let u = strings(&["1.1.1.1@853#cloudflare-dns.com"]);
        let r = strings(&["198.51.100.1", "198.51.100.2"]);
        let s = resolver(&f, &u, &r).install_script();
        let drill = s.find("substrate-drill.conf").unwrap();
        let soa = s.find("SOA 'example.com'").unwrap();
        let adopt = s.find("nmcli con mod").unwrap();
        assert!(
            soa < adopt && drill < adopt,
            "every proof runs before the host's resolver changes"
        );
        assert!(s.contains("ipv4.dns '198.51.100.1 198.51.100.2'"));
        assert!(
            !s.contains("nmcli device reapply"),
            "reapply refuses a bridge carrying the VIP"
        );
        assert!(s.contains("set -euo pipefail"));
    }

    #[test]
    fn upstreams_without_an_auth_name_are_refused() {
        assert!(check_upstream("1.1.1.1@853#cloudflare-dns.com").is_ok());
        assert!(
            check_upstream("1.1.1.1@853").is_err(),
            "nothing to verify the certificate against"
        );
        assert!(
            check_upstream("1.1.1.1#cloudflare-dns.com").is_err(),
            "no port"
        );
        assert!(check_upstream("1.1.1.1@853#").is_err());
    }
}
