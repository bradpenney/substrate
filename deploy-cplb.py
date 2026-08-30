#!/bin/sh
"exec" "$(cd $(dirname $0); pwd)/.venv/bin/python3" "-u" "$0" "$@"
"""Deploy the control-plane load balancer to both hypervisors (ADR-045).

WHY BOTH HAPROXY AND KEEPALIVED, WHEN A VIP LOOKS LIKE ENOUGH
They solve different halves and neither alone is sufficient:

  HAProxy    DISTRIBUTES  — spreads connections across every controller
  keepalived AVAILABLE    — floats one address so HAProxy has a stable home

The distributing half is the one that fixes konnectivity. Agents are told how
many servers exist and try to hold one connection to each, discovering them by
dialling the same address repeatedly. A VRRP virtual IP is held by exactly ONE
node at a time, so every dial returns the same server and the agent discards the
rest as duplicates — the `duplicate server connection attempt` loop that left
four of five API servers unable to reach the pod network. k0s issue #5503 is
this exact configuration failing. A VIP gives failover; this needs distribution.

WHY ON THE HYPERVISORS AND NOT IN THE CLUSTER
The thing that makes the control plane reachable must not depend on the control
plane. Same rule that put auto-roll on a hypervisor and ruled out an in-cluster
registry and secret store.

Usage:
    ./deploy-cplb.py            # dry run: render and print, change nothing
    ./deploy-cplb.py --apply
"""

import argparse
import subprocess
import sys

import siteconfig

CFG = siteconfig.load()
CP = CFG["control_plane"]
VIP = CP["vip"]
ADMIN = CFG["admin_user"]
BRIDGE = CFG["network"]["bridge"]

# 6443 API · 8132 konnectivity · 9443 controller join API.
# All three must be balanced: konnectivity is what was broken, but a VIP that
# only fronts 6443 leaves joins pinned to one controller as well.
PORTS = [("k8s-api", 6443), ("konnectivity", 8132), ("k0s-join", 9443)]


def controllers() -> list:
    """Every controller as (name, ip), sorted by address.

    Sorted so the rendered config is stable: an unordered dict would produce a
    different file on every run and make a real change indistinguishable from
    reordering in a diff."""
    return sorted(((n, c["ip"]) for n, c in CFG["nodes"].items()), key=lambda x: x[1])


def haproxy_cfg() -> str:
    """Render haproxy.cfg: one backend entry per controller.

    konnectivity needs a connection per SERVER, which a VRRP virtual IP cannot
    provide -- that is failover, not distribution."""
    out = [
        "# Managed by substrate deploy-cplb.py — do not edit by hand.",
        "global",
        # `warning` caps the log at warning-and-MORE-severe, which drops the
        # per-request access log (info) while keeping every state change.
        #
        # Note what this does NOT do: "Server X is DOWN" is alert and "backend
        # has no server available" is emerg — both more severe than warning, so
        # both still log. That is correct; they are real events. They reach the
        # terminal because journald walls emerg by default, which is a journald
        # setting, not a haproxy one.
        "    log /dev/log local0 warning",
        "    maxconn 4096",
        "    daemon",
        "",
        "defaults",
        "    mode tcp",
        "    log global",
        "    option tcplog",
        "    timeout connect 5s",
        # Long client/server timeouts are REQUIRED, not tuning. konnectivity
        # agents hold persistent gRPC tunnels and kubectl watches are
        # long-lived; a short timeout silently severs them and surfaces as
        # random reconnects rather than as a proxy problem.
        "    timeout client  4h",
        "    timeout server  4h",
        "    retries 2",
        "",
    ]
    for name, port in PORTS:
        out += [
            f"frontend {name}",
            f"    bind {VIP}:{port}",
            f"    default_backend {name}-be",
            "",
            f"backend {name}-be",
            # Round-robin, NOT source-hash. Source-hash would pin each agent to
            # one controller and reproduce the exact bug this exists to fix.
            "    balance roundrobin",
            "    option tcp-check",
            "",
        ]
        for node, ip in controllers():
            out.append(f"    server {node} {ip}:{port} check inter 3s fall 3 rise 2")
        out.append("")
    return "\n".join(out)


def keepalived_cfg(host: str) -> str:
    """Render keepalived.conf for one hypervisor.

    Differs per host: the priority decides which node holds the VIP, so identical
    config on both would leave them contesting it."""
    prio = (CP.get("priorities") or {}).get(host, 100)
    state = (
        "MASTER"
        if prio == max((CP.get("priorities") or {100: 100}).values())
        else "BACKUP"
    )
    return f"""# Managed by substrate deploy-cplb.py — do not edit by hand.
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
    script "/usr/bin/killall -0 haproxy"
    interval 2
    weight -40
    fall 2
    rise 2
}}

vrrp_instance CPLB {{
    state {state}
    interface {BRIDGE}
    virtual_router_id {CP['vrrp_router_id']}
    priority {prio}
    advert_int 1
    authentication {{
        auth_type PASS
        auth_pass {CP['auth_pass']}
    }}
    virtual_ipaddress {{
        {VIP}/24
    }}
    track_script {{
        chk_haproxy
    }}
}}
"""


def remote(host: str) -> list:
    """The ssh prefix for reaching a host, or an empty list when it is local.

    Returning a list lets callers build one command that works either way."""
    tgt = CFG["hypervisors"][host].get("ssh_target")
    if not tgt:
        return []
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", tgt]


def run(host: str, script: str, apply: bool) -> int:
    """Install on one host, returning the exit status.

    Returns 0 WITHOUT executing when apply is False, so a dry run cannot change
    a host even by accident."""
    cmd = remote(host) + ["sudo", "bash", "-s"]
    if not apply:
        return 0
    p = subprocess.run(cmd, input=script, text=True, check=False)
    return p.returncode


def install_script(host: str) -> str:
    """The full installer for one host, with both configs embedded.

    Embedded rather than copied so the whole install is one stdin stream: no
    temporary files to clean up, and nothing left behind if it fails midway."""
    hc = haproxy_cfg().replace("'", "'\\''")
    kc = keepalived_cfg(host).replace("'", "'\\''")
    return f"""set -euo pipefail
dnf install -y haproxy keepalived psmisc >/dev/null 2>&1 || \
  apt-get install -y haproxy keepalived psmisc >/dev/null 2>&1

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
"""


def main() -> int:
    """Print the plan; install only when --apply is given.

    Dry run by default. This reconfigures the control-plane load balancer, and
    the failure mode of getting it wrong is losing the API server."""
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--apply", action="store_true", help="actually install (default: dry run)"
    )
    args = ap.parse_args()

    print("=== control-plane load balancer ===\n")
    print(f"  VIP        : {VIP}  on {BRIDGE}")
    print(f"  balanced   : {', '.join(f'{n}/{p}' for n, p in PORTS)}")
    print("  backends   :")
    for node, ip in controllers():
        print(f"      {node:<8} {ip}")
    print("  hypervisors:")
    for h in CFG["hypervisors"]:
        prio = (CP.get("priorities") or {}).get(h, 100)
        print(
            f"      {h:<8} priority {prio}"
            f"{'   <- holds the VIP by default' if prio == max((CP.get('priorities') or {}).values()) else ''}"
        )

    if not args.apply:
        print("\n--- haproxy.cfg ---")
        print(haproxy_cfg())
        print("\nDRY RUN — nothing installed. Re-run with --apply.")
        return 0

    rc = 0
    for h in CFG["hypervisors"]:
        print(f"\n=== installing on {h} ===")
        r = run(h, install_script(h), True)
        if r != 0:
            print(f"  FAILED on {h} (exit {r})", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
