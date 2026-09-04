#!/bin/sh
"exec" "$(cd $(dirname $0); pwd)/.venv/bin/python3" "-u" "$0" "$@"
"""Install the host-tier observability stack onto the hypervisors (ADR-098).

WHY THE HOST AND NOT THE CLUSTER
The metrics store must survive a cluster rebuild and be able to WATCH one
happen. Something running inside that cluster can do neither, and the fleet is
about to be rebuilt repeatedly to validate the Rust implementation against the
Python and Ansible ones.

WHAT GOES WHERE
  every hypervisor      node_exporter      node metrics are useful with or
                                           without a store to send them to
  observability.host    victoria-metrics   the store, and later Grafana

WHY BINARIES ARE FETCHED ON THE HOST RATHER THAN PUSHED
Same reason the flux-operator manifest is: pushing ~25 MB per component through
an ssh pipe is slower and no safer. Pinned by version AND verified by sha256
from versions.yml, so a rebuild months from now installs the same bytes — the
checksum is what guarantees that, not the tag.

WHY ONE PRIVILEGED INSTALLER (ADR-078)
Staging happens as the ordinary user; exactly one `sudo` runs the installer.
sudo 1.9 uses per-tty tickets, so ~15 separate privileged calls cannot
authenticate against a password-protected host — that is why this shape exists
and not because it is tidier.

Usage — NOT under sudo; it escalates once, internally:
    ./deploy-observability.py            # every hypervisor
    ./deploy-observability.py --dry-run  # print the plan and the installer
"""

import argparse
import hashlib
import os
import shlex
import subprocess
import sys
from pathlib import Path

import deploy_updates
import hosts
import siteconfig

REPO = Path(__file__).resolve().parent
UNIT_DIR = REPO / "systemd" / "observability"

# The docker bridge gateway. Grafana binds this and nothing else, so it is
# unreachable from the LAN and the internet except through the edge. Becomes
# 127.0.0.1 when the edge moves to a native systemd Traefik — at which point
# two host processes talk over loopback and docker leaves this path entirely.
GRAFANA_BIND = "172.18.0.1"


def peer_addresses(cfg) -> list[str]:
    """Every hypervisor's address, as its PEERS would reach it.

    Used to allow-list the node_exporter port. `ssh_target` is written from the
    controller's point of view and is None for the local machine, which from
    another host is an ordinary remote — `peer_target` is the field that always
    carries a reachable address.
    """
    found = []
    for hv in cfg.hypervisors.values():
        target = hv.peer_target or hv.ssh_target
        if target:
            found.append(target.rpartition("@")[2])
    return sorted(set(found))


def peer_targets_by_name(cfg) -> list[tuple[str, str]]:
    """Each hypervisor as (name, address), sorted by name.

    `peer_addresses` deliberately discards the name, because an allow-list only
    needs the address. A scrape target needs both: the address to reach it and
    the name to label it, so that dashboards can identify a host without
    printing where it lives.
    """
    found = {}
    for name, hv in cfg.hypervisors.items():
        target = hv.peer_target or hv.ssh_target
        if target:
            found[name] = target.rpartition("@")[2]
    return sorted(found.items())


def node_addresses(cfg) -> list[str]:
    """Every k0s node's address.

    Distinct from `peer_addresses`: log ingest is pushed FROM inside the cluster,
    so 9428 must admit the nodes — while 9100 admits only the hypervisors that
    scrape it. Two ports, two allow-lists, because they are reached by different
    things. One combined list would open each port to callers that have no
    business on it.
    """
    return sorted({n.ip for n in cfg.nodes.values()})


def components_for(cfg, host_name: str) -> list[str]:
    """Which components this host installs.

    node_exporter everywhere; the store only on the nominated host. Returning a
    LIST rather than branching inside the installer keeps the decision here, in
    Python, where it can be tested.
    """
    which = ["node_exporter"]
    if cfg.observability.host == host_name:
        # The datasource plugin is tied to grafana, not to victoria_logs: it is
        # the piece that lets GRAFANA read VictoriaLogs, and it installs into
        # Grafana's data directory. A host storing logs without serving
        # dashboards has no use for it.
        which += [
            "victoria_metrics",
            "victoria_logs",
            "grafana",
            "victoria_logs_datasource",
        ]
    return which


def scrape_config(cfg) -> bytes:
    """VictoriaMetrics' own scrape config: the hypervisors, directly.

    This is the path that survives everything. It does NOT scrape the cluster —
    a host scraper can reach node IPs but not pod IPs, so cluster-internal
    metrics arrive by remote_write from a vmagent running inside (ADR-098).
    """
    # One static_config PER HOST, so each target can carry its own `host` label.
    # A single block listing every address can only apply one set of labels, and
    # `instance` is then the only thing distinguishing two hypervisors — which
    # means an address, and an address is the one thing that must not end up in
    # a committed dashboard. The cluster tier gets a readable `node` label from
    # the in-cluster vmagent for free; this is the hypervisor equivalent.
    blocks = "\n".join(f"""      - targets: [{address}:9100]
        labels:
          tier: hypervisor
          host: {name}""" for name, address in peer_targets_by_name(cfg))
    return f"""# Generated by deploy-observability.py — do not edit by hand.
#
# Only the hypervisors. Cluster metrics arrive by remote_write from the
# in-cluster vmagent, because a scraper on the host cannot reach pod IPs.
global:
  scrape_interval: 30s

scrape_configs:
  - job_name: hypervisors
    static_configs:
{blocks}
""".encode()


INSTALLER = """#!/bin/bash
# Generated by deploy-observability.py. Everything privileged happens here, once.
set -euo pipefail
umask 022
HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP=/usr/local/lib/substrate-observability

install -d -m 0755 "$STAMP" /etc/victoria-metrics /etc/substrate
tar -xzpf "$HERE/payload.tar.gz" -C /

# Fetch, VERIFY, then install. A download that fails its checksum is deleted
# rather than left on disk, so a later run cannot pick up a bad artefact.
install_binary() {
    local name=$1 version=$2 url=$3 sha=$4 member=$5 as=$6
    if [ -f "$STAMP/$name" ] && [ "$(cat "$STAMP/$name")" = "$version" ] \\
       && [ -x "/usr/local/bin/$as" ]; then
        echo "  $as $version already installed"
        return
    fi
    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    echo "  fetching $as $version"
    curl -fsSL -o "$tmp/pkg.tar.gz" "$url"
    echo "$sha  $tmp/pkg.tar.gz" | sha256sum -c - >/dev/null
    tar -xzf "$tmp/pkg.tar.gz" -C "$tmp" "$member"
    install -m 0755 "$tmp/$member" "/usr/local/bin/$as"
    printf '%s' "$version" > "$STAMP/$name"
}

# Grafana ships a 455 MB directory tree (bin/, conf/, public/), not one binary,
# so install_binary does not apply. Extracted whole and swapped into place: a
# half-extracted tree that systemd then starts would serve a broken UI rather
# than fail, which is worse than not starting at all.
install_tree() {
    local name=$1 version=$2 url=$3 sha=$4 root=$5 dest=$6
    if [ -f "$STAMP/$name" ] && [ "$(cat "$STAMP/$name")" = "$version" ] \
       && [ -d "$dest" ]; then
        echo "  $name $version already installed"
        return
    fi
    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    echo "  fetching $name $version (large)"
    curl -fsSL -o "$tmp/pkg.tar.gz" "$url"
    echo "$sha  $tmp/pkg.tar.gz" | sha256sum -c - >/dev/null
    tar -xzf "$tmp/pkg.tar.gz" -C "$tmp"
    rm -rf "$dest.new" "$dest.old"
    mv "$tmp/$root" "$dest.new"
    [ -d "$dest" ] && mv "$dest" "$dest.old"
    mv "$dest.new" "$dest"
    rm -rf "$dest.old"

    # `mv` PRESERVES the SELinux context; `cp` and `install` relabel. The tree
    # was extracted under mktemp -d, so every file arrives here wearing
    # /tmp's label (user_tmp_t) and systemd refuses to exec it:
    #
    #   Unable to locate executable '/usr/local/share/grafana/bin/grafana':
    #   Permission denied ... status=203/EXEC
    #
    # The mode is fine and the path is fine; only the label is wrong, and
    # `ls -l` shows nothing. install_binary never hit this because `install`
    # relabels — which is exactly why Grafana was the only component affected.
    #
    # tar also preserves the archive's uid, leaving a system tree owned by
    # whichever unprivileged user happened to build it upstream.
    chown -R root:root "$dest"
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -R "$dest"
    fi

    printf '%s' "$version" > "$STAMP/$name"
}

# A Grafana PLUGIN tree — the third shape, after a lone binary and a program
# tree. It differs from install_tree in three ways that all matter:
#
#   1. It lands in /var/lib/grafana, not /usr/local. grafana.ini points
#      `plugins` there, and ProtectSystem=strict makes /usr read-only to the
#      service, so /usr is not a place Grafana could manage plugins even if it
#      wanted to.
#   2. Grafana only ever READS it. Left root-owned, so a compromised Grafana
#      cannot rewrite the backend binary it is about to execute.
#   3. Grafana enumerates plugins ONCE, at startup. Installing one under a
#      running Grafana changes nothing until it restarts, so this records that
#      a restart is owed rather than assuming the next deploy will do it.
#
# The plugin is signed (signatureType: commercial, signedByOrg: victoriametrics)
# and its MANIFEST.txt ships inside the tarball, so Grafana validates it without
# allow_loading_unsigned_plugins — which would have to be set globally and would
# weaken every other plugin path at the same time.
PLUGIN_INSTALLED=0
install_plugin() {
    local name=$1 version=$2 url=$3 sha=$4 root=$5 dest=$6
    if [ -f "$STAMP/$name" ] && [ "$(cat "$STAMP/$name")" = "$version" ] && [ -d "$dest" ]; then
        echo "  $name $version already installed"
        return
    fi
    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    echo "  fetching $name $version (large)"
    curl -fsSL -o "$tmp/pkg.tar.gz" "$url"
    echo "$sha  $tmp/pkg.tar.gz" | sha256sum -c - >/dev/null
    tar -xzf "$tmp/pkg.tar.gz" -C "$tmp"
    install -d -m 0755 "$(dirname "$dest")"
    rm -rf "$dest.new" "$dest.old"
    mv "$tmp/$root" "$dest.new"
    [ -d "$dest" ] && mv "$dest" "$dest.old"
    mv "$dest.new" "$dest"
    rm -rf "$dest.old"

    # Same trap that produced 203/EXEC for Grafana itself (ADR-114): `mv`
    # preserves the SELinux context, so a tree extracted under mktemp -d arrives
    # wearing /tmp's user_tmp_t label. This plugin declares `backend: true`, so
    # Grafana FORKS victoriametrics_logs_backend_plugin_linux_amd64 out of this
    # directory — an exec, subject to exactly the same refusal, and equally
    # invisible to `ls -l`.
    chown -R root:root "$dest"
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -R "$dest"
    fi

    printf '%s' "$version" > "$STAMP/$name"
    PLUGIN_INSTALLED=1
}

__INSTALL_CALLS__

# A system account with no shell and no home: it owns the data directory and
# nothing else. node_exporter needs no account at all — its unit uses
# DynamicUser, so systemd allocates one for the lifetime of the process.
if __WANTS_STORE__; then
    for svc in victoriametrics victorialogs grafana; do
        if ! id "$svc" >/dev/null 2>&1; then
            useradd --system --no-create-home --shell /usr/sbin/nologin "$svc"
        fi
    done
    install -d -m 0750 -o victoriametrics -g victoriametrics /var/lib/victoria-metrics
    install -d -m 0750 -o victorialogs -g victorialogs /var/lib/victoria-logs

    # Grafana scans every provisioning subdirectory at startup and logs an ERROR
    # for each one that does not exist. Only `datasources` and `dashboards` carry
    # files here, so `plugins` and `alerting` were absent and produced two errors
    # on every single start. They are empty ON PURPOSE -- plugins are pinned in
    # versions.yml and installed by install_plugin, and there are no provisioned
    # alerts yet -- so the directories exist to say "nothing here", which is a
    # different statement from "not configured".
    #
    # An error that is expected and permanent is worse than no error: it trains
    # whoever reads this journal to skim past a red line, on the one host whose
    # journal is read precisely when something has gone wrong.
    install -d -m 0755 /etc/grafana/provisioning/plugins /etc/grafana/provisioning/alerting
fi

# ALLOW-LIST, not a LAN range (the standing rule) — and, since 2026-09-02,
# actually enforced.
#
# THE DEFECT THIS REPLACES. These were plain `accept` rich rules, and Fedora
# Workstation's default zone opens 1025-65535/tcp. An accept on top of an
# already-open range restricts NOTHING: 9100 and 9428 were reachable from every
# host on the LAN for as long as the rules had existed, under a comment claiming
# they were allow-listed. Found by connecting from a host that was never on the
# list and getting HTTP 200.
#
# So each port now gets TWO rules. Negative priorities are evaluated ahead of the
# zone's own port accepts, which is what makes the drop bite:
#
#   priority -100   accept from each allow-listed source
#   priority  -50   drop everything else on that port
#
# Loopback is unaffected — it lives in the `trusted` zone — so Grafana keeps
# reaching VictoriaMetrics locally.
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    # The zone that owns the LAN interface, not merely the default zone. Writing
    # rules into the wrong zone is another way to produce rules that look right
    # and filter nothing.
    LAN_IF=$(ip -o -4 addr show | awk -v a="__HOST_ADDR__" '$4 ~ "^"a"/" {print $2; exit}')
    ZONE=$(firewall-cmd --get-zone-of-interface="$LAN_IF" 2>/dev/null || true)
    [ -n "$ZONE" ] || ZONE=$(firewall-cmd --get-default-zone)
    echo "  firewalld: zone $ZONE (interface $LAN_IF)"

    # Drop this deploy's own previous rules first, so a node removed from
    # site.yml stops being allow-listed instead of lingering forever.
    firewall-cmd --permanent --zone="$ZONE" --list-rich-rules 2>/dev/null \\
      | grep -E 'port="(9100|9428|8428)"' \\
      | while IFS= read -r old_rule; do
            firewall-cmd --permanent --quiet --zone="$ZONE" \\
                --remove-rich-rule="$old_rule" || true
        done

    # Built with printf and passed as one argument. Writing the rule inline
    # inside a double-quoted string collapses its inner quotes — firewalld needs
    # priority="-100", not priority=-100, and rejects the latter. With --quiet
    # and `|| true` that rejection would be invisible, which is how a firewall
    # ends up full of rules that were never accepted. shellcheck caught it.
    rich() { firewall-cmd --permanent --quiet --zone="$ZONE" --add-rich-rule="$1" || true; }
    allow_from() {
        rich "$(printf 'rule priority="-100" family="ipv4" source address="%s" port port="%s" protocol="tcp" accept' "$1" "$2")"
    }
    deny_port() {
        rich "$(printf 'rule priority="-50" family="ipv4" port port="%s" protocol="tcp" drop' "$1")"
    }

    for src in __SCRAPERS__; do
        allow_from "$src" 9100
    done
    deny_port 9100

    if __WANTS_STORE__; then
        # 9428 (logs, pushed by Vector) and 8428 (metrics, remote_written by
        # vmagent) are reached FROM the cluster, so both admit the node
        # addresses and nothing else.
        #
        # 8428 also serves the QUERY and DELETE apis — VictoriaMetrics has no
        # per-path authorisation — so this allow-list is the only boundary
        # between a host and the ability to read or destroy series.
        for src in __CLUSTER_NODES__; do
            allow_from "$src" 9428
            allow_from "$src" 8428
        done
        deny_port 9428
        deny_port 8428
    fi

    firewall-cmd --reload >/dev/null
    echo "  firewalld: 9100 accept __SCRAPERS__, drop all else"
    if __WANTS_STORE__; then
        echo "  firewalld: 9428 + 8428 accept __CLUSTER_NODES__, drop all else"
    fi
    echo "  firewalld: verify with posture-check (check_firewall_restrictions)"
else
    echo "  firewalld not active — 9100 is NOT restricted on this host"
fi

systemctl daemon-reload
systemctl enable --now node-exporter.service >/dev/null
systemctl enable --now substrate-reconcile.timer >/dev/null
__ENABLE_STORE__

# RESTART WHAT CHANGED — added 2026-09-02.
#
# `enable --now` STARTS a unit; it does nothing to one already running. So a
# changed ExecStart was written to disk, loaded by daemon-reload, and then never
# reached the running process: the host kept executing the previous command line
# indefinitely. This is how VictoriaMetrics stayed bound to 127.0.0.1 through a
# deploy whose entire purpose was to rebind it.
#
# substrate-reconcile.sh cannot catch this either — it verifies FILE checksums,
# and the file was correct. Both the deploy and the drift check agreed the host
# matched the repository while the process disagreed with both.
#
# The comparison is the unit FILE's mtime against the service's
# ActiveEnterTimestamp — "is this process older than its own configuration?" —
# NOT whether the file changed during this deploy. The first version of this fix
# made that mistake and was blind to exactly the host it was written for: the
# file had been updated by an earlier run, so the second run saw no change and
# restarted nothing while the process stayed 17 hours stale.
#
# systemd will not tell you this. NeedDaemonReload reports `no` once the config
# is loaded; whether the RUNNING process predates it is not tracked at all.
UNIT_STAMPS=/usr/local/lib/substrate-observability/units
install -d -m 0755 "$UNIT_STAMPS"

RESTARTED=""
for u in __UNIT_FILES__; do
    case "$u" in *@*) continue ;; esac          # templates are not restartable
    f="/etc/systemd/system/$u"
    [ -e "$f" ] || continue
    # Stopped units stay stopped. Restarting one the operator deliberately shut
    # down would be the deploy overriding a human decision.
    systemctl is-active --quiet "$u" || continue

    cur=$(sha256sum "$f" | cut -d" " -f1)
    stamp="$UNIT_STAMPS/$u.sha256"
    stale=0
    if [ -r "$stamp" ]; then
        # CONTENT, not mtime. The payload rewrites every unit file on every
        # deploy, so an mtime comparison would call everything stale and restart
        # the whole stack each time — gaps in the metrics store for nothing.
        [ "$(cat "$stamp")" = "$cur" ] || stale=1
    else
        # No stamp yet: first run after this check existed, or a host deployed
        # by an older version. Fall back to asking whether the process predates
        # its own configuration — the question systemd does not answer, and the
        # one that catches a host already drifted before this code shipped.
        started=$(systemctl show "$u" -p ActiveEnterTimestamp --value)
        started_epoch=$(date -d "$started" +%s 2>/dev/null || echo 0)
        [ "$(stat -c %Y "$f")" -gt "$started_epoch" ] && stale=1
    fi

    if [ "$stale" -eq 1 ]; then
        echo "  process does not match its unit, restarting: $u"
        systemctl try-restart "$u" || echo "    WARNING: $u failed to restart"
        RESTARTED="$RESTARTED $u"
    fi
    printf "%s" "$cur" > "$stamp"
done

# CONFIG THAT IS ONLY READ AT STARTUP — the same defect, one layer over.
#
# The loop above watches unit FILES. grafana.ini is not a unit file, and Grafana
# parses it exactly once, at startup. So a changed grafana.ini is shipped,
# installed at the right path with the right mode, and confirmed by
# substrate-reconcile.sh to match the repository byte for byte, while the running
# Grafana goes on serving the configuration it was started with. Deploy, drift
# check and `systemctl status` all report success and all three are describing
# the file rather than the process.
#
# VictoriaMetrics is deliberately NOT listed. It runs with
# -promscrape.configCheckInterval and re-reads its own scrape config, so
# restarting it would discard scrape state to fix something that fixes itself.
restart_if_config_changed() {
    local u=$1 f=$2
    [ -e "$f" ] || return 0
    systemctl is-active --quiet "$u" || return 0

    local cur stamp stale started started_epoch
    cur=$(sha256sum "$f" | cut -d" " -f1)
    stamp="$UNIT_STAMPS/config-$(echo "$f" | tr / _).sha256"
    stale=0
    if [ -r "$stamp" ]; then
        # CONTENT, not mtime: the payload rewrites grafana.ini on every deploy,
        # so an mtime test would restart Grafana every run for no change at all.
        [ "$(cat "$stamp")" = "$cur" ] || stale=1
    else
        # No stamp: the same bootstrap question asked of the units above. Is the
        # running process older than the configuration it claims to be using?
        started=$(systemctl show "$u" -p ActiveEnterTimestamp --value)
        started_epoch=$(date -d "$started" +%s 2>/dev/null || echo 0)
        [ "$(stat -c %Y "$f")" -gt "$started_epoch" ] && stale=1
    fi

    if [ "$stale" -eq 1 ]; then
        case " $RESTARTED " in
            *" $u "*) ;;
            *)
                echo "  process has not read its config, restarting: $u ($f)"
                systemctl try-restart "$u" || echo "    WARNING: $u failed to restart"
                RESTARTED="$RESTARTED $u"
                ;;
        esac
    fi
    printf "%s" "$cur" > "$stamp"
}

restart_if_config_changed grafana.service /etc/grafana/grafana.ini

# LOAD WHAT WAS INSTALLED — the plugin case of the same defect.
#
# Grafana enumerates its plugin directory ONCE, at startup. A plugin installed
# under a running Grafana is on disk, checksum-verified, correctly labelled, and
# completely absent from the running process. The datasource keeps reporting the
# same "unknown type" it reported before the install, so the deploy looks like it
# did nothing — the third layer to show this shape, after the unit files above
# and the vmagent ConfigMap in the cluster (ADR-116).
if [ "$PLUGIN_INSTALLED" -eq 1 ]; then
    case " $RESTARTED " in
        *" grafana.service "*)
            echo "  plugin installed; grafana.service was already restarted above"
            ;;
        *)
            # Not active means ConditionPathExists=/etc/grafana/grafana.env has
            # not been satisfied yet. Nothing to reload: whenever Grafana is
            # first started it will enumerate the plugin along with the rest.
            if systemctl is-active --quiet grafana.service; then
                echo "  plugin installed, restarting grafana.service to load it"
                systemctl try-restart grafana.service || echo "    WARNING: grafana.service failed to restart"
            else
                echo "  plugin installed; grafana.service not running, will load at first start"
            fi
            ;;
    esac
fi

echo "  node-exporter:   $(systemctl is-active node-exporter.service) / $(systemctl is-enabled node-exporter.service)"
echo "  OnFailure:       $(systemctl show -p OnFailure --value node-exporter.service)"
echo "  StartLimit:      $(systemctl show -p StartLimitIntervalUSec --value node-exporter.service)"
echo "  drift timer:     $(systemctl is-enabled substrate-reconcile.timer)"
# Run it once now. A drift check nobody has ever seen run is a drift check
# nobody should trust, and this is the cheapest possible moment to prove it.
/usr/local/bin/substrate-reconcile.sh || echo "  (drift reported above)"
__VERIFY_STORE__
"""


def host_address(cfg, host_name: str) -> str:
    """This host's own LAN address, as its peers reach it.

    Used to find which firewalld zone owns the LAN interface. Writing rules into
    the default zone when the interface lives in another is one more way to
    produce a firewall that looks configured and filters nothing.
    """
    hv = cfg.hypervisors[host_name]
    target = hv.peer_target or hv.ssh_target or ""
    return target.rpartition("@")[2]


def unit_files_for(cfg, host_name: str) -> list[str]:
    """The systemd unit basenames this host receives.

    Derived from the same payload the host is actually sent, rather than listed
    separately — a hand-maintained second list is one that silently stops
    matching, which is the failure this whole module keeps running into.
    """
    return sorted(
        Path(dest).name
        for _, dest, *_ in files_for(cfg, host_name)
        if dest.endswith((".service", ".timer"))
    )


def render_installer(cfg, host_name: str) -> str:
    """Substitute the per-host decisions into the installer.

    Rendered per host rather than branched inside bash: which components a host
    installs is a decision made from typed config, and bash is a poor place to
    re-derive it.
    """
    versions = siteconfig.load_versions()["observability"]
    calls = []
    for name in components_for(cfg, host_name):
        spec = versions[name]
        url = spec["url"].format(version=spec["version"])
        # Three shapes: a single binary lifted out of the archive, a whole
        # program tree, or a Grafana plugin tree. Which one is a property of the
        # upstream release AND of where it has to land, so it is declared in
        # versions.yml rather than guessed from the name.
        if "plugin_root" in spec:
            fields = (
                name,
                spec["version"],
                url,
                spec["sha256"],
                spec["plugin_root"],
                spec["install_to"],
            )
            verb = "install_plugin"
        elif "tree_root" in spec:
            fields = (
                name,
                spec["version"],
                url,
                spec["sha256"],
                spec["tree_root"],
                spec["install_to"],
            )
            verb = "install_tree"
        else:
            fields = (
                name,
                spec["version"],
                url,
                spec["sha256"],
                spec["member"],
                spec["install_as"],
            )
            verb = "install_binary"
        args = " ".join(shlex.quote(f) for f in fields)
        calls.append(f"{verb} {args}")
    wants_store = "victoria_metrics" in components_for(cfg, host_name)
    return (
        INSTALLER.replace("__INSTALL_CALLS__", "\n".join(calls))
        .replace("__WANTS_STORE__", "true" if wants_store else "false")
        .replace("__SCRAPERS__", " ".join(peer_addresses(cfg)))
        .replace("__CLUSTER_NODES__", " ".join(node_addresses(cfg)))
        .replace("__UNIT_FILES__", " ".join(unit_files_for(cfg, host_name)))
        .replace("__HOST_ADDR__", host_address(cfg, host_name))
        .replace(
            "__ENABLE_STORE__",
            (
                "systemctl enable --now victoria-metrics.service "
                "victoria-logs.service grafana.service grafana-health.timer "
                ">/dev/null"
                if wants_store
                else ""
            ),
        )
        .replace(
            "__VERIFY_STORE__",
            (
                'echo "  victoria-metrics: $(systemctl is-active victoria-metrics.service)"\n'
                'echo "  victoria-logs:    $(systemctl is-active victoria-logs.service)"\n'
                # Grafana carries ConditionPathExists on its EnvironmentFile, so
                # an unconfigured host reports `inactive` rather than failing —
                # correct, but indistinguishable from "stopped" unless we say
                # why. Before that condition existed this component took the
                # WHOLE fleet deploy down with it: server1's installer exited
                # non-zero and server2 was never reached.
                "if [ ! -e /etc/grafana/grafana.env ]; then\n"
                '  echo "  grafana:          NOT CONFIGURED — '
                '/etc/grafana/grafana.env is missing (GitHub OAuth secret)"\n'
                "else\n"
                '  echo "  grafana:          $(systemctl is-active grafana.service)"\n'
                "fi"
                if wants_store
                else ""
            ),
        )
    )


def files_for(cfg, host_name: str) -> list:
    """The (bytes, path, mode) set this host receives."""
    payload = [
        (
            (UNIT_DIR / "node-exporter.service").read_bytes(),
            "etc/systemd/system/node-exporter.service",
            0o644,
        ),
        (
            (UNIT_DIR / "observability-notify@.service").read_bytes(),
            "etc/systemd/system/observability-notify@.service",
            0o644,
        ),
    ]
    payload += [
        (
            (UNIT_DIR / "substrate-reconcile.service").read_bytes(),
            "etc/systemd/system/substrate-reconcile.service",
            0o644,
        ),
        (
            (UNIT_DIR / "substrate-reconcile.timer").read_bytes(),
            "etc/systemd/system/substrate-reconcile.timer",
            0o644,
        ),
        (
            (REPO / "substrate-reconcile.sh").read_bytes(),
            "usr/local/bin/substrate-reconcile.sh",
            0o755,
        ),
    ]
    if "victoria_metrics" in components_for(cfg, host_name):
        payload += (
            [
                (
                    (UNIT_DIR / "victoria-metrics.service").read_bytes(),
                    "etc/systemd/system/victoria-metrics.service",
                    0o644,
                ),
                (
                    (UNIT_DIR / "victoria-logs.service").read_bytes(),
                    "etc/systemd/system/victoria-logs.service",
                    0o644,
                ),
                (scrape_config(cfg), "etc/victoria-metrics/scrape.yml", 0o644),
                (grafana_ini(cfg), "etc/grafana/grafana.ini", 0o644),
                (
                    (
                        REPO
                        / "observability-host/provisioning/datasources/victoria.yaml"
                    ).read_bytes(),
                    "etc/grafana/provisioning/datasources/victoria.yaml",
                    0o644,
                ),
                (
                    (
                        REPO
                        / "observability-host/provisioning/dashboards/repository.yaml"
                    ).read_bytes(),
                    "etc/grafana/provisioning/dashboards/repository.yaml",
                    0o644,
                ),
            ]
            + [
                (
                    board.read_bytes(),
                    f"var/lib/grafana/dashboards/{board.name}",
                    0o644,
                )
                for board in sorted(
                    (REPO / "observability-host/dashboards").glob("*.json")
                )
            ]
            + [
                (
                    (UNIT_DIR / "grafana.service").read_bytes(),
                    "etc/systemd/system/grafana.service",
                    0o644,
                ),
                (
                    (UNIT_DIR / "grafana-health.service").read_bytes(),
                    "etc/systemd/system/grafana-health.service",
                    0o644,
                ),
                (
                    (UNIT_DIR / "grafana-health.timer").read_bytes(),
                    "etc/systemd/system/grafana-health.timer",
                    0o644,
                ),
                (
                    (REPO / "grafana-health.sh").read_bytes(),
                    "usr/local/bin/grafana-health.sh",
                    0o755,
                ),
            ]
        )
    return payload


def check(host, cfg) -> list[str]:
    """Report drift between the repository and what is installed on a host.

    WHY THIS EXISTS
    The cluster has Flux: a hand-edit is reverted within ten minutes and the
    repository is the truth by construction. **The host tier has no such thing.**
    A unit edited in place on server1 persists silently and forever, and the
    next rebuild would quietly produce a different machine — which is precisely
    the failure the whole rebuildable-fleet discipline exists to prevent.

    So this is the host tier's reconciliation loop, minus the reconciling: it
    cannot fix drift, but it refuses to let drift be invisible. Observability
    infrastructure must be rebuildable from the repository alone; only its DATA
    is irreplaceable (ADR-100).
    """
    problems = []
    for data, path, _mode in files_for(cfg, host.name):
        want = hashlib.sha256(data).hexdigest()
        result = deploy_updates.run(host, ["sha256sum", f"/{path}"], check=False)
        if result.returncode != 0:
            problems.append(f"{host.name}: /{path} is MISSING")
            continue
        got = result.stdout.split()[0]
        if got != want:
            problems.append(f"{host.name}: /{path} differs from the repository")

    versions = siteconfig.load_versions()["observability"]
    for name in components_for(cfg, host.name):
        want = versions[name]["version"]
        result = deploy_updates.run(
            host,
            ["cat", f"/usr/local/lib/substrate-observability/{name}"],
            check=False,
        )
        got = result.stdout.strip() if result.returncode == 0 else "(absent)"
        if got != want:
            problems.append(f"{host.name}: {name} is {got}, repository pins {want}")
    return problems


def grafana_ini(cfg) -> bytes:
    """Render grafana.ini from the template and site.yml.

    REFUSES to render GitHub auth without an organisation. Grafana's default
    with `[auth.github] enabled = true` and no `allowed_organizations` is not
    "nobody" — it is EVERYBODY with a GitHub account. That is a one-line
    difference between a private dashboard and a public one, and it fails open,
    so it is checked here rather than trusted to a reviewer.
    """
    org = (cfg.observability.github_org or "").strip()
    hostname = (cfg.observability.hostname or "").strip()
    if not hostname:
        raise SystemExit(
            "site.yml: observability.hostname is required — Grafana needs it "
            "for root_url, and without it login fails in a way that looks like "
            "a proxy fault."
        )
    template = (REPO / "observability-host" / "grafana.ini.template").read_text()
    return (
        template.replace("__HOSTNAME__", hostname).replace(
            "__GITHUB_ENABLED__", "true" if org else "false"
        )
        # A literal that cannot match any real org, so a template bug fails
        # closed instead of admitting everyone.
        .replace("__GITHUB_ORG__", org or "!none")
    ).encode()


def traefik_route(cfg) -> bytes:
    """Render the edge route for Grafana.

    Kept in this repository rather than hand-written into the edge's config
    directory: the route and the service it points at are one decision, and
    splitting them across two places is how a bind address changes in one and
    not the other.
    """
    template = (
        REPO / "observability-host" / "traefik" / "observe.yml.template"
    ).read_text()
    return (
        template.replace("__HOSTNAME__", cfg.observability.hostname or "")
        .replace("__GRAFANA_ADDR__", GRAFANA_BIND)
        .encode()
    )


def manifest_for(cfg, host_name: str, payload: list) -> bytes:
    """The offline drift check's entire input.

    Two things in one file, on purpose: `sha256sum -c` lines for the installed
    files, and the pinned version of each binary as a COMMENT — which sha256sum
    ignores, so one file describes the whole installed state and there is
    nothing to keep in step between two.

    Written at deploy time rather than read from the repository at check time,
    because the checker must not need git: a root timer that pulls and executes
    makes push access to the repository root on the hypervisor (ADR-101).
    """
    versions = siteconfig.load_versions()["observability"]
    lines = [
        "# Written by deploy-observability.py. Input to substrate-reconcile.sh.",
        "# `# pinned:` lines are read by that script; sha256sum ignores them.",
    ]
    for name in components_for(cfg, host_name):
        lines.append(f"# pinned: {name}={versions[name]['version']}")
    for data, path, _mode in payload:
        lines.append(f"{hashlib.sha256(data).hexdigest()}  /{path}")
    return ("\n".join(lines) + "\n").encode()


def deploy(host, cfg, dry_run: bool) -> None:
    """Stage this host's payload, then run its installer under one sudo."""
    which = ", ".join(components_for(cfg, host.name))
    print(f"=== {host.name}: {which}")
    installer = render_installer(cfg, host.name)
    files = files_for(cfg, host.name)
    # Appended after the set is complete, and deliberately NOT listed in itself:
    # a manifest that hashed its own contents could never match.
    files.append(
        (
            manifest_for(cfg, host.name, files),
            "etc/substrate/observability.manifest",
            0o644,
        )
    )

    if dry_run:
        for _, path, mode in files:
            print(f"    would install /{path} ({mode:o})")
        print("    --- installer ---")
        for line in installer.splitlines():
            print(f"    {line}")
        return

    staging = deploy_updates.run(
        host, ["mktemp", "-d", "/tmp/substrate-observability.XXXXXX"]
    ).stdout.strip()
    if not staging:
        raise RuntimeError(f"[{host.name}] could not create a staging directory")
    try:
        deploy_updates.run(host, ["chmod", "700", staging])
        deploy_updates.stage_bytes(
            host, deploy_updates.build_payload(files), f"{staging}/payload.tar.gz"
        )
        deploy_updates.stage_bytes(host, installer.encode(), f"{staging}/install.sh")

        inner = f"sudo bash {shlex.quote(staging)}/install.sh"
        if host.ssh_target is None:
            cmd = ["bash", "-c", inner]
        else:
            # -t so sudo can prompt on a real pty, and the output is NOT
            # captured: a captured prompt is an invisible prompt, and the run
            # looks like a hang.
            cmd = ["ssh", "-t", host.ssh_target, inner]
        if subprocess.run(cmd, check=False).returncode != 0:
            raise RuntimeError(f"[{host.name}] installer failed")
    finally:
        deploy_updates.run(host, ["rm", "-rf", staging], check=False)


def main() -> int:
    """Deploy to every hypervisor."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be installed, and the installer itself",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift between this repository and the installed hosts",
    )
    args = parser.parse_args()

    # Refuse to run privileged. This script STAGES as the ordinary user and
    # escalates exactly once, for the installer (ADR-078). Run whole under sudo
    # it would resolve $HOME to /root, look for an admin SSH key that is not
    # there, and defeat the reason the staging/installer split exists.
    if os.geteuid() == 0:
        raise SystemExit(
            "Do not run this under sudo.\n"
            "  It stages as you and escalates once, for the installer alone "
            "(ADR-078) —\n"
            "  running the whole thing as root resolves $HOME to /root and "
            "breaks key\n"
            "  and ssh-agent resolution. Just:  ./deploy-observability.py"
        )

    cfg = siteconfig.load_model()
    if cfg.observability.host and cfg.observability.host not in cfg.hypervisors:
        raise SystemExit(
            f"site.yml: observability.host is '{cfg.observability.host}', which is "
            f"not a hypervisor. Known: {', '.join(sorted(cfg.hypervisors))}"
        )

    if args.check:
        problems = []
        for host in hosts.HOSTS:
            problems += check(host, cfg)
        if problems:
            print("DRIFT — the hosts do not match this repository:")
            for line in problems:
                print(f"  [BUG] {line}")
            print(
                "\nThe host tier has no reconciler. Re-run without --check to "
                "restore the repository's version."
            )
            return 1
        print("every host matches the repository")
        return 0

    for host in hosts.HOSTS:
        deploy(host, cfg, args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
