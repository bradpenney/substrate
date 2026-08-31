#!/usr/bin/env bash
# Restart Grafana if it is alive but not serving (ADR-098).
#
# `Restart=always` only fires on process EXIT. A wedged process — deadlocked,
# out of descriptors, stuck on a database lock — stays `active (running)`
# indefinitely while serving nothing, and systemd reports it as healthy.
#
# -f is load-bearing for the same reason it is in notify.sh: without it curl
# exits 0 on an HTTP 5xx, so a Grafana returning "500 database is locked" would
# read as healthy. That defect has now appeared twice in this estate; it does
# not get to appear a third time.
set -euo pipefail

URL="${GRAFANA_HEALTH_URL:-http://172.18.0.1:3000/api/health}"

log() { printf '%s %s\n' "$(date -Is)" "$*"; }

if curl -fsS --max-time 10 "$URL" > /dev/null 2>&1; then
    exit 0
fi

# Only restart something that systemd believes is UP. If the unit is already
# failed, `Restart=always` owns the problem and racing it would only confuse
# the restart counters.
if ! systemctl is-active --quiet grafana.service; then
    log "grafana is not active; leaving it to Restart=always"
    exit 0
fi

log "grafana is active but not serving $URL — restarting"
systemctl restart grafana.service

# Say so. A service that quietly restarts itself every two minutes looks
# perfectly healthy from the outside, which is the worst way to lose a week.
/usr/local/bin/homelab-notify.sh \
    "Grafana was wedged" \
    "active but not serving $URL on $(hostname); restarted" || \
    log "WARNING: notification failed"
