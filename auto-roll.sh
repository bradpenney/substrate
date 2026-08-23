#!/usr/bin/env bash
#
# Roll the k0s fleet onto a newly-pinned node image, shortly after the bump PR
# is merged.
#
# WHY IT RUNS ON THE HYPERVISOR AND NOT IN THE CLUSTER
# Three reasons, any one sufficient:
#   1. The roll DESTROYS the nodes it runs on. A pod executing this would be
#      evicted the moment its own node was replaced, mid-operation.
#   2. In-cluster it would need SSH credentials to both hypervisors — a pod able
#      to create and destroy VMs is a far worse blast radius than a host-local
#      systemd unit.
#   3. Circular dependency: the thing that rebuilds the cluster must not live
#      inside it. Same rule that ruled out an in-cluster registry and secret
#      store. When the cluster is broken is exactly when this must still work.
#
# ⚠️ ONE HOST ONLY (server1 by convention — where provisioning already runs
# from). Two pollers would race to replace the same node; the lockfile below
# only protects against overlap on a single host.
#
# WHY A POLLER AND NOT A GITHUB ACTION
# GitHub-hosted runners cannot reach this LAN, and a self-hosted runner would
# mean inbound registration plus a long-lived credential on a hypervisor. A
# pull-based poller needs neither: it only ever makes outbound requests, which
# is the same reasoning that makes GitOps pull-based in the first place.
#
# WHAT IT DOES
# Every N minutes: fetch origin, compare the pinned node-image checksum on
# `main` against the one this host last rolled to. If they differ, run
# `gate.py roll --yes`, which replaces nodes ONE AT A TIME with full health
# checks between each.
#
# So the flow is:
#   bump-kairos opens a PR  ->  phone notification  ->  you approve+merge
#   ->  (within POLL_INTERVAL)  ->  fleet rolls, one node at a time
#
# ⚠️ APPROVING THE PR IS THE AUTHORISATION. There is no second confirmation.
# That is deliberate — the goal is patched nodes within 24h of a release — but
# it means a merge from a phone starts a fleet-wide node rebuild.
#
# SAFETY: this script deliberately does very little of its own. All the real
# guarding lives in `gate.py roll`, which refuses to start on a degraded
# cluster, never mints a join token from the node being replaced, prunes etcd
# membership, and halts mid-roll if system pods do not settle.
#
# Install with deploy-auto-roll.sh; runs from systemd as the admin user.

set -uo pipefail

REPO_DIR="${REPO_DIR:-/var/lib/substrate/repo}"
REPO_URL="${REPO_URL:?REPO_URL must be set (see /etc/substrate/auto-roll.env)}"
BRANCH="${BRANCH:-main}"
STATE_FILE="${STATE_FILE:-/var/lib/substrate/last-rolled-sha256}"
LOCK_FILE=/var/lib/substrate/auto-roll.lock

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# A roll takes minutes and the timer fires on a schedule — overlapping runs
# would try to replace the same node twice.
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "another auto-roll is in progress; exiting"
    exit 0
fi

mkdir -p "$(dirname "$STATE_FILE")"

# --- get the current pin from origin, WITHOUT touching any working tree ---
#
# Deliberately a dedicated clone, never the operator's checkout: pulling into a
# working tree someone might have edits in is a good way to lose work or roll
# from unexpected code.
if [[ ! -d "$REPO_DIR/.git" ]]; then
    log "cloning $REPO_URL -> $REPO_DIR"
    git clone --quiet --branch "$BRANCH" "$REPO_URL" "$REPO_DIR" || {
        log "ERROR: clone failed"; exit 1; }
fi

git -C "$REPO_DIR" fetch --quiet origin "$BRANCH" || { log "ERROR: fetch failed"; exit 1; }
git -C "$REPO_DIR" reset --quiet --hard "origin/$BRANCH" || { log "ERROR: reset failed"; exit 1; }

PINNED=$(grep -A3 '^kairos:' "$REPO_DIR/versions.yml" | grep 'iso_sha256:' \
         | awk -F'"' '{print $2}')
if [[ -z "$PINNED" ]]; then
    log "ERROR: could not read the pinned image checksum from versions.yml"
    exit 1
fi

LAST=$(cat "$STATE_FILE" 2>/dev/null || echo "")

if [[ "$PINNED" == "$LAST" ]]; then
    log "up to date (${PINNED:0:12}...) — nothing to do"
    exit 0
fi

# --- first run: adopt the current pin rather than rolling ---
#
# Without this, installing the poller onto an already-correct cluster would
# immediately roll the whole fleet for no reason.
if [[ -z "$LAST" ]]; then
    log "first run — adopting current pin ${PINNED:0:12}... without rolling"
    echo "$PINNED" > "$STATE_FILE"
    exit 0
fi

log "pinned image changed: ${LAST:0:12}... -> ${PINNED:0:12}..."
log "starting rolling replacement (one node at a time)"

if "$REPO_DIR/gate.py" roll --yes; then
    echo "$PINNED" > "$STATE_FILE"
    log "roll complete — fleet is on ${PINNED:0:12}..."
else
    # Deliberately do NOT record the new pin on failure: the next run should
    # retry rather than silently declaring the fleet updated.
    log "ERROR: roll failed — state NOT advanced, will retry next cycle"
    exit 1
fi
