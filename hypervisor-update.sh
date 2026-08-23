#!/usr/bin/env bash
#
# Nightly hypervisor updates with safety gates.
#
# Applies updates every night, but only REBOOTS when the system genuinely
# requires it (kernel/glibc/systemd class updates) AND it is safe to do so.
#
# Safety gates before any reboot — ALL must pass:
#   1. The peer hypervisor is reachable over SSH.
#   2. The peer's VMs are all running.
#   3. The k0s cluster is fully healthy: every expected node Ready, and no
#      node already NotReady.
#   4. No other hypervisor is currently mid-reboot (a lock file on the peer),
#      so the two can never reboot simultaneously.
#
# Rationale: rebooting a hypervisor takes ALL its k0s nodes down at once. With
# nodes split 2/3 across two hosts, either host rebooting means temporary loss
# of etcd quorum regardless of ordering. The cluster recovers on its own
# (verified), but the gates ensure it only ever happens from a known-good
# starting state, one host at a time, and only when actually necessary.
#
# Nodes are drained before shutdown so workloads terminate gracefully rather
# than being killed with the VM.
#
# Deployed by deploy-updates.sh; runs from a systemd timer.

set -uo pipefail

PEER_HOST="${PEER_HOST:?PEER_HOST must be set (e.g. user@10.0.0.5)}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-/etc/homelab/kubeconfig}"
LOCK_FILE="/var/run/hypervisor-reboot.lock"
LOG_TAG="hypervisor-update"

# DRY_RUN=1 runs every check and reports what would happen, without applying
# updates, draining nodes, or rebooting. Use it to verify the safety gates —
# untested safety logic is worse than none.
DRY_RUN="${DRY_RUN:-0}"

log() { logger -t "$LOG_TAG" "$*"; echo "$(date -Is) $*"; }

# This script runs as root (systemd), but root has no SSH key — and shouldn't.
# Peer health checks are read-only, so run them as the unprivileged admin user
# who does have keys. Without this, the peer gate fails permanently and NO
# reboot ever happens — caught by a DRY_RUN before it could silently block
# updates forever.
SSH_USER="${SSH_USER:?SSH_USER must be set — the unprivileged account used for peer health checks}"

ssh_peer() {
    runuser -u "$SSH_USER" -- \
        ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
            "$PEER_HOST" "$@" 2>/dev/null
}

kubectl_q() {
    KUBECONFIG="$KUBECONFIG_PATH" kubectl --request-timeout=15s "$@" 2>/dev/null
}

# ---------------------------------------------------------------- updates ---

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY RUN — skipping dnf upgrade"
else
    log "applying updates"
    if ! dnf -y upgrade --refresh; then
        log "ERROR: dnf upgrade failed — not rebooting"
        exit 1
    fi
    log "updates applied"
fi

if needs-restarting -r >/dev/null 2>&1; then
    log "no reboot required — done"
    [[ "$DRY_RUN" == "1" ]] && log "DRY RUN: continuing to exercise the gates anyway" || exit 0
fi
log "checking safety gates"

# ------------------------------------------------------------------ gates ---

if [[ -e "$LOCK_FILE" ]]; then
    log "ABORT: local reboot lock present ($LOCK_FILE) — a previous run may not have completed"
    exit 1
fi

if ! ssh_peer true; then
    log "ABORT: peer $PEER_HOST unreachable — refusing to reboot"
    exit 1
fi

if ssh_peer "test -e $LOCK_FILE"; then
    log "ABORT: peer $PEER_HOST is mid-reboot (lock present) — refusing to reboot simultaneously"
    exit 1
fi

# Peer's VMs must all be running. If the peer hosts no VMs yet (server1 today)
# this is vacuously true, which is correct.
peer_not_running=$(ssh_peer "virsh -c qemu:///system list --all --name" \
    | while read -r vm; do
          [[ -z "$vm" ]] && continue
          state=$(ssh_peer "virsh -c qemu:///system domstate $vm")
          [[ "$state" != "running" ]] && echo "$vm"
      done)
if [[ -n "$peer_not_running" ]]; then
    log "ABORT: peer has VMs not running: $peer_not_running"
    exit 1
fi

# Cluster must be fully healthy: at least one node, and none NotReady.
nodes=$(kubectl_q get nodes --no-headers)
if [[ -z "$nodes" ]]; then
    log "ABORT: cannot reach the cluster to verify health"
    exit 1
fi
not_ready=$(echo "$nodes" | awk '$2!="Ready"')
if [[ -n "$not_ready" ]]; then
    log "ABORT: cluster has non-Ready nodes:"
    log "$not_ready"
    exit 1
fi
log "gates passed: peer healthy, all $(echo "$nodes" | wc -l) cluster nodes Ready"

# ----------------------------------------------------------- graceful down ---

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY RUN: all gates passed — would drain [$(virsh -c qemu:///system list --state-running --name | tr '\n' ' ')] and reboot"
    exit 0
fi

touch "$LOCK_FILE"
# Clear the lock even if we die before rebooting; a real reboot wipes /var/run
# anyway (tmpfs), so this can't wedge future runs.
trap 'rm -f "$LOCK_FILE"' EXIT

local_vms=$(virsh -c qemu:///system list --state-running --name | grep -v '^$' || true)

for vm in $local_vms; do
    log "cordon+drain node $vm"
    kubectl_q cordon "$vm" || log "WARN: cordon failed for $vm"
    kubectl_q drain "$vm" --ignore-daemonsets --delete-emptydir-data \
        --force --timeout=120s || log "WARN: drain incomplete for $vm (continuing)"
done

for vm in $local_vms; do
    log "graceful shutdown of $vm"
    virsh -c qemu:///system shutdown "$vm" || log "WARN: shutdown command failed for $vm"
done

# Give guests time to shut down cleanly before the host pulls the rug.
for _ in $(seq 1 30); do
    still_up=$(virsh -c qemu:///system list --state-running --name | grep -v '^$' || true)
    [[ -z "$still_up" ]] && break
    sleep 5
done
still_up=$(virsh -c qemu:///system list --state-running --name | grep -v '^$' || true)
[[ -n "$still_up" ]] && log "WARN: still running after grace period, forcing: $still_up"

# Nodes are marked unschedulable; they're uncordoned on the way back up by
# hypervisor-update-uncordon.service.
log "rebooting"
systemctl reboot
