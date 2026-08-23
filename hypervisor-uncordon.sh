#!/usr/bin/env bash
#
# Uncordon this hypervisor's k0s nodes after a reboot.
#
# hypervisor-update.sh cordons+drains its nodes before rebooting, which marks
# them unschedulable. That state is stored in the CLUSTER, not on the node, so
# it survives the reboot — without this, nodes come back Ready but permanently
# unschedulable and the cluster slowly starves.
#
# Runs once at boot, after libvirt has had a chance to autostart the VMs.

set -uo pipefail

KUBECONFIG_PATH="${KUBECONFIG_PATH:-/etc/homelab/kubeconfig}"
LOG_TAG="hypervisor-uncordon"

log() { logger -t "$LOG_TAG" "$*"; echo "$(date -Is) $*"; }

kubectl_q() {
    KUBECONFIG="$KUBECONFIG_PATH" kubectl --request-timeout=15s "$@" 2>/dev/null
}

vms=$(virsh -c qemu:///system list --all --name | grep -v '^$' || true)
if [[ -z "$vms" ]]; then
    log "no VMs on this host — nothing to uncordon"
    exit 0
fi

# Wait for the API to be reachable and this host's nodes to register. After a
# host reboot the whole control plane may be coming back at once, so this can
# legitimately take a couple of minutes.
for _ in $(seq 1 40); do
    kubectl_q get nodes >/dev/null && break
    sleep 15
done

if ! kubectl_q get nodes >/dev/null; then
    log "ERROR: cluster unreachable after waiting — nodes may remain cordoned"
    exit 1
fi

for vm in $vms; do
    # Only act on VMs that are actually cluster nodes.
    if ! kubectl_q get node "$vm" >/dev/null; then
        continue
    fi
    for _ in $(seq 1 20); do
        status=$(kubectl_q get node "$vm" --no-headers | awk '{print $2}')
        [[ "$status" == "Ready" || "$status" == "Ready,SchedulingDisabled" ]] && break
        sleep 15
    done
    log "uncordon $vm"
    kubectl_q uncordon "$vm" || log "WARN: uncordon failed for $vm"
done

log "done"
