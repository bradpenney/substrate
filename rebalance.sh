#!/usr/bin/env bash
# Spread the platform back across the fleet after a rebuild.
#
# WHY THIS IS NEEDED EVERY TIME, NOT ONCE
# provision.py builds the bootstrap controller first and waits for k0s to be
# READY before joining anything else — and that readiness is exactly when k0s
# applies the Flux manifests. So the whole platform reconciles onto a one-node
# cluster and is placed there permanently: Kubernetes never moves a running pod.
#
# Measured after the 2026-08-29 rebuild, with all five nodes healthy:
#
#   s2-vm1  26 scheduled pods   (1.52 Gi allocatable)  <- the bootstrap node
#   s2-vm2   9                  (1.52 Gi)
#   s2-vm3   6                  (1.52 Gi)
#   s1-vm1   1                  (17.2 Gi)
#   s1-vm2   2                  (17.2 Gi)
#
# 41 of 43 pods on 4.5 Gi while 34.4 Gi sat idle. Nothing is misconfigured and
# nothing is pinned — the node simply did not exist when the scheduler chose.
#
# Traefik is the proof: it is the ONLY component in substrate_config declaring
# topologySpreadConstraints, and it is the only Deployment that reached two
# nodes. A spread constraint is evaluated when a pod is SCHEDULED; it does not
# rebalance a running one either.
#
# WHAT THIS IS NOT
# Not a fix. It is remediation for a cluster already built, and it stays useful
# while the Rust port is validated against the Python and Ansible
# implementations across many rebuilds.
#
# The actual fix is to stop reconciling the platform onto a ONE-NODE cluster:
# the Flux manifests are baked into the bootstrap node's cloud-config and
# applied by k0s the instant it is ready, before any peer has joined. Deferring
# that until the fleet is complete removes the cause (ADR-097).
#
# NOT by moving `bootstrap: true` to a large node. That was suggested and
# WITHDRAWN: it relocates the pile onto server1, the office workstation that
# reboots. server2's 4.5 Gi cannot absorb the platform; server1's 34 Gi can
# absorb server2's. Concentration on the always-on machine is less bad. The
# goal is spread, not relocation.
#
# REQUIRES ELEVATION. The everyday identity is read-only by design (ADR-065):
#     jit-admin.py <user> --minutes 30
# which itself needs the break-glass context. That refusal is the control
# working, not an obstacle to route around.
set -euo pipefail

DRY_RUN=${DRY_RUN:-0}
KUBECTL=${KUBECTL:-kubectl}

# Ordered least-disruptive first. Each batch is allowed to settle before the
# next, so a failure stops the run with the cluster in a known state rather
# than halfway through restarting everything at once.
#
# Batches, and why they are in this order:
#   1  stateless, nothing depends on them being up this second
#   2  admission webhooks — brief unavailability affects only their own API group
#   3  the edge and cluster DNS, both multi-replica so a rolling restart keeps one
#   4  authoritative DNS — the most externally visible thing here
#   5  Flux last, so an earlier failure still leaves a working reconciler
BATCH_1=(
    "hello-site/hello-site"
    "longhorn-system/longhorn-ui"
    "longhorn-system/longhorn-driver-deployer"
    "longhorn-system/csi-attacher"
    "longhorn-system/csi-provisioner"
    "longhorn-system/csi-resizer"
    "longhorn-system/csi-snapshotter"
    "kube-system/metrics-server"
    "metallb-system/controller"
)
BATCH_2=(
    "external-secrets/external-secrets"
    "external-secrets/external-secrets-cert-controller"
    "external-secrets/external-secrets-webhook"
    "cert-manager/cert-manager"
    "cert-manager/cert-manager-cainjector"
    "cert-manager/cert-manager-webhook"
)
BATCH_3=(
    "traefik/traefik"
    "kube-system/coredns"
)
BATCH_4=(
    "bindy-system/bindy"
    "bindy-system/homelab-primary-0"
    "bindy-system/homelab-primary-1"
)
BATCH_5=(
    "flux-system/flux-operator"
    "flux-system/source-controller"
    "flux-system/kustomize-controller"
    "flux-system/notification-controller"
)

restart_batch() {
    local label=$1
    shift
    echo "==> $label"
    for target in "$@"; do
        local ns=${target%%/*}
        local name=${target##*/}
        if ! "$KUBECTL" get "deployment/$name" -n "$ns" >/dev/null 2>&1; then
            echo "    [skip] $ns/$name does not exist"
            continue
        fi
        if [ "$DRY_RUN" = "1" ]; then
            echo "    [dry ] would restart $ns/$name"
            continue
        fi
        echo "    restarting $ns/$name"
        "$KUBECTL" rollout restart "deployment/$name" -n "$ns" >/dev/null
    done

    [ "$DRY_RUN" = "1" ] && return 0

    # Wait for each one SEPARATELY. Restarting the batch together and then
    # waiting means a single stuck rollout is attributed to whichever deployment
    # happens to be checked first.
    for target in "$@"; do
        local ns=${target%%/*}
        local name=${target##*/}
        "$KUBECTL" get "deployment/$name" -n "$ns" >/dev/null 2>&1 || continue
        if ! "$KUBECTL" rollout status "deployment/$name" -n "$ns" --timeout=180s >/dev/null; then
            echo "    [BUG] $ns/$name did not become ready — stopping here" >&2
            exit 1
        fi
    done
    echo "    batch ready"
}

preflight() {
    # Check the permission BEFORE touching anything. Without this the run dies
    # on the first restart with kubectl's raw "is forbidden" text, which says
    # nothing about the grant that fixes it — and, worse, a batch could be
    # half-restarted before a later verb turns out to be denied.
    local missing=0
    for verb in "patch deployments" "get pods"; do
        # shellcheck disable=SC2086
        if [ "$("$KUBECTL" auth can-i ${verb} -A 2>/dev/null | tail -1)" != "yes" ]; then
            echo "    [deny] cannot ${verb}" >&2
            missing=1
        fi
    done
    if [ "$missing" = "1" ]; then
        cat >&2 <<MSG

The everyday identity is read-only by design (ADR-065). Rebalancing needs a
time-boxed grant, and issuing one needs the break-glass context:

    jit-admin.py ${USER:-<your-user>} --minutes 30

The grant expires on its own; the jit-reaper CronJob enforces it every two
minutes. Re-run this script once it is live.
MSG
        exit 1
    fi
    echo "==> permissions ok"
}

distribution() {
    echo "==> pods per node (excluding DaemonSets)"
    "$KUBECTL" get pods -A -o json | python3 -c '
import json, sys, collections
counts = collections.Counter()
for p in json.load(sys.stdin)["items"]:
    owner = (p["metadata"].get("ownerReferences") or [{}])[0].get("kind", "")
    if owner in ("DaemonSet", "Job"):
        continue
    counts[p["spec"].get("nodeName", "?")] += 1
for node in sorted(counts):
    print(f"    {node}: {counts[node]}")
'
}

if [ "$DRY_RUN" != "1" ]; then
    preflight
fi
distribution
restart_batch "batch 1 — stateless" "${BATCH_1[@]}"
restart_batch "batch 2 — webhooks" "${BATCH_2[@]}"
restart_batch "batch 3 — edge and cluster DNS" "${BATCH_3[@]}"
restart_batch "batch 4 — authoritative DNS" "${BATCH_4[@]}"
restart_batch "batch 5 — flux" "${BATCH_5[@]}"
distribution

echo
echo "Rebalanced. This recurs on EVERY rebuild until the platform stops being"
echo "reconciled onto a one-node cluster, and until the gate asserts"
echo "distribution rather than only readiness (ADR-097)."
