#!/usr/bin/env bash
# Report local drift between what was deployed and what is on this host.
#
# DELIBERATELY OFFLINE. No git, no network, no credentials (ADR-101).
#
# An earlier draft fetched the repository and hard-reset a clone, the way
# auto-roll.sh does. That was rejected: a root timer that pulls from git and
# executes means PUSH ACCESS TO THE REPOSITORY IS ROOT ON THE HYPERVISOR — and
# substrate is going public, so the set of people who can open a pull request
# is no longer the set of people who should have root here.
#
# This answers a narrower and safer question: "has anything on this host been
# changed since it was deployed?" It needs nothing but a manifest written at
# deploy time. It cannot answer "is this host running the current version" —
# that requires a remote source of truth, and the decision is that the source
# must be a SIGNED, SEMANTICALLY VERSIONED OCI ARTIFACT, verified the same way
# the cluster verifies its config (ADR-069/094). Until that exists, staleness is
# a human's job and this stays offline rather than pretending otherwise.
#
# It ALERTS, it does not apply. A hypervisor has no rollback.
set -euo pipefail

MANIFEST=/etc/substrate/observability.manifest

log() { printf '%s %s\n' "$(date -Is)" "$*"; }

if [ ! -r "$MANIFEST" ]; then
    log "ERROR: $MANIFEST missing — has deploy-observability.py ever run here?"
    exit 1
fi

drift=0

# Files. `sha256sum -c` is the entire check: it reports each path and whether it
# still matches, and needs no configuration to do it.
if ! sha256sum -c --quiet "$MANIFEST" 2>&1 | sed 's/^/  /'; then
    log "DRIFT: installed files no longer match what was deployed"
    drift=1
fi

# Binaries. The manifest carries the version each component was pinned to at
# deploy time, in comment lines that sha256sum ignores — so one file describes
# the whole installed state and there is nothing to keep in step.
while IFS= read -r line; do
    name=${line%%=*}
    want=${line#*=}
    got="(absent)"
    stamp="/usr/local/lib/substrate-observability/$name"
    [ -r "$stamp" ] && got=$(cat "$stamp")
    if [ "$got" != "$want" ]; then
        log "DRIFT: $name is $got, was deployed as $want"
        drift=1
    fi
done < <(sed -n 's/^# pinned: //p' "$MANIFEST")

if [ "$drift" -ne 0 ]; then
    log "re-run deploy-observability.py to restore the deployed state"
    exit 1
fi

log "host matches what was deployed"
