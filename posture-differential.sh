#!/usr/bin/env bash
# Prove the Rust posture-check reaches the same verdict as the Python.
#
# WHY THIS EXISTS
# The renderer's port had goldens: byte-exact files, committed, two witnesses.
# posture-check has no such artefact -- its output describes a LIVE cluster and
# changes as the cluster does. So the contract is differential instead: run both
# implementations against the same cluster at the same moment, and require the
# lines they both claim to produce to be identical.
#
# WHAT THIS DOES AND DOES NOT PROVE.
# It proves the two AGREE on the checks Rust has ported, against the state the
# cluster happens to be in right now. It does NOT prove either is correct -- the
# same limitation the dual Python/Jinja renderer had, and the reason goldens
# replaced it (ADR-088). A healthy cluster exercises only the happy path of
# every check; the FAILURE paths are covered by the Rust unit tests in
# crates/substrate-core/tests/posture.rs, against fixtures the real cluster had
# better never match. The two halves together are the argument.
#
# Run it whenever a check is ported, and before retiring any Python check.
set -euo pipefail

cd "$(dirname "$0")"

# All THIRTEEN checks, ported, identified by the exact prefixes they emit.
# Adding a check to the Rust means adding its prefixes HERE too, or the
# differential silently stops comparing the new one -- a harness that quietly
# narrows its own scope is worse than no harness.
PORTED='^  \[(ok  |FAIL)\] (pod security: |namespaces with NO Pod Security enforcement: |network policy: |namespaces with NO default-deny NetworkPolicy: |cluster-admin: |UNEXPECTED cluster-admin subjects: |cluster-admin subjects removed since baseline: |admission: |admission policies MISSING: |no admission policy binding is set to Deny|flux: |Flux Kustomizations not Ready: |credentials: |ExternalSecrets not syncing |jit grant: |a jit-platform-admin grant |jit grant EXPIRED |host units: |systemd unit |systemd is degraded|selinux: |peer |public site|origin lock|ORIGIN LOCK BROKEN|supply chain: |the config artifact is |cosign verification |artifact signature |firewall: )'

BOLD=$'\033[1m'; OFF=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$OFF"; }

step "Building the Rust binary"
cargo build --quiet

step "Running both implementations against the same cluster"
# Either may exit non-zero if an invariant is genuinely broken. That is a
# finding about the CLUSTER, not about the port, so neither exit code fails
# this script -- only a DIFFERENCE between them does.
py_out=$(.venv/bin/python posture-check.py 2>&1 || true)
rs_out=$(./target/debug/substrate posture-check 2>&1 || true)

py_ported=$(printf '%s\n' "$py_out" | grep -E "$PORTED" | sort || true)
rs_ported=$(printf '%s\n' "$rs_out" | grep -E "$PORTED" | sort || true)

# Empty output comparing equal to empty output is exactly the failure this
# harness exists to prevent, so it is refused explicitly rather than passing.
if [ -z "$rs_ported" ]; then
    echo "FATAL: the Rust implementation produced none of the ported lines." >&2
    echo "Its full output was:" >&2
    printf '%s\n' "$rs_out" >&2
    exit 1
fi

step "Comparing"
if diff <(printf '%s\n' "$py_ported") <(printf '%s\n' "$rs_ported") > "/tmp/posture-diff.$$"; then
    n=$(printf '%s\n' "$rs_ported" | grep -c . || true)
    echo "  AGREE on all $n ported lines:"
    printf '%s\n' "$rs_ported" | sed 's/^/    /'
    rm -f "/tmp/posture-diff.$$"
else
    # ⚠️ A DIFFERENCE IS NOT YET A DIVERGENCE.
    #
    # The two implementations run SEQUENTIALLY against a LIVE cluster, so a
    # state that changes between them shows up here as a diff with nothing
    # wrong. Observed on 2026-09-10: the Python caught a Kustomization mid
    # `Progressing` and the Rust, a fraction of a second later, saw it Ready.
    # Reporting that as "the port does not reproduce the Python" is a false
    # alarm, and a harness that cries wolf on normal reconciliation is one
    # nobody runs twice.
    #
    # So: re-run both and compare again. A REAL divergence is deterministic and
    # survives; cluster drift does not. Only a difference that reproduces is
    # reported as a failure.
    echo "  differed on the first pass -- re-running to tell a real divergence"
    echo "  from a cluster that simply moved between the two runs"
    py2=$(.venv/bin/python posture-check.py 2>&1 || true)
    rs2=$(./target/debug/substrate posture-check 2>&1 || true)
    py2_ported=$(printf '%s\n' "$py2" | grep -E "$PORTED" | sort || true)
    rs2_ported=$(printf '%s\n' "$rs2" | grep -E "$PORTED" | sort || true)

    if diff <(printf '%s\n' "$py2_ported") <(printf '%s\n' "$rs2_ported") >/dev/null; then
        n=$(printf '%s\n' "$rs2_ported" | grep -c . || true)
        echo "  AGREE on all $n ported lines (the first difference was transient):"
        printf '%s\n' "$rs2_ported" | sed 's/^/    /'
        echo
        echo "  The transient difference was:"
        sed 's/^/    /' "/tmp/posture-diff.$$"
        rm -f "/tmp/posture-diff.$$"
    else
        echo "  DIVERGED -- the port does not reproduce the Python."
        echo "  The difference REPRODUCED on a second run, so it is not drift:"
        diff <(printf '%s\n' "$py2_ported") <(printf '%s\n' "$rs2_ported") | sed 's/^/    /'
        rm -f "/tmp/posture-diff.$$"
        exit 1
    fi
fi

step "Python checks NOT yet ported (still only in posture-check.py)"
printf '%s\n' "$py_out" | grep -E '^  \[(ok  |FAIL)\]' | grep -vE "$PORTED" | sed 's/^/    /' || echo "    none -- the port is complete"
