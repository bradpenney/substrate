#!/usr/bin/env bash
# Assert a built binary needs no shared libraries.
#
# The whole distribution story (ADR-093) rests on `curl | bash` dropping ONE
# file onto a Kairos node. A dynamically linked artifact still runs on the
# builder and fails on the node, which is the worst possible place to find out
# — so this is asserted rather than inferred from the target triple.
#
# THIS EXISTS AS A SCRIPT, NOT AN INLINE CI STEP, ON PURPOSE.
# The first version was inline and wrong: it grepped `file` output for
# "statically linked", which is `ldd`'s wording. `file` says "static-pie
# linked". The binary was correct and the check was not, and it was never run
# locally because it only existed inside the workflow (ADR-090, third
# occurrence). A script can be run exactly as CI runs it.
set -euo pipefail

BIN=${1:?usage: check-static-binary.sh <path-to-binary>}

if [ ! -f "$BIN" ]; then
    echo "error: $BIN does not exist — was it built?" >&2
    exit 1
fi

# Two independent witnesses, because each has a blind spot. `file` reads the ELF
# header and reports the link mode; `ldd` actually resolves the interpreter and
# lists what would be loaded at runtime.
file_out=$(file "$BIN")
# `static-pie linked` is what a musl PIE build reports; `statically linked` is
# the non-PIE form. Both are static — accept either, name both.
if ! printf '%s' "$file_out" | grep -qE 'static-pie linked|statically linked'; then
    echo "error: $BIN is not statically linked" >&2
    echo "  file: $file_out" >&2
    exit 1
fi

# A dynamic binary's ldd output contains `=>` lines resolving each shared
# object. A static one says "statically linked" or "not a dynamic executable".
# Checking for the ABSENCE of resolutions is the robust form: it does not
# depend on which of those two phrasings the local libc's ldd chooses.
ldd_out=$(ldd "$BIN" 2>&1 || true)
if printf '%s' "$ldd_out" | grep -q '=>'; then
    echo "error: $BIN resolves shared libraries at runtime" >&2
    printf '%s\n' "$ldd_out" >&2
    exit 1
fi

echo "ok: $BIN is static ($(du -h "$BIN" | cut -f1))"
echo "  file: $file_out"
