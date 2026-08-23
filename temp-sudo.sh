#!/usr/bin/env bash
#
# Grant / revoke a TIME-BOXED passwordless-sudo grant for provisioning runs.
#
# Why this exists: provisioning needs sudo many times over ~15 minutes with no
# TTY available to answer a password prompt. The alternatives were worse — a
# "least privilege" sudoers file with wildcards turned out to be a
# privilege-escalation hole (sudo's `*` matches `/`, so
# `-o /var/lib/libvirt/isos/../../../etc/shadow` would have matched), and
# leaving a permanent NOPASSWD grant is exactly what we're trying to avoid.
#
# So: a blunt but SHORT-LIVED grant, with an automatic expiry attached at the
# moment it's created — because a "temporary" grant on another host had
# already outlived its intent by hours. A grant you have to remember to remove
# is a grant that stays.
#
# Usage (as root):
#   sudo ./temp-sudo.sh grant [minutes]   # default 90
#   sudo ./temp-sudo.sh revoke
#   sudo ./temp-sudo.sh status

set -uo pipefail

USER_NAME="${SUDO_USER:?run this via sudo (SUDO_USER must be set)}"
SUDOERS_FILE="/etc/sudoers.d/91-${USER_NAME}-provisioning-temp"
TIMER_UNIT=revoke-temp-sudo

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "must run as root: sudo $0 $*" >&2
        exit 1
    fi
}

# Report ANY passwordless grant in sudoers.d, not just the one file this script
# manages. This exists because a mangled copy-paste once created a SECOND grant
# under a TRUNCATED filename (mode 0644, because the chmod never ran either).
# Removing the tracked file left root wide open via a file nothing
# was watching. Never trust the filename you expect — check what sudo actually
# honours.
scan_strays() {
    local found
    found=$(grep -rlE '^[^#]*NOPASSWD' /etc/sudoers.d/ 2>/dev/null || true)
    if [[ -n "$found" ]]; then
        echo
        echo "WARNING: other passwordless sudo grants are still present:"
        while IFS= read -r f; do
            printf '  %s  (mode %s)\n' "$f" "$(stat -c '%a' "$f")"
            sed 's/^/      /' "$f"
        done <<< "$found"
        echo "  Review and remove any that are not intentional."
    else
        echo "clean: no NOPASSWD grants remain in /etc/sudoers.d"
    fi
}

case "${1:-status}" in

grant)
    require_root "$@"
    minutes="${2:-90}"

    echo "$USER_NAME ALL=(ALL) NOPASSWD:ALL" > "$SUDOERS_FILE"
    chmod 0440 "$SUDOERS_FILE"

    # Validate BEFORE trusting it. A malformed file in sudoers.d is ignored
    # silently by sudo rather than erroring loudly, so a broken grant looks
    # identical to no grant at all.
    if ! visudo -c -q -f "$SUDOERS_FILE"; then
        echo "ERROR: sudoers file failed validation — removing" >&2
        rm -f "$SUDOERS_FILE"
        exit 1
    fi

    # Dead-man switch. Verify it actually got created: a previous attempt
    # left no trace at all, which meant the grant had no expiry and nobody
    # noticed.
    systemctl stop "${TIMER_UNIT}.timer" 2>/dev/null || true
    if systemd-run --unit="$TIMER_UNIT" --on-active="${minutes}min" \
            /usr/bin/rm -f "$SUDOERS_FILE" >/dev/null 2>&1 \
       && systemctl is-active "${TIMER_UNIT}.timer" >/dev/null 2>&1; then
        echo "granted: $SUDOERS_FILE"
        echo "auto-revokes in ${minutes} min:"
        systemctl list-timers "${TIMER_UNIT}.timer" --no-pager | sed -n 2p
    else
        echo "granted: $SUDOERS_FILE"
        echo "WARNING: could not arm the auto-revoke timer — REVOKE THIS MANUALLY:"
        echo "  sudo $0 revoke"
    fi
    ;;

revoke)
    require_root "$@"
    rm -f "$SUDOERS_FILE"
    systemctl stop "${TIMER_UNIT}.timer" 2>/dev/null || true
    systemctl reset-failed "${TIMER_UNIT}.timer" "${TIMER_UNIT}.service" 2>/dev/null || true
    echo "revoked: $SUDOERS_FILE removed"
    scan_strays
    ;;

status)
    # Must be root: /etc/sudoers.d is mode 0750 root-only, so an unprivileged
    # `[[ -e ]]` returns false even when the grant is live — reporting "not
    # granted" for a file that is very much still handing out root. Fail loudly
    # instead of answering wrongly.
    require_root "$@"
    if [[ -e "$SUDOERS_FILE" ]]; then
        echo "ACTIVE: $SUDOERS_FILE exists"
        systemctl list-timers "${TIMER_UNIT}.timer" --no-pager 2>/dev/null | sed -n 2p \
            || echo "  (no expiry timer armed — revoke manually when done)"
    else
        echo "not granted (this script's file is absent)"
    fi
    scan_strays
    ;;

*)
    echo "usage: $0 {grant [minutes]|revoke|status}" >&2
    exit 1
    ;;
esac
