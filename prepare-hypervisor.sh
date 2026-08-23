#!/usr/bin/env bash
#
# One-time host preparation for a machine that will run k0s node VMs.
#
# WHY THIS EXISTS
# Provisioning used to require blanket passwordless sudo on every hypervisor.
# That was never inherent — it was an artefact of `/var/lib/libvirt/isos` being
# root-owned 0711. The privileged operations were only ever:
#
#   curl / mkisofs / chmod  -> writing into the ISO pool directory
#   sha256sum               -> reading a file in it
#   chattr +C               -> the btrfs VM-disk pool dir (btrfs hosts only)
#
# `virsh` never needed root at all, because the admin user is in the `libvirt`
# group.
#
# So instead of CONSTRAINING the privilege (a forced-command SSH key was the
# original plan), this ELIMINATES it: make the ISO pool group-writable by
# `libvirt`, and the whole provisioning path runs unprivileged. On btrfs hosts a
# single narrow sudoers rule remains for `chattr`.
#
# A forced-command key would have wrapped root-equivalent operations anyway —
# real constraint, questionable benefit. Removing the requirement beats gating
# it.
#
# This script also exists so hypervisor state stops being hand-made: a new host
# is prepared by running this, not by remembering what was typed once.
#
# Usage (on the hypervisor, as a user with sudo):
#   sudo ./prepare-hypervisor.sh [--btrfs-pool /var/lib/libvirt/images]

set -euo pipefail

ISO_POOL_PATH="${ISO_POOL_PATH:-/var/lib/libvirt/isos}"
BTRFS_POOL=""
ADMIN_USER="${SUDO_USER:?run this via sudo (SUDO_USER must be set)}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --btrfs-pool) BTRFS_POOL="$2"; shift 2 ;;
        *) echo "usage: sudo $0 [--btrfs-pool <dir>]" >&2; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo $0" >&2
    exit 1
fi

echo "==> preparing $(hostname) for k0s VM hosting (admin user: $ADMIN_USER)"

# ---- 1. admin user must be able to drive libvirt unprivileged ----
if id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx libvirt; then
    echo "  [ok] $ADMIN_USER already in the libvirt group"
else
    usermod -aG libvirt "$ADMIN_USER"
    echo "  [+]  added $ADMIN_USER to the libvirt group (re-login required)"
fi

# ---- 2. ISO pool writable by the libvirt group ----
# setgid (2775) so files CREATED here inherit the libvirt group, which is what
# lets a later run read/modify them without root.
mkdir -p "$ISO_POOL_PATH"
chgrp libvirt "$ISO_POOL_PATH"
chmod 2775 "$ISO_POOL_PATH"
# Existing files predate the change and may be root- or qemu-owned.
chgrp libvirt "$ISO_POOL_PATH"/* 2>/dev/null || true
chmod g+rw    "$ISO_POOL_PATH"/* 2>/dev/null || true
echo "  [+]  $ISO_POOL_PATH -> root:libvirt 2775 (group-writable, setgid)"

# ---- 3. btrfs hosts only: one narrow sudoers rule for chattr ----
#
# VM images on a copy-on-write filesystem fragment badly, so the pool dir needs
# `chattr +C` before the first image is created. That needs root, and the dir is
# libvirt-managed so we don't want to reassign its ownership.
#
# ⚠️ NO WILDCARDS. An earlier draft used `chattr +C /var/lib/libvirt/images/*`,
# which is NOT least privilege: sudo's `*` matches `/` too, so
# `../../etc/shadow` would have satisfied the rule. This is an exact command
# with fixed arguments — nothing else, no traversal possible.
if [[ -n "$BTRFS_POOL" ]]; then
    SUDOERS=/etc/sudoers.d/60-substrate-chattr
    cat > "$SUDOERS" <<EOF
# Managed by substrate/prepare-hypervisor.sh — do not edit by hand.
# Exactly two fixed commands, no wildcards, no path traversal possible.
$ADMIN_USER ALL=(root) NOPASSWD: /usr/bin/chattr +C $BTRFS_POOL
$ADMIN_USER ALL=(root) NOPASSWD: /usr/bin/lsattr -d $BTRFS_POOL
EOF
    chmod 0440 "$SUDOERS"
    # Validate before trusting it: a malformed file in sudoers.d is IGNORED
    # silently rather than erroring, so a broken rule looks identical to none.
    if ! visudo -c -q -f "$SUDOERS"; then
        echo "  ERROR: sudoers rule failed validation — removing" >&2
        rm -f "$SUDOERS"
        exit 1
    fi
    echo "  [+]  $SUDOERS -> chattr/lsattr on $BTRFS_POOL only"
else
    echo "  [--] no --btrfs-pool given; skipping the chattr sudoers rule"
    echo "       (correct for LVM-backed pools, which need no chattr)"
fi

echo
echo "==> done. Provisioning should now need NO blanket sudo on this host."
echo "    Verify:  sudo -n true   # should FAIL"
echo "             virsh -c qemu:///system list --all   # should WORK"
