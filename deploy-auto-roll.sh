#!/usr/bin/env bash
#
# Install the automated node-patching poller on ONE hypervisor.
#
# Completes the path from ADR-030:
#
#   Kairos release -> daily bump PR -> phone approval -> merge
#                  -> this poller (<=20 min) -> gate.py roll --yes
#                  -> nodes replaced one at a time, health-gated
#
# ⚠️ RUN ON EXACTLY ONE HOST (server1 by convention — where provisioning already
# happens). Two pollers would race to replace the same node; auto-roll.sh's
# lockfile only guards overlap on a single host.
#
# Usage (on that hypervisor):
#   sudo ./deploy-auto-roll.sh --repo-url git@github.com:bradpenney/substrate.git
#
# Two things a naive installer would get wrong, both handled below:
#
#   1. A FRESH CLONE HAS NO VENV. gate.py's shebang execs
#      `$(dirname $0)/.venv/bin/python3`, which does not exist in a bare clone,
#      so the poller could never run it. This creates one in the clone.
#
#   2. site.yml IS GITIGNORED, so the clone never contains it — yet hosts.py
#      cannot load without it. Rather than copy secrets into a git working tree,
#      site.yml is installed to /etc/substrate/site.yml (0600) and the unit
#      points at it via $SUBSTRATE_SITE_FILE.

set -euo pipefail

REPO_URL=""
BRANCH="${BRANCH:-main}"
STATE_DIR=/var/lib/substrate
REPO_DIR="$STATE_DIR/repo"
CONF_DIR=/etc/substrate
ADMIN_USER="${SUDO_USER:?run this via sudo (SUDO_USER must be set)}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-url) REPO_URL="$2"; shift 2 ;;
        --branch)   BRANCH="$2"; shift 2 ;;
        *) echo "usage: sudo $0 --repo-url <git-url> [--branch main]" >&2; exit 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "must run as root: sudo $0 ..." >&2; exit 1; }
[[ -n "$REPO_URL" ]] || { echo "--repo-url is required" >&2; exit 1; }
[[ -f "$SRC_DIR/site.yml" ]] || { echo "no site.yml beside $0 — run this from a configured checkout" >&2; exit 1; }

echo "==> installing auto-roll on $(hostname) (as $ADMIN_USER)"

# ---- 1. state + config directories, owned by the admin user ----
install -d -o "$ADMIN_USER" -g "$ADMIN_USER" -m 0755 "$STATE_DIR"
install -d -o root -g "$ADMIN_USER" -m 0750 "$CONF_DIR"

# ---- 2. site.yml to a system location, NOT into the git clone ----
# It carries the ghcr bootstrap token, so 0600 and owned by the service user.
install -o "$ADMIN_USER" -g "$ADMIN_USER" -m 0600 "$SRC_DIR/site.yml" "$CONF_DIR/site.yml"
echo "  [+] $CONF_DIR/site.yml (0600)"

# ---- 3. dedicated clone ----
# Deliberately NOT the operator's checkout: auto-roll.sh does `git reset --hard`,
# which would discard uncommitted work in a working tree someone is using.
if [[ ! -d "$REPO_DIR/.git" ]]; then
    sudo -u "$ADMIN_USER" git clone --quiet --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
    echo "  [+] cloned $REPO_URL -> $REPO_DIR"
else
    echo "  [ok] clone already present at $REPO_DIR"
fi

# ---- 4. venv inside the clone, because gate.py's shebang requires it ----
# Only PyYAML is needed: `roll` drives provision.py directly and never touches
# Ansible.
if [[ ! -x "$REPO_DIR/.venv/bin/python3" ]]; then
    sudo -u "$ADMIN_USER" python3 -m venv "$REPO_DIR/.venv"
    sudo -u "$ADMIN_USER" "$REPO_DIR/.venv/bin/pip" install --quiet --upgrade pip
    sudo -u "$ADMIN_USER" "$REPO_DIR/.venv/bin/pip" install --quiet pyyaml
    echo "  [+] venv created in the clone (PyYAML only)"
else
    echo "  [ok] venv already present"
fi

# ---- 5. environment file ----
cat > "$CONF_DIR/auto-roll.env" <<EOF
# Managed by deploy-auto-roll.sh — do not edit by hand.
REPO_URL=$REPO_URL
REPO_DIR=$REPO_DIR
BRANCH=$BRANCH
STATE_FILE=$STATE_DIR/last-rolled-sha256
# site.yml is gitignored, so the clone has none — point at the system copy.
SUBSTRATE_SITE_FILE=$CONF_DIR/site.yml
EOF
chmod 0640 "$CONF_DIR/auto-roll.env"
chgrp "$ADMIN_USER" "$CONF_DIR/auto-roll.env"
echo "  [+] $CONF_DIR/auto-roll.env"

# ---- 6. the script itself ----
# /usr/local/sbin, never $HOME: SELinux labels home directories `user_home_t`,
# and systemd cannot exec from there — it fails with a misleading
# "Permission denied ... 203/EXEC" even when the file is chmod +x. restorecon
# applies the correct label. (Learned during the server1 network cutover.)
install -o root -g root -m 0755 "$SRC_DIR/auto-roll.sh" /usr/local/sbin/auto-roll.sh
# `if`, not `A && B || true`: shellcheck SC2015 flags that form because the
# fallback runs when A succeeds and B fails, not only when A fails.
if command -v restorecon >/dev/null; then
    restorecon -F /usr/local/sbin/auto-roll.sh || true
fi
echo "  [+] /usr/local/sbin/auto-roll.sh"

# ---- 7. systemd units, with the admin user substituted in ----
# The unit ships a __ADMIN_USER__ placeholder so the repo carries no identity.
sed "s/__ADMIN_USER__/$ADMIN_USER/g" "$SRC_DIR/systemd/auto-roll.service" \
    > /etc/systemd/system/auto-roll.service
install -m 0644 "$SRC_DIR/systemd/auto-roll.timer" /etc/systemd/system/auto-roll.timer
install -m 0644 "$SRC_DIR/systemd/auto-roll-notify.service" \
    /etc/systemd/system/auto-roll-notify.service
chmod 0644 /etc/systemd/system/auto-roll.service
echo "  [+] systemd units installed"

# auto-roll.service now has OnFailure=auto-roll-notify.service, and that unit
# execs the notifier that deploy_updates.py installs. Without it the alert path
# is a dangling reference that only shows up as a journal line at 3am, on the
# one night it was needed.
if [[ ! -x /usr/local/bin/homelab-notify.sh ]]; then
    echo "  [!] WARNING: /usr/local/bin/homelab-notify.sh is missing."
    echo "      auto-roll failures will NOT notify. Run deploy_updates.py first."
elif [[ ! -r /etc/homelab/notify.env ]]; then
    echo "  [!] WARNING: /etc/homelab/notify.env is missing."
    echo "      auto-roll failures will NOT notify. Run deploy_updates.py first."
else
    echo "  [+] notifier present — auto-roll failures will alert"
fi

systemctl daemon-reload
systemctl enable --now auto-roll.timer
echo "  [+] auto-roll.timer enabled"

echo
echo "==> done."
echo
echo "    FIRST RUN ADOPTS the current pin WITHOUT rolling — otherwise installing"
echo "    this onto an already-correct cluster would immediately rebuild the fleet"
echo "    for nothing. Trigger it now to record the baseline:"
echo
echo "      sudo systemctl start auto-roll.service"
echo "      journalctl -u auto-roll -n 20 --no-pager"
echo
systemctl list-timers auto-roll.timer --no-pager | sed -n '1,2p'
