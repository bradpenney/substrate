#!/bin/bash
# Send a push notification via ntfy.
#
# Lives in substrate rather than ~/homelab because the units that need it run on
# BOTH hypervisors, and server2 has no ~/homelab checkout at all. The earlier
# notify unit pointed at /home/brad/homelab/notify.sh, which meant the alerting
# it provided silently did not exist on server2.
#
# NTFY_TOPIC is a capability URL — anyone holding it can publish to the topic —
# so it lives in a root-only file on the host, never in this repo.
set -euo pipefail

ENV_FILE="/etc/homelab/notify.env"
if [[ ! -r "$ENV_FILE" ]]; then
    echo "notify: $ENV_FILE missing or unreadable; cannot send alert" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "$ENV_FILE"

if [[ -z "${NTFY_TOPIC:-}" ]]; then
    echo "notify: NTFY_TOPIC unset in $ENV_FILE; cannot send alert" >&2
    exit 1
fi

TITLE="${1:-Homelab Alert}"
MESSAGE="${2:-Something needs your attention on $(hostname)}"

# -f is LOAD-BEARING. Without it curl exits 0 on any HTTP error — a wrong
# topic, a rate limit, ntfy returning 500 — so the script would report success
# having delivered nothing, systemd would log "Finished", and a total alerting
# outage would be indistinguishable from a quiet night.
#
# This is the same defect as the component nag calling `gh`, which exits 0
# without credentials and made a broken check look like good news. It matters
# more here: this is the channel every other alert in the estate depends on, so
# it is the one component whose silent failure hides all the others.
#
# ⚠️ WHAT -f STILL DOES NOT CATCH: ntfy.sh accepts ANY topic string. A typo in
# NTFY_TOPIC publishes successfully to a topic nobody is subscribed to, returns
# 200, and every alert vanishes silently forever. No exit code can detect that.
# The only real check is to publish and then POLL THE MESSAGE BACK:
#
#   curl -s "https://ntfy.sh/$NTFY_TOPIC/json?poll=1&since=10m"
#
# which is how the 2026-08-30 test was confirmed when the phone was broken. Worth
# adding to posture-check as a periodic canary — a notifier nobody has verified
# recently is a notifier nobody should trust.
if ! curl -fsS --max-time 20 \
  -H "Title: ${TITLE}" \
  -H "Priority: high" \
  -H "Tags: warning" \
  -d "${MESSAGE}" \
  "https://ntfy.sh/${NTFY_TOPIC}" > /dev/null; then
    # Journald is the fallback channel. If the push failed, the text must still
    # land somewhere a human can find it — losing the alert entirely because the
    # transport was down is the worst possible outcome for a notifier.
    echo "notify: DELIVERY FAILED — ${TITLE}: ${MESSAGE}" >&2
    exit 1
fi
