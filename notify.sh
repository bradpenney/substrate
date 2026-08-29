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

curl -sS --max-time 20 \
  -H "Title: ${TITLE}" \
  -H "Priority: high" \
  -H "Tags: warning" \
  -d "${MESSAGE}" \
  "https://ntfy.sh/${NTFY_TOPIC}" > /dev/null
