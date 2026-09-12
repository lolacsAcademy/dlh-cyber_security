#!/bin/bash
set -euo pipefail

META="$ASSETS_DIR"

if [ ! -f "$META/hc_red7_advisory.md" ]; then
    META="$HOME/3x05_assets/capstone_pack/meta"
fi

ADVISORY="$META/hc_red7_advisory.md"
IOC="$META/ioc_feed.json"
TICKETS="$META/change_tickets.json"
NOTES="$META/prior_shift_notes.md"
BASELINE="$SHIFT_WORKSPACE/runtime/baseline_run.json"
SHIFT_START="$SHIFT_WORKSPACE/runtime/shift_start.json"
OUTPUT="$SHIFT_WORKSPACE/alerts/shift_briefing.json"

for f in "$ADVISORY" "$IOC" "$TICKETS" "$NOTES" "$BASELINE" "$SHIFT_START"; do
    [ -s "$f" ] || {
        echo "[brief] missing: $f"
        exit 1
    }
done

echo "[brief] checking input files... OK"

CLUSTER=$(grep -m1 -o 'HC-RED7' "$ADVISORY")
EXPECTED=$(jq -r '.advisory_cluster_id' "$SHIFT_START")

[ "$CLUSTER" = "$EXPECTED" ] || {
    echo "[brief] cluster ID cross-check: FAILED"
    exit 1
}

echo "[brief] cluster $CLUSTER loaded"

TACTICS=$(grep -oE 'T[0-9]{4}(\.[0-9]{3})?' "$ADVISORY" | sort -u)

IOC_COUNT=$(jq '.iocs | length' "$IOC")

IOC_BY_TYPE=$(jq '
  {
    ip:          ([.iocs[] | select(.type=="ip")] | length),
    domain:      ([.iocs[] | select(.type=="domain")] | length),
    hash:        ([.iocs[] | select(.type=="hash")] | length),
    account:     ([.iocs[] | select(.type=="account")] | length),
    service_name:([.iocs[] | select(.type=="service_name")] | length),
    port:        ([.iocs[] | select(.type=="port")] | length)
  }
' "$IOC")

IOC_VALUES=$(jq '[.iocs[].value]' "$IOC")

echo "[brief] tactics: $(echo "$TACTICS" | tr '\n' ' ')"
echo "[brief] IOCs: ip=$(jq -r '.ip' <<<"$IOC_BY_TYPE") domain=$(jq -r '.domain' <<<"$IOC_BY_TYPE") hash=$(jq -r '.hash' <<<"$IOC_BY_TYPE") account=$(jq -r '.account' <<<"$IOC_BY_TYPE") service_name=$(jq -r '.service_name' <<<"$IOC_BY_TYPE") port=$(jq -r '.port' <<<"$IOC_BY_TYPE") total=$IOC_COUNT"

ACTIVE_TICKETS=$(jq '
  [.tickets[] | {
    ticket_id,
    window_start: (.window | split("/")[0]),
    window_end: (.window | split("/")[1]),
    hosts,
    owner,
    approved_activity
  }]
' "$TICKETS")

TICKET_COUNT=$(jq 'length' <<<"$ACTIVE_TICKETS")
echo "[brief] active change tickets in window: $TICKET_COUNT"

OPEN_ITEMS=$(awk '
    /^## Open Items for Next Shift/ {on=1; next}
    /^## / {on=0}
    on && /^[0-9]+\./ {
        sub(/^[0-9]+\. /, "")
        gsub(/^[*][*]/, "")
        gsub(/[*][*].*$/, "")
        print
    }
' "$NOTES" | jq -R -s 'split("\n") | map(select(length > 0))')

HOT_HOSTS=$(jq '.hot_hosts' "$BASELINE")
DEVIATIONS=$(jq '.hosts_with_deviations' "$BASELINE")

jq -n \
  --arg cluster "$CLUSTER" \
  --argjson tactics "$(printf '%s\n' "$TACTICS" | jq -R -s 'split("\n") | map(select(length > 0))')" \
  --argjson ioc_count "$IOC_COUNT" \
  --argjson ioc_by_type "$IOC_BY_TYPE" \
  --argjson ioc_values "$IOC_VALUES" \
  --argjson tickets "$ACTIVE_TICKETS" \
  --argjson open_items "$OPEN_ITEMS" \
  --argjson hot_hosts "$HOT_HOSTS" \
  --argjson deviations "$DEVIATIONS" \
  '{
    cluster_id: $cluster,
    cluster_tactics: $tactics,
    ioc_count: $ioc_count,
    ioc_by_type: $ioc_by_type,
    ioc_values: $ioc_values,
    active_change_tickets: $tickets,
    prior_shift_open_items: $open_items,
    baseline_hot_hosts: $hot_hosts,
    hosts_with_deviations: $deviations
  }' > "$OUTPUT"

echo "[brief] prior shift open items: $(jq 'length' <<<"$OPEN_ITEMS")"
echo "[brief] baseline hot hosts: $(jq 'length' <<<"$HOT_HOSTS")"
echo "[brief] cluster ID cross-check: OK"
echo "[brief] shift_briefing.json written"
