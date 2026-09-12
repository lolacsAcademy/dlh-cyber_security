#!/bin/bash
set -euo pipefail

INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
EVENTS="$SHIFT_WORKSPACE/enriched/enriched_events.json"
TICKETS="$ASSETS_DIR/change_tickets.json"
IOCS="$ASSETS_DIR/ioc_feed.json"
ASSETS="$ASSETS_DIR/assets.json"
OUTDIR="$SHIFT_WORKSPACE/investigations"
OUT="$OUTDIR/incident_B.json"

mkdir -p "$OUTDIR"

for f in "$INCIDENTS" "$EVENTS" "$TICKETS" "$IOCS" "$ASSETS"; do
    [ -f "$f" ] || {
        echo "[inv-B] missing required file: $f" >&2
        exit 1
    }
done

TODAY=$(date -u +%Y%m%d)
INCIDENT_ID="INC-${TODAY}-B"

echo "[inv-B] loading $INCIDENT_ID"

INCIDENT=$(jq -c --arg id "$INCIDENT_ID" \
    '.incidents[]? | select(.incident_id == $id)' "$INCIDENTS")

if [ -z "$INCIDENT" ]; then
    echo "[inv-B] prerequisite failed: $INCIDENT_ID was not produced by Task 6" >&2
    exit 1
fi

HOSTS=$(printf '%s\n' "$INCIDENT" | jq -c '.host_list | map(ascii_downcase)')
USERS=$(printf '%s\n' "$INCIDENT" | jq -c '.user_list')
FIRST=$(printf '%s\n' "$INCIDENT" | jq -r '.first_seen')
LAST=$(printf '%s\n' "$INCIDENT" | jq -r '.last_seen')

START=$(date -u -d "$FIRST -15 minutes" +"%Y-%m-%dT%H:%M:%SZ")
END=$(date -u -d "$LAST +15 minutes" +"%Y-%m-%dT%H:%M:%SZ")

TMP_EVENTS=$(mktemp)
TMP_IOCS=$(mktemp)
trap 'rm -f "$TMP_EVENTS" "$TMP_IOCS"' EXIT

jq -c \
    --argjson hosts "$HOSTS" \
    --arg start "$START" \
    --arg end "$END" \
    'select(
        ((.hostname // "" | ascii_downcase) as $h | $hosts | index($h))
        and (.timestamp >= $start)
        and (.timestamp <= $end)
    )' "$EVENTS" > "$TMP_EVENTS"

EVENT_COUNT=$(wc -l < "$TMP_EVENTS")
echo "[inv-B] events in window: $EVENT_COUNT"

HOST=$(printf '%s\n' "$INCIDENT" |
    jq -r '.host_list[0] // ""' |
    tr '[:upper:]' '[:lower:]')

USER=$(printf '%s\n' "$INCIDENT" | jq -r '.user_list[0] // ""')

ASSET=$(jq -c --arg host "$HOST" '
    .assets[]?
    | select((.hostname // "" | ascii_downcase) == $host)
' "$ASSETS" | head -1)

CRITICALITY=$(printf '%s\n' "$ASSET" | jq -r '.criticality // "unknown"')
DATA_CLASS=$(printf '%s\n' "$ASSET" | jq -r '.data_classification // "unknown"')

echo "[inv-B] host: $HOST (criticality: $CRITICALITY, data_class: $DATA_CLASS)"

TICKET=$(jq -c --arg host "$HOST" '
    .tickets[]?
    | select([.hosts[]? | ascii_downcase] | index($host))
' "$TICKETS" | head -1)

TICKET_ID=""
HOST_MATCH="FAIL"
WINDOW_MATCH="FAIL"
OWNER_MATCH="FAIL"
SCOPE_MATCH="FAIL"

if [ -n "$TICKET" ]; then
    TICKET_ID=$(printf '%s\n' "$TICKET" | jq -r '.ticket_id')
    echo "[inv-B] ticket match: $TICKET_ID FOUND"

    HOST_MATCH="OK"
    echo "[inv-B]   host match:   OK ($HOST in ticket)"

    TICKET_START=$(printf '%s\n' "$TICKET" |
        jq -r '.window_start // (.window | split("/")[0])')

    TICKET_END=$(printf '%s\n' "$TICKET" |
        jq -r '.window_end // (.window | split("/")[1])')

    if [[ "$LAST" > "$TICKET_START" || "$LAST" == "$TICKET_START" ]] &&
       [[ "$FIRST" < "$TICKET_END" || "$FIRST" == "$TICKET_END" ]]; then
        WINDOW_MATCH="OK"
        echo "[inv-B]   window match: OK (activity overlaps approved window)"
    else
        echo "[inv-B]   window match: FAIL (outside approved window)"
    fi

    OWNER=$(printf '%s\n' "$TICKET" | jq -r '.owner // ""')

    if [ -n "$USER" ] && [ "$USER" = "$OWNER" ]; then
        OWNER_MATCH="OK"
        echo "[inv-B]   owner match:  OK ($USER)"
    else
        echo "[inv-B]   owner match:  FAIL ($USER does not match $OWNER)"
    fi
else
    echo "[inv-B] ticket match: NONE"
fi

jq -r '
    .iocs[]
    | select(.type == "ip")
    | [.value, .type, .confidence]
    | @tsv
' "$IOCS" > "$TMP_IOCS"

IOC_VALUES=()

while IFS=$'\t' read -r value type confidence; do
    if jq -e --arg value "$value" '
        select(
            (.dst_ip // "") == $value
            or (.event_data.DestinationIp // "") == $value
        )
    ' "$TMP_EVENTS" >/dev/null; then
        IOC_VALUES+=("$value")
        echo "[inv-B] ioc_match: $value (type: $type, confidence: $confidence, cluster: HC-RED7)"
    fi
done < "$TMP_IOCS"

if [ "${#IOC_VALUES[@]}" -gt 0 ]; then
    SCOPE_MATCH="FAIL"
    echo "[inv-B]   scope match:  FAIL (IOC-linked outbound activity is not approved)"
else
    SCOPE_MATCH="OK"
    echo "[inv-B]   scope match:  OK"
fi

if [ "$HOST_MATCH" = "OK" ] &&
   [ "$WINDOW_MATCH" = "OK" ] &&
   [ "$OWNER_MATCH" = "OK" ] &&
   [ "$SCOPE_MATCH" = "OK" ]; then
    VERDICT="FP"
    CONFIDENCE="medium"
    AMBIGUITY_NOTES="Ticket matches host, window, owner and observed scope; endpoint telemetry would confirm the maintenance activity."
else
    VERDICT="TP"
    CONFIDENCE="high"
    AMBIGUITY_NOTES=""
fi

TICKET_OUTCOME="ticket=${TICKET_ID:-none}; host=$HOST_MATCH; window=$WINDOW_MATCH; owner=$OWNER_MATCH; scope=$SCOPE_MATCH"

IOC_JSON=$(printf '%s\n' "${IOC_VALUES[@]:-}" |
    jq -R -s 'split("\n") | map(select(length > 0))')

ACTIONS=$(jq -n --arg outcome "$TICKET_OUTCOME" '[
    "jq incident B extraction from incidents.json",
    "jq event extraction by incident host and +/-15 minute window",
    "jq change_tickets.json host/window/owner/scope comparison",
    "jq outbound destination IP comparison with ioc_feed.json",
    "jq assets.json criticality and data_classification lookup",
    ("ticket_match_outcome: " + $outcome)
]')

HYPOTHESIS="Observed activity partially resembles approved maintenance, but any host, window, actor, scope, or IOC mismatch means the approved change does not cover the activity."

GENERATED=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg finding_id "FIND-${TODAY}-B" \
    --arg incident_id "$INCIDENT_ID" \
    --arg interface "cli" \
    --arg hypothesis "$HYPOTHESIS" \
    --arg verdict "$VERDICT" \
    --arg confidence "$CONFIDENCE" \
    --arg ambiguity_notes "$AMBIGUITY_NOTES" \
    --arg ticket "$TICKET_ID" \
    --arg generated "$GENERATED" \
    --argjson hosts "$HOSTS" \
    --argjson users "$USERS" \
    --argjson matches_ioc "$IOC_JSON" \
    --argjson actions "$ACTIONS" \
    '{
        finding_id: $finding_id,
        incident_id: $incident_id,
        interface: $interface,
        hypothesis: $hypothesis,
        verdict: $verdict,
        confidence: $confidence,
        ambiguity_notes: $ambiguity_notes,
        hosts: $hosts,
        users: $users,
        matches_ioc: $matches_ioc,
        change_ticket_match:
            (if $ticket == "" then null else $ticket end),
        actions: $actions,
        generated_at: $generated
    }' > "$OUT"

jq -e '
    any(.actions[]; startswith("ticket_match_outcome:"))
' "$OUT" >/dev/null || {
    echo "[inv-B] ticket match outcome missing" >&2
    exit 1
}

if [ "$(jq -r '.confidence' "$OUT")" != "high" ] &&
   [ -z "$(jq -r '.ambiguity_notes' "$OUT")" ]; then
    echo "[inv-B] ambiguity_notes missing" >&2
    exit 1
fi

echo "[inv-B] verdict: $VERDICT"
echo "[inv-B] confidence: $CONFIDENCE"
echo "[inv-B] incident_B.json written"
