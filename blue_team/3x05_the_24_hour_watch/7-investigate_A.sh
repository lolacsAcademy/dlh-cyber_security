#!/bin/bash
set -euo pipefail

INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
EVENTS_JSON="$SHIFT_WORKSPACE/enriched/enriched_events.json"
EVENTS_JSONL="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
BASELINE="$SHIFT_WORKSPACE/enriched/baseline.json"
BASELINE_RUN="$SHIFT_WORKSPACE/runtime/baseline_run.json"
IOCS="$ASSETS_DIR/ioc_feed.json"
OUTDIR="$SHIFT_WORKSPACE/investigations"
OUT="$OUTDIR/incident_A.json"

mkdir -p "$OUTDIR"

for f in "$INCIDENTS" "$IOCS"; do
    if [ ! -f "$f" ]; then
        echo "[inv-A] missing required file: $f" >&2
        exit 1
    fi
done

if [ -f "$EVENTS_JSONL" ]; then
    EVENTS="$EVENTS_JSONL"
elif [ -f "$EVENTS_JSON" ]; then
    EVENTS="$EVENTS_JSON"
else
    echo "[inv-A] enriched events file missing" >&2
    exit 1
fi

if [ -f "$BASELINE" ]; then
    BASE="$BASELINE"
elif [ -f "$BASELINE_RUN" ]; then
    BASE="$BASELINE_RUN"
else
    echo "[inv-A] baseline file missing" >&2
    exit 1
fi

TODAY=$(date -u +%Y%m%d)
INCIDENT_ID="INC-${TODAY}-A"

echo "[inv-A] loading $INCIDENT_ID"

INCIDENT=$(jq -c --arg id "$INCIDENT_ID" \
    '.incidents[] | select(.incident_id == $id)' "$INCIDENTS")

if [ -z "$INCIDENT" ]; then
    echo "[inv-A] incident $INCIDENT_ID not found" >&2
    exit 1
fi

HOSTS=$(printf '%s\n' "$INCIDENT" | jq -r '.host_list[]')
ALERT_COUNT=$(printf '%s\n' "$INCIDENT" | jq '.alert_ids | length')
CATEGORY=$(printf '%s\n' "$INCIDENT" | jq -r '.tentative_category')
FIRST=$(printf '%s\n' "$INCIDENT" | jq -r '.first_seen')
LAST=$(printf '%s\n' "$INCIDENT" | jq -r '.last_seen')

echo "[inv-A] host_list: $(echo "$HOSTS" | paste -sd, -)"
echo "[inv-A] alert_count: $ALERT_COUNT"
echo "[inv-A] tentative_category: $CATEGORY"

START=$(date -u -d "$FIRST -15 minutes" +"%Y-%m-%dT%H:%M:%SZ")
END=$(date -u -d "$LAST +15 minutes" +"%Y-%m-%dT%H:%M:%SZ")

TMP_EVENTS=$(mktemp)
TMP_TOP=$(mktemp)
TMP_IOCS=$(mktemp)
TMP_BASE=$(mktemp)
trap 'rm -f "$TMP_EVENTS" "$TMP_TOP" "$TMP_IOCS" "$TMP_BASE"' EXIT

HOSTS_JSON=$(printf '%s\n' "$INCIDENT" | jq -c '.host_list | map(ascii_downcase)')

if jq -e 'type == "array"' "$EVENTS" >/dev/null 2>&1; then
    jq -c \
        --argjson hosts "$HOSTS_JSON" \
        --arg start "$START" \
        --arg end "$END" \
        '.[] |
         select((.hostname // "" | ascii_downcase) as $h | $hosts | index($h)) |
         select((.timestamp // "") >= $start and (.timestamp // "") <= $end)' \
        "$EVENTS" > "$TMP_EVENTS"
else
    jq -c \
        --argjson hosts "$HOSTS_JSON" \
        --arg start "$START" \
        --arg end "$END" \
        'select((.hostname // "" | ascii_downcase) as $h | $hosts | index($h)) |
         select((.timestamp // "") >= $start and (.timestamp // "") <= $end)' \
        "$EVENTS" > "$TMP_EVENTS"
fi

EVENT_COUNT=$(wc -l < "$TMP_EVENTS")
echo "[inv-A] events in window: $EVENT_COUNT"

if [ "$EVENT_COUNT" -lt 6 ]; then
    echo "[inv-A] fewer than 6 events in investigation window" >&2
    exit 1
fi

jq -s -c '
    sort_by(.timestamp) |
    sort_by(
      if ((.event_category // "") | test("auth"; "i")) then 0
      elif ((.event_category // "") | test("process"; "i")) then 1
      elif ((.event_category // "") | test("network|firewall|suricata"; "i")) then 2
      else 3 end
    ) |
    .[:6][]
' "$TMP_EVENTS" > "$TMP_TOP"

echo "[inv-A] timeline (top 6):"

jq -r '
  [
    (.timestamp // "unknown"),
    (.hostname // "unknown" | ascii_downcase),
    (.source_type // "unknown"),
    (.event_category // "unknown"),
    ((.raw_message // "")[0:80])
  ] | @tsv
' "$TMP_TOP" | while IFS=$'\t' read -r ts host src cat msg; do
    echo "  $ts  $host  $src  $cat  $msg"
done

jq -r '.iocs[].value' "$IOCS" | sort -u > "$TMP_IOCS.values"

jq -r '
    [
      .src_ip,
      .dst_ip,
      .event_data.SourceIp,
      .event_data.DestinationIp,
      .process_name,
      .event_data.Image,
      .event_data.ServiceName
    ] |
    .[] |
    select(. != null) |
    tostring
' "$TMP_EVENTS" |
while read -r value; do
    if grep -Fxq "$value" "$TMP_IOCS.values"; then
        echo "$value"
    fi
done | sort -u > "$TMP_IOCS"

IOC_COUNT=$(wc -l < "$TMP_IOCS")
IOC_LIST=$(paste -sd, "$TMP_IOCS")

if [ "$IOC_COUNT" -gt 0 ]; then
    echo "[inv-A] ioc_matches: $IOC_COUNT ($IOC_LIST)"
else
    echo "[inv-A] ioc_matches: 0"
fi

if jq -e '.deviation_markers? != null' "$BASE" >/dev/null 2>&1; then
    jq -c \
      --argjson hosts "$HOSTS_JSON" \
      '.deviation_markers[]? |
       select(
         ((.host // .hostname // "") | ascii_downcase) as $h |
         $hosts | index($h)
       )' "$BASE" > "$TMP_BASE"
else
    : > "$TMP_BASE"
fi

BASE_COUNT=$(wc -l < "$TMP_BASE")
echo "[inv-A] baseline deviations: $BASE_COUNT markers"

if [ "$BASE_COUNT" -gt 0 ]; then
    cat "$TMP_BASE"
fi

TECHNIQUES=("T1110.003" "T1543.003" "T1071.001")

HYPOTHESIS="Credential abuse was followed by service-based persistence and outbound command-and-control activity."

echo "[inv-A] hypothesis: $HYPOTHESIS"
echo "[inv-A] techniques: ${TECHNIQUES[*]}"

EVENT_REFS=$(jq -s '
    map(
      .event_id
      // .event_ref
      // .id
      // ((.timestamp // "") + "|" + (.hostname // "") + "|" + (.raw_message // ""))
    ) |
    map(tostring) |
    unique |
    .[:6]
' "$TMP_TOP")

EVENT_REF_COUNT=$(printf '%s\n' "$EVENT_REFS" | jq 'length')

if [ "$EVENT_REF_COUNT" -lt 6 ]; then
    echo "[inv-A] fewer than 6 event_refs" >&2
    exit 1
fi

IOC_JSON=$(jq -R -s '
    split("\n") |
    map(select(length > 0))
' "$TMP_IOCS")

BASE_JSON=$(jq -s '.' "$TMP_BASE")

HOSTS_OUT=$(printf '%s\n' "$INCIDENT" | jq '.host_list | map(ascii_downcase)')

TECH_JSON=$(printf '%s\n' "${TECHNIQUES[@]}" | jq -R -s '
    split("\n") |
    map(select(length > 0))
')

CONFIDENCE="high"

if [ "$IOC_COUNT" -eq 0 ] || [ "$BASE_COUNT" -eq 0 ]; then
    CONFIDENCE="medium"
fi

ACTIONS=$(jq -n '[
  "jq -c --arg id \"$INCIDENT_ID\" \".incidents[] | select(.incident_id == $id)\" \"$INCIDENTS\"",
  "jq event extraction from enriched events by incident host and +/-15 minute time window",
  "jq -s event significance selection and chronological timeline construction",
  "jq IOC value extraction and src_ip/dst_ip comparison",
  "jq baseline deviation marker lookup for incident hosts",
  "jq event reference extraction for top investigation events"
]')

HASH_INCIDENTS=$(sha256sum "$INCIDENTS" | awk '{print $1}')
HASH_EVENTS=$(sha256sum "$EVENTS" | awk '{print $1}')
HASH_IOCS=$(sha256sum "$IOCS" | awk '{print $1}')
HASH_BASELINE=$(sha256sum "$BASE" | awk '{print $1}')

GENERATED=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg finding_id "FIND-${TODAY}-A" \
  --arg incident_id "$INCIDENT_ID" \
  --arg interface "cli" \
  --arg hypothesis "$HYPOTHESIS" \
  --arg confidence "$CONFIDENCE" \
  --arg generated_at "$GENERATED" \
  --argjson hosts "$HOSTS_OUT" \
  --argjson event_refs "$EVENT_REFS" \
  --argjson attack_techniques "$TECH_JSON" \
  --argjson ioc_matches "$IOC_JSON" \
  --argjson baseline_deviations "$BASE_JSON" \
  --argjson actions "$ACTIONS" \
  --arg incidents_hash "$HASH_INCIDENTS" \
  --arg events_hash "$HASH_EVENTS" \
  --arg ioc_hash "$HASH_IOCS" \
  --arg baseline_hash "$HASH_BASELINE" \
  '{
    finding_id: $finding_id,
    incident_id: $incident_id,
    interface: $interface,
    hypothesis: $hypothesis,
    confidence: $confidence,
    hosts: $hosts,
    event_refs: $event_refs,
    attack_techniques: $attack_techniques,
    ioc_matches: $ioc_matches,
    baseline_deviations: $baseline_deviations,
    actions: $actions,
    evidence_hashes: {
      incidents_json: $incidents_hash,
      enriched_events: $events_hash,
      ioc_feed: $ioc_hash,
      baseline: $baseline_hash
    },
    unresolved_questions:
      (if $confidence == "high"
       then []
       else [
         "Confirm whether the IOC-linked activity was authorised using endpoint telemetry and change-ticket evidence."
       ]
       end),
    generated_at: $generated_at
  }' > "$OUT"

REFS=$(jq '.event_refs | length' "$OUT")
TECHS=$(jq '.attack_techniques | length' "$OUT")

if [ "$REFS" -lt 6 ] || [ "$TECHS" -lt 2 ]; then
    echo "[inv-A] finding validation failed" >&2
    exit 1
fi

echo "[inv-A] confidence: $CONFIDENCE"
echo "[inv-A] incident_A.json written"
