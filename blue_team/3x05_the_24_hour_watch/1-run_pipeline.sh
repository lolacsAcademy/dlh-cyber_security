#!/bin/bash
set -euo pipefail

fail() {
    echo "[pipeline] ERROR: $1" >&2
    exit 1
}

test -s "$SHIFT_WORKSPACE/runtime/shift_start.json" \
    || fail "shift_start.json missing or empty"

START_EPOCH=$(date +%s)
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

OUT="$SHIFT_WORKSPACE/enriched"
LOG="$SHIFT_WORKSPACE/runtime/pipeline_run.log"

mkdir -p "$OUT" "$SHIFT_WORKSPACE/runtime"

echo "[pipeline] intake check ... ok"
echo "[pipeline] invoking $PIPELINE_BIN"
echo "[pipeline] input: $CAPSTONE_PACK"
echo "[pipeline] output: $OUT"

set +e
"$PIPELINE_BIN" "$CAPSTONE_PACK" "$OUT" 2>&1 | tee "$LOG"
STATUS=${PIPESTATUS[0]}
set -e

[ "$STATUS" -eq 0 ] || fail "pipeline failed (exit $STATUS)"

EVENTS=""
TIMELINE=""

for file in enriched_events.jsonl enriched_events.json; do
    if [ -s "$OUT/$file" ]; then
        EVENTS="$OUT/$file"
        break
    fi
done

[ -n "$EVENTS" ] \
    || fail "enriched_events.jsonl or enriched_events.json missing or empty"

for file in timeline.jsonl timeline_index.json; do
    if [ -s "$OUT/$file" ]; then
        TIMELINE="$OUT/$file"
        break
    fi
done

[ -n "$TIMELINE" ] \
    || fail "timeline.jsonl or timeline_index.json missing or empty"

[ -s "$OUT/source_stats.json" ] \
    || fail "source_stats.json missing or empty"

WINDOWS=$(jq -r '.source_counts.windows_json // 0' "$OUT/source_stats.json")
LINUX=$(jq -r '.source_counts.linux_text // 0' "$OUT/source_stats.json")
FIREWALL=$(jq -r '.source_counts.firewall // 0' "$OUT/source_stats.json")
SURICATA=$(jq -r '.source_counts.suricata_alert // 0' "$OUT/source_stats.json")
PCAP=$(jq -r '.source_counts.pcap_flow // 0' "$OUT/source_stats.json")

echo "[pipeline] source windows_json=$WINDOWS"
echo "[pipeline] source linux_text=$LINUX"
echo "[pipeline] source firewall=$FIREWALL"
echo "[pipeline] source suricata_alert=$SURICATA"
echo "[pipeline] source pcap_flow=$PCAP"

NONZERO=0
for count in "$WINDOWS" "$LINUX" "$FIREWALL" "$SURICATA" "$PCAP"; do
    [ "$count" -gt 0 ] && NONZERO=$((NONZERO + 1))
done

[ "$NONZERO" -ge 4 ] \
    || fail "fewer than four source types have non-zero counts"

EVENTS_IN=$(jq -r '.events_in // 0' "$OUT/source_stats.json")
EVENTS_OUT=$(jq -r '.events_out // .total_events // 0' "$OUT/source_stats.json")
EVENTS_DROPPED=$(jq -r '.events_dropped // 0' "$OUT/source_stats.json")
DIRTY=$(jq -c '.dirty_data_detected // []' "$OUT/source_stats.json")

[ "$EVENTS_OUT" -gt 0 ] || fail "events_out is zero"

PIPELINE_VERSION=$("$PIPELINE_BIN" --version 2>/dev/null || true)
[ -n "$PIPELINE_VERSION" ] || PIPELINE_VERSION="unknown"

END_EPOCH=$(date +%s)
ENDED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DURATION=$((END_EPOCH - START_EPOCH))

jq -n \
    --arg version "$PIPELINE_VERSION" \
    --arg started "$STARTED_AT" \
    --arg ended "$ENDED_AT" \
    --arg input "$CAPSTONE_PACK" \
    --argjson duration "$DURATION" \
    --argjson events_in "$EVENTS_IN" \
    --argjson events_out "$EVENTS_OUT" \
    --argjson dropped "$EVENTS_DROPPED" \
    --argjson windows "$WINDOWS" \
    --argjson linux "$LINUX" \
    --argjson firewall "$FIREWALL" \
    --argjson suricata "$SURICATA" \
    --argjson pcap "$PCAP" \
    --argjson dirty "$DIRTY" \
'{
    pipeline_version: $version,
    started_at: $started,
    ended_at: $ended,
    duration_seconds: $duration,
    input_pack: $input,
    events_in: $events_in,
    events_out: $events_out,
    events_dropped: $dropped,
    source_counts: {
        windows_json: $windows,
        linux_text: $linux,
        firewall: $firewall,
        suricata_alert: $suricata,
        pcap_flow: $pcap
    },
    dirty_data_detected: $dirty,
    exit_status: 0
}' > "$SHIFT_WORKSPACE/runtime/pipeline_run.json"

echo "[pipeline] duration ${DURATION}s"
echo "[pipeline] events_in=$EVENTS_IN events_out=$EVENTS_OUT events_dropped=$EVENTS_DROPPED"
echo "[pipeline] pipeline_run.json written"
