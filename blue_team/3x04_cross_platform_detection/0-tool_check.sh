#!/bin/bash

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

fail=0

tool() {
    if command -v "$1" >/dev/null 2>&1; then
        printf "%-12s: %s\n" "$2" "$("$1" --version 2>&1 | head -1)"
    else
        printf "%-12s: missing\n" "$2"
        fail=1
    fi
}

tool jq jq
tool yq yq
tool python3 python3
tool sigma sigma-cli
tool xmllint xmllint
tool curl curl

for dir in "$HANDOFF_DIR" "$BASELINE_PKG" "$CATALOG_DIR" "$TRIAGE_PKG" "$ASSETS_DIR"; do
    [ -d "$dir" ] || fail=1
done

evidence="$HANDOFF_DIR/data/enriched_events.json"
if [ -s "$evidence" ]; then
    echo "handoff     : ok (enriched_events.json present)"
else
    echo "handoff     : failed"
    fail=1
fi

rules="$CATALOG_DIR/rules/sigma"
if [ -d "$rules" ]; then
    count=$(find "$rules" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) | wc -l)
    echo "catalog     : ok ($count sigma rules)"
else
    echo "catalog     : failed"
    fail=1
fi

exports="$ASSETS_DIR/wazuh_exports"
exports_ok=1
for file in field_mapping.json index_metadata.json \
    anchor_search_results.json scenario_a_search_results.json \
    scenario_b_search_results.json scenario_c_search_results.json \
    anchor_dashboard_trace.json scenario_a_dashboard_trace.json \
    scenario_b_dashboard_trace.json scenario_c_dashboard_trace.json; do
    [ -s "$exports/$file" ] || exports_ok=0
done

if [ "$exports_ok" -eq 1 ]; then
    echo "wazuh_exports : ok (field_mapping, index_metadata, 4 search_results, 4 dashboard_traces)"
else
    echo "wazuh_exports : failed"
    fail=1
fi

anchor="$ASSETS_DIR/anchor_event.json"
host=$(jq -r '.target_host' "$anchor")
start=$(jq -r '.time_window.start' "$anchor")
end=$(jq -r '.time_window.end' "$anchor")

match=$(jq -r --arg h "$host" --arg s "$start" --arg e "$end" \
    'select(.hostname == $h and .timestamp >= $s and .timestamp <= $e) | .hostname' \
    "$evidence" | head -1)

if [ "$match" = "$host" ]; then
    echo "anchor      : ok ($host matched in enriched_events.json)"
else
    echo "anchor      : failed"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "all checks  : passed"
else
    echo "all checks  : failed"
    exit 1
fi
