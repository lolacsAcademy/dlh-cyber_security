#!/bin/bash
set -euo pipefail

fail() {
    echo "[intake] ERROR: $1" >&2
    exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq missing"
command -v python3 >/dev/null 2>&1 || fail "python3 missing"
command -v yq >/dev/null 2>&1 || fail "yq missing"
command -v sigma >/dev/null 2>&1 || fail "sigma-cli missing"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum missing"

JQ_VERSION="$(jq --version | sed 's/^jq-//')"
PYTHON_VERSION="$(python3 --version | awk '{print $2}')"
YQ_VERSION="$(yq --version | sed 's/.*version //')"
SIGMA_VERSION="$(sigma version | head -1 | awk '{print $1}')"

echo "[intake] jq $JQ_VERSION OK"
echo "[intake] python3 $PYTHON_VERSION OK"
echo "[intake] yq $YQ_VERSION OK"
echo "[intake] sigma-cli $SIGMA_VERSION OK"
echo "[intake] sha256sum OK"

test -x "$PIPELINE_BIN" || fail "PIPELINE_BIN missing: $PIPELINE_BIN"
echo "[intake] PIPELINE_BIN OK"

test -x "$BASELINE_BIN" || fail "BASELINE_BIN missing: $BASELINE_BIN"
echo "[intake] BASELINE_BIN OK"

test -d "$CATALOG_DIR" || fail "CATALOG_DIR missing: $CATALOG_DIR"
RULE_COUNT="$(find "$CATALOG_DIR" -maxdepth 1 -type f -name '*.yml' | wc -l)"
test "$RULE_COUNT" -ge 1 || fail "CATALOG_DIR contains no .yml files"
echo "[intake] CATALOG_DIR OK ($RULE_COUNT rules)"

test -x "$TRIAGE_BIN" || fail "TRIAGE_BIN missing: $TRIAGE_BIN"
echo "[intake] TRIAGE_BIN OK"

test -d "$CAPSTONE_PACK" || fail "CAPSTONE_PACK missing: $CAPSTONE_PACK"
test -n "$(find "$CAPSTONE_PACK" -mindepth 1 -maxdepth 1 -print -quit)" || fail "CAPSTONE_PACK empty"
echo "[intake] CAPSTONE_PACK OK"
find "$CAPSTONE_PACK" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort

for f in assets.json ioc_feed.json hc_red7_advisory.md change_tickets.json prior_shift_notes.md; do
    test -f "$ASSETS_DIR/$f" || fail "$f missing"
done
echo "[intake] ASSETS_DIR: 5 meta files OK"

for f in incident_A_search_results.json incident_B_search_results.json incident_C_search_results.json campaign_dashboard_summary.md; do
    test -f "$WAZUH_EXPORTS/$f" || fail "$f missing"
done
echo "[intake] WAZUH_EXPORTS: 4 export files OK"

IOC_COUNT="$(jq '.iocs | length' "$ASSETS_DIR/ioc_feed.json")"
grep -q 'HC-RED7' "$ASSETS_DIR/hc_red7_advisory.md" || fail "HC-RED7 missing"

echo "[intake] ioc_feed.json OK ($IOC_COUNT entries)"
echo "[intake] advisory HC-RED7 loaded"

mkdir -p "$SHIFT_WORKSPACE"/{runtime,enriched,alerts,investigations,campaign,reports,response,handoff}

touch \
"$SHIFT_WORKSPACE/MANIFEST.json" \
"$SHIFT_WORKSPACE/runtime/pipeline_run.json" \
"$SHIFT_WORKSPACE/runtime/baseline_run.json" \
"$SHIFT_WORKSPACE/runtime/catalog_run.json" \
"$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" \
"$SHIFT_WORKSPACE/enriched/timeline.jsonl" \
"$SHIFT_WORKSPACE/enriched/baseline.json" \
"$SHIFT_WORKSPACE/enriched/source_stats.json" \
"$SHIFT_WORKSPACE/alerts/alert_queue.json" \
"$SHIFT_WORKSPACE/alerts/shift_briefing.json" \
"$SHIFT_WORKSPACE/alerts/triage_log.jsonl" \
"$SHIFT_WORKSPACE/alerts/incidents.json" \
"$SHIFT_WORKSPACE/investigations/incident_A.json" \
"$SHIFT_WORKSPACE/investigations/incident_B.json" \
"$SHIFT_WORKSPACE/investigations/incident_C_cli.json" \
"$SHIFT_WORKSPACE/investigations/incident_C_export.json" \
"$SHIFT_WORKSPACE/campaign/campaign_assessment.json" \
"$SHIFT_WORKSPACE/reports/incident_A.md" \
"$SHIFT_WORKSPACE/reports/incident_B.md" \
"$SHIFT_WORKSPACE/reports/incident_C.md" \
"$SHIFT_WORKSPACE/response/tuning_recommendations.json" \
"$SHIFT_WORKSPACE/response/containment.json" \
"$SHIFT_WORKSPACE/response/ioc_package.json" \
"$SHIFT_WORKSPACE/handoff/shift_handoff.md"

echo "[intake] workspace layout created at $SHIFT_WORKSPACE"

SHIFT_ID="SHIFT-$(date -u +%Y%m%d-%H%M)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
  --arg shift_id "$SHIFT_ID" \
  --arg host "$(hostname)" \
  --arg started "$STARTED_AT" \
  --arg pack "$(readlink -f "$CAPSTONE_PACK")" \
  --arg jqv "$JQ_VERSION" \
  --arg pyv "$PYTHON_VERSION" \
  --arg yqv "$YQ_VERSION" \
  --arg sigmav "$SIGMA_VERSION" \
  --argjson count "$IOC_COUNT" \
'{
  shift_id:$shift_id,
  analyst_host:$host,
  started_at:$started,
  tools:{
    jq:$jqv,
    python3:$pyv,
    yq:$yqv,
    "sigma-cli":$sigmav,
    sha256sum:"present"
  },
  prior_project_bins:{
    pipeline:true,
    baseline:true,
    catalog:true,
    triage:true
  },
  capstone_pack:$pack,
  ioc_feed_count:$count,
  advisory_cluster_id:"HC-RED7",
  wazuh_exports_verified:true
}' > "$SHIFT_WORKSPACE/runtime/shift_start.json"

echo "[intake] shift_start.json written"
