#!/bin/bash
# restore
set -uo pipefail

OUT="pipeline_test_results.json"
SIM_FEED="cve_feed.simulated.json"
BACKUP="cve_feed.json.bak"
EXPECTED="patch_plan.expected.json"

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[*] Scenario: simulated CVE advisory"

echo -n "[*] Backing up cve_feed.json...              "
cp cve_feed.json "$BACKUP"
echo "OK"

echo -n "[*] Injecting cve_feed.simulated.json...     "
cp "$SIM_FEED" cve_feed.json
echo "OK"

echo "[*] Running pipeline (PIPELINE_TEST=1)..."
export PIPELINE_TEST=1
./13-patch_pipeline.sh
PIPELINE_EXIT=$?

STAGES_OK="true"
PIPELINE_STATUS=$(jq -r '.pipeline_status' pipeline_run.json 2>/dev/null || echo "unknown")
if [ "$PIPELINE_STATUS" != "ok" ] && [ "$PIPELINE_STATUS" != "deferred" ]; then
    STAGES_OK="false"
fi

# Check every stage emitted a non-empty artifact
ARTIFACT_PATHS=$(jq -r '.artifacts | to_entries[] | .value' pipeline_run.json 2>/dev/null)
while IFS= read -r ap; do
    [ -z "$ap" ] && continue
    if [ ! -s "$ap" ]; then
        STAGES_OK="false"
    fi
done <<< "$ARTIFACT_PATHS"

# Normalize timestamps in patch_plan.json before comparing
normalize() {
    jq 'walk(if type == "string" and test("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}") then "TIMESTAMP" else . end)' "$1"
}

if [ ! -f "$EXPECTED" ]; then
    echo "[*] No expected baseline found — saving current plan as the golden baseline"
    normalize patch_plan.json > "$EXPECTED"
fi

echo -n "[*] Comparing patch_plan.json to expected...  "
CURRENT_NORM=$(normalize patch_plan.json)
EXPECTED_NORM=$(cat "$EXPECTED")

DIFF_ARRAY="[]"
PLAN_MATCHES="true"
if [ "$CURRENT_NORM" = "$EXPECTED_NORM" ]; then
    echo "match"
else
    echo "MISMATCH"
    PLAN_MATCHES="false"
    DIFF_TEXT=$(diff <(echo "$EXPECTED_NORM") <(echo "$CURRENT_NORM") | head -40)
    DIFF_ARRAY=$(echo "$DIFF_TEXT" | jq -R -s 'split("\n") | map(select(length > 0))')
fi

echo -n "[*] Restoring cve_feed.json...                "
cp "$BACKUP" cve_feed.json
echo "OK"

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

VERDICT="fail"
if [ "$STAGES_OK" = "true" ] && [ "$PLAN_MATCHES" = "true" ]; then
    VERDICT="pass"
fi

jq -n --arg scenario "simulated CVE advisory" --arg started "$STARTED_AT" --arg finished "$FINISHED_AT" \
    --argjson stages_ok "$STAGES_OK" --argjson matches "$PLAN_MATCHES" --argjson diff "$DIFF_ARRAY" --arg verdict "$VERDICT" \
    '{scenario:$scenario, started_at:$started, finished_at:$finished, stages_ok:$stages_ok, plan_matches_expected:$matches, diff:$diff, verdict:$verdict}' > "$OUT"

echo "VERDICT: $VERDICT"
echo "Report saved to: $OUT"

if [ "$VERDICT" = "pass" ]; then
    exit 0
fi
exit 1
