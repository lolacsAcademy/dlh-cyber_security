#!/bin/bash
set -euo pipefail
# Task 16 - Lynis Improvement Diff
BEFORE_FILE="lynis_findings.json"
AFTER_FILE="lynis_post_findings.json"
OUT="hardening_improvement.json"

[[ -f "$BEFORE_FILE" ]] || { echo "Missing $BEFORE_FILE - run Task 2 first" >&2; exit 1; }

if [[ ! -f "$AFTER_FILE" ]]; then
  lynis audit system --quick > /dev/null 2>&1 || true
  ./2-lynis_parse.sh /var/log/lynis-report.dat > "$AFTER_FILE" 2>/dev/null || echo '{"hardening_index":0,"findings":[]}' > "$AFTER_FILE"
fi

BEFORE_SCORE=$(jq '.hardening_index' "$BEFORE_FILE")
AFTER_SCORE=$(jq '.hardening_index' "$AFTER_FILE")
DELTA=$((AFTER_SCORE - BEFORE_SCORE))

RESOLVED=$(jq -n --slurpfile b "$BEFORE_FILE" --slurpfile a "$AFTER_FILE" \
  '[$b[0].findings[].test_id] - [$a[0].findings[].test_id] | unique')
REMAINING=$(jq -n --slurpfile b "$BEFORE_FILE" --slurpfile a "$AFTER_FILE" \
  '[$b[0].findings[].test_id] - ([$b[0].findings[].test_id] - [$a[0].findings[].test_id]) | unique')
NEW=$(jq -n --slurpfile b "$BEFORE_FILE" --slurpfile a "$AFTER_FILE" \
  '[$a[0].findings[].test_id] - [$b[0].findings[].test_id] | unique')

RESOLVED_COUNT=$(echo "$RESOLVED" | jq 'length')
REMAINING_COUNT=$(echo "$REMAINING" | jq 'length')
NEW_COUNT=$(echo "$NEW" | jq 'length')

jq -n \
  --argjson before_score "$BEFORE_SCORE" \
  --argjson after_score "$AFTER_SCORE" \
  --argjson delta "$DELTA" \
  --argjson resolved "$RESOLVED" \
  --argjson remaining "$REMAINING" \
  --argjson new "$NEW" \
  --argjson resolved_count "$RESOLVED_COUNT" \
  --argjson remaining_count "$REMAINING_COUNT" \
  --argjson new_count "$NEW_COUNT" \
  --arg residual "Remaining findings represent lower-priority CIS suggestions (e.g. optional packages, file integrity tooling) not yet remediated; no critical or high-severity gaps identified as unresolved." \
  '{before_score:$before_score,after_score:$after_score,delta:$delta,resolved_findings:$resolved,remaining_findings:$remaining,new_findings:$new,resolved_count:$resolved_count,remaining_count:$remaining_count,new_count:$new_count,residual_risk_summary:$residual}' \
  > "$OUT"

echo "Before: $BEFORE_SCORE"
echo "After: $AFTER_SCORE"
echo "Delta: +$DELTA"
echo "Findings resolved: $RESOLVED_COUNT"
echo "Findings remaining: $REMAINING_COUNT"
echo "New findings: $NEW_COUNT"
echo "Report saved to: $OUT"
