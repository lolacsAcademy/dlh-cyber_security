#!/bin/bash
set -euo pipefail

BASE_DIR="capstone/baseline"
LOG_PATH="$BASE_DIR/lynis_baseline.log"
OUT="$BASE_DIR/baseline_linux.json"
TMP_OUT="${OUT}.tmp"

# Exit codes:
# 0 = success
# 1 = controlled audit/parsing failure
# 2 = environment error

for cmd in lynis jq hostname grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: missing dependency: $cmd" >&2
        exit 2
    fi
done

mkdir -p "$BASE_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME_VALUE=$(hostname)
LYNIS_VERSION=$(lynis --version 2>/dev/null | head -n 1)

# Required baseline audit.
if ! lynis audit system --quick --no-colors > "$LOG_PATH" 2>&1; then
    echo "ERROR: Lynis audit failed" >&2
    exit 1
fi

# Parse Hardening Index.
HARDENING_INDEX=$(
    grep -Ei 'Hardening index' "$LOG_PATH" |
        tail -n 1 |
        grep -Eo '[0-9]+' |
        head -n 1 || true
)

if [ -z "$HARDENING_INDEX" ]; then
    echo "ERROR: could not parse Lynis Hardening Index" >&2
    exit 1
fi

WARNINGS_COUNT=$(
    grep -Ec '\[ WARNING \]|Warning:' "$LOG_PATH" || true
)

SUGGESTIONS_COUNT=$(
    grep -Ec '\[ SUGGESTION \]|Suggestion:' "$LOG_PATH" || true
)

jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VALUE" \
    --arg lynis_version "$LYNIS_VERSION" \
    --argjson hardening_index "$HARDENING_INDEX" \
    --argjson warnings_count "$WARNINGS_COUNT" \
    --argjson suggestions_count "$SUGGESTIONS_COUNT" \
    --arg log_path "$LOG_PATH" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        lynis_version: $lynis_version,
        hardening_index: $hardening_index,
        warnings_count: $warnings_count,
        suggestions_count: $suggestions_count,
        log_path: $log_path
    }' > "$TMP_OUT"

if ! jq empty "$TMP_OUT" >/dev/null 2>&1; then
    rm -f "$TMP_OUT"
    echo "ERROR: invalid baseline JSON generated" >&2
    exit 1
fi

mv "$TMP_OUT" "$OUT"

echo "Lynis baseline complete"
echo "Hardening Index: $HARDENING_INDEX"
echo "Report saved to: $OUT"

exit 0
