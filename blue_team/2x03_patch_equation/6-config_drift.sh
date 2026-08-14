#!/bin/bash
set -uo pipefail

PRE_FILE="pre_patch_state.json"
LOG_FILE="patch_execution_log.json"
OUT="config_drift.json"

# Packages upgraded during this run (for expected/unexpected cross-reference)
UPGRADED_PKGS=$(jq -r '.entries[] | select(.status=="success") | .package' "$LOG_FILE")

FILES="[]"
UNCHANGED=0
MODIFIED=0
MISSING=0
NEW=0

# 1 & 2. Load pre conffile hashes, recompute current
while IFS=$'\t' read -r path pre_hash; do
    [ -z "$path" ] && continue

    if [ ! -f "$path" ]; then
        classification="missing"
        MISSING=$((MISSING+1))
        entry=$(jq -n --arg p "$path" --arg c "$classification" '{path:$p, classification:$c}')
        FILES=$(echo "$FILES" | jq --argjson e "$entry" '. + [$e]')
        continue
    fi

    current_hash=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')

    if [ "$current_hash" = "$pre_hash" ]; then
        classification="unchanged"
        UNCHANGED=$((UNCHANGED+1))
        entry=$(jq -n --arg p "$path" --arg c "$classification" '{path:$p, classification:$c}')
        FILES=$(echo "$FILES" | jq --argjson e "$entry" '. + [$e]')
    else
        classification="modified"
        MODIFIED=$((MODIFIED+1))

        owning_pkg=$( (dpkg -S "$path" 2>/dev/null || true) | head -1 | cut -d':' -f1)
        [ -z "$owning_pkg" ] && owning_pkg="unknown"

        expected="false"
        if echo "$UPGRADED_PKGS" | grep -qxF "$owning_pkg"; then
            expected="true"
        fi

        # 4. Unified diff truncated to 40 lines (best effort; pre-content not stored, so diff against current only if a .dpkg-old backup exists)
        diff_output=""
        if [ -f "${path}.dpkg-old" ]; then
            diff_output=$(diff -u "${path}.dpkg-old" "$path" 2>/dev/null | head -40)
        fi

        entry=$(jq -n --arg p "$path" --arg c "$classification" --arg op "$owning_pkg" \
            --argjson exp "$expected" --arg diff "$diff_output" \
            '{path:$p, classification:$c, owning_package:$op, expected:$exp, diff:$diff}')
        FILES=$(echo "$FILES" | jq --argjson e "$entry" '. + [$e]')
    fi
done < <(jq -r '.conffile_hashes | to_entries[] | "\(.key)\t\(.value)"' "$PRE_FILE")

# 3. New tracked conffiles not present in the pre-patch list
CURRENT_CONFFILES=$(dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | tr ',' '\n' | awk '{print $1}' | grep '^/etc/' | sort -u)
PRE_PATHS=$(jq -r '.conffile_hashes | keys[]' "$PRE_FILE")

while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! echo "$PRE_PATHS" | grep -qxF "$f"; then
        NEW=$((NEW+1))
        owning_pkg=$( (dpkg -S "$f" 2>/dev/null || true) | head -1 | cut -d':' -f1)
        [ -z "$owning_pkg" ] && owning_pkg="unknown"
        expected="false"
        if echo "$UPGRADED_PKGS" | grep -qxF "$owning_pkg"; then
            expected="true"
        fi
        entry=$(jq -n --arg p "$f" --arg c "new" --arg op "$owning_pkg" --argjson exp "$expected" \
            '{path:$p, classification:$c, owning_package:$op, expected:$exp}')
        FILES=$(echo "$FILES" | jq --argjson e "$entry" '. + [$e]')
    fi
done <<< "$CURRENT_CONFFILES"

SUMMARY=$(jq -n --argjson u "$UNCHANGED" --argjson m "$MODIFIED" --argjson mi "$MISSING" --argjson n "$NEW" \
    '{unchanged:$u, modified:$m, missing:$mi, new:$n}')

jq -n --argjson summary "$SUMMARY" --argjson files "$FILES" '{summary:$summary, files:$files}' > "$OUT"

UNEXPECTED=$(echo "$FILES" | jq '[.[] | select(.expected==false and .classification!="unchanged" and .classification!="missing")] | length')

echo "Config drift summary: unchanged=$UNCHANGED modified=$MODIFIED missing=$MISSING new=$NEW"
echo "Report saved to: $OUT"

if [ "$UNEXPECTED" -gt 0 ]; then
    exit 1
fi
exit 0
