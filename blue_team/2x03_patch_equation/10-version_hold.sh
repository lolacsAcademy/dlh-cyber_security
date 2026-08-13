#!/bin/bash
set -uo pipefail

REGISTRY="hold_registry.json"
PIN_FILE="/etc/apt/preferences.d/meddefense-pins"
OUT="hold_management.json"

REG_COUNT=$(jq '.holds | length' "$REGISTRY")
echo "[*] Reading hold_registry.json...           ($REG_COUNT entries)"

CURRENT_HOLDS=$(apt-mark showhold 2>/dev/null)
CURRENT_COUNT=0
if [ -n "$CURRENT_HOLDS" ]; then
    CURRENT_COUNT=$(echo "$CURRENT_HOLDS" | grep -c .)
fi
echo "[*] Reading current apt-mark showhold...    ($CURRENT_COUNT entries)"

# 2. Apply holds + write preferences fragment
echo "Applying holds:"
APPLIED="[]"
: > "$PIN_FILE"

REGISTRY_PKGS=$(jq -r '.holds[].package' "$REGISTRY")

while IFS= read -r entry; do
    pkg=$(echo "$entry" | jq -r '.package')
    reason=$(echo "$entry" | jq -r '.reason')
    owner=$(echo "$entry" | jq -r '.owner')
    review_date=$(echo "$entry" | jq -r '.review_date')
    pin_version=$(echo "$entry" | jq -r '.pin_version')

    hold_ok="no"
    if apt-mark hold "$pkg" >/dev/null 2>&1; then
        hold_ok="yes"
    fi

    {
        echo "Package: $pkg"
        echo "Pin: version $pin_version"
        echo "Pin-Priority: 1001"
        echo ""
    } >> "$PIN_FILE"

    today=$(date -u +%Y-%m-%d)
    days_to_review=$(( ( $(date -u -d "$review_date" +%s) - $(date -u -d "$today" +%s) ) / 86400 ))

    printf "  %-24s hold + pin %-30s %s\n" "$pkg" "$pin_version" "$([ "$hold_ok" = "yes" ] && echo OK || echo FAILED)"

    entry_json=$(jq -n --arg p "$pkg" --arg r "$reason" --arg o "$owner" \
        --arg rd "$review_date" --arg pv "$pin_version" --argjson dtr "$days_to_review" --arg status "$hold_ok" \
        '{package:$p, reason:$r, owner:$o, review_date:$rd, pin_version:$pv, days_to_review:$dtr, applied:$status}')
    APPLIED=$(echo "$APPLIED" | jq --argjson e "$entry_json" '. + [$e]')
done < <(jq -c '.holds[]' "$REGISTRY")

# 3. Release holds not in registry (convergence mode)
echo "Releasing holds no longer in registry:"
RELEASED="[]"
RELEASED_ANY="no"
if [ -n "$CURRENT_HOLDS" ]; then
    while IFS= read -r held_pkg; do
        [ -z "$held_pkg" ] && continue
        if ! echo "$REGISTRY_PKGS" | grep -qxF "$held_pkg"; then
            apt-mark unhold "$held_pkg" >/dev/null 2>&1
            echo "  $held_pkg"
            RELEASED=$(echo "$RELEASED" | jq --arg p "$held_pkg" '. + [$p]')
            RELEASED_ANY="yes"
        fi
    done <<< "$CURRENT_HOLDS"
fi
[ "$RELEASED_ANY" = "no" ] && echo "  (none)"

OVERDUE=$(echo "$APPLIED" | jq '[.[] | select(.days_to_review < 0)]')
OVERDUE_COUNT=$(echo "$OVERDUE" | jq 'length')
TOTAL_HELD=$(echo "$APPLIED" | jq '[.[] | select(.applied=="yes")] | length')

echo "Overdue reviews: $OVERDUE_COUNT"

jq -n --argjson applied "$APPLIED" --argjson released "$RELEASED" --argjson overdue "$OVERDUE" --argjson total "$TOTAL_HELD" \
    '{applied:$applied, released:$released, overdue_reviews:$overdue, total_held:$total}' > "$OUT"

echo "Report saved to: $OUT"
