#!/bin/bash

set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
OUT="source_inventory.json"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo '[]' > "$TMP"

add_file() {
    local file="$1"
    local type="$2"
    local count_key="$3"
    local count="$4"
    local first="$5"
    local last="$6"

    local path size hash item
    path="${file#"$PACK_ROOT"/}"
    size=$(stat -c '%s' "$file")
    hash=$(sha256sum "$file" | awk '{print $1}')

    item=$(jq -n \
        --arg path "$path" \
        --arg type "$type" \
        --argjson size "$size" \
        --arg hash "$hash" \
        --arg key "$count_key" \
        --argjson count "$count" \
        --arg first "$first" \
        --arg last "$last" \
        '{
          path: $path,
          source_type: $type,
          size_bytes: $size,
          sha256: $hash,
          first_event_time: $first,
          last_event_time: $last
        } + {($key): $count}')

    jq --argjson item "$item" '. + [$item]' "$TMP" > "$TMP.new"
    mv "$TMP.new" "$TMP"
}

for file in "$PACK_ROOT/windows"/*.json; do
    [ -f "$file" ] || continue

    if jq -e -s 'length == 1 and (.[0] | type == "array")' "$file" >/dev/null 2>&1; then
        count=$(jq 'length' "$file")
        first=$(jq -r 'map(.timestamp_raw) | min' "$file")
        last=$(jq -r 'map(.timestamp_raw) | max' "$file")
    else
        count=$(jq -s 'length' "$file")
        first=$(jq -sr 'map(.timestamp_raw) | min' "$file")
        last=$(jq -sr 'map(.timestamp_raw) | max' "$file")
    fi

    add_file "$file" "windows_json" "record_count" "$count" "$first" "$last"
done

for file in "$PACK_ROOT/linux"/*; do
    [ -f "$file" ] || continue

    count=$(wc -l < "$file")

    if [ "$(basename "$file")" = "audit.log" ]; then
        first_epoch=$(sed -n 's/.*audit(\([0-9][0-9]*\)\.[0-9][0-9]*:.*/\1/p' "$file" | sort -n | sed -n '1p')
        last_epoch=$(sed -n 's/.*audit(\([0-9][0-9]*\)\.[0-9][0-9]*:.*/\1/p' "$file" | sort -n | tail -n 1)

        first=$(date -u -d "@$first_epoch" '+%Y-%m-%dT%H:%M:%SZ')
        last=$(date -u -d "@$last_epoch" '+%Y-%m-%dT%H:%M:%SZ')
    else
        year=$(date -u -d "@$(stat -c '%Y' "$file")" '+%Y')

        first_raw=$(sed -n '1{s/^\([A-Z][a-z][a-z] *[0-9][0-9]* [0-9:]*\).*/\1/p}' "$file")
        last_raw=$(sed -n '$s/^\([A-Z][a-z][a-z] *[0-9][0-9]* [0-9:]*\).*/\1/p' "$file")

        first=$(date -u -d "$first_raw $year" '+%Y-%m-%dT%H:%M:%SZ')
        last=$(date -u -d "$last_raw $year" '+%Y-%m-%dT%H:%M:%SZ')
    fi

    add_file "$file" "linux_text" "line_count" "$count" "$first" "$last"
done

for file in "$PACK_ROOT/network"/*; do
    [ -f "$file" ] || continue

    if [[ "$file" == *.csv ]]; then
        count=$(awk 'END {print (NR > 0 ? NR - 1 : 0)}' "$file")
        first_epoch=$(awk -F, 'NR > 1 {print $1}' "$file" | sort -n | sed -n '1p')
        last_epoch=$(awk -F, 'NR > 1 {print $1}' "$file" | sort -n | tail -n 1)

        first=$(date -u -d "@$first_epoch" '+%Y-%m-%dT%H:%M:%SZ')
        last=$(date -u -d "@$last_epoch" '+%Y-%m-%dT%H:%M:%SZ')

        add_file "$file" "network_csv" "record_count" "$count" "$first" "$last"

    elif [ "$(basename "$file")" = "pcap_summary.json" ]; then
        count=$(jq -s 'length' "$file")

        first_epoch=$(jq -r '.start_time' "$file" |
            while IFS= read -r t; do date -u -d "$t" '+%s'; done |
            sort -n | sed -n '1p')

        last_epoch=$(jq -r '.end_time' "$file" |
            while IFS= read -r t; do date -u -d "$t" '+%s'; done |
            sort -n | tail -n 1)

        first=$(date -u -d "@$first_epoch" '+%Y-%m-%dT%H:%M:%SZ')
        last=$(date -u -d "@$last_epoch" '+%Y-%m-%dT%H:%M:%SZ')

        add_file "$file" "network_json" "record_count" "$count" "$first" "$last"

    else
        count=$(jq -s 'length' "$file")

        first=$(jq -sr 'map(.timestamp) | min' "$file" |
            xargs -I{} date -u -d "{}" '+%Y-%m-%dT%H:%M:%SZ')

        last=$(jq -sr 'map(.timestamp) | max' "$file" |
            xargs -I{} date -u -d "{}" '+%Y-%m-%dT%H:%M:%SZ')

        add_file "$file" "network_json" "record_count" "$count" "$first" "$last"
    fi
done

jq '.' "$TMP" > "$OUT"

total_files=0
total_bytes=0

for category in windows linux network; do
    files=$(jq --arg p "$category/" \
        '[.[] | select(.path | startswith($p))] | length' "$OUT")

    bytes=$(jq --arg p "$category/" \
        '[.[] | select(.path | startswith($p)) | .size_bytes] | add // 0' "$OUT")

    total_files=$((total_files + files))
    total_bytes=$((total_bytes + bytes))

    mb=$(awk -v b="$bytes" 'BEGIN {printf "%.1f", b/1048576}')
    printf "%-8s: %d files  |  %6s MB\n" "$category" "$files" "$mb"
done

total_mb=$(awk -v b="$total_bytes" 'BEGIN {printf "%.1f", b/1048576}')

printf "%-8s: %d files  |  %6s MB\n" "total" "$total_files" "$total_mb"
echo "manifest written to $OUT"
