#!/bin/bash

set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
OUT="source_inventory.json"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo '[]' > "$TMP"

for category in windows linux network; do
    while IFS= read -r file; do
        path="${file#"$PACK_ROOT"/}"
        size=$(stat -c '%s' "$file")
        hash=$(sha256sum "$file" | awk '{print $1}')
        first=""
        last=""

        if [ "$category" = "windows" ]; then
            type="windows_json"
            count_key="record_count"
            count=$(wc -l < "$file")

            first=$(jq -r '.timestamp_raw // empty' "$file" | sort | sed -n '1p')
            last=$(jq -r '.timestamp_raw // empty' "$file" | sort | tail -n 1)

        elif [ "$category" = "linux" ]; then
            type="linux_text"
            count_key="line_count"
            count=$(wc -l < "$file")

            if [ "$(basename "$file")" = "audit.log" ]; then
                first_raw=$(grep -o 'audit([0-9]*' "$file" | grep -o '[0-9]*' | sort -n | sed -n '1p')
                last_raw=$(grep -o 'audit([0-9]*' "$file" | grep -o '[0-9]*' | sort -n | tail -n 1)

                first=$(date -u -d "@$first_raw" '+%Y-%m-%dT%H:%M:%SZ')
                last=$(date -u -d "@$last_raw" '+%Y-%m-%dT%H:%M:%SZ')
            else
                first_raw=$(sed -n '1p' "$file" | grep -Eo '[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}' || true)
                last_raw=$(tail -n 1 "$file" | grep -Eo '[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}' || true)

                [ -n "$first_raw" ] && first=$(date -u -d "$first_raw 2026" '+%Y-%m-%dT%H:%M:%SZ')
                [ -n "$last_raw" ] && last=$(date -u -d "$last_raw 2026" '+%Y-%m-%dT%H:%M:%SZ')
            fi

        elif [[ "$file" == *.csv ]]; then
            type="network_csv"
            count_key="record_count"
            lines=$(wc -l < "$file")
            count=$((lines > 0 ? lines - 1 : 0))

            first_raw=$(tail -n +2 "$file" | cut -d, -f1 | sort -n | sed -n '1p')
            last_raw=$(tail -n +2 "$file" | cut -d, -f1 | sort -n | tail -n 1)

            first=$(date -u -d "@$first_raw" '+%Y-%m-%dT%H:%M:%SZ')
            last=$(date -u -d "@$last_raw" '+%Y-%m-%dT%H:%M:%SZ')

        else
            type="network_json"
            count_key="record_count"
            count=$(wc -l < "$file")

            if [ "$(basename "$file")" = "pcap_summary.json" ]; then
                first_raw=$(jq -r '.start_time // empty' "$file" | while read -r t; do date -u -d "$t" '+%Y-%m-%dT%H:%M:%SZ'; done | sort | sed -n '1p')
                last_raw=$(jq -r '.end_time // empty' "$file" | while read -r t; do date -u -d "$t" '+%Y-%m-%dT%H:%M:%SZ'; done | sort | tail -n 1)
                first="$first_raw"
                last="$last_raw"
            else
                first_raw=$(jq -r '.timestamp // empty' "$file" | sort | sed -n '1p')
                last_raw=$(jq -r '.timestamp // empty' "$file" | sort | tail -n 1)

                [ -n "$first_raw" ] && first=$(date -u -d "$first_raw" '+%Y-%m-%dT%H:%M:%SZ')
                [ -n "$last_raw" ] && last=$(date -u -d "$last_raw" '+%Y-%m-%dT%H:%M:%SZ')
            fi
        fi

        entry=$(jq -n \
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
                first_event_time: (if $first == "" then null else $first end),
                last_event_time: (if $last == "" then null else $last end)
            } + {($key): $count}')

        jq --argjson item "$entry" '. + [$item]' "$TMP" > "$TMP.new"
        mv "$TMP.new" "$TMP"

    done < <(find "$PACK_ROOT/$category" -maxdepth 1 -type f | sort)
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
