#!/bin/bash

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
FILE="$HANDOFF_DIR/data/enriched_events.json"

help() {
    echo "query_toolkit.sh <verb> [options]"
    echo "  filter   emit matching records as ndjson"
    echo "  top      top N values of a field"
    echo "  distinct distinct values of a field"
    echo "  count    number of matching records"
    echo "  window   bucketed counts by time window"
    echo "  help     this message"
}

VERB="${1:-help}"
shift || true

SOURCE=""
HOST=""
FROM=""
TO=""
CATEGORY=""
FIELD=""
LIMIT=10
BUCKET=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source) SOURCE="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --from) FROM="$2"; shift 2 ;;
        --to) TO="$2"; shift 2 ;;
        --category) CATEGORY="$2"; shift 2 ;;
        --field) FIELD="$2"; shift 2 ;;
        --limit) LIMIT="$2"; shift 2 ;;
        --bucket) BUCKET="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

run_filter() {
    jq -c \
        --arg source "$SOURCE" \
        --arg host "$HOST" \
        --arg from "$FROM" \
        --arg to "$TO" \
        --arg category "$CATEGORY" \
        'select(
            ($source == "" or .source_type == $source) and
            ($host == "" or .hostname == $host) and
            ($from == "" or .timestamp >= $from) and
            ($to == "" or .timestamp <= $to) and
            ($category == "" or .event_category == $category)
        )' "$FILE"
}

case "$VERB" in
    filter)
        run_filter
        ;;
    count)
        run_filter | wc -l
        ;;
    distinct)
        run_filter | jq -r --arg field "$FIELD" '.[$field] // empty' | sort -u
        ;;
    top)
        run_filter | jq -r --arg field "$FIELD" '.[$field] // empty' |
        sort | uniq -c | sort -nr | head -n "$LIMIT"
        ;;
    window)
        if [ "$BUCKET" = "day" ]; then
            run_filter | jq -r '.timestamp[0:10]' | sort | uniq -c | awk '{print $2, $1}'
        else
            run_filter | jq -r '.timestamp[0:13]' | sort | uniq -c | awk '{print $2, $1}'
        fi
        ;;
    help)
        help
        ;;
    *)
        help
        exit 1
        ;;
esac
