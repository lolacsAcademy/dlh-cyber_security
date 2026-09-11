#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
EXPORTS="$ASSETS_DIR/wazuh_exports"
QUERIES="$ASSETS_DIR/query_results"

META="$EXPORTS/index_metadata.json"
MAPPING="$EXPORTS/field_mapping.json"
CREDS="$ASSETS_DIR/dashboard_credentials.json"

required=(
    "$EXPORTS/index_metadata.json"
    "$EXPORTS/field_mapping.json"
    "$EXPORTS/anchor_search_results.json"
    "$EXPORTS/scenario_a_search_results.json"
    "$EXPORTS/scenario_b_search_results.json"
    "$EXPORTS/scenario_c_search_results.json"
    "$QUERIES/kql_anchor_query.json"
    "$QUERIES/lucene_anchor_query.json"
    "$QUERIES/kql_scenario_a.json"
    "$QUERIES/kql_scenario_b.json"
    "$QUERIES/kql_scenario_c.json"
)

for file in "${required[@]}"; do
    if [ ! -r "$file" ]; then
        echo "missing: $file"
        exit 1
    fi
done

index=$(jq -r '.source_index' "$META")
documents=$(jq -r '.total_documents' "$META")
earliest=$(jq -r '.time_range.earliest' "$META")
latest=$(jq -r '.time_range.latest' "$META")
username=$(jq -r '.username' "$CREDS")
mapping_count=$(jq '.mappings | length' "$MAPPING")

echo "mode          : wazuh_export (no live dashboard required)"
echo "index         : $index"
printf "documents     : %'d\n" "$documents"
echo "time range    : $earliest to $latest"
echo "credentials   : $username (from dashboard_credentials.json)"
echo "field mapping : loaded ($mapping_count mappings)"

jq -r '.mappings[0:10][] | "  \(.normalized) -> \(.wazuh)"' "$MAPPING"

echo "export files  : all present (11 files verified)"

mkdir -p workspace

jq -n \
    --arg index "$index" \
    --argjson documents "$documents" \
    --arg earliest "$earliest" \
    --arg latest "$latest" \
    --arg initialized "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
        mode: "wazuh_export",
        source_index: $index,
        total_documents: $documents,
        time_range: {
            earliest: $earliest,
            latest: $latest
        },
        export_files_verified: true,
        field_mapping_loaded: true,
        initialized_at: $initialized
    }' > workspace/workspace_init.json

echo "workspace_init.json written"
