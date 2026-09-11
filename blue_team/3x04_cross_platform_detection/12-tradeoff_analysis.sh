#!/bin/bash

FINDINGS_DIR="findings"
OUTPUT_DIR="comparison"
JSON_OUT="$OUTPUT_DIR/tradeoff_table.json"
MD_OUT="$OUTPUT_DIR/tradeoff_table.md"

mkdir -p "$OUTPUT_DIR"

scenarios=("anchor" "scenario_a" "scenario_b" "scenario_c")
rows='[]'
export_advantages=0
cli_advantages=0

for scenario in "${scenarios[@]}"; do
    cli_file=""
    export_file=""

    for file in "$FINDINGS_DIR"/*.json; do
        file_scenario=$(jq -r '.scenario_id' "$file")
        interface=$(jq -r '.interface' "$file")

        if [ "$file_scenario" = "$scenario" ]; then
            if [ "$interface" = "cli" ]; then
                cli_file="$file"
            elif [ "$interface" = "wazuh_export" ]; then
                export_file="$file"
            fi
        fi
    done

    if [ -z "$cli_file" ] || [ -z "$export_file" ]; then
        echo "missing finding pair for $scenario"
        exit 1
    fi

    cli_time=$(jq '.time_to_first_answer_seconds' "$cli_file")
    export_time=$(jq '.time_to_first_answer_seconds' "$export_file")
    cli_actions=$(jq '.actions | length' "$cli_file")
    export_actions=$(jq '.actions | length' "$export_file")

    time_delta=$((export_time - cli_time))
    action_delta=$((export_actions - cli_actions))

    if [ "$cli_time" -lt "$export_time" ]; then
        faster="cli"
        cli_advantages=$((cli_advantages + 1))
    elif [ "$export_time" -lt "$cli_time" ]; then
        faster="wazuh_export"
        export_advantages=$((export_advantages + 1))
    else
        faster="tie"
    fi

    case "$scenario" in
        anchor)
            cause="native_field_surface"
            ;;
        scenario_a)
            cause="timeline_visualization"
            ;;
        scenario_b)
            cause="filter_bar_efficiency"
            ;;
        scenario_c)
            cause="pipeline_expressiveness"
            ;;
    esac

    row=$(jq -n \
        --arg scenario "$scenario" \
        --argjson cli_time "$cli_time" \
        --argjson export_time "$export_time" \
        --argjson time_delta "$time_delta" \
        --argjson cli_actions "$cli_actions" \
        --argjson export_actions "$export_actions" \
        --argjson action_delta "$action_delta" \
        --arg faster "$faster" \
        --arg cause "$cause" \
        '{
            scenario_id: $scenario,
            cli_time_seconds: $cli_time,
            wazuh_export_time_seconds: $export_time,
            time_delta_export_minus_cli: $time_delta,
            cli_action_count: $cli_actions,
            wazuh_export_action_count: $export_actions,
            action_delta_export_minus_cli: $action_delta,
            faster_interface: $faster,
            advantage_cause: $cause
        }')

    rows=$(jq --argjson row "$row" '. + [$row]' <<< "$rows")
done

jq -n \
    --argjson rows "$rows" \
    --argjson export_advantages "$export_advantages" \
    --argjson cli_advantages "$cli_advantages" \
    '{
        scenarios_analyzed: ($rows | length),
        export_advantages: $export_advantages,
        cli_advantages: $cli_advantages,
        scenarios: $rows
    }' > "$JSON_OUT"

{
    echo "# Interface Trade-off Analysis"
    echo
    echo "| Scenario | CLI Time | Export Time | Time Delta | CLI Actions | Export Actions | Action Delta | Faster | Cause |"
    echo "|---|---:|---:|---:|---:|---:|---:|---|---|"

    jq -r '.scenarios[] |
        "| \(.scenario_id) | \(.cli_time_seconds)s | \(.wazuh_export_time_seconds)s | \(.time_delta_export_minus_cli)s | \(.cli_action_count) | \(.wazuh_export_action_count) | \(.action_delta_export_minus_cli) | \(.faster_interface) | \(.advantage_cause) |"
    ' "$JSON_OUT"

    echo
    echo "Export advantages: $export_advantages"
    echo
    echo "CLI advantages: $cli_advantages"
} > "$MD_OUT"

echo "scenarios analyzed   : ${#scenarios[@]} (anchor + 3)"
echo "export advantages    : $export_advantages"
echo "cli advantages       : $cli_advantages"
echo "comparison/tradeoff_table.json written"
echo "comparison/tradeoff_table.md written"
