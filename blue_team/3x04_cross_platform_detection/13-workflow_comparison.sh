#!/bin/bash

FINDINGS_DIR="findings"
OUTPUT_DIR="comparison"
OUTPUT="$OUTPUT_DIR/workflow_comparison.json"

mkdir -p "$OUTPUT_DIR"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

jq -s '
    map({
        scenario_id,
        interface,
        time: .time_to_first_answer_seconds,
        actions: (.actions | length),
        fields: (.fields_touched | length),
        refs: (.event_refs | length),
        confidence
    })
' "$FINDINGS_DIR"/*.json > "$tmp"

generated_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq --arg generated_at "$generated_at" '
    def median:
        sort as $s
        | length as $n
        | if $n == 0 then 0
          elif ($n % 2) == 1 then $s[($n / 2 | floor)]
          else (($s[$n / 2 - 1] + $s[$n / 2]) / 2)
          end;

    def stats($items):
        ($items | length) as $count
        | {
            finding_count: $count,
            time_to_first_answer_seconds: {
                total: ($items | map(.time) | add),
                average: (($items | map(.time) | add) / $count),
                median: ($items | map(.time) | median)
            },
            action_count: {
                total: ($items | map(.actions) | add),
                average: (($items | map(.actions) | add) / $count)
            },
            fields_touched_count: {
                total: ($items | map(.fields) | add),
                average: (($items | map(.fields) | add) / $count)
            },
            event_refs_count: {
                total: ($items | map(.refs) | add),
                average: (($items | map(.refs) | add) / $count)
            }
        };

    . as $all
    | ($all | map(select(.interface == "cli"))) as $cli
    | ($all | map(select(.interface == "wazuh_export"))) as $export
    | {
        per_interface: {
            cli: stats($cli),
            wazuh_export: stats($export)
        },
        per_scenario: (
            ["anchor", "scenario_a", "scenario_b", "scenario_c"]
            | map(
                . as $scenario
                | ($all[] | select(.scenario_id == $scenario and .interface == "cli")) as $c
                | ($all[] | select(.scenario_id == $scenario and .interface == "wazuh_export")) as $w
                | {
                    scenario_id: $scenario,
                    cli_time_seconds: $c.time,
                    wazuh_export_time_seconds: $w.time,
                    time_delta_wazuh_export_minus_cli: ($w.time - $c.time),
                    cli_action_count: $c.actions,
                    wazuh_export_action_count: $w.actions,
                    action_delta_wazuh_export_minus_cli: ($w.actions - $c.actions),
                    cli_fields_touched_count: $c.fields,
                    wazuh_export_fields_touched_count: $w.fields,
                    cli_event_refs_count: $c.refs,
                    wazuh_export_event_refs_count: $w.refs
                }
            )
        ),
        confidence_distribution: {
            cli: {
                low: ($cli | map(select(.confidence == "low")) | length),
                medium: ($cli | map(select(.confidence == "medium")) | length),
                high: ($cli | map(select(.confidence == "high")) | length)
            },
            wazuh_export: {
                low: ($export | map(select(.confidence == "low")) | length),
                medium: ($export | map(select(.confidence == "medium")) | length),
                high: ($export | map(select(.confidence == "high")) | length)
            }
        },
        generated_at: $generated_at
    }
' "$tmp" > "$OUTPUT"

cli_total=$(jq '.per_interface.cli.time_to_first_answer_seconds.total' "$OUTPUT")
cli_avg=$(jq '.per_interface.cli.time_to_first_answer_seconds.average' "$OUTPUT")
cli_median=$(jq '.per_interface.cli.time_to_first_answer_seconds.median' "$OUTPUT")
cli_actions=$(jq '.per_interface.cli.action_count.total' "$OUTPUT")

export_total=$(jq '.per_interface.wazuh_export.time_to_first_answer_seconds.total' "$OUTPUT")
export_avg=$(jq '.per_interface.wazuh_export.time_to_first_answer_seconds.average' "$OUTPUT")
export_median=$(jq '.per_interface.wazuh_export.time_to_first_answer_seconds.median' "$OUTPUT")
export_actions=$(jq '.per_interface.wazuh_export.action_count.total' "$OUTPUT")

echo "findings loaded       : 8 (4 cli + 4 wazuh_export)"
echo "per interface totals:"
echo "  cli            : ${cli_total}s total, avg ${cli_avg}s, median ${cli_median}s, $cli_actions actions"
echo "  wazuh_export   : ${export_total}s total, avg ${export_avg}s, median ${export_median}s, $export_actions actions"

echo "per interface confidence:"
jq -r '
    "  cli            : high=\(.confidence_distribution.cli.high) medium=\(.confidence_distribution.cli.medium) low=\(.confidence_distribution.cli.low)",
    "  wazuh_export   : high=\(.confidence_distribution.wazuh_export.high) medium=\(.confidence_distribution.wazuh_export.medium) low=\(.confidence_distribution.wazuh_export.low)"
' "$OUTPUT"

echo "per scenario deltas (wazuh_export - cli):"

jq -r '
    .per_scenario[]
    | .time_delta_wazuh_export_minus_cli as $d
    | if $d < 0 then
        "  \(.scenario_id) : \($d)s (wazuh_export faster)"
      elif $d > 0 then
        "  \(.scenario_id) : +\($d)s (cli faster)"
      else
        "  \(.scenario_id) : 0s (tie)"
      end
' "$OUTPUT"

echo "comparison/workflow_comparison.json written"
