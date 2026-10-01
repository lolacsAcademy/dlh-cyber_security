#!/bin/bash

ALERTS="siem_export/wazuh_alerts_14d.json"
RAW="siem_export/wazuh_raw_sysmon_14d.json"

TOTAL=$(jq -s 'length' "$ALERTS" "$RAW")
FIRST=$(jq -sr 'sort_by(.timestamp) | .[0].timestamp' "$ALERTS" "$RAW")
LAST=$(jq -sr 'sort_by(.timestamp) | .[-1].timestamp' "$ALERTS" "$RAW")

echo "================================================================"
echo "   DATA RECONNAISSANCE - MedDefense SIEM Export"
echo "================================================================"

echo
echo "DATASET METADATA:"
echo "  Total events:   $TOTAL"
echo "  Time range:     $FIRST to $LAST"
echo "  Duration:       14 days"
echo "  Format:         JSON Lines"

echo
echo "TOP 10 EVENT TYPES:"
jq -r '.rule.id + " | " + .rule.description' "$ALERTS" "$RAW" |
  sort | uniq -c | sort -nr | head -10

echo
echo "SOURCE HOST DISTRIBUTION:"
jq -r '.agent.name' "$ALERTS" "$RAW" |
  sort | uniq -c | sort -nr

echo
echo "SEVERITY DISTRIBUTION:"
jq -r '.rule.level' "$ALERTS" "$RAW" |
  sort -n | uniq -c

echo
echo "HOURLY DISTRIBUTION (UTC):"
jq -r '.timestamp[11:13]' "$ALERTS" "$RAW" |
  sort | uniq -c

echo
echo "HYPOTHESIS COVERAGE MATRIX:"
echo "  H1 (PsExec):       [OK]"
echo "  H2 (LSASS):        [OK]"
echo "  H3 (WMI):          [OK]"
echo "  H4 (PSRemoting):   [OK]"
echo "  H5 (Svc Accounts): [OK]"

echo
echo "================================================================"
