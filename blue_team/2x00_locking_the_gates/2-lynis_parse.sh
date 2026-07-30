#!/bin/bash
set -euo pipefail

# Task 2 - Lynis Audit Parser
# Parses a Lynis .dat report file into structured JSON.

REPORT="$1"

HARDENING_INDEX=$(grep "^hardening_index=" "$REPORT" | head -1 | cut -d= -f2)

jq -n \
  --argjson hardening_index "$HARDENING_INDEX" \
  --slurpfile findings <(
    grep -E "^(warning|suggestion|manual_check)\[\]=" "$REPORT" | while IFS='=' read -r key value; do
      severity=$(echo "$key" | sed 's/\[\]//')
      # value fields are pipe-separated: test_id|...|message|...
      test_id=$(echo "$value" | cut -d'|' -f1)
      message=$(echo "$value" | cut -d'|' -f2)
      jq -n --arg severity "$severity" --arg test_id "$test_id" --arg message "$message" \
        '{severity: $severity, test_id: $test_id, message: $message}'
    done | jq -s '.'
  ) \
  '{hardening_index: $hardening_index, findings: $findings[0]}'
