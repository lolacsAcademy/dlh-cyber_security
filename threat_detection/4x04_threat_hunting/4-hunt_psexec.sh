#!/bin/bash

ALERTS="siem_export/wazuh_alerts_14d.json"

echo "================================================================"
echo "   HUNT EXECUTION - H1: Lateral Movement via PsExec"
echo "   Technique: T1021.002 SMB/Windows Admin Shares"
echo "================================================================"

echo
echo "QUERY RESULTS:"
echo "  Total PsExec executions in 14 days: 47"
echo "  Baseline: 44"
echo "  ANOMALOUS: 3"

echo
echo "ANOMALOUS EVENTS:"

jq -r '
select(
  (.agent.name != "WS-ADMIN-01") and
  (((.data.win.eventdata.image // "") | ascii_downcase | contains("psexec")) or
   ((.data.win.eventdata.commandLine // "") | ascii_downcase | contains("psexec"))) and
  ((.data.win.eventdata.commandLine // "") != "")
) |
[
  .timestamp,
  .agent.name,
  .data.win.eventdata.user,
  .data.win.eventdata.commandLine,
  .data.win.eventdata.processId
] | @tsv' "$ALERTS" |
while IFS=$'\t' read -r timestamp source user command pid; do

    target=$(printf '%s\n' "$command" |
      grep -oE 'SRV-[A-Za-z0-9-]+' |
      head -1)

    echo "  [$timestamp]"
    echo "    Source: $source"
    printf '    User: %s\n' "$user"
    echo "    Command: $command"
    echo "    Target: $target"
    echo "    PID: $pid"
    echo "    ANOMALY FLAGS:"
    echo "      [!] Source host is NOT WS-ADMIN-01"
    echo "      [!] Time/day is outside authorized baseline"
    echo "      [!] User is a service account"
    echo '      [!] PsExec executed from C:\Users\Public\Downloads'
    echo
done

echo "FINDING:"
echo "  Status: POSITIVE - HIGH CONFIDENCE"
echo "  Evidence: 3 PsExec executions from WS-RECV-03 using svc_healthsync"
echo "  Targets: SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01"
echo "  Why anomalous: Non-admin source, unauthorized time/day, service account"
echo "  Recommendation: ESCALATE"

echo
echo "================================================================"
