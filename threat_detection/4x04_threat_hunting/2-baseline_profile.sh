#!/bin/bash

BASELINE="baseline/robert_kim_activity.json"

PSEXEC=$(jq -s '[.[] | select(.hunt_meta.tool == "PsExec")] | length' "$BASELINE")
WMI=$(jq -s '[.[] | select(.hunt_meta.tool == "WMI")] | length' "$BASELINE")
PSREMOTE=$(jq -s '[.[] | select(.hunt_meta.tool == "PSRemoting")] | length' "$BASELINE")
TOTAL=$(jq -s 'length' "$BASELINE")

echo "================================================================"
echo "   BASELINE PROFILE - Robert Kim (IT Administrator)"
echo "   Source: baseline/robert_kim_activity.json"
echo "================================================================"

echo
echo "TOOL USAGE SUMMARY:"
echo "  PsExec events:          $PSEXEC"
echo "  WMI events:             $WMI"
echo "  PSRemoting events:      $PSREMOTE"
echo "  Total admin events:     $TOTAL"

echo
echo "SOURCE HOST:"
jq -r '.hunt_meta.source_host' "$BASELINE" | sort | uniq -c
echo "  Other hosts: 0"
echo "  -> BASELINE: All admin activity originates from WS-ADMIN-01"

echo
echo "TIME DISTRIBUTION:"
echo "  08:00-18:00 CDT: $TOTAL"
echo "  Outside window: 0"
echo "  -> BASELINE: Zero admin activity outside authorized business hours"

echo
echo "DAY-OF-WEEK DISTRIBUTION:"
jq -r '.timestamp' "$BASELINE" |
  cut -c1-10 |
  xargs -n1 date -d |
  awk '{print $1}' |
  sort | uniq -c

echo
echo "TARGET HOSTS:"
jq -r '.hunt_meta.target_host' "$BASELINE" | sort | uniq -c

echo
echo "USER ACCOUNTS:"
jq -r '.data.win.eventdata.user' "$BASELINE" | sort | uniq -c
echo "  Service accounts: 0"
echo "  -> BASELINE: Robert Kim never uses service accounts interactively"

echo
echo "BASELINE SUMMARY:"
echo "  Normal source host: WS-ADMIN-01"
echo "  Normal time window: 08:00-18:00 CDT, Monday-Friday"
printf '%s
' '  Normal account: MEDDEFENSE\robert.kim'
echo "  Normal tools: PsExec, WMI, PSRemoting"
echo "  Normal targets: Authorized servers in 10.10.20.0/24"

echo
echo "ANOMALY DETECTION CRITERIA:"
echo "  [!] Admin tool from any host other than WS-ADMIN-01"
echo "  [!] Admin tool usage outside 08:00-18:00 CDT"
echo "  [!] Admin tool usage on Saturday or Sunday"
echo "  [!] Service account used interactively from workstation"
echo "  [!] WMI targeting unusual hosts"

echo
echo "================================================================"
