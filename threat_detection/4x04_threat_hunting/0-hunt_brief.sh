#!/bin/bash

MAPPING="reference/4x03_attack_mapping.json"

echo "================================================================"
echo "   THREAT HUNT BRIEF - HEALTHBANE Stage 4 (LOLBin Lateral Movement)"
echo "   Classification: TLP:AMBER"
echo "================================================================"

echo
echo "HC3 ADVISORY SUMMARY:"
echo "  Stage 4 TTPs:"
echo "    [*] PsExec for remote command execution on servers"
echo "    [*] WMI for remote process creation and enumeration"
echo "    [*] PowerShell Remoting for interactive access and staging"
echo "    [*] Credential dumping via LSASS memory access"
echo "    [*] Service account abuse for lateral authentication"
echo "    [*] Off-hours operations to avoid detection"

echo
echo "ATT&CK COVERAGE GAP ANALYSIS:"
jq -r '.techniques[] |
  select(.tactic == "lateral-movement" or .tactic == "credential-access") |
  "  \(.techniqueID)  \(.comment)"' "$MAPPING"

echo
echo "  Stage 4 techniques in gap:"
jq -r '.techniques[] |
  select(.comment | startswith("NOT COVERED")) |
  select(.techniqueID == "T1021.002" or
         .techniqueID == "T1047" or
         .techniqueID == "T1021.006" or
         .techniqueID == "T1003.001" or
         .techniqueID == "T1078.002") |
  "    \(.techniqueID)  NOT COVERED"' "$MAPPING"

echo
echo "SCOPE:"
echo "  HEALTHBANE Stage 4 LOLBin-based lateral movement and credential access"

echo
echo "HUNT PRIORITY RANKING:"
echo "  P1: T1021.002 PsExec"
echo "  P2: T1003.001 LSASS"
echo "  P3: T1047 WMI"
echo "  P4: T1021.006 PSRemoting"
echo "  P5: T1078.002 Domain Accounts"

echo
echo "DATA SOURCES:"
echo "  Primary: siem_export/wazuh_alerts_14d.json"
echo "  Secondary: siem_export/wazuh_raw_sysmon_14d.json"
echo "  Baseline: baseline/robert_kim_activity.json"

echo
echo "TIME WINDOW: 14 days"

echo
echo "FALSE-POSITIVE CONTROLS:"
echo "  Robert Kim schedule: reference/admin_schedule.txt"
echo "  Service account matrix: reference/service_accounts.txt"
echo "  Network topology: reference/network_topology.txt"

echo
echo "================================================================"
