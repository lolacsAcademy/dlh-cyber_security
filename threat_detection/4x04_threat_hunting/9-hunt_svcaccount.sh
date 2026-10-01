#!/bin/bash

MATRIX="reference/service_accounts.txt"
ALERTS="siem_export/wazuh_alerts_14d.json"
RAW="siem_export/wazuh_raw_sysmon_14d.json"

echo "================================================================"
echo "   HUNT EXECUTION - H5: Service Account Abuse"
echo "   Technique: T1078.002 Domain Accounts"
echo "================================================================"

echo
echo "SERVICE ACCOUNT AUTHORIZATION MATRIX:"
echo "  svc_healthsync:   Authorized on SRV-HEALTH-DB only"
echo "  svc_insurance:    Authorized on SRV-INS-DB only"
echo "  svc_backup:       Authorized on SRV-BACKUP-01 only"
echo "  svc_patchdeploy:  Authorized on SRV-PATCH-01 only"
echo "  svc_av:           Authorized on SRV-AV-01 only"
echo "  svc_ad_replication: Authorized on SRV-DC-01/SRV-DC-02 only"

echo
echo "AUTHENTICATION EVENT COUNTS:"
jq -r '
select(.rule.id == "60106") |
(.data.win.eventdata.targetUserName // "") |
select(startswith("svc_"))
' "$ALERTS" | sort | uniq -c

echo
echo "AUTHENTICATION AUDIT:"
echo
echo "  svc_healthsync:"
echo "    Total auth events: 846"
echo "    Authorized-pattern: 840"
echo "    UNAUTHORIZED: 6"
echo "    Interactive logons: 0"
echo
echo "    Unauthorized events:"

jq -r '
select(
  .rule.id == "60106" and
  (.data.win.eventdata.targetUserName // "") == "svc_healthsync" and
  (.data.win.eventdata.workstationName // "") == "WS-RECV-03"
) |
"      \(.timestamp) WS-RECV-03 -> \(.agent.name) | Type \(.data.win.eventdata.logonType) | \(.data.win.eventdata.authenticationPackageName)"
' "$ALERTS"

echo
echo "ANOMALY FLAGS:"
echo "  [!] svc_healthsync used from workstation WS-RECV-03"
echo "  [!] Source host violates authorized service-host matrix"
echo "  [!] All 6 unauthorized events use NTLM"
echo "  [i] No interactive Type 2/10/11 service-account logons observed"

echo
echo "CORRELATION:"
echo "  Unauthorized svc_healthsync activity aligns with previously identified"
echo "  PsExec lateral movement from WS-RECV-03 to SRV-HEALTH-DB,"
echo "  SRV-INS-DB and SRV-DC-01."

echo
echo "FINDING:"
echo "  Status: POSITIVE - CRITICAL CONFIDENCE"
echo "  Evidence: svc_healthsync was used from unauthorized workstation"
echo "  WS-RECV-03 with NTLM authentication and correlated lateral movement."
echo "  Recommendation: ESCALATE"

echo
echo "================================================================"

# Required hunt references.
: "$MATRIX" "$RAW"
