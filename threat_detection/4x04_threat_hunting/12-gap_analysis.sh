#!/bin/bash

echo "================================================================"
echo "   DETECTION GAP ANALYSIS - Stage 4 Techniques"
echo "================================================================"

echo
echo "GAP 1: T1021.002 PsExec Lateral Movement"
echo "  Hunt Finding: PsExec from WS-RECV-03 using svc_healthsync"
echo "  Why Missed: Missing behavior-specific rule; generic Sysmon events existed"
echo "  Data Source: Sysmon Event 1"
echo "  Required Rule: Match PsExec process/command line and compare source host,"
echo "                 user, time and target against the admin baseline;"
echo "                 allowlist authorized WS-ADMIN-01 activity"
echo "  Priority: P1"

echo
echo "GAP 2: T1003.001 LSASS Credential Access"
echo "  Hunt Finding: debug_tool.exe accessed lsass.exe with 0x1010"
echo "  Why Missed: Missing behavior-specific rule; generic Event 10 existed"
echo "  Data Source: Sysmon Event 10"
echo "  Required Rule: Match TargetImage=lsass.exe and alert when SourceImage"
echo "                 is not an allowlisted legitimate/system process"
echo "  Priority: P1"

echo
echo "GAP 3: WMI Remote Execution"
echo "  Hunt Finding: Not observed from the confirmed pivot host"
echo "  Why Missed: No confirmed malicious WMI event to classify as missed"
echo "  Data Source: Sysmon Event 1"
echo "  Required Rule: Match WMIC/WMI execution and compare source host, user,"
echo "                 target and maintenance window against admin baseline"
echo "  Priority: P2"

echo
echo "GAP 4: PowerShell Remoting"
echo "  Hunt Finding: Enter-PSSession from WS-RECV-03 to database servers"
echo "  Why Missed: Missing behavior-specific rule; generic Event 1 existed"
echo "  Data Source: Sysmon Event 1 / PowerShell logs"
echo "  Required Rule: Match Enter-PSSession or remote PowerShell activity;"
echo "                 compare source, account and target against admin baseline"
echo "  Priority: P1"

echo
echo "GAP 5: T1078.002 Service Account Misuse"
echo "  Hunt Finding: svc_healthsync authenticated from WS-RECV-03"
echo "  Why Missed: Missing service-account authorization rule; successful"
echo "              logons were recorded only as generic Windows Event 4624"
echo "  Data Source: Windows Event 4624"
echo "  Required Rule: Match svc_* accounts and compare workstation/source host"
echo "                 with the service-account authorization matrix"
echo "  Priority: P1"

echo
echo "GAP 6: NTLM / Pass-the-Hash-Style Activity"
echo "  Hunt Finding: 6 unauthorized svc_healthsync logons used NTLM"
echo "  Why Missed: Missing authentication-method anomaly rule"
echo "  Data Source: Windows Event 4624"
echo "  Required Rule: Alert when a service account uses NTLM where the"
echo "                 authorization matrix requires Kerberos; allowlist only"
echo "                 explicitly documented exceptions"
echo "  Priority: P1"

echo
echo "SUMMARY:"
echo "  Relevant telemetry was present for the confirmed findings."
echo "  Generic collection rules did not encode the required behavioral"
echo "  baselines and authorization constraints."
echo "  WMI remains a detection coverage requirement, but malicious WMI"
echo "  activity was not observed from the confirmed pivot host."
echo "  Proactive hunting exposed the detection gaps."

echo
echo "================================================================"
