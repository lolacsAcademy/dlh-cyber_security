#!/bin/bash

echo "================================================================"
echo "   DETECTION ENGINEERING - Hunt-Derived Rules"
echo "================================================================"

echo
echo "=== WAZUH-STYLE RULE DRAFTS ==="

echo
echo "[Rule 100100] PsExec from Non-Admin Workstation / Off-Hours"
echo "  Behavior: PsExec execution outside the authorized admin baseline"
echo "  Evidence: Hunt Task 4 - PsExec from WS-RECV-03 using svc_healthsync"
echo "  Data: Sysmon Event 1"
echo "  Logic: Match PsExec in Image/CommandLine; alert when source is not"
printf '%s\n' '         WS-ADMIN-01, account differs from MEDDEFENSE\robert.kim,'
echo "         or execution occurs outside the authorized maintenance window"
echo "  Allowlist: Robert Kim activity matching documented admin baseline"
echo "  FP Rate: VERY LOW"

echo
echo "[Rule 100101] LSASS Memory Access from Non-System Process"
echo "  Behavior: Non-allowlisted process accessing lsass.exe"
echo "  Evidence: Hunt Task 4 - debug_tool.exe accessed LSASS with 0x1010"
echo "  Data: Sysmon Event 10"
echo "  Logic: TargetImage contains lsass.exe and SourceImage is not an"
echo "         allowlisted legitimate Windows/system process"
echo "  Allowlist: Known legitimate system processes"
echo "  FP Rate: LOW"

echo
echo "[Rule 100102] Service Account from Unauthorized Host"
echo "  Behavior: Service account authentication violating authorization matrix"
echo "  Evidence: Hunt Task 5 - svc_healthsync Type 3/NTLM from WS-RECV-03"
echo "  Data: Windows Event 4624"
echo "  Logic: Match svc_* accounts; compare source host and authentication"
echo "         method with reference/service_accounts.txt authorization"
echo "  Allowlist: Documented service host and permitted authentication context"
echo "  FP Rate: VERY LOW"

echo
echo "[Rule 100103] WMI Remote Child Process Anomaly"
echo "  Behavior: WMI provider spawning shell or PowerShell process"
echo "  Evidence: Preventive gap identified in Task 7; malicious WMI was"
echo "            not observed from the confirmed pivot host"
echo "  Data: Sysmon Event 1"
echo "  Logic: ParentImage contains WmiPrvSE.exe and child Image matches"
echo "         cmd.exe or powershell.exe; compare source/user/time with baseline"
echo "  Allowlist: Documented Robert Kim maintenance activity"
echo "  FP Rate: MEDIUM"

echo
echo "[Rule 100104] Service Account NTLM Authentication"
echo "  Behavior: Service account using unauthorized NTLM authentication"
echo "  Evidence: Hunt Task 5 - 6 svc_healthsync NTLM authentication events"
echo "  Data: Windows Event 4624"
echo "  Logic: TargetUserName begins svc_ and AuthenticationPackageName=NTLM"
echo "  Allowlist: Explicitly documented exceptions only"
echo "  FP Rate: VERY LOW"

echo
echo "=== NETWORK RULE DRAFTS ==="

echo
echo "[Rule 9000030] SMB Lateral Movement - PsExec Service Pattern"
echo "  Behavior: SMB lateral movement consistent with PsExec remote execution"
echo "  Evidence: Hunt Task 4 - PsExec from WS-RECV-03 to three servers"
echo "  Data: Network/SMB telemetry"
echo "  Logic: Detect SMB activity associated with PsExec remote service use"
echo "         from a source outside the authorized admin baseline"
echo "  Allowlist: WS-ADMIN-01 during documented maintenance activity"
echo "  FP Rate: LOW"

echo
echo "=== DETECTION POSTURE UPDATE ==="
echo "  Before hunt: Generic telemetry existed, but Stage 4 behavioral"
echo "               baselines and authorization checks were missing"
echo "  After hunt: Draft detections cover PsExec anomaly, LSASS access,"
echo "              service-account misuse, NTLM misuse, WMI child-process"
echo "              anomaly and SMB lateral-movement behavior"
echo "  ATT&CK coverage improved for T1021.002, T1003.001 and T1078.002"
echo "  WMI coverage added preventively based on the identified detection gap"

echo
echo "================================================================"
