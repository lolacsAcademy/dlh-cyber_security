#!/bin/bash

echo "================================================================"
echo "   ATTACK RECONSTRUCTION: Stage 4"
echo "   Lateral Movement, Data Staging, and Containment"
echo "================================================================"

echo
echo "LATERAL MOVEMENT CHAIN:"
echo
echo "  2026-05-05 03:22 CDT  Credential dump on WS-RECV-03"
echo "    Tool: debug_tool.exe"
echo "    Target: LSASS"
echo "    Result: svc_healthsync credential harvested"
echo "    Evidence: 4x04 hunt + IR memory + IR disk"
echo "    Technique: T1003.001 LSASS Memory"
echo "    Confidence: CONFIRMED"
echo
echo "  2026-05-06 02:12 CDT  WS-RECV-03 -> SRV-HEALTH-DB"
echo "    Tool: PsExec; follow-on WMI and PowerShell Remoting"
echo "    Credential: svc_healthsync via NTLM"
echo "    Evidence: 4x04 hunt + IR disk + IR firewall"
echo "    Technique: T1021.002 SMB/Windows Admin Shares"
echo "    Confidence: CONFIRMED"
echo
echo "  2026-05-09 03:40 CDT  WS-RECV-03 -> SRV-INS-DB"
echo "    Tool: PsExec; follow-on WMI and PowerShell Remoting"
echo "    Credential: svc_healthsync via NTLM"
echo "    Evidence: 4x04 hunt + IR disk + IR firewall"
echo "    Confidence: CONFIRMED"
echo
echo "  2026-05-13 01:56 CDT  WS-RECV-03 -> SRV-DC-01"
echo "    Tool: PsExec + PowerShell Remoting"
echo "    Credential: svc_healthsync via NTLM"
echo "    Activity: Get-ADUser enumeration"
echo "    Evidence: 4x04 hunt + IR disk + IR firewall"
echo "    Confidence: CONFIRMED"

echo
echo "HUNT VISIBILITY GAP:"
echo "  203.0.113.47:8443 secondary C2 was missed by 4x04 because"
echo "  the hunt lacked firewall visibility."
echo "  IR memory identified the live RAT connection and IR firewall"
echo "  corroborated its activity from 2026-05-07."
echo "  Confidence: PROBABLE secondary/fallback C2"

echo
echo "CREDENTIAL ASSESSMENT:"
echo "  svc_healthsync:"
echo "    Harvested from LSASS by debug_tool.exe."
echo "    Recovered out.dat contains svc_healthsync strings."
echo "    Used for lateral movement to the three target servers."
echo "    Confidence: CONFIRMED"
echo
echo "  2026-05-12 02:45 CDT  Second LSASS dump"
echo "    Assessment: consistent with credential re-acquisition."
echo "    Confidence: PROBABLE"
echo
echo "  svc_backup:"
echo "    Name discovered during AD enumeration."
echo "    No evidence it was abused or compromised."
echo "  Additional compromised credentials: none confirmed."

echo
echo "DATA ACCESS AND STAGING:"
echo
echo "  2026-05-08 02:36 CDT  Patient data staged on WS-RECV-03"
echo "    Source: SRV-HEALTH-DB"
echo "    Records: 47,138 patient records"
echo "    Archive: staging_export_001.zip (14.2 MB)"
echo "    Techniques: T1005, T1074.001, T1560.001"
echo "    Confidence: CONFIRMED"
echo
echo "  2026-05-11 03:14 CDT  Insurance data staged on WS-RECV-03"
echo "    Source: SRV-INS-DB"
echo "    Records: 51,002 insurance records"
echo "    Archive: staging_export_002.zip (11.8 MB)"
echo "    Techniques: T1005, T1074.001, T1560.001"
echo "    Confidence: CONFIRMED"
echo
echo "  2026-05-13 02:31 CDT  AD enumeration staged"
echo "    Source: SRV-DC-01"
echo "    Records: 1,184 domain user/service-account records"
echo "    File: query_results.csv (8.4 MB)"
echo "    Confidence: CONFIRMED"
echo
echo "  STAGING FLOW:"
echo "    Target servers -> WS-RECV-03 -> local staging files -> C2"
echo "    Data was pulled to WS-RECV-03 before outbound transfer."
echo
echo "  EXFILTRATION STATUS: CONFIRMED"
echo "    Firewall outbound byte counts exactly match all three staging files."
echo "    Confirmed exfiltration: 34,441,660 bytes."

echo
echo "PERSISTENCE AND OPERATIONAL SECURITY:"
echo "  2026-05-07 01:47:33 CDT  HealthSync Update Service created"
echo "    Trigger: daily at 02:00"
echo "    Technique: T1053.005 Scheduled Task/Job"
echo "    Confidence: CONFIRMED by memory + disk"
echo
echo "  Defender exclusion added for C:\Windows\Temp before LSASS dumping."
echo "  Security.evtx cleared on 2026-05-09; 12-minute event gap."
echo "    Technique: T1070.001 Clear Windows Event Logs"
echo "  Staging artifacts were deleted after use."
echo "    Technique: T1070.004 File Deletion"
echo "  OPSEC assessment: off-hours activity, native/admin tools,"
echo "  encrypted C2, log clearing and file deletion reduced visibility."
echo "  Behavioral anomalies ultimately exposed activity because a records"
echo "  workstation used administrative tools against server systems."

echo
echo "CONTAINMENT TIMELINE:"
echo "  2026-05-15 02:00 CDT  Final exfiltration attempt"
echo "  2026-05-15 13:42 CDT  WS-RECV-03 isolated"
echo "  2026-05-15 14:18 CDT  Volatile memory captured"
echo "  2026-05-15 19:45 CDT  Disk image completed and verified"
echo
echo "  Containment stopped further C2 communication from WS-RECV-03."
echo "  Evidence confirms major patient, insurance and AD datasets had"
echo "  already been exfiltrated before isolation."
echo
echo "  IF NOT CONTAINED:"
echo "    Evidence supports continued scheduled C2/exfiltration activity."
echo "    The supplied evidence does not support a reliable estimate of"
echo "    the attacker's next target or time to another transfer."

echo
echo "================================================================"
