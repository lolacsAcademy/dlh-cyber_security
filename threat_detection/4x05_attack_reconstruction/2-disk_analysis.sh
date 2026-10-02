#!/bin/bash

echo "================================================================"
echo "   DISK FORENSICS ANALYSIS - WS-RECV-03"
echo "   Source: ir_evidence/disk_forensics_report.txt"
echo "================================================================"

echo
echo "RECOVERED DELETED FILES:"
echo "  staging_export_001.zip  C:\Users\Public\Tmp  2026-05-08 02:38  14.2 MB"
echo "    -> 47,138 patient records from SRV-HEALTH-DB"
echo "  staging_export_002.zip  C:\Users\Public\Tmp  2026-05-11 03:17  11.8 MB"
echo "    -> 51,002 insurance records from SRV-INS-DB"
echo "  query_results.csv       C:\Users\Public\Tmp  2026-05-13 02:34   8.4 MB"
echo "    -> 1,184 AD user/service-account records"
echo "  out.dat                 C:\Windows\Temp       PARTIAL            ~11 MB"
echo "    -> LSASS dump; svc_healthsync recovered"
echo
echo "  Analysis: Complete database exports were staged, archived and deleted."
echo "  ATT&CK: T1074.001 Local Data Staging, T1560.001 Archive Collected Data"

echo
echo "PREFETCH ANALYSIS:"
echo "  PsExec64.exe       First: 2026-05-06 02:11  Last: 2026-05-13 02:08  SUSPICIOUS"
echo "  debug_tool.exe     First: 2026-05-05 03:22  Last: 2026-05-12 02:45  SUSPICIOUS"
echo "  schtasks.exe       2026-05-07 01:47                              SUSPICIOUS"
echo "  WMIC.exe           2026-05-06 to 2026-05-13                      SUSPICIOUS"
echo "  PowerShell.exe     Last: 2026-05-15 02:00                        MIXED"
echo "  Topology: WS-RECV-03 is a records workstation; administrative"
echo "            tools are authorized only from IT administration hosts."

echo
echo "SCHEDULED TASK:"
echo "  Task: HealthSync Update Service"
echo "  Trigger: Daily at 02:00"
echo "  Action: Encoded PowerShell executing HEALTHBANE payload"
echo "  Created: 2026-05-07 01:47:33 CDT"
echo "  ATT&CK: T1053.005 Scheduled Task/Job"
echo "  Status: CONFIRMS Task 1 memory finding"

echo
echo "REGISTRY PERSISTENCE:"
echo "  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HealthSync"
echo "    -> svchost_update.exe"
echo "  Defender exclusion: C:\Windows\Temp"
echo "    -> Added before LSASS credential dumping"

echo
echo "NTFS TIMELINE:"
echo "  2026-05-05  debug_tool.exe created; LSASS dump produced"
echo "  2026-05-06  PsExec staged and first executed"
echo "  2026-05-07  HealthSync scheduled task created"
echo "  2026-05-08  patient data staged, archived and deleted"
echo "  2026-05-09  Security event log cleared"
echo "  2026-05-11  insurance data staged, archived and deleted"
echo "  2026-05-12  second LSASS dump"
echo "  2026-05-13  AD enumeration exported and deleted"

echo
echo "ANTI-FORENSICS INDICATORS:"
echo "  Security.evtx cleared/recreated: 2026-05-09 03:01:42 CDT"
echo "  Event gap: 03:00-03:12 CDT"
echo "  ATT&CK: T1070.001 Clear Windows Event Logs"
echo "  Deleted staging files: T1070.004 File Deletion"
echo "  Timestamp manipulation: none identified"

echo
echo "SUMMARY:"
echo "  Data staging confirmed: patient, insurance and AD data"
echo "  Persistence confirmed by scheduled task and Run key"
echo "  Anti-forensics confirmed: event-log clearing and file deletion"
echo "  Techniques: T1074.001, T1560.001, T1070.001, T1070.004"
echo "  Confidence: HIGH - primary disk evidence"

echo
echo "================================================================"
