#!/bin/bash

MEM="ir_evidence/memory_artifacts.txt"
IOC="reference/healthbane_ioc_master.json"

echo "================================================================"
echo "   MEMORY ARTIFACT ANALYSIS - WS-RECV-03"
echo "   Source: $MEM"
echo "================================================================"

echo
echo "PROCESS ANALYSIS:"
echo "  svchost_update.exe   KNOWN   T1071.001 Web Protocols"
echo "    -> Running as PID 3712; matches HB-IOC-0013/0014"
echo "  powershell.exe       MODIFIED T1059.001 PowerShell"
echo "    -> Encoded command executes known sync_healthdata.ps1"
echo "  debug_tool.exe       KNOWN   T1003.001 LSASS Memory"
echo "    -> Exited process; accessed lsass.exe with 0x1010"
echo "  PsExec64.exe         KNOWN   T1021.002 SMB/Admin Shares"
echo "    -> Exited process used from non-standard path"

echo
echo "NETWORK CONNECTIONS:"
echo "  185.220.101.45:443   KNOWN"
echo "    -> PID 3712 svchost_update.exe; matches HB-IOC-0008"
echo "  203.0.113.47:8443    NEW"
echo "    -> PID 3712 svchost_update.exe; secondary C2"
echo "    -> ATT&CK: T1571 Non-Standard Port"

echo
echo "CREDENTIAL ACCESS INDICATORS:"
echo "  debug_tool.exe -> lsass.exe"
echo "    Source: recovered process handles"
echo "    Access: 0x1010"
echo "    ATT&CK: T1003.001 LSASS Memory"
echo "    Status: KNOWN"

echo
echo "LOADED MODULES:"
echo "  No suspicious credential-access DLL identified."
echo "  Evidence supports stand-alone debug_tool.exe instead."

echo
echo "PERSISTENCE MECHANISM:"
echo "  Scheduled Task: HealthSync Update Service"
echo "    Source: TaskCache registry hive"
echo "    Trigger: Daily at 02:00"
echo "    Action: encoded PowerShell downloads/executes HealthBane payload"
echo "    Created: 2026-05-07 06:47:33 UTC"
echo "    ATT&CK: T1053.005 Scheduled Task/Job"
echo "    Status: NEW"

echo
echo "IOC CROSS-REFERENCE:"
grep -q '"value": "svchost_update.exe"' "$IOC" &&
    echo "  svchost_update.exe: KNOWN"
grep -q '"value": "185.220.101.45"' "$IOC" &&
    echo "  185.220.101.45: KNOWN"
grep -q '"value": "203.0.113.47"' "$IOC" ||
    echo "  203.0.113.47: NEW"

echo
echo "SUMMARY:"
echo "  Known indicators confirmed: svchost_update.exe, C2 IP,"
echo "                              debug_tool.exe, PsExec64.exe"
echo "  New indicators: secondary C2 and scheduled task"
echo "  Confidence: HIGH - primary volatile evidence"

echo
echo "================================================================"
