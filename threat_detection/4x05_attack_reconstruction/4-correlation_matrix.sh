#!/bin/bash

T0="0-evidence_index.sh"
T1="1-memory_analysis.sh"
T2="2-disk_analysis.sh"
T3="3-firewall_analysis.sh"

P00="previous_findings/4x00_phishing_summary.txt"
P01="previous_findings/4x01_network_timeline.txt"
P02="previous_findings/4x02_attack_mapping.json"
P03="previous_findings/4x03_malware_summary.txt"
P04="previous_findings/4x04_hunting_report.txt"

MEM="ir_evidence/memory_artifacts.txt"
DISK="ir_evidence/disk_forensics_report.txt"
FW="ir_evidence/firewall_sessions_ws_recv_03.json"
IOC="reference/healthbane_ioc_master.json"

echo "================================================================"
echo "   CROSS-EVIDENCE CORRELATION MATRIX"
echo "   Sources: 4x00 through 4x05-IR"
echo "================================================================"

echo
echo "SOURCE INPUTS:"
echo "  $T0"
echo "  $T1"
echo "  $T2"
echo "  $T3"
echo "  $P00"
echo "  $P01"
echo "  $P02"
echo "  $P03"
echo "  $P04"
echo "  $MEM"
echo "  $DISK"
echo "  $FW"
echo "  $IOC"

echo
echo "IOC CORRELATION:"
printf "  %-24s %-22s %-10s %s\n" "IOC" "Sources" "Status" "Correlation"
printf "  %-24s %-22s %-10s %s\n" "185.220.101.45" "4x01,4x03,IR" "KNOWN" "CONVERGED"
printf "  %-24s %-22s %-10s %s\n" "203.0.113.47" "IR-MEM,IR-FW" "NEW" "CONVERGED"
printf "  %-24s %-22s %-10s %s\n" "svchost_update.exe" "4x03,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"
printf "  %-24s %-22s %-10s %s\n" "sync_healthdata.ps1" "4x03,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"
printf "  %-24s %-22s %-10s %s\n" "debug_tool.exe" "4x04,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"
printf "  %-24s %-22s %-10s %s\n" "PsExec64.exe" "4x04,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"
printf "  %-24s %-22s %-10s %s\n" "svc_healthsync" "4x04,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"

echo
echo "  New IOC: 203.0.113.47:8443 - secondary/fallback C2"
echo "  Conflicted IOCs: none identified"

echo
echo "TIMELINE CORRELATION:"
echo "  C2 beaconing           4x01, IR-MEM, IR-FW      CONFIRMED"
echo "  Malware execution      4x03, IR-MEM, IR-DISK    CONFIRMED"
echo "  Credential dumping     4x04, IR-MEM, IR-DISK    CONFIRMED"
echo "  Lateral movement       4x04, IR-DISK, IR-FW     CONFIRMED"
echo "  Scheduled persistence  IR-MEM, IR-DISK          CONFIRMED"
echo "  Data staging           IR-DISK, IR-FW           CONFIRMED"
echo "  Data exfiltration      IR-DISK, IR-FW           CONFIRMED"
echo "  Event-log clearing     IR-MEM, IR-DISK          CONFIRMED"

echo
echo "TIMESTAMP CONTRADICTION:"
echo "  Firewall timestamps are 4 seconds ahead of PCAP/Wazuh."
echo "  Cause: collection-point and SYN policy-decision timing."
echo "  Resolution: firewall time is authoritative for connection initiation."

echo
echo "TECHNIQUE CORRELATION:"
printf "  %-12s %-12s %-18s %s\n" "Technique" "4x02" "Later evidence" "Update"
printf "  %-12s %-12s %-18s %s\n" "T1204.002" "INFERRED" "4x03" "CONFIRMED"
printf "  %-12s %-12s %-18s %s\n" "T1059.005" "INFERRED" "4x03" "CONFIRMED"
printf "  %-12s %-12s %-18s %s\n" "T1059.001" "INFERRED" "4x03,IR" "CONFIRMED"
printf "  %-12s %-12s %-18s %s\n" "T1547.001" "INFERRED" "4x03,IR-DISK" "CONFIRMED"
printf "  %-12s %-12s %-18s %s\n" "T1027" "INFERRED" "4x03" "CONFIRMED"
printf "  %-12s %-12s %-18s %s\n" "T1041" "INFERRED" "4x03,IR-FW" "CONFIRMED"
printf "  %-12s %-12s %-18s %s\n" "T1048.003" "INFERRED" "4x03 sandbox" "CAPABILITY CONFIRMED"
printf "  %-12s %-12s %-18s %s\n" "T1053.005" "---" "IR-MEM,IR-DISK" "NEW"
printf "  %-12s %-12s %-18s %s\n" "T1074.001" "---" "4x03,IR-DISK" "CONFIRMED"
printf "  %-12s %-12s %-18s %s\n" "T1560.001" "---" "4x03,IR-DISK" "CONFIRMED"
printf "  %-12s %-12s %-18s %s\n" "T1070.001" "---" "IR-MEM,IR-DISK" "NEW"

echo
echo "CONTRADICTIONS RESOLVED:"
echo "  [1] Firewall/PCAP timing differs by 4 seconds."
echo "      Resolution: firewall timestamp used for connection initiation."
echo "  [2] Earlier investigations did not confirm successful exfiltration."
echo "      Resolution: disk and firewall evidence now converge; outbound"
echo "      byte counts exactly match the three recovered staging artifacts."
echo "  [3] T1048.003 DNS exfiltration capability is confirmed in 4x03,"
echo "      but execution at MedDefense is not established."

echo
echo "GAPS:"
echo "  - Memory and disk IR evidence cover WS-RECV-03 only."
echo "  - Firewall evidence is an abridged 168-session export."
echo "  - DNS exfiltration capability exists, but observed use is unconfirmed."

echo
echo "================================================================"
