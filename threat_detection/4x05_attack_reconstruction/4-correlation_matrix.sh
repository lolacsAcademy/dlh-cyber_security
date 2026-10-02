#!/bin/bash

echo "================================================================"
echo "   CROSS-EVIDENCE CORRELATION MATRIX"
echo "   Sources: 4x00 through 4x05-IR"
echo "================================================================"

echo
echo "IOC CORRELATION:"
printf "  %-24s %-18s %-18s %s\n" "IOC" "Sources" "IR Status" "Correlation"
printf "  %-24s %-18s %-18s %s\n" "185.220.101.45" "4x01,4x03,IR" "KNOWN" "CONVERGED"
printf "  %-24s %-18s %-18s %s\n" "203.0.113.47" "IR-MEM,IR-FW" "NEW" "CONVERGED"
printf "  %-24s %-18s %-18s %s\n" "svchost_update.exe" "4x03,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"
printf "  %-24s %-18s %-18s %s\n" "sync_healthdata.ps1" "4x03,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"
printf "  %-24s %-18s %-18s %s\n" "debug_tool.exe" "4x04,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"
printf "  %-24s %-18s %-18s %s\n" "PsExec64.exe" "4x04,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"
printf "  %-24s %-18s %-18s %s\n" "svc_healthsync" "4x04,IR-MEM,IR-DISK" "KNOWN" "CONVERGED"

echo
echo "  New IOC from IR: 203.0.113.47:8443 - secondary/fallback C2"
echo "  Conflicted IOCs: none identified in analyzed evidence"

echo
echo "TIMELINE CORRELATION:"
echo "  Event                    Sources                 Confidence"
echo "  C2 beaconing             4x01,IR-MEM,IR-FW      CONFIRMED"
echo "  Malware execution        4x03,IR-MEM,IR-DISK    CONFIRMED"
echo "  Credential dumping       4x04,IR-MEM,IR-DISK    CONFIRMED"
echo "  Lateral movement         4x04,IR-DISK,IR-FW     CONFIRMED"
echo "  Scheduled persistence    IR-MEM,IR-DISK          CONFIRMED"
echo "  Patient data staging     IR-DISK,IR-FW           CONFIRMED"
echo "  Insurance data staging   IR-DISK,IR-FW           CONFIRMED"
echo "  Data exfiltration        IR-DISK,IR-FW           CONFIRMED"
echo "  Event-log clearing       IR-DISK,IR-MEM          CONFIRMED"

echo
echo "TIMESTAMP RESOLUTION:"
echo "  Firewall timestamps are 4 seconds ahead of PCAP/Wazuh timestamps."
echo "  Cause: different collection points and SYN policy-decision timing."
echo "  Resolution: firewall timestamp is authoritative for connection initiation."
echo "  Timezone differences are normalized using UTC/CDT labels in the evidence."

echo
echo "TECHNIQUE CORRELATION:"
printf "  %-12s %-14s %-18s %s\n" "Technique" "4x02" "Later Evidence" "Update"
printf "  %-12s %-14s %-18s %s\n" "T1204.002" "INFERRED" "4x03" "CONFIRMED"
printf "  %-12s %-14s %-18s %s\n" "T1059.005" "INFERRED" "4x03" "CONFIRMED"
printf "  %-12s %-14s %-18s %s\n" "T1059.001" "INFERRED" "4x03,IR" "CONFIRMED"
printf "  %-12s %-14s %-18s %s\n" "T1547.001" "INFERRED" "4x03,IR-DISK" "CONFIRMED"
printf "  %-12s %-14s %-18s %s\n" "T1027" "INFERRED" "4x03" "CONFIRMED"
printf "  %-12s %-14s %-18s %s\n" "T1041" "INFERRED" "4x03,IR-FW" "CONFIRMED"
printf "  %-12s %-14s %-18s %s\n" "T1048.003" "INFERRED" "4x03 sandbox" "CAPABILITY CONFIRMED"
printf "  %-12s %-14s %-18s %s\n" "T1053.005" "---" "IR-MEM,IR-DISK" "NEW"
printf "  %-12s %-14s %-18s %s\n" "T1074.001" "---" "4x03,IR-DISK" "CONFIRMED"
printf "  %-12s %-14s %-18s %s\n" "T1560.001" "---" "4x03,IR-DISK" "CONFIRMED"
printf "  %-12s %-14s %-18s %s\n" "T1070.001" "---" "IR-MEM,IR-DISK" "NEW"

echo
echo "CRITICAL CONTRADICTIONS:"
echo "  [1] Network timing differs by 4 seconds between firewall and PCAP/Wazuh."
echo "      RESOLVED: expected collection-point variance; firewall is authoritative"
echo "      for connection initiation."
echo
echo "  [2] Earlier findings did not confirm successful data exfiltration."
echo "      RESOLVED: IR disk and firewall evidence now converge. Three outbound"
echo "      transfers exactly match recovered staging-file byte counts."
echo
echo "  [3] T1048.003 DNS exfiltration capability exists in the 4x03 malware,"
echo "      but supplied evidence does not establish that DNS exfiltration was"
echo "      exercised at MedDefense. Capability and observed activity remain distinct."

echo
echo "GAPS:"
echo "  - IR memory and disk evidence are limited to WS-RECV-03."
echo "  - The firewall file is an abridged 168-session export of 39,412 sessions."
echo "  - DNS exfiltration capability is confirmed, but execution at MedDefense"
echo "    is not established by the supplied evidence."

echo
echo "================================================================"
