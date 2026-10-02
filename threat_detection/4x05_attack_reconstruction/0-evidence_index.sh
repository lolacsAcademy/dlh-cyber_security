#!/bin/bash

echo "================================================================"
echo "   EVIDENCE INVENTORY - HEALTHBANE Reconstruction"
echo "   Analyst: $(hostname)    Date: $(date +%F)"
echo "================================================================"

echo
echo "SOURCE CATALOG:"

echo "  [01] 4x00_phishing_summary.txt"
echo "       Phase: 4x00"
echo "       Type: Email"
echo "       Coverage: 2026-04-14 to 2026-04-15"
echo "       Reliability: MEDIUM - derived findings"
echo "       Key content: phishing campaign and credential compromise"

echo
echo "  [02] 4x01_network_timeline.txt"
echo "       Phase: 4x01"
echo "       Type: Network"
echo "       Coverage: 48-hour investigation window"
echo "       Reliability: MEDIUM - derived findings"
echo "       Key content: C2 activity and network attack timeline"

echo
echo "  [03] 4x02_attack_mapping.json"
echo "       Phase: 4x02"
echo "       Type: Intelligence"
echo "       Coverage: Through 2026-04-21"
echo "       Reliability: MEDIUM - derived ATT&CK mapping"
echo "       Key content: HEALTHBANE ATT&CK coverage and intelligence"

echo
echo "  [04] 4x03_malware_summary.txt"
echo "       Phase: 4x03"
echo "       Type: Malware"
echo "       Coverage: 2026-04-22 to 2026-05-02"
echo "       Reliability: MEDIUM - derived findings"
echo "       Key content: malware capabilities, persistence and IOCs"

echo
echo "  [05] 4x04_hunting_report.txt"
echo "       Phase: 4x04"
echo "       Type: SIEM"
echo "       Coverage: 2026-05-04 to 2026-05-18"
echo "       Reliability: MEDIUM - derived findings"
echo "       Key content: credential access and lateral movement"

echo
echo "  [06] memory_artifacts.txt"
echo "       Phase: 4x05-IR"
echo "       Type: Memory"
echo "       Coverage: Capture 2026-05-15"
echo "       Reliability: HIGH - primary evidence"
echo "       Key content: malware, persistence, processes and connections"

echo
echo "  [07] disk_forensics_report.txt"
echo "       Phase: 4x05-IR"
echo "       Type: Disk"
echo "       Coverage: 2026-04-22 to 2026-05-15"
echo "       Reliability: HIGH - primary evidence"
echo "       Key content: persistence, staging, deleted files and anti-forensics"

echo
echo "  [08] firewall_sessions_ws_recv_03.json"
echo "       Phase: 4x05-IR"
echo "       Type: Firewall"
echo "       Coverage: 2026-05-02 to 2026-05-15"
echo "       Reliability: HIGH - primary evidence"
echo "       Key content: C2, exfiltration and lateral movement"

echo
echo "  [09] ir_team_notes.txt"
echo "       Phase: 4x05-IR"
echo "       Type: IR observations"
echo "       Coverage: 2026-05-15 to 2026-05-18"
echo "       Reliability: LOW - preliminary observations"
echo "       Key content: IR observations and unresolved questions"

echo
echo "  [10] healthbane_ioc_master.json"
echo "       Phase: Reference"
echo "       Type: Intelligence"
echo "       Coverage: 4x00 through 4x04"
echo "       Reliability: MEDIUM - consolidated reference"
echo "       Key content: master HEALTHBANE IOC database"

echo
echo "  [11] attck_navigator_80pct.json"
echo "       Phase: Reference"
echo "       Type: Intelligence"
echo "       Coverage: Through 4x04"
echo "       Reliability: MEDIUM - derived reference"
echo "       Key content: 80% observed ATT&CK coverage baseline"

echo
echo "  [12] meddefense_asset_inventory.txt"
echo "       Phase: Reference"
echo "       Type: Asset inventory"
echo "       Coverage: Current environment"
echo "       Reliability: HIGH - organizational reference"
echo "       Key content: host roles and data sensitivity"

echo
echo "  [13] network_topology.txt"
echo "       Phase: Reference"
echo "       Type: Network reference"
echo "       Coverage: Current environment"
echo "       Reliability: HIGH - organizational reference"
echo "       Key content: network segments, hosts and authorized paths"

echo
echo "TEMPORAL COVERAGE MATRIX:"
echo "  Apr 14-15  [EMAIL][NETWORK]"
echo "  Apr 22-May02 [MALWARE][DISK]"
echo "  May 02-15  [FIREWALL][DISK][SIEM]"
echo "  May 15     [MEMORY][DISK][FIREWALL][SIEM]"
echo "  May 15-18  [IR NOTES][SIEM]"
echo
echo "  GAP: Network capture is limited to the earlier 48-hour window"
echo "  GAP: Memory and disk evidence cover only WS-RECV-03"
echo "  GAP: Some attack phases rely on a single evidence domain"

echo
echo "CRITICAL QUESTIONS FOR RECONSTRUCTION:"
echo "  [Q1] Do the new IR sources confirm or contradict previous findings?"
echo "  [Q2] What is the role of the secondary C2?"
echo "  [Q3] Was sensitive data successfully exfiltrated?"
echo "  [Q4] What persistence and anti-forensics activity occurred?"
echo "  [Q5] Which ATT&CK and evidence gaps remain?"

echo
echo "================================================================"
