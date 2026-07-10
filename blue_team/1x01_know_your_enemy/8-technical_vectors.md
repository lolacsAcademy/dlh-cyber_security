# Technical Vector Assessment — MedDefense

## 1. Vulnerable Software
Evidence: Apache 2.4.29 w/ known RCE on billing-srv-01 (T0); Ubuntu 18.04 LTS EOL since Jun 2023 (A-04)
Affected Asset(s): billing-srv-01 (A-04)
Actor Most Likely: Unskilled/Opportunistic (T6) — already exploited once (crypto-miner)
Exploitation Scenario: Automated scanner finds the exposed Apache RCE and exploits it without targeting (already happened); a ransomware affiliate could use the same unpatched Apache as initial access instead of buying broker access.
Current Protection: None specific — perimeter firewall (C-001) doesn't block traffic the service needs open
Gap Reference: GAP-003

## 2. Unsupported Systems
Evidence: WS-RAD-01 Windows XP SP3 (EOL); print-srv-01 Windows Server 2012 (EOL Oct 2023)
Affected Asset(s): WS-RAD-01 (A-14), print-srv-01 (A-08)
Actor Most Likely: Ransomware/Organized crime (T6) — legacy systems are BlackReef's cited easy-entry factor
Exploitation Scenario: No patches exist for either OS; an attacker finds a known unpatched exploit, gains code execution, and pivots across the flat network to the ~320 workstations on the same segment.
Current Protection: WS-RAD-01: compensating controls exist per Task 6 (details not in current file set). print-srv-01: none documented.
Gap Reference: No dedicated Gap ID for either — flagged
## 3. Open Service Ports
Evidence: MySQL 3306 + PostgreSQL 5432 open network-wide; IoT web interfaces reachable everywhere
Affected: billing-srv-01, ehr-db-01, monitors, pumps
Actor: Ransomware + Unskilled/Opportunistic (T6)
Exploitation: Any foothold reaches DBs/IoT directly, no segmentation to stop it
Protection: None
Gap: GAP-003 (MySQL), GAP-001 (pumps); PostgreSQL not gap-mapped

## 4. Default Credentials
Evidence: PACS shared login (raduser/radiology1); pump default creds not confirmed, only known CVE
Affected: pacs-srv-01, Infusion Pumps
Actor: Insider (malicious/negligent) for PACS; Ransomware if pumps pivoted
Exploitation: Shared login = no attribution; pump CVE + flat network = remote dosage tampering risk
Protection: C-012 exists but defeated by shared use
Gap: GAP-008, GAP-001
## 5. Unsecure Networks
Evidence: Flat network confirmed by scan; Westside consumer router runs VPN; guest WiFi isolation unverified
Affected: All 5 subnets
Actor: Ransomware (T6) — core mechanism of T2 attack sequence
Exploitation: One compromised device anywhere reaches everything; consumer router = bridge into Central
Protection: None — segmentation absent org-wide
Gap: Underlies GAP-005 → GAP-010 → GAP-004 → GAP-002

## 6. Removable Devices / Unmanaged Endpoints
Evidence: Undocumented devices (10.10.2.99, 10.10.10.200); Dr. Patel's NAS; orphaned Pi. USB GPO/iPads not confirmed in provided files — flagged.
Affected: Segment the device sits on
Actor: Insider (Negligent)
Exploitation: Unmanaged device on flat network = unmonitored pivot point
Protection: None — zero controls apply per Task 10
Gap: GAP-009 (Pi); no Gap ID for the other devices
