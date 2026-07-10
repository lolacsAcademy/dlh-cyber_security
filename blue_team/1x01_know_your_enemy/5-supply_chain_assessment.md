# Supply Chain Risk Assessment — MedDefense

## 1. MedTech Solutions
Service: EHR maintenance, direct server access, 4hr SLA
Access Type: Network + Application (direct server access)
Access Scope: ehr-srv-01 (A-01) + ehr-db-01 (A-02) directly — but both sit on flat 10.10.2.0/24 with every other core server (PACS, billing, both DCs, backup-srv-01, NAS-01)
Compromise Scenario: MedTech breach → attacker lands on EHR server → flat network with no segmentation → reaches AD (ad-dc-01/02), backup-srv-01 and NAS-01 (single point of failure) → effectively the whole server tier
Existing Controls: Perimeter firewall (C-001) only — no segmentation limiting a vendor's server access from spreading
Risk Assessment: Critical — one vendor breach exposes the entire critical server segment

## 2. Microsoft (O365 E3)
Service: Org-wide email, SharePoint, OneDrive; identity if Entra ID used
Access Type: Application + Identity (cloud, org-wide)
Access Scope: All org email/SharePoint/OneDrive data, every site (Central, Westside, HQ); identity federation impact unconfirmed — asset registry shows on-prem AD (ad-dc-01/02), Entra ID linkage not documented
Compromise Scenario: M365 breach → attacker reads all org email/files; if Entra ID hybrid sync exists, possible pivot to on-prem AD (unconfirmed)
Existing Controls: Password policy (C-012); MFA status not documented
Risk Assessment: Critical — largest data footprint of any vendor, org-wide, single point of email/doc access
## 3. Sophos
Service: Endpoint protection agent, all managed endpoints, push updates/config
Access Type: Application (agent-level, code-push capability)
Access Scope: Every managed endpoint org-wide: ~320 Central workstations (A-13), ~36 Westside (A-26), ~120+25-30 HQ (A-30/31)
Compromise Scenario: Compromised vendor pushes malicious update → simultaneous compromise of every managed endpoint org-wide in one push (SolarWinds pattern)
Existing Controls: None documented beyond the agent itself — no separate monitoring for anomalous vendor push behavior
Risk Assessment: Critical — single push has the widest simultaneous blast radius of all 5 vendors

## 4. Siemens
Service: MRI scanner maintenance + firmware updates
Access Type: Physical + Application (on-site maintenance, firmware channel)
Access Scope: WS-RAD-01 (A-14, Windows XP SP3, EOL) — sits on 10.10.1.0/24, same flat network as ~320 clinical/admin workstations (A-13) and ER thin clients (A-15)
Compromise Scenario: Compromised Siemens access/firmware plants malware on the already-unsupported XP workstation → pivots across flat 10.10.1.0/24 to clinical/admin endpoints
Existing Controls: Compensating controls exist per Task 6 for WS-RAD-01 specifically (details not in current file set)
Risk Assessment: High — single legacy endpoint, but on a large flat clinical segment
## 5. Greenfield Building Management
Service: HQ network/internet infrastructure; MedDefense has a VLAN on their network
Access Type: Network (physical infrastructure ownership)
Access Scope: Underlying switching/routing for Corporate HQ — MedDefense's HQ VLAN (10.10.20.0/24: ~120 workstations A-30, ~25-30 laptops A-31) rides on hardware MedDefense doesn't own
Compromise Scenario: Greenfield breach → attacker controls underlying network layer → possible VLAN hop into MedDefense's HQ segment (Finance/HR/Legal/Exec)
Existing Controls: VLAN segmentation only — no additional encryption/monitoring documented for HQ
Risk Assessment: Medium — HQ holds admin/exec data, not core clinical Critical assets, but path into Finance/Exec is real

## Supply Chain Risk Summary
MedTech Solutions would cause the most damage if breached: its maintenance access lands directly on the EHR servers, and because 10.10.2.0/24 is flat with no internal segmentation, that one vendor's access effectively reaches every Critical server MedDefense has — both domain controllers, PACS, billing, and the backup/NAS single point of failure — in a single compromise. The one control to implement first, across all vendors, is network segmentation with a dedicated vendor-access VLAN and jump host/PAM for any third-party remote access — it directly limits MedTech, Siemens, and Greenfield's blast radius, and reduces how far a compromised Sophos endpoint agent could spread once inside.
