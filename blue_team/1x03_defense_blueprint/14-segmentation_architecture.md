# Task 14 — The Segmentation Architecture

MedDefense Health Systems — network segmentation design (Network Segmentation, Phase 1, RISK-003).

## Part 1 — Zone Definition

### Zone 1: Server Zone (VLAN 10)
- IP Range: 10.10.10.0/24
- Systems: ehr-srv-01, ehr-db-01, billing-srv-01, ad-dc-01, ad-dc-02, file server
- Allowed Outbound: To Backup Zone only (replication traffic); no direct internet access
- Allowed Inbound: From Clinical Workstation Zone (app-layer ports only, e.g. HTTPS to EHR web front end); from Medical Device Zone (PACS data interface, specific port only); from Management Zone (admin ports, restricted source IPs)

### Zone 2: Clinical Workstation Zone (VLAN 20)
- IP Range: 10.10.20.0/24
- Systems: Nurse station and physician workstations (subset of the 280 clinical workstations)
- Allowed Outbound: HTTPS to Server Zone (EHR web app); limited internet via web proxy
- Allowed Inbound: From Management Zone only (patch deployment, support)

### Zone 3: Medical Device Zone (VLAN 30)
- IP Range: 10.10.30.0/24
- Systems: Infusion pumps, patient monitors, pacs-srv-01, MRI
- Allowed Outbound: To Server Zone only, specific ports (e.g. PACS DICOM traffic); no internet access
- Allowed Inbound: From Management Zone only (patching, support)

### Zone 4: Management Zone (VLAN 40)
- IP Range: 10.10.40.0/24
- Systems: IT admin workstations, security tooling (future SIEM)
- Allowed Outbound: To all zones for administration (SSH/RDP, monitoring agents); internet for updates
- Allowed Inbound: From VPN only, MFA-authenticated

### Zone 5: Guest/IoT Zone (VLAN 50)
- IP Range: 10.10.50.0/24
- Systems: Visitor WiFi, non-clinical IoT (smart TVs, unmanaged printers)
- Allowed Outbound: Internet only
- Allowed Inbound: None from any internal zone

## Part 2 — Firewall Rules

1. Clinical Workstation -> Server : 443/HTTPS (EHR web app) : ALLOW
   Purpose: The only path clinical staff need to reach patient data — through the application, not the database directly.

2. Clinical Workstation -> Server : 5432,1433/TCP (direct DB ports) : DENY
   Prevents: A compromised workstation reaching ehr-db-01's PostgreSQL directly — closes the exact exposure in Finding 003.

3. Medical Device -> Server : 104/TCP (DICOM, PACS interface only) : ALLOW
   Purpose: PACS imaging devices need this single path to store studies; nothing else.

4. Medical Device -> Internet : any : DENY
   Prevents: Infusion pumps, monitors, or PACS reaching external command-and-control or exfiltration infrastructure.

5. Guest/IoT -> Server : any : DENY
   Prevents: A compromised guest device or visitor laptop reaching EHR, billing, or AD — the core flat-network failure.

6. Guest/IoT -> Clinical Workstation : any : DENY
   Prevents: Lateral movement from guest WiFi into clinical staff devices.

7. Guest/IoT -> Medical Device : any : DENY
   Prevents: A guest-zone compromise reaching infusion pumps or monitors.

8. Clinical Workstation -> Medical Device : any : DENY
   Prevents: A compromised nurse workstation pivoting directly to infusion pumps — the exact pattern in the Breach 3/Community Hospital Gamma correlation.

9. Management -> Server : 22,3389/TCP (SSH/RDP, restricted admin source IPs) : ALLOW
   Purpose: The only path for legitimate administrative access to servers.

10. Server -> Backup Target (isolated) : 443/TCP, one-way replication only : ALLOW
    Purpose: Backups can receive data from the Server Zone but nothing can reach back into the backup target from elsewhere — protects backup integrity even if a Server Zone host is compromised.

## Part 3 — Kill Chain Impact

Kill Chain 1: VPN Exploit -> Full Ransomware Deployment (Ransomware/RaaS, target EHR -> Backup -> all reachable servers):

1. Initial Access (VPN exploit, permissive FortiGate rules) — not stopped by segmentation; this step is addressed by MFA (RISK-002), not this design.
2. Foothold (recon of AD/backups across the flat network) — partially broken. With segmentation, a VPN-originating attacker lands in a defined zone, not the whole 10.10.0.0/16 — recon visibility is now confined to that zone's subnet, not the Server Zone where AD and backups actually live.
3. Lateral Movement (credential harvest, reach domain controllers via the flat 10.10.2.0/24 network) — fully broken. This step depended entirely on the flat network. Rules 2, 5, 6, 7, and 8 above mean there is no default path from a compromised workstation or VPN landing point into the Server Zone — only the specific app-layer ports in Rule 1 are open, and those don't reach ad-dc-01/02 directly.
4. Objective Execution (neutralize backups, deploy ransomware via GPO across all core servers) — broken as a second layer, even in the event Step 3 is somehow bypassed: Rule 10 makes backup replication one-way, so a compromised Server Zone host still cannot reach into the backup target to destroy it.
5. Impact (clinical, financial, regulatory, reputational) — avoided if Steps 2-4 hold.

Result: Kill Chain 1 is broken at Step 3 (Lateral Movement), with Step 2 degraded and Step 4 given a second independent layer of protection.

Percentage of the top 5 kill chains disrupted: This task's own context states the flat network appeared in every kill chain built in 1x01, so segmentation touches all five to some degree — an estimated 100% are at least partially disrupted. Confirmed, itemized break points are shown above for Kill Chain 1, and Kill Chain 3 (Vulnerable Software -> billing-srv-01 Compromise) shares the same flat-network lateral-movement dependency and would be disrupted the same way. The specific steps for Kill Chains 2, 4, and 5 were not retrieved in this session, so their individual break points aren't itemized here — flagged honestly rather than invented.
