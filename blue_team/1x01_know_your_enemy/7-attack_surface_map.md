# Attack Surface Map — MedDefense

## Section 1 — External Surface

### Patient portal / public website
web-srv-01, DMZ, ports 22/80/443. Protection: perimeter firewall (C-001). Gap: not covered by a numbered 1x00 Gap ID — flagged, not invented.

### VPN endpoints
FortiGate 100F (A-17) — Central VPN termination. Note: "VPN rules too permissive" (registry note, no formal Gap ID).
Netgear consumer router (A-28) — runs Westside's site-to-site VPN. Consumer-grade device carrying a security-critical function — documented finding, no formal Gap ID.

### Email / O365
Cloud-hosted, external entry point via phishing/BEC (T4 Sc.1-2). Protection: password policy (C-012); MFA status not documented.

### DNS
No dedicated public DNS server documented in the scan — ad-dc-01/02 port 53 is internal AD DNS only, not public-facing.
## Section 2 — Internal Surface
Flat network is the core finding: scan confirms full reachability from any subnet to any other — zero segmentation. Any single foothold anywhere reaches everything below.

### Exposed services
- billing-srv-01: MySQL 3306 open network-wide — ties to GAP-003 (controls already failed twice)
- ehr-db-01: PostgreSQL 5432 open to entire /16 — documented finding, no numbered Gap ID
- NAS-01: management ports 5000/5001 exposed network-wide — related to GAP-010 (backup single point of failure)

### Management interfaces
FortiGate admin interface, NAS-01 web console, all IoT device HTTP/HTTPS interfaces reachable network-wide.
Infusion pumps: reachability + known BD Alaris CVE = GAP-001 (zero controls of any function).
Patient monitors: same reachability pattern, no dedicated Gap ID — flagged.

### Legacy systems
WS-RAD-01 (Windows XP SP3, MRI) — compensating controls exist per Task 6 (details not in current file set).
print-srv-01 (Windows Server 2012, EOL) — no dedicated Gap ID.
### Default / shared credentials
PACS shared login — GAP-008.
IoT default credentials: scan confirms interface reachability only, not confirmed default creds — flagged, not assumed.

### Undocumented devices
10.10.2.99 (Linux, SSH + 2 web services) and 10.10.10.200 (Linux, port 3000) — shadow IT, unknown function, unmonitored.

## Section 3 — Human Surface

### Clinical staff
Access: EHR/PACS. Targetable: low training completion (GAP-007, 58% at Westside), busy/trusting culture (T4 Sc.3).

### Reception
Access: physical entry point, first phone/visitor contact. Targetable: no verification habit for phone/vishing requests (T4 Sc.3).

### IT staff
Access: elevated/admin privileges. Targetable: small team (single analyst per T0 dossier), fatigue-driven shortcuts (T3 Sc.5).
### Executives
Access: financial authority, strategic info. Targetable: BEC (T4 Sc.2, CFO wire transfer).

### External contractors
Access: vendor-granted, beyond MedDefense's direct control (T5 — MedTech, Siemens). Targetable: MedDefense can't enforce its own controls on vendor-side systems.

## Surface Assessment Summary
The internal surface represents the greatest risk today. External entry points and human targets are real, but each is still just one way in — the flat network is what turns any single successful entry, through any surface, into full exposure. The scan confirms every subnet can reach every other subnet with zero segmentation, which is exactly the mechanism behind the T2 ransomware attack sequence and the T5 MedTech compromise scenario: one foothold anywhere reaches the EHR, PACS, AD and backup systems. Fixing external or human weaknesses reduces how attackers get in; fixing the internal surface reduces what happens once they do — and right now nothing limits that.
