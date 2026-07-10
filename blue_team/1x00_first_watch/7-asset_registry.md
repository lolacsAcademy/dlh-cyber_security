# MedDefense — Asset Registry

## Asset Registry (31 assets)

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|
| A-01 | ehr-srv-01 | Server | Central server room | IT | Ubuntu 20.04 | EHR application | 10.10.2.0/24 | Active | Core clinical system |
| A-02 | ehr-db-01 | Server | Central server room | IT | Ubuntu 20.04 | EHR database (PostgreSQL) | 10.10.2.0/24 | Active | DB port 5432 open network-wide (Task 4 gap) |
| A-03 | pacs-srv-01 | Server | Central server room | IT / Radiology | Windows Server 2016 | PACS imaging | 10.10.2.0/24 | Active | Excluded from backups (Task 4) |
| A-04 | billing-srv-01 | Server | Central server room | IT / Finance | Ubuntu 18.04 (support ended Jun 2023) | Billing/claims | 10.10.2.0/24 | Active | Compromised twice: ransomware (Task 1), cryptominer (Task 2) |
| A-05 | ad-dc-01 | Server | Central server room | IT | Windows Server 2019 | Primary domain controller | 10.10.2.0/24 | Active | — |
| A-06 | ad-dc-02 | Server | Central server room | IT | Windows Server 2019 | Secondary domain controller | 10.10.2.0/24 | Active | Excluded from backups (Task 4) |
| A-07 | file-srv-01 | Server | Central server room | IT | Windows Server 2016 | Department file shares | 10.10.2.0/24 | Active | — |
| A-08 | print-srv-01 | Server | Central server room | IT | Windows Server 2012 (EOL Oct 2023) | Print services | 10.10.2.0/24 | Active | Was [UNVERIFIED] in Task 0; scan confirms it is live |
| A-09 | backup-srv-01 | Server | Central server room | IT | Ubuntu 22.04 | Veeam backup agent | 10.10.2.0/24 | Active | — |
| A-10 | NAS-01 | Data Store | Central server room | IT | Synology DSM 7 | Backup storage | 10.10.2.0/24 | Active | Same room/rack as production — single point of failure (Task 4/5) |
| A-11 | web-srv-01 | Server | Central server room (DMZ) | IT | Ubuntu 20.04 | Public website + patient portal | 10.10.2.0/24 (DMZ) | Active | — |
| A-12 | UNKNOWN-01 (10.10.2.99) | Unknown | Central server room | Unknown | Linux 4.x | SSH + 2 unidentified web services | 10.10.2.0/24 | Shadow IT | Not in any documentation |
| A-13 | Central Clinical/Admin Workstations (~320) | Endpoint | Central, all floors | Various (Nursing, Admin, Pharmacy, Lab, Reception) | Windows 10 | Day-to-day clinical/admin operations | 10.10.1.0/24 | Active | Same flat network as servers and medical devices |
| A-14 | WS-RAD-01 (MRI control workstation) | Endpoint | Central, Radiology | Radiology | Windows XP SP3 (EOL) | MRI imaging control | 10.10.1.0/24 | Active | Subject of Task 6 compensating controls |
| A-15 | Central ER Thin Clients (TC-ER-01 to 04+) | Endpoint | Central, ER | Emergency | Linux thin client | ER clinical access | 10.10.1.0/24 | Active | — |
| A-16 | Central WiFi Access Points (12x) | Network Device | Central, all floors | IT | Ubiquiti UniFi | Staff/guest WiFi | 10.10.1.0/24 | Active | Guest network isolation unverified (Task 0) |
| A-17 | FortiGate 100F Firewall | Network Device | Central server room | IT | FortiOS | Perimeter firewall, VPN termination | Perimeter / all sites | Active | VPN rules too permissive (Task 4, Artifact 1) |
| A-18 | Patient Monitors (~80, Philips IntelliVue) | IoT Medical | Central, ICU/ER/3F | Clinical/Nursing | Philips firmware | Vital sign monitoring | 10.10.3.0/24 (flat, no VLAN) | Active | Management interface exposed network-wide |
| A-19 | Infusion Pumps (~120, BD Alaris fw 12.1.2) | IoT Medical | Central, ICU/ER/3F | Clinical/Nursing | BD Alaris fw 12.1.2 | Medication dosage delivery | 10.10.3.0/24 (flat, no VLAN) | Active | Known CVEs; vendor-recommended isolation not done |
| A-20 | MON-VITALS-3F-01 | IoT Medical | Central, 3rd floor patient room | Clinical/Nursing | Unknown vendor, firmware from 2019 | Vital signs display | 10.10.3.0/24 | Active | Same IP range as nurse station workstations (Task 3) |
| A-21 | Nurse Call System (2 units) | IoT Medical | Central | Clinical/Nursing | IP-based | Patient-to-staff alerting | 10.10.3.0/24 | Active | — |
| A-22 | Badge Readers (3 units, HID Global) | Physical Infrastructure | Central (main, server room, ER) | Facilities | HID Global | Physical access control | 10.10.3.0/24 | Active | Connected to AD for some doors only (Task 0) |
| A-23 | Server Room | Physical Infrastructure | Central, ground floor | Facilities / IT | — | Houses core servers | N/A | Active | Generic badge access, no camera (Task 3, Obs 1) |
| A-24 | Network Closet (2nd floor) | Physical Infrastructure | Central, 2nd floor | Facilities / IT | — | Houses switches/patch panels | N/A | Active | Unlocked, credentials posted on wall (Task 3, Obs 2) |
| A-25 | ws-srv-01 | Server | Westside Clinic | IT | Windows Server 2016 | Local file server + scheduling | 10.10.10.0/24 | Active | — |
| A-26 | Westside Clinic Workstations (~36) | Endpoint | Westside Clinic | Westside staff | Windows 10 | Clinic operations | 10.10.10.0/24 | Active | Fewer than the ~45 originally documented (Task 0) |
| A-27 | WS-WC-XRAY | Endpoint / Medical | Westside Clinic | Westside / Radiology | Unknown OS | X-ray imaging workstation | 10.10.10.0/24 | Active | Not previously documented anywhere before this scan |
| A-28 | Netgear Consumer Router | Network Device | Westside Clinic | IT | Netgear firmware | Internet/VPN gateway for Westside | 10.10.10.0/24 | Active | Consumer-grade, also runs the site-to-site VPN (Task 0) |
| A-29 | Unknown Device (10.10.10.200) | Unknown | Westside Clinic | Unknown | Linux 5.x | Possibly an unofficial monitoring tool (port 3000) | 10.10.10.0/24 | Shadow IT | Not in any documentation |
| A-30 | Corporate HQ Workstations (~120) | Endpoint | Corporate HQ | Finance/HR/Legal/Marketing/Exec | Windows 10/11 | Administrative operations | 10.10.20.0/24 | Active | — |
| A-31 | Corporate HQ Laptops (~25-30) | Endpoint | Corporate HQ (mobile) | Various HQ depts | Windows 11 | Remote/mobile work | 10.10.20.0/24 | Active | Intermittent presence during scan |
## Reconciliation Notes

### Assets in the scan but not in any documentation (shadow IT / undocumented)

- UNKNOWN-01 (10.10.2.99, Central servers subnet) — unidentified Linux device running SSH and two web services. Sarah Park could not identify it.
- Unknown Device (10.10.10.200, Westside) — unidentified Linux device with port 3000 open, possibly an unofficial monitoring tool someone installed without IT's knowledge.
- WS-WC-XRAY (Westside) — an X-ray imaging workstation that does not appear in any prior documentation, including the original onboarding packet, which only described Westside's imaging as "X-ray, ultrasound" without naming a specific system.

### Assets in documentation but not found in the scan

- The second possible Westside server that Marcus's notes referenced (via Mike Torres) still cannot be confirmed — it does not appear in the scan either, meaning it may not exist, may have been offline during scanning, or may be on a network segment outside the scanned range.
- The MRI scanner itself (Siemens MAGNETOM) and the CT scanner (GE Revolution) — only the MRI's control workstation (WS-RAD-01) appears in the scan. The imaging hardware itself is not listed, which may mean it does not have its own network presence, was offline, or sits on an unscanned segment.
- The ~25 physician iPads documented in Task 0 do not appear anywhere in the scan results, likely because Nmap-style scanning does not reliably fingerprint WiFi-connected mobile devices, especially if they were not active during the scan window.
- The separate guest WiFi SSID mentioned in Task 0 has no corresponding subnet in the scan results, so its network scope and isolation status remain unverified.

### Discrepancies between sources

- print-srv-01 was marked [UNVERIFIED] in the original Task 0 asset list — the scan resolves this: the server is confirmed live and responding, which updates that Known Unknown from Task 0.
- Minor OS labeling difference: the original asset list recorded print-srv-01 as "Windows Server 2012 R2," while the scan's OS fingerprinting shows "Windows Server 2012" without the R2 designation — likely a fingerprinting imprecision rather than a real conflict.
- Westside workstation count: Task 0 documented approximately 45 Windows 10 workstations at Westside; the scan shows only 36 (WS-WC-01 through WS-WC-36). This could reflect devices offline during the scan or an outdated original estimate.
