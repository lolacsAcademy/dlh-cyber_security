# MedDefense — Structured Environment Summary

## 1. Organization Overview

| Site | Type | Function | Staff |
|---|---|---|---|
| Central Hospital | Downtown, 6 floors + basement | 350-bed acute care | ~1,400 |
| Westside Clinic | Suburban outpatient | Imaging, primary care, PT | ~180 |
| Corporate HQ | Business park offices | Admin, Finance, IT, Legal | ~220 |

Total staff: ~2,000.

**Reporting:** CEO to CISO (vacant) to James Chen (Deputy CISO, acts as CISO, security policy only). Sarah Park (IT Director) is his peer, controls IT operations. James has no authority over IT, this creates friction.

## 2. IT Infrastructure

**Central servers:** ehr-srv-01/ehr-db-01 (EHR), pacs-srv-01 (imaging), billing-srv-01 (billing, flagged as faulty), ad-dc-01/02 (domain controllers), file-srv-01, print-srv-01 (unverified, EOL), backup-srv-01 (backs up to local NAS, same rack), web-srv-01 (patient portal, in DMZ).

**Westside:** 1 server (ws-srv-01, file+scheduling). A possible second server was mentioned but never confirmed.

**HQ:** no servers, cloud + VPN to Central.

**Network:** Central has a firewall (FortiGate 100F) and Cisco switches, but it's flat, one network for servers, workstations, and medical devices. Westside has no firewall, just a consumer router.

**Endpoints:** ~320 (Central) + ~45 (Westside) + ~120 (HQ) workstations, ~25 iPads (unmanaged status unknown). Counts are from an 8-month-old report.

**Medical devices:** ~80 patient monitors, ~120 infusion pumps, 1 MRI (runs Windows XP), 1 CT scanner, all on the same flat network as everything else.

## 3. Data and Services

- **PHI**: EHR, PACS, medical devices.
- **Financial data**: billing server.
- **Admin/HR/Legal data**: HQ.
- Critical services: EHR, PACS, medical devices, nurse call, billing, badge access, patient portal, used by clinical staff, billing staff, patients, and the public.

## 4. Known Unknowns

- Possible undocumented server at Westside, mentioned secondhand, never confirmed.
- print-srv-01's physical existence is unverified for over a year; current status unknown.
- No full endpoint inventory exists (data is 8 months old, self-described as incomplete).
- CT scanner OS unknown; iPad management/enrollment status unknown.
- Central's guest WiFi network isolation is unverified. HQ VPN ACLs have never been audited.
- Network diagram does not show floors 5 and 6, even though the HR guide lists Central as 6 floors + basement. The diagram's author states it is simplified and incomplete, so this is a documentation gap, not a confirmed discrepancy.
- **Contradiction:** Legal states MedDefense "is compliant" with the HIPAA Security Rule, but internal notes confirm no formal HIPAA compliance assessment has ever been performed and no evidence supports the claim.
- No vulnerability assessment, incident response plan, or BC/DR plan has ever been done.
