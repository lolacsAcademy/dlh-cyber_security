# MedDefense — Gap Analysis

## Prioritized Gap Analysis

| Gap ID | Title | Asset (Criticality) | Data at Risk | Control Status | Missing | Risk Level | Justification | Impact |
|---|---|---|---|---|---|---|---|---|
| GAP-001 | Infusion pumps: no controls at all | Infusion Pumps — Critical | Dosage data (Restricted-equiv.) | None (Unprotected, Task 10) | All 4 functions | Critical | Critical asset, zero detective/corrective control | Known CVE could alter patient dosage undetected |
| GAP-002 | PACS: no corrective control | pacs-srv-01 — Critical | Medical Imaging — Restricted | Firewall + generic logs only; no backup | Corrective (backup) | Critical | Critical asset, Restricted data, zero corrective control | Loss/ransomware destroys imaging data permanently |
| GAP-003 | billing-srv-01: controls exist but already failed twice | billing-srv-01 — High | Financial data — Restricted | Basic controls present, passive | Effective detective + reliable corrective | High | High asset, incomplete/proven-ineffective coverage | 3rd compromise plausible; more claims downtime |
| GAP-004 | ad-dc-02 has no backup | ad-dc-02 — Critical | Credentials — Restricted | Backup covers ad-dc-01 only | Corrective for ad-dc-02 | Critical | Critical asset, no recovery path for failover DC | Org-wide auth recovery not guaranteed if both DCs lost |
| GAP-005 | Network closet exposes credentials, no detection | Network Core — Critical | Credentials — Restricted | Weak badge access; no camera | Physical detective control | Critical | Restricted data, zero detective/corrective control | Anyone entering gets full network admin control |
| GAP-006 | HR share has no detective control | Admin Endpoints — Medium | HR Records — Confidential | Password policy only | Detective control on HR access | Medium | Medium asset, partial controls reduce but do not remove risk | Repeat of Task 1 intern-laptop incident could recur |
| GAP-007 | Training does not reach enough staff | Org-wide/Westside — Medium | Not data-specific | 58% completion at Westside, no phishing sims | Effective reach of existing control | Medium | Partial control, reduces but does not eliminate risk | Westside stays vulnerable to social engineering |
| GAP-008 | Shared PACS login removes accountability | PACS — Critical | Medical Imaging — Restricted | Password policy exists but shared account defeats it | Individual login + attribution | Critical | Critical asset, Restricted data, no attribution possible | Misuse of imaging data cannot be traced to a person |
| GAP-009 | Orphaned Raspberry Pi: no controls, unconfirmed identity | Unidentified device — not in Task 8 framework | Unknown, possibly credentials | None ever applied (Task 11) | Every function + basic visibility | High | Zero control on a credentialed unmonitored device | Could be an undetected pivot into the server subnet |
| GAP-010 | Backup has no compensating control | Backup & Storage — Critical | Copies of Restricted/Confidential data | Only 1 corrective control, untested, co-located | Compensating control (offsite backup) | Critical | Critical category, sole corrective control unreliable | One incident destroys production and backup at once |

## Gap Distribution Summary

By risk level: 6 Critical, 2 High, 2 Medium, 0 Low.

By asset category: PACS/Medical Imaging has the most gaps (2); every other category has 1.

By control function: gaps concentrate in Detective and Corrective. Preventive controls exist in some form nearly everywhere; Detective is passive or absent, Corrective is untested or missing, Compensating is 0 org-wide (Task 10) — matching the pattern from Task 5.
