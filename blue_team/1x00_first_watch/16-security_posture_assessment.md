# MedDefense — Security Posture Assessment

## 1. Executive Summary

Posture: High-risk. Prevention exists in pockets; detection and recovery are almost absent. Not theoretical — billing-srv-01 was compromised twice in one year.

Most critical finding: No network segmentation. One compromised device can reach the EHR, domain controllers, and medical devices with zero barriers. This exact combo caused an 11-day ambulance-diversion breach at a comparable hospital (Task 13).

Top 3 actions:
- Segment the network (Central, Phase 1) — fixes the biggest amplifier.
- Fix backup gaps — add PACS and ad-dc-02 to backups, move offsite.
- Close cheap wins now — individual PACS logins, closet lock, MFA.

Budget: $120,000 funds all 7 priority fixes in full this year; segmentation and a SIEM continue next FY.

## 2. Scope and Methodology

Assessed: All 3 sites, 34 assets, 8 data categories.
Sources: onboarding docs, incident log, server diagnostics, physical walkthrough, control artifacts, network scan, real breach case studies, predecessor's draft.
Limitations: artifact-based, not a live pentest. Some items unverified (DMZ egress, device credentials) and flagged, not assumed. Some source data is outdated (8-month-old endpoint count).
## 3. Asset Landscape

34 assets: 11 servers, 7 endpoint groups, 5 network devices, 8 medical IoT, 2 data stores, 3 physical infra, plus shadow IT found and logged. Mostly at Central; smaller footprint at Westside and HQ.

Top 5 critical assets:
- Infusion pumps — direct physical harm risk.
- EHR — already caused a real 9-hour outage.
- Domain controllers — auth root of trust; secondary DC has no backup.
- PACS — zero backup, unrecoverable if lost.
- billing-srv-01 — only asset compromised twice already.

Data: Restricted = patient records, imaging, financial data, credentials. Confidential = HR, legal/corporate. Public = website only. Widest gap: Restricted network credentials written on paper in an unlocked room.

## 4. Current Security Controls

18 controls total: 13 Technical, 2 Administrative, 3 Physical. By function: 10 Preventive, 7 Detective, 1 Corrective. Compensating and Deterrent: 0.

Maturity: Moderate prevention, weak passive detection, almost no recovery capability.

Key findings:
- No control rated Strong — most are Weak or Adequate.
- billing-srv-01 proves documented controls aren't the same as effective ones.
- No endpoint protection on any server — why the cryptominer went undetected.
## 5. Gap Analysis

16 gaps total: 8 Critical, 5 High, 2 Medium, 1 Low.

### Critical gaps
- Infusion pumps: zero controls. Known CVE could alter dosing. Mitigate — isolate on its own segment.
- PACS: no backup. Total, permanent data loss if lost. Mitigate — add to backup job.
- ad-dc-02: no backup. Threatens DC recovery if both are lost. Mitigate — extend backup.
- Network closet: exposed credentials, no detection. Grants full network control to anyone entering. Mitigate — lock + camera.
- Shared PACS login: no accountability. Misuse can't be traced. Mitigate — individual accounts.
- Backup co-located with production: single event destroys both. Mitigate — move offsite.
- Flat network: root cause of most other gaps. Mitigate — segment.
- No centralized monitoring: compromise can run for weeks unseen. Mitigate — deploy log monitoring.

### High gaps
- billing-srv-01: controls exist but already failed twice. Mitigate — strengthen detection/recovery.
- Orphaned device: unknown, unmonitored. Decommission.
- No offboarding automation, no MFA: weeks of undetected access possible. Mitigate — automate + deploy MFA.
- DMZ/device credentials unverified: could enable IoT pivot. Mitigate — verify and fix.
- No DLP/USB controls: silent data exfiltration possible. Mitigate — restrict USB, add DLP.

### Medium/Low
Medium: no HR access review; training gaps at Westside (58% completion).
Low: print server past end-of-life, low exposure.

Distribution: gaps concentrate in detection/recovery, not prevention. Flat network, no monitoring, and no MFA connect to nearly everything else.

## 6. Risk Treatment Recommendations

| Recommendation | Strategy | Cost | Timeline |
|---|---|---|---|
| Isolate medical IoT | Mitigate | $1-10K | Short-term |
| Add PACS to backup | Mitigate | $10-50K | Short-term |
| Add ad-dc-02 to backup | Mitigate | $0-1K | Quick win |
| Lock + camera network closet | Mitigate | $1-10K | Quick win/Short-term |
| Individual PACS logins | Mitigate | $0-1K | Quick win |
| Offsite backup | Mitigate | $10-50K |Short-term |
| Network segmentation, Phase 1 | Mitigate | $50K+ | Long-term |

Budget ($120,000 total):
- PACS logins $500, DC backup $500, closet $5,000, IoT isolation $8,000, offsite backup $14,400, PACS backup $15,000, segmentation Phase 1 $76,600 = **$120,000 exactly**.
- Deferred to next FY: rest of segmentation, Westside hardware, SIEM (~$80K alone).

Timeline:
- Quick wins (<1 week): PACS logins, DC backup, closet lock.
- Short-term (<1 month): IoT isolation, PACS backup, offsite backup, camera.
- Long-term (>1 month): network segmentation Phase 1.

## 7. Conclusion and Next Steps

MedDefense carries real, documented risk to patient safety, patient data, and care continuity — proven by 2 real incidents plus 3 matching real-world breaches at other hospitals (Task 13).

Without these fixes: expect a more severe incident next time — extended downtime, permanent data loss, or a patient-safety event — far costlier than the $120,000 requested.

Next phase: External Threat Landscape Assessment, continuing Marcus's unfinished work (Task 15). Internal posture shows what could be exploited; the threat landscape shows who is likely to do it and how urgently to act. Recommended to start immediately after Board approval.
