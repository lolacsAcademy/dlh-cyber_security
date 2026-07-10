# MedDefense — Shadow Systems

## 1. Dr. Patel's Personal NAS

Sensitive data: Cardiology research data, possibly patient-linked.
Uncovered controls: None of the 18 controls apply — not on AV, backup, logging, or password policy (org-managed only).
Worst case: Weak default credentials get exploited; data is stolen or the device becomes a foothold into the flat network, same pattern as billing-srv-01.
Response: Migrate — root cause is a slow shared drive, not malice; move data to proper storage. Legitimize would mean supporting a consumer device; Decommission alone doesn't fix why he bought it.
Registry entry: A-32 | Dr. Patel's Personal NAS | Data Store | Central, Cardiology office | Cardiology | Unknown consumer NAS | Research data storage | 10.10.1.0/24 (assumed) | Shadow IT | Discovered via Mike Torres.

## 2. Marketing Google Drive (personal Gmail)

Sensitive data: Media files, press communications, some potentially embargoed.
Uncovered controls: Password policy and lockout don't apply — it's a personal account MedDefense doesn't own or control.
Worst case: Gmail compromised via reuse/phishing; attacker gets the files and can phish others as "MedDefense Marketing" with no way for MedDefense to revoke access.
Response: Migrate — MedDefense already pays for O365 org-wide; moving there costs nothing extra and brings it under AD control.
Registry entry: A-33 | Marketing Google Drive | Application/Data Store | Corporate HQ, Marketing | Marketing | Google Drive (personal Gmail) | Media/press storage | N/A (external) | Shadow IT | Discovered via Mike Torres.

## 3. Raspberry Pi (2nd floor, Central)

Sensitive data: Unknown — may hold network credentials if it was a monitoring tool.
Uncovered controls: Not in any inventory before now, so no control ever applied to it.
Worst case: Abandoned since both people who set it up left — classic persistence risk if quietly compromised and never checked.
Response: Decommission — no confirmed active function to legitimize or migrate; locate it, preserve logs, remove it.
Registry entry: A-34 | Orphaned Raspberry Pi | Network Device/Unknown | Central, 2nd floor | None (orphaned) | Raspberry Pi OS, unknown version | Possibly network monitoring (unconfirmed) | Segment unconfirmed | Shadow IT | May or may not be Task 7's UNKNOWN-01 — not confirmed.

## Shadow IT Policy Recommendation

Require a fast, lightweight IT approval step for any new device or cloud service, with a guaranteed quick turnaround. Marcus's notes show a repeated pattern — segmentation "planned," AV budget "denied," cameras "on the roadmap" — of staff routing around a slow IT process to solve real problems. Fixing the bottleneck removes the reason to go around it.
