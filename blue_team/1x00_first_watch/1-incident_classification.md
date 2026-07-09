# MedDefense — Incident Classification (CIA Triad)

## Classification Table

| Incident | Date | Primary Pillar | Justification | Secondary Pillar | Justification |
|---|---|---|---|---|---|
| A — Ransomware on billing-srv-01 | Jan 15 | Availability | Claims processing was unusable for 4 days; the service was inaccessible when finance needed it. | Integrity | Ransomware encrypts data without authorization, which is an unauthorized modification of the data itself. |
| B — Patient portal IDOR (broken access control) | Feb 2 | Confidentiality | An authenticated patient could view another patient's lab results just by changing a URL parameter — data was exposed to someone not entitled to see it. | — | No data was altered and no outage occurred, so only Confidentiality applies. |
| C — Pharmacy dosage display error | Mar 18 | Integrity | A buggy update script overwrote dosage values, so the system displayed incorrect data — that is unauthorized modification, even though it was accidental rather than malicious. | Availability | For 6 hours, correct dosage information was effectively unavailable to staff, since what was displayed could not be trusted. |
| D — Website defacement | Apr 5 | Integrity | The homepage content was changed by an attacker without authorization. | Availability | The legitimate website was unavailable/unusable for up to 2 hours until it was restored. |
| E — EHR outage during migration | May 22 | Availability | The EHR was inaccessible for 9 hours, forcing a fallback to paper records. | — | No unauthorized access or data modification occurred; this was a planned change that ran over time, not a security breach. |
| F — Intern's personal laptop on internal network | Jun 10 | Confidentiality | The unauthorized device sat on the same network segment as the HR file share for 3 weeks, creating exposure risk to sensitive HR data it was never meant to reach. | Integrity | A torrent client is a common malware delivery vector; if the laptop was compromised, it could have altered files or systems on that same segment. |

## Notes

- Incidents A, C, and D show that unauthorized modification (Integrity) often causes a service to become unusable, which is why Availability shows up as a secondary pillar in those cases.
- Incidents B and F are both Confidentiality-primary, but B is a confirmed exposure (a patient actually saw data they shouldn't have), while F is an exposure *risk* — no evidence yet that HR data was actually accessed. This distinction matters when prioritizing response.
- Incident E is the only incident with no security-relevant secondary pillar — it was an operational failure (untested rollback procedure), not an attack or unauthorized action.
