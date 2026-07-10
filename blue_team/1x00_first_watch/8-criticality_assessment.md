# MedDefense — Criticality Assessment

## Asset Criticality Matrix

| Asset Category | Confidentiality | Integrity | Availability | Overall Criticality | Justification |
|---|---|---|---|---|---|
| EHR System | Critical | Critical | Critical | Critical | Primary clinical record for both sites; already caused a 9-hour paper fallback (Task 1). |
| PACS / Imaging | High | Critical | Critical | Critical | Zero backup coverage (Task 7) — loss is unrecoverable, not just delayed. |
| Billing Infrastructure | High | High | High | High | Compromised twice already (Task 1, 2); disrupts revenue, not patient care directly. |
| Identity / AD | High | Critical | Critical | Critical | Authentication root for nearly every other system; ad-dc-02 has no backup. |
| Network Core | High | Critical | Critical | Critical | No segmentation exists — compromise here reaches every other asset at once. |
| Medical IoT | Medium | Critical | Critical | Critical | Only category where compromise causes direct physical harm to a patient. |
| Backup & Storage | Medium | High | Critical | Critical | Co-located with production, untested DR — a single event destroys both (Task 5). |
| Clinical Endpoints | Medium | Medium | Low | Medium | Large attack surface, likely entry point, but individually replaceable. |
| Admin Endpoints (HQ) | Medium | Low | Low | Medium | Sensitive but non-clinical data; lower regulatory/safety weight. |
| Physical Security | High | High | High | High | Server room and network closet are unrestricted (Task 3) — bypasses all technical controls. |

## Top 5 Most Critical Assets

1. **Infusion Pumps** — Compromise = real-time physical harm to a patient; known CVE, vendor-recommended isolation never done.
2. **EHR System** — Already caused a real 9-hour outage forcing paper records hospital-wide (Task 1).
3. **Domain Controllers** — Root of authentication trust; ad-dc-02 has no backup, so recovery isn't guaranteed.
4. **PACS Server** — The only clinical system with zero backup — loss is permanent, not recoverable.
5. **billing-srv-01** — Only asset with a documented history of repeated real compromise (ransomware + cryptominer).
