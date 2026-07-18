# MedDefense Health Systems — Security Strategy Document

Companion to the Security Posture Assessment (1x00), Threat Landscape Report (1x01), and Vulnerability Assessment Summary (1x02).

## 1. Executive Summary

MedDefense's current risk posture is weak: 0 of 18 CIS Controls fully implemented, 4 of 6 NIST CSF functions rated Partial or Not Implemented, and roughly $1.38M/year in unmitigated exposure across the top 5 identified risks alone. The strategy adopts NIST CSF 2.0 as the strategic backbone and CIS Controls v8 as the operational layer, deferring formal ISO 27001 certification given a 2-person security team.

Investment requested: $120,000 total — $87,500 funded across 6 controls this cycle, $32,500 reserved for remaining Critical gaps. Expected risk reduction: approximately $1,137,960/year in ALE closed by the 6 funded controls, plus 5 additional zero-cost quick wins.

Top 3 priority actions:
1. Deploy MFA on VPN and admin accounts — cheapest control in the program, breaks the top ransomware access vector.
2. Isolate backups offline/immutable — highest single ALE reduction, closes the single point of failure that would turn any incident into total data loss.
3. Segment the flat network into VLANs — structural fix that contains lateral movement for every other risk in the register.

## 2. Governance Framework

Framework rationale (T0): NIST CSF 2.0 answers "what should we do," CIS Controls v8 answers "how," and ISO 27001 answers "can we prove it" — deferred for now given no certification staffing and no HIPAA mandate to certify.

NIST CSF Current vs. Target (T1): Govern, Identify, and Protect move from Partial to Managed. Detect moves from Not Implemented to Partial only (full SIEM not realistic this cycle). Respond and Recover move from Not Implemented to Managed.

CIS Controls scorecard (T2): 0 Implemented, 7 Partial, 11 Not Implemented out of 18. Top 5 priority controls: Access Control (6), Network Infrastructure Management (12), Data Recovery (11), Audit Log Management (8), Secure Configuration (4).

Governance structure (T4): RACI places budget, policy, and risk-acceptance Accountability with the CEO given the vacant CISO seat; Deputy CISO James Chen is Responsible for day-to-day execution. Data Owner/Controller/Processor/Custodian roles are formally defined. Recommendation: a vCISO (fractional), not a full-time hire — a full salary would consume most of the technical budget.

## 3. Quantitative Risk Analysis

Top 5 risks by ALE (T6):
| Risk | ALE |
|---|---|
| Backup destroyed with production (GAP-010) | $468,300 |
| VPN compromise, no MFA (GAP-012) | $375,550 |
| Ransomware encrypts EHR (GAP-011) | $370,800 |
| Undetected malware dwell time (GAP-014) | $106,800 |
| Infusion pump compromise (GAP-001) | $62,100 |

Risk Register (T10): 10 risks logged (RISK-001 through RISK-010). 9 carry a Mitigate decision; RISK-004 (negligent insider, $300,000 ALE) is formally Accepted, not funded, this cycle.

Risk appetite (T16): Zero tolerance for risks with a plausible path to patient harm, regardless of cost. Risks under a $50,000 ALE or Inherent Score below 10 may be accepted by the Deputy CISO alone; anything above that, or anything patient-safety-adjacent, requires CEO approval.

## 4. Control Strategy

Cost-benefit results (T7): 7 of 8 evaluated controls are cost-justified. Only the 24/7 outsourced SOC ($150,000/year) is Not Justified — it costs more than the entire security budget by itself for a fraction of the risk reduction cheaper controls already deliver.

Budget allocation (T8): $87,500 funded across MFA, backup replication, network segmentation, EDR, medical device isolation, and the Westside Clinic firewall. SIEM ($30,000) deferred one fiscal year for labor bandwidth. $32,500 reserved for the remaining Critical gaps (ad-dc-02 backup, PACS backup, shared PACS login, network closet security).

Control selection (T11): Every funded control maps to a specific CIS Safeguard and NIST CSF category. Two dependency chains govern implementation order: the backup infrastructure chain (offsite replication first, then ad-dc-02 and PACS extensions) and the network architecture chain (segmentation first, then medical device isolation and SIEM).

Quick wins (T13): 5 zero-cost fixes deployable within 2 weeks using existing tools — disabling dormant accounts, enabling MFA, resetting infusion pump default credentials, extending the existing backup job, and replacing the shared PACS login with individual accounts.

## 5. Architecture Recommendations

Network segmentation (T14): 5 VLANs — Server, Clinical Workstation, Medical Device, Management, and Guest/IoT — each with defined IP ranges and 10 enforced firewall rules, 6 of them deny rules that directly close the flat-network exposure identified across every prior project.

Kill chain disruption: Kill Chain 1 (VPN Exploit -> Full Ransomware Deployment) is broken at Step 3 (Lateral Movement), with Step 2 (Foothold/recon) degraded and Step 4 (backup destruction) given a second independent layer of protection. The flat network was a factor in all 5 of 1x01's kill chains, so segmentation touches all five to some degree, though only Kill Chain 1's break points are itemized in detail here.

## 6. Policy Foundation

AUP summary (T12): An 8-section Acceptable Use Policy now exists, covering acceptable use, prohibited activities (tied to named risks, not generic lists), personal devices and removable media, password/MFA requirements, data handling by classification tier, and proportional enforcement.

Policy roadmap: Next needed — a formal, tested Incident Response Plan (Respond is still only Managed-on-paper, never exercised); a Vendor/Third-Party Risk Management Policy (the Red Team exercise in T15 found this is currently unaddressed by any funded control); a Data Retention/Backup Policy formalizing the new isolated-backup practice; and a Security Awareness Training Policy to close the human-risk gap behind RISK-004.

## 7. Residual Risk Assessment

Red team findings (T15): Even with every funded control implemented, Kill Chain 1 remains viable through the Management Zone, which necessarily retains broad cross-zone access for administration. An alternative attack path through a compromised third-party vendor (never addressed by any of the 8 evaluated controls) combined with the deferred SIEM's lack of detection remains fully viable. The negligent insider scenario is untouched, since every funded control is technical, not behavioral.

Accepted risks (T16): RISK-004 (negligent insider, $300,000 ALE), RISK-011 (Windows XP MRI workstation, tied to an 18-month scanner lease), and RISK-005 (undetected dwell time, reclassified from a rolling deferral to a formal Accept given persistent 2-person team bandwidth constraints) — each with a named compensating measure and review trigger.

Year 2 priorities: Fund the deferred SIEM first; launch a security awareness training program; establish a vendor/third-party risk management process; and formally harden the Management Zone (privileged access management, admin session monitoring) given its identification as the new highest-value target.

## 8. Implementation Roadmap

Phase 1 — Months 1-2 (Quick Wins + Procurement):
- Execute all 5 T13 quick wins (dormant accounts, MFA, pump credentials, backup extension, PACS accounts).
- Begin MFA rollout using existing O365 licenses; select and contract backup replication and segmentation hardware vendors.
- Success metrics: 5/5 quick wins verified complete by end of Month 1; 100% MFA enrollment on admin/VPN accounts by Month 2; backup replication contract signed by Month 2.

Phase 2 — Months 3-4 (Core Controls Deployment):
- Deploy network segmentation (5 VLANs, 10 firewall rules); complete medical device isolation and monitoring; roll out EDR upgrade across all endpoints; install the Westside Clinic firewall; bring backup isolation fully live.
- Success metrics: All 5 VLANs live with enforced firewall rules by Month 4; EDR deployed to 100% of the ~330 endpoints/servers; first successful isolated-backup replication cycle completed.

Phase 3 — Months 5-6 (Validation + Optimization):
- Run test restores from the isolated backup for every critical asset; commission a validation penetration test against the segmented architecture to confirm the T15 red team findings are addressed or formally accepted; review all 10 Risk Register KRIs; prepare the Year 2 budget request (SIEM, training, vendor risk management).
- Success metrics: 100% of critical assets have a confirmed successful test restore; validation pentest complete with findings triaged; Year 2 budget proposal submitted to the Board by end of Month 6.

## 9. Next Steps

This strategy hands off to Project 1x04 (Cryptographic Foundation), which builds the encryption-at-rest and encryption-in-transit layer on top of the data classification (T12) and segmented architecture (T14) established here — protecting data itself, not just the paths to reach it. This document is the plan; 1x04 and the projects that follow it are the execution against the roadmap in Section 8.
