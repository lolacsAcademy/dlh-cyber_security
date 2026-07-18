# Task 16 — The Risk Appetite Debate

MedDefense Health Systems — formal risk appetite and 3 documented Accept decisions.

## Part 1 — Risk Appetite Statement

MedDefense accepts a moderate level of operational and financial risk in pursuit of patient care and business continuity, but holds zero tolerance for any risk with a plausible path to patient harm — those risks must always be mitigated regardless of cost. Risks with an Inherent Risk Score below 10 (Task 10 scale) or an ALE under $50,000 may be accepted by the Deputy CISO alone; anything at or above that threshold, or any risk touching patient safety or regulatory compliance, requires CEO approval per the RACI matrix (Task 4). Every accepted risk must carry a named compensating measure and a documented review trigger — acceptance without monitoring is not a governance decision, it is negligence.

## Part 2 — The Three Decisions

### Decision 1

Risk: RISK-004 — Negligent insider data exposure
Treatment Decision: Accept
Authority: Deputy CISO (James Chen) — ALE ($300,000) exceeds the $50,000 solo-authority threshold, so this was escalated to and confirmed by the CEO.
Justification: None of the 8 Task 7 controls addressed DLP or training; funding a new control mid-cycle would exceed the $120,000 budget already committed. Cost-benefit favors waiting for a dedicated Phase 2 request rather than a rushed, unbudgeted fix.
Compensating Measure: EDR (funded) provides partial visibility into endpoint data movement; existing password/account policies remain in force.
Review Trigger: Any confirmed negligent-insider incident, or approval of a Phase 2 budget that includes DLP and training.

### Decision 2

Risk: RISK-011 — Windows XP MRI workstation (unsupported OS)
Treatment Decision: Accept
Authority: CEO (Dr. Patricia Morales) — patient-safety-adjacent asset, above the Deputy CISO's solo threshold per the appetite statement.
Justification: The MRI scanner lease runs 18 more months; replacing the workstation early means breaking a $2.1M lease or duplicating capital spend before the scheduled refresh. Task 14 segmentation already isolates the Medical Device Zone from the internet and from Clinical Workstation Zone, materially reducing realistic exposure.
Compensating Measure: Confirm the workstation sits in the segmented Medical Device Zone with no internet access; disable all non-essential services on the machine; restrict physical access to MRI-authorized staff only.
Review Trigger: Any new CVE targeting the specific OS/software combination, any confirmed compromise attempt on the Medical Device Zone, or the scanner lease renewal date.

### Decision 3

Risk: RISK-005 — Undetected malware dwell time (reclassified from Mitigate/deferred)
Treatment Decision: Accept (for this fiscal year)
Authority: Deputy CISO (James Chen) — ALE ($106,800) is above the solo threshold on paper, but Task 7 rated this control's return as the weakest "Justified/Marginal" verdict in the entire set, and 2-person team bandwidth remains the binding constraint, not budget.
Justification: SIEM's Net Value ($23,400) is the thinnest positive case of any funded-or-considered control (Task 7). Given the same labor constraint will persist beyond one fiscal year, formally accepting this risk — rather than repeatedly deferring it — is a more honest governance status than an indefinitely rolling "Mitigate, deferred" label.
Compensating Measure: EDR (funded) already claims a partial 15% reduction on this same risk; continue relying on that overlap until dedicated monitoring is funded.
Review Trigger: A third incident on any critical asset, or the security team growing beyond 2 people.

## Part 3 — The Debate

James Chen (mitigate): "Windows XP has had no security patches since 2014 and never will again — every day it stays on our network is a widening, permanent gap that no amount of segmentation fully closes. This directly touches patient safety: if that MRI workstation is manipulated or taken offline mid-procedure, we are not talking about a financial loss, we are talking about a patient. Our own risk appetite statement says patient-safety risks get mitigated regardless of cost — this is exactly that case, not a budget line item."

Robert Kim (accept): "Replacing this workstation early means either breaking a $2.1M lease or duplicating capital spend eighteen months before the scheduled refresh — that money is better spent on the negligent insider gap, which is a $300,000 ALE risk we haven't touched at all. The segmentation work MedDefense already funded puts this workstation in an isolated zone with no internet access — the realistic, present-day exposure is much lower than the label 'unsupported OS' makes it sound. This is a scheduled, time-bound problem that resolves itself in 18 months without emergency spending."

My verdict: James is right about the framing — this is fundamentally a patient-safety question, and the appetite statement I drafted in Part 1 says those don't get a pure cost-benefit pass. But Robert is right that full early replacement is disproportionate given segmentation already isolates the device. The correct call is neither side's extreme: formally Accept with the compensating measures listed in Decision 2 above — isolate further, disable unneeded services, monitor closely — rather than either ignoring the asset or paying to replace it 18 months early. That converts a genuine disagreement into exactly what Part 1 requires: a documented, monitored acceptance, not a shrug.
