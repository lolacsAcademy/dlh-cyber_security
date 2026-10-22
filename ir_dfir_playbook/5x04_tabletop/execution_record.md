
# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Simulation date:** 2026-10-22  
**Simulated by:** Exercise Designer  
**Type:** Simulated exercise, not a live incident

---

## INJ-00 (T+0 min)

**Inject delivered:**
> The SOC reports unusual outbound traffic from SCHED-SVR-01 at Main campus. EDR shows connections every four hours to an unknown external IP. The alert appeared 45 minutes ago. Scheduling remains operational.

**Participant responses:**
- SOC Lead: "I declare a SEV2 incident and request EDR and network logs. The signed Nexus update may be involved."
- IT Director: "I will notify the Incident Commander and preserve server evidence before considering isolation."

**Evaluation:**
- PASS — Incident declared with severity rationale.
- PASS — Incident Commander and IT Director notified.
- PASS — EDR and network evidence preservation requested.
- PASS — Nexus supply chain risk considered.

**Facilitator note:** Asked, "Does a valid signature prove the update is safe?" Participants correctly said no.

## INJ-01 (T+20 min)

**Inject delivered:**
> Nexus confirms its build infrastructure was compromised three days ago. A malicious update was distributed with a valid Nexus signature. Security recommends isolating Nexus agents, but Clinical Operations warns that appointment disruption could affect patient care.

**Participant responses:**
- IT Director: "I recommend isolating affected agents, subject to Incident Commander approval."
- Clinical Director: "Before isolation, I need a manual scheduling process to protect patient appointments."
- Incident Commander: "I authorize controlled isolation with clinical coordination and documented fallback."

**Evaluation:**
- PASS — Isolation authority identified.
- PASS — Clinical Director consulted.
- PASS — Manual scheduling fallback discussed.
- PASS — Signed update not assumed trustworthy.

**Facilitator note:** Asked, "Who verifies existing appointments?" No clear owner was initially identified.

## INJ-02 (T+35 min)

**Inject delivered:**
> Nexus SecOps acknowledges the incident but cannot confirm which customers received affected updates. Its incident response team has not provided a recovery timeline.

**Participant responses:**
- Vendor Risk Lead: "I will contact Nexus SecOps at soc@nexushealth.io and request affected versions and indicators."
- Incident Commander: "Assign Vendor Risk to escalate and request an update within 30 minutes."

**Evaluation:**
- PASS — Nexus SecOps contact identified.
- PASS — Affected versions and indicators requested.
- PASS — Escalation owner and deadline assigned.

**Facilitator note:** Asked, "When was this communication path last tested?" The team identified the missing joint exercise.

## INJ-03 (T+50 min)

**Inject delivered:**
> Investigators identify suspicious access to scheduling data. Nexus processes patient demographics, insurance information, and appointment records. The number of affected patients and whether data left the environment remain unknown.

**Participant responses:**
- Privacy Officer: "I will identify potentially affected patient records and separate suspected access from confirmed exposure."
- SOC Lead: "I will request relevant access logs from Nexus and preserve local evidence."

**Evaluation:**
- PASS — Patient data categories identified.
- PASS — Evidence requested by SOC and Privacy.
- PASS — No unconfirmed exfiltration presented as fact.

**Facilitator note:** Asked, "Can Nexus provide tenant-specific logs?" The team could not confirm their availability.

## INJ-04 (T+65 min)

**Inject delivered:**
> Nexus confirms an ongoing investigation but cannot establish whether ePHI was accessed. Its BAA requires notification to MedDefense within 24 hours of discovery. Leadership requests an immediate notification recommendation.

**Participant responses:**
- Privacy Officer: "Nexus has a 24-hour BAA notification duty. I will document our separate HIPAA assessment."
- Legal Counsel: "I will review applicable notification triggers and deadlines with Privacy before recommending external notices."

**Evaluation:**
- PASS — BAA obligation distinguished from HIPAA duties.
- PASS — Legal and Privacy involved.
- FAIL — No named owner or deadline for completing the notification assessment.
- PASS — No unsupported breach conclusion issued.

**Facilitator note:** Asked, "Who owns the assessment deadline?" Neither participant accepted explicit ownership.

**Finding:** Notification assessment ownership was undefined. Privacy Officer must assign a deadline and test the notification workflow.

## INJ-05 (T+80 min)

**Inject delivered:**
> Clinical Operations reports that several appointments appear to have changed without staff authorization. At the same time, a journalist requests confirmation of a patient data breach. Neither the full integrity impact nor data exposure is confirmed.

**Participant responses:**
- Clinical Director: "I will verify changed appointments against trusted records and prioritize patients at risk."
- Communications Lead: "I will draft a factual holding statement for approval."
- Privacy Officer: "Do not confirm a data breach without supporting evidence."

**Evaluation:**
- PASS — Appointment verification initiated.
- PASS — Clinical owner and patient safety priority identified.
- PASS — Media response requires approval.
- PASS — Unverified breach claims excluded.

**Facilitator note:** Asked, "Which appointment records are trusted?" The team had no agreed verification source.

## INJ-06 (T+95 min)

**Inject delivered:**
> Nexus has no verified clean agent update or confirmed recovery timeline. Leadership must decide whether scheduling can safely resume. The board requests a status briefing within 90 minutes. Investigators still cannot determine whether all appointment changes have been identified.

**Participant responses:**
- Incident Commander: "Keep affected agents isolated until recovery criteria are met. I own the board briefing due within 90 minutes."
- IT Director: "I will document technical recovery requirements."
- Clinical Director: "Manual scheduling continues until appointment integrity is verified."
- Executive Leadership: "The board needs confirmed facts, operational impact, outstanding risks, and next steps."

**Evaluation:**
- PASS — Continuity decision documented.
- PASS — Clinical safeguards identified.
- PASS — Board briefing owner and deadline assigned.
- PASS — Required briefing content identified.
- PASS — Unresolved appointment integrity risk acknowledged.

**Facilitator note:** Asked, "Can we guarantee every appointment is accurate?" The team correctly acknowledged that this remains unresolved.

---

## Design feedback

### DF-01: Patient safety information arrives too late

The team made its isolation decision at INJ-01 before learning about altered appointments at INJ-05.

**Change:** Add suspected appointment integrity problems to INJ-01 so patient safety informs the initial isolation decision.

### DF-02: Vendor communication lacks a measurable deadline

INJ-02 requires vendor escalation but does not define how quickly participants must contact Nexus.

**Change:** Add a 10-minute contact target and require an escalation record in the INJ-02 evaluation criteria.

### DF-03: Notification assessment ownership is unclear

INJ-04 revealed that participants could identify BAA and HIPAA obligations without assigning responsibility for the assessment.

**Change:** Require a named Privacy or Legal owner, an assessment deadline, and a documented decision in the INJ-04 evaluation criteria.

## Simulation outcome

Six injects passed all criteria. INJ-04 had one failed criterion.

Three design improvements were identified for the scenario, inject schedule, and evaluation criteria before a live tabletop.
