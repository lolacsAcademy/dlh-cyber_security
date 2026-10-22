
# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise date:** 2026-10-22  
**Report date:** 2026-10-22  
**Facilitator:** Exercise Designer  
**Participants:** SOC Lead, IT Director, Incident Commander, Vendor Risk Lead, Privacy Officer, Legal Counsel, Clinical Director, Communications Lead, Executive Leadership  
**Classification:** Internal - Exercise Use Only  
**Exercise type:** Simulated tabletop

---

## Executive summary

The simulation tested MedDefense's response to a compromised Nexus software update affecting patient scheduling across three sites.

Seven injects assessed supply chain detection, vendor communication, business continuity, ePHI exposure, HIPAA notification, appointment integrity, crisis communications, and executive reporting.

Six injects passed all evaluation criteria. INJ-04 revealed one failure: the notification assessment had no named owner or completion deadline. Additional facilitator questions identified weaknesses in appointment verification ownership and trusted record identification.

**Priority action:** Establish a documented Business Associate notification assessment workflow with clear ownership, deadlines, and evidence requirements.

These results reflect a simulated exercise, not verified production capabilities.

---

## Findings table

| ID | Inject | Capability | Gap description | Severity | Recommended action | Owner role | Deadline | Validation method |
|---|---|---|---|---|---|---|---|---|
| F-001 | INJ-04 | CAP-05 | No owner or deadline assigned for the notification assessment; failed the ownership and deadline criteria | P1 | Define assessment ownership, deadlines, and documented decisions | Privacy Officer | 14 days | Timed notification decision exercise |
| F-002 | INJ-01 | CAP-03 | Facilitator probing revealed no initial owner for verifying existing appointments; appointment integrity ownership criterion | P2 | Assign clinical verification responsibility in the continuity procedure | Clinical Director | 21 days | Scheduling continuity drill |
| F-003 | INJ-05 | CAP-06 | Facilitator probing revealed no agreed trusted source for appointment verification; appointment verification criterion | P2 | Define trusted records and reconciliation steps | Clinical Director | 30 days | Appointment integrity drill |

F-001 is a recorded evaluation failure. F-002 and F-003 are improvement findings from facilitator probing, despite the overall PASS results for their injects.

---

## P1 Finding narratives

### F-001: Notification assessment ownership undefined

At INJ-04, participants correctly distinguished Nexus's 24-hour BAA notification duty from MedDefense's HIPAA obligations. However, when the facilitator asked who owned the assessment deadline, neither Legal nor Privacy accepted explicit responsibility. This failed the criteria requiring a named assessment owner and documented deadline. Without clear accountability, MedDefense risks delaying its notification assessment during a Business Associate incident. The Privacy Officer should establish an assessment workflow with assigned ownership, deadlines, and evidence-based decisions, then validate it through a timed exercise within 14 days.

---

## What worked

- **INJ-00 / CAP-01:** The SOC declared an incident, requested EDR and network evidence, and considered the signed vendor update as a possible attack source.
- **INJ-03 / CAP-04:** Privacy and SOC identified relevant patient data categories and distinguished suspected access from confirmed exposure.
- **INJ-06 / CAP-03 and CAP-08:** Leadership maintained clinical safeguards, assigned board briefing responsibility, and acknowledged unresolved appointment integrity risks.

---

## Exercise design feedback

**DF-01 - Patient safety sequencing:** INJ-01 was updated to introduce suspected appointment changes before the initial isolation decision. The evaluation criteria now require an appointment verification owner.

**DF-02 - Vendor communication timing:** INJ-02 was updated with a 10-minute Nexus contact target. Its evaluation criteria now require a recorded escalation and named follow-up responsibility.

**DF-03 - Notification assessment ownership:** INJ-04 was updated to require an explicit assessment owner, deadline, and documented decision. The evaluation criteria now test these observable actions.

---

## Conclusion

The simulation identified one failed evaluation area and two additional improvement opportunities. Each finding has a responsible role, deadline, and validation method.

Closure requires evidence from the assigned validation activity, not simply updating the documentation.
