# Task 0 — The Framework Landscape

## Part 1 — Three-Framework Summary

### NIST CSF 2.0

NIST Cybersecurity Framework (CSF) 2.0 is published by the U.S. National Institute of Standards and Technology, updated to version 2.0 in February 2024. It is designed as a strategic, outcome-based framework that helps an organization understand, communicate, and manage cybersecurity risk at a governance level — it does not prescribe specific technical controls. It is structured around six core Functions: Govern, Identify, Protect, Detect, Respond, and Recover, broken down into 22 Categories and 106 Subcategories. It is typically used by executives, boards, and risk managers — of any organization size or sector since the 2.0 update — as a common language to set strategy, define target profiles, and report risk posture upward.

### CIS Controls v8

CIS Controls v8 (current revision v8.1, June 2024) is published by the Center for Internet Security. It is designed as a prioritized, prescriptive set of defensive actions grounded in real-world attack data, telling an organization concretely what to configure, patch, log, or restrict. It is structured as 18 Controls containing 153 Safeguards, grouped into three cumulative Implementation Groups (IG1: 56 safeguards for essential hygiene, IG2 adds 74 more, IG3 covers all 153) based on organizational risk profile and maturity. It is typically used by security analysts, system administrators, and small-to-mid-sized IT/security teams as an operational checklist to close specific technical gaps.

### ISO/IEC 27001

ISO/IEC 27001 is published jointly by the International Organization for Standardization and the International Electrotechnical Commission; the current edition is ISO/IEC 27001:2022. It is designed to specify the requirements for building, operating, and certifying an Information Security Management System (ISMS) — a management system, not a technical control list. It is structured as 10 clauses (Clauses 1–3 are scope/references/definitions; Clauses 4–10 are the mandatory, audited requirements covering context, leadership, planning, support, operation, evaluation, and improvement), supported by Annex A, which catalogues 93 controls across four themes (organizational, people, physical, technological) that the organization selects from based on its own risk assessment and records in a Statement of Applicability. It is typically used by organizations that must formally prove their security posture to regulators, clients, or auditors through third-party certification.

## Part 2 — Relationship Map

The three frameworks are not competitors because they operate at different altitudes and answer different questions. NIST CSF sits at the strategic layer and answers "What should we do?" — it gives MedDefense a common vocabulary to organize risk conversations with the Board (Govern, Identify, Protect, Detect, Respond, Recover) without telling IT which specific setting to change. CIS Controls sits at the operational layer and answers "How should we do it?" — once CSF says "Protect," CIS Control 4 (Secure Configuration) or Control 6 (Access Control Management) gives the analyst a concrete, testable safeguard to implement. ISO 27001 sits at the assurance layer and answers "Can we prove we are doing it?" — it wraps the whole effort in a formal management system (risk register, ownership, internal audit, management review, Statement of Applicability) that produces a certificate a regulator or client can trust. In practice, an organization can build its CSF Profile to define target outcomes, use CIS Controls (mapped via published CIS-to-CSF crosswalks) to implement and measure the underlying safeguards, and use ISO 27001's ISMS structure to govern, document, and certify that the whole program is actually running — three layers of the same program, not three separate programs.

## Part 3 — MedDefense Framework Selection

**Recommendation: NIST CSF 2.0 as the strategic backbone, with CIS Controls v8 (IG1, expanding to IG2) as the operational implementation layer. Defer formal ISO 27001 certification.**

Justification against MedDefense's actual constraints:

- **Staffing (1 analyst, 1 deputy CISO).** ISO 27001 certification requires a working ISMS with document control, internal audits, and a formal management review cycle — overhead that consumes analyst time MedDefense does not have. NIST CSF requires no certification body and no fixed audit cadence; CIS Controls IG1 is explicitly built for organizations with limited cybersecurity expertise (56 safeguards, not 153). This is the only combination two people can realistically operate.
- **No current framework in place.** Starting from zero, NIST CSF gives James Chen and Dr. Morales an immediate way to talk about "where we are" (Current Profile) versus "where regulators expect us to be" (Target Profile) without a multi-year certification project. CIS Controls then gives the analyst a concrete, ordered worklist (asset inventory first, then access control, then vulnerability management) instead of an abstract goal.
- **Must demonstrate compliance to regulators and the Board.** HIPAA (the applicable regulatory driver for a U.S. hospital) does not require ISO 27001 or any single named framework — it requires a documented, defensible security program. A NIST CSF Target Profile mapped to CIS Safeguard evidence is sufficient to show a regulator or auditor "here is our risk-based program and here is proof each control is implemented," without paying for or staffing a certification audit.
- **Regional hospital, not a federal agency.** NIST SP 800-53 and RMF are the correct frameworks for federal information systems bound by FISMA; MedDefense has no such obligation, so adopting them would spend limited hours on control families sized for a much larger, federally-regulated environment.
- **ISO 27001 is not rejected outright — it is deferred.** If MedDefense later pursues cyber-insurance discounts, a strategic partnership, or a client contract that specifically requires ISO 27001 certification, the CSF + CIS foundation already built will map directly onto Annex A controls (published crosswalks exist), meaningfully reducing the lift to certify at that point.

