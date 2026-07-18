# Task 9 — The CFO Challenge

MedDefense Health Systems — rebuttals to Robert Kim's 5 objections.

## Objection 1: "We have never been breached. Why spend now?"

```vbnet
Objection 1: "We have never been breached. Why spend $120,000 now?"
Acknowledgment: "Fair — no reportable HIPAA breach on record."
Counter-Evidence: "billing-srv-01 was compromised twice this year (ransomware, then a cryptominer). Both were survived by luck, not controls. Sector rate: 1 ransomware attack every 3-4 years for similar hospitals. 3 peer hospitals hit in 8 months."
Business Framing: "Backup failure alone (GAP-010) is $468,300/year in exposure — 4x the ask."
Recommendation: "Fund cheapest, highest-return item first — MFA is $4,000/year, closes $317,900 of exposure."
```

## Objection 2: "Your ALE numbers are estimates, not facts."

```vbnet
Objection 2: "Your ALE numbers are estimates, not facts."
Acknowledgment: "Correct — every Task 5 scenario states its confidence level and swing variable."
Counter-Evidence: "Even halved, the case holds. Halved EHR breach ARO still leaves ~$1.5M/year exposure. A 50% haircut on every control's net value still leaves MFA at $158,950 and Backup at $203,535 — both far above cost."
Business Framing: "Decisions need direction, not precision. Every scenario points the same way."
Recommendation: "One control is estimate-fragile: Medical Device Isolation + Monitoring nets only $17,945 under a 50% haircut against $20,000 cost. Scale it back to isolation-only ($8,000) until real incident data exists."
```

## Objection 3: "Insurance is cheaper than controls."

```vbnet
Objection 3: "Insurance is cheaper than controls."
Acknowledgment: "Agreed, insurance is real protection already in place."
Counter-Evidence: "The $50,000 deductible alone exceeds MFA + Backup + Westside combined ($20,000). The $1M limit likely won't cover full EHR breach costs — litigation and reputation usually fall outside standard coverage."
Business Framing: "Insurers require baseline controls to pay claims. No MFA, flat network — that's a known gap that can trigger denial or non-renewal."
Recommendation: "Keep the policy. Fund the controls too — a stronger posture is leverage for a lower premium next renewal."
```

## Objection 4: "This should be IT's regular budget."

```vbnet
Objection 4: "This should be IT's regular budget, not a special ask."
Acknowledgment: "Agreed long-term — security should be a normal line item eventually."
Counter-Evidence: "Sarah's $1.2M budget is IT operations, not security. Folding this in forces her to cut something the Board never approved. It also recreates the exact ownership conflict James raised — Task 4 put budget approval with the CEO for that reason."
Business Framing: "A distinct line item gives the auditability HIPAA expects."
Recommendation: "Fund as its own line this year. Fold into formal budgeting once a vCISO (Task 4) owns that governance."
```

## Objection 5: "Start with $60,000?"

```vbnet
Objection 5: "Can we start with $60,000 and see if it works?"
Acknowledgment: "Reasonable — prove the concept, then scale."
Counter-Evidence: "Task 8's plan is already $87,500, not $120,000. Ranked by return per dollar: MFA returns 79x, Backup 28x, Segmentation 9x, Westside 4x. Those four cost $45,500 combined."
Business Framing: "A $60,000 cap doesn't force a worse plan — it forces a smarter one."
Recommendation: "Fund MFA, Backup, Segmentation, Westside now ($45,500). Defer EDR, SIEM, and Medical Device Isolation to Phase 2 next year."
```

---

## Closing Statement

The five highest-priority risks total roughly **$1,383,550/year** in unmitigated exposure — backup failure alone is $468,300. The proposed program costs $87,500/year, or $45,500 phased. That's a fraction of MedDefense's $4.2M in billing revenue alone. Inaction isn't zero risk — it's over a million dollars a year in expected loss, whether the Board sees it on a line item or not.
