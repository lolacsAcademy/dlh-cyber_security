# The Insider File — MedDefense

## Scenario 1 — Shared Login
Classification: Negligent — systemic dept practice, not intent to harm
Behavioral Indicators: Multiple simultaneous logins on one account; no logout between patients; usage pattern inconsistent with one person
Existing Control (1x00): C-012 (password policy) applies but is defeated by shared use
Gap Exploited (1x00): GAP-008 — shared PACS login, no individual accountability
Mitigation: Enforce individual PACS logins (badge tap for fast switching)

## Scenario 2 — Ghost Account
Classification: Malicious use — activity itself is intentional; root cause is a negligent offboarding process
Behavioral Indicators: Auth from a terminated account at all; off-hours access; no ticket/business reason for access
Existing Control (1x00): None found — no control in 1x00 covers account deprovisioning
Gap Exploited (1x00): No exact Gap ID in 1x00 Gap Analysis — related but undocumented gap (mirrors Incident F)
Mitigation: Automated account deprovisioning triggered by HR termination
## Scenario 3 — Personal NAS
Classification: Negligent — convenience-driven, not malicious
Behavioral Indicators: Unknown device on network port scan/NAC; unencrypted traffic to unrecognized MAC; unexpected data volume
Existing Control (1x00): None — not in Task 10 Coverage Matrix (A-32 in Task 11 registry, but uncovered by all 18 controls)
Gap Exploited (1x00): GAP-009 covers a similar pattern (unauthorized/unmonitored device) but is technically the Raspberry Pi (A-34), not this NAS — no dedicated Gap ID exists for it
Mitigation: Network Access Control (NAC) / port security to block unauthorized devices

## Scenario 4 — Curious Employee
Classification: Malicious — curiosity-driven unauthorized access
Behavioral Indicators: EHR access outside her job scope; no clinical relationship to patient; single anomalous high-profile record access
Existing Control (1x00): C-008 (manual logging) exists but passive, no real-time alerting
Gap Exploited (1x00): No exact Gap ID covers EHR access-scope monitoring — closest overlap is the org-wide passive-Detective weakness pattern
Mitigation: RBAC + anomaly/UBA alerting on out-of-scope record access
## Scenario 5 — Overworked Admin
Classification: Negligent — reckless, no malicious intent
Behavioral Indicators: Plaintext credential file created on desktop; script/creds emailed as attachment; sensitive strings in outbound mail
Existing Control (1x00): C-012 (password policy) exists but doesn't prevent plaintext storage/sharing elsewhere
Gap Exploited (1x00): No exact Gap ID covers this — related informally to the "no DLP" finding in Task 0 dossier, not a numbered 1x00 gap
Mitigation: Secrets vaulting for admin creds + DLP scanning outbound email for credential patterns

## Pattern Assessment
MedDefense's systemic weakness is Detective and Corrective control coverage — the Gap Distribution Summary from 1x00 shows gaps concentrate almost entirely there, with Compensating controls at zero org-wide. Insider threats bypass perimeter/preventive controls by design, since the person already has legitimate access — so detection is the only layer that can catch misuse, and that's exactly the layer 1x00 found weakest (passive manual logging, no real-time alerting). GAP-008's shared PACS login makes this worse: even where logging exists, a shared account means nothing can be attributed to an individual, so insider misuse stays invisible twice over — once because it isn't detected, and again because it can't be traced.
