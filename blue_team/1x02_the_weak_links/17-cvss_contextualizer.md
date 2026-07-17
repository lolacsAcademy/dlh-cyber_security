# Task 17 — The CVSS Contextualizer

8 findings from Task 16's Actionable Critical list: 031, 003, 004, 001, 002, 015, 007, 010.

## Finding 031 - CVE-2020-1938 (Ghostcat)
CVSS Base Score: 9.8

Factor 1 - Asset Criticality: EHR System, Critical/Critical/Critical. Raises urgency to maximum.
Factor 2 - Kill Chain: Chains 1 & 5, final target. Raises urgency.
Factor 3 - Exploitability: Score 5, KEV Yes. Raises urgency.
Factor 4 - Controls: C-003/004/011 don't cover this vector; C-001 doesn't segment internally. No mitigation exists.

Environmental CVSS: CR/IR/AR = High. Adjusted Score: 9.8 (unchanged, already at ceiling).

Final Priority: Critical
Final Justification: Top-rated asset, named final target in two kill chains, weaponized KEV, zero effective controls.

## Finding 003 - PostgreSQL Exposure (ehr-db-01)
CVSS Base Score: N/A (misconfig, Critical per scanner)

Factor 1 - Asset Criticality: EHR System, Critical/Critical/Critical. Raises urgency.
Factor 2 - Kill Chain: Chains 1 & 5, final target. Raises urgency.
Factor 3 - Exploitability: N/A, no exploit even needed — network reachability alone is enough.
Factor 4 - Controls: None specific to DB access anywhere in registry. No mitigation.

Environmental CVSS: No base vector to adjust (no CVE). Adjusted Score: N/A.

Final Priority: Critical
Final Justification: No exploit required, top-rated asset, named in two kill chains, zero controls.

## Finding 004 - Windows XP EOL Cluster (WS-RAD-01, BlueKeep representative)
CVSS Base Score: 9.8

Factor 1 - Asset Criticality: Medical IoT-adjacent, Integrity/Availability Critical. Raises urgency.
Factor 2 - Kill Chain: Not named directly; enables Chain 1's lateral-spread phase.
Factor 3 - Exploitability: Score 5, KEV Yes. Raises urgency.
Factor 4 - Controls: 1x00 T6 proposed a VLAN, but registry shows it was never implemented.

Environmental CVSS: CR/IR/AR = High. Adjusted Score: 9.8 (unchanged).

Final Priority: Critical
Final Justification: Patient safety, weaponized KEV, proposed control exists only on paper.

## Finding 001 - CVE-2021-44790 (billing-srv-01)
CVSS Base Score: 9.8

Factor 1 - Asset Criticality: Billing Infrastructure, Overall High. Confirms high urgency.
Factor 2 - Kill Chain: Chain 3, initial access point. Raises urgency.
Factor 3 - Exploitability: Score 2, KEV No. Lowers urgency somewhat.
Factor 4 - Controls: C-006 Sophos AV Weak; C-010 Apache logging passive only.

Environmental CVSS: CR/IR/AR = Medium (default). Adjusted Score: 9.8 (unchanged).

Final Priority: Critical
Final Justification: Named in a formal kill chain, host with 2 prior real compromises, weak controls — business context keeps this Critical despite no public exploit.

## Finding 002 - CVE-2019-0211 (billing-srv-01)
CVSS Base Score: 7.8

Factor 1 - Asset Criticality: Billing Infrastructure, Overall High.
Factor 2 - Kill Chain: Chain 3, second-stage privesc step.
Factor 3 - Exploitability: Not scored in T4, KEV No.
Factor 4 - Controls: Same weak AV/logging as Finding 001.

Environmental CVSS: CR/IR/AR = Medium. Adjusted Score: 7.8 (unchanged).

Final Priority: High
Final Justification: Real second-stage of the chain, but requires local access already and asset is High not Critical.

## Finding 015 - NAS-01 + CVE-2024-10441
CVSS Base Score: 9.8 (sourced via Task 9)

Factor 1 - Asset Criticality: Backup & Storage, Overall Critical.
Factor 2 - Kill Chain: Chains 1 & 5, final target (immutable backup break point).
Factor 3 - Exploitability: Not scored in T4, KEV No.
Factor 4 - Controls: C-007 Veeam backup Weak, co-located with production.

Environmental CVSS: CR/IR/AR = High. Adjusted Score: 9.8 (unchanged).

Final Priority: Critical
Final Justification: Last line of defense against ransomware, named in 2 kill chain break points, its one control is Weak.

## Finding 007 - LDAP Relay / SMBv1 (ad-dc-01)
CVSS Base Score: N/A (misconfig, High per scanner)

Factor 1 - Asset Criticality: Identity/AD, Overall Critical.
Factor 2 - Kill Chain: Not named directly. Weaker signal than top-tier findings.
Factor 3 - Exploitability: N/A, requires relay attack conditions.
Factor 4 - Controls: C-005 doesn't stop relay; C-008 Weak, manual only.

Environmental CVSS: No base vector to adjust. Adjusted Score: N/A.

Final Priority: High
Final Justification: Was Actionable Critical in Task 16's broader triage; deeper analysis settles it at High since no kill chain names it directly and exploitation needs more attacker positioning.

## Finding 010 - CVE-2020-25165 (BD Alaris)
CVSS Base Score: 6.5

Factor 1 - Asset Criticality: Medical IoT, Integrity/Availability Critical (patient safety).
Factor 2 - Kill Chain: None identified.
Factor 3 - Exploitability: Not scored in T4; BD confirms not exploited in the wild.
Factor 4 - Controls: Zero medical-IoT-specific controls anywhere in registry.

Environmental CVSS: CR/IR/AR = High. Adjusted Score: 7.5 (real increase from 6.5).

Final Priority: High
Final Justification: Base score alone underrates this — patient-safety weighting pushes it to a real 7.5, though it's DoS-class and not currently exploited, keeping it below the fully weaponized Critical tier.

## Priority Comparison Table

| Finding | CVSS Base | Adjusted Priority | Change |
|---|---|---|---|
| 031 | 9.8 | Critical | Same |
| 003 | N/A | Critical | Same |
| 004 | 9.8 | Critical | Same |
| 001 | 9.8 | Critical | Same |
| 002 | 7.8 | High | Same |
| 015 | 9.8 | Critical | Same |
| 007 | N/A | High | **Lower** (was AC in T16) |
| 010 | 6.5 | High | **Higher** (6.5→7.5 env) |

Highlight: Finding 010 shows the clearest upward shift — CVSS alone underrates it. Finding 007 shows context can lower urgency too, not just raise it.
