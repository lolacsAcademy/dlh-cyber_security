# Gap-Threat Correlation — MedDefense

### GAP-001 — Infusion pumps zero controls
Original: Critical | Actors: Ransomware (pivot potential) | Kill Chains: none of the 5 directly | Scenarios: none directly
Updated: Same (Critical) — already at ceiling; T8/T9 confirm exploitability but no chain routed through it

### GAP-002 — PACS no corrective control
Original: Critical | Actors: Ransomware | Kill Chains: #1, #5 | Scenarios: 1, 3
Updated: Same (Critical) — terminal step of 2/5 chains and 2/3 scenarios, validates original rating

### GAP-003 — billing-srv-01 controls failed twice
Original: High | Actors: Unskilled/Opportunistic (primary), Ransomware (secondary) | Kill Chains: #3 | Scenarios: none directly
Updated: UPGRADED → Critical — only gap tied to an already-proven, twice-realized compromise; same RCE also viable for ransomware entry

### GAP-004 — ad-dc-02 no backup
Original: Critical | Actors: Ransomware | Kill Chains: #1, #5 | Scenarios: 1, 3
Updated: Same (Critical) — reinforced across majority of chains/scenarios

### GAP-005 — Network closet exposes creds
Original: Critical | Actors: Ransomware, Insider (Malicious) | Kill Chains: #1, #5 | Scenarios: 1, 3
Updated: Same (Critical) — most-cited gap across T9-T14, entry point for nearly every major chain
### GAP-006 — HR file share no detective control
Original: Medium | Actors: Insider (loosely) | Kill Chains: none | Scenarios: none
Updated: Same (Medium) — no new threat evidence elevated it

### GAP-007 — Security training gap, Westside
Original: Medium | Actors: Insider (Negligent), broad social-engineering enabler | Kill Chains: indirect (T13 Alpha starts with phishing) | Scenarios: indirect (all 3)
Updated: UPGRADED → High — foundational enabler behind nearly all 7 T4 vectors and T13's successful phishing entry; 1x00's asset-centric view missed this cross-cutting role

### GAP-008 — Shared PACS login
Original: Critical | Actors: Insider (Malicious/Negligent) | Kill Chains: none of the 5 directly | Scenarios: none directly
Updated: Same (Critical) — not in built chains, but T9 independently confirms PACS as most-reachable asset (7/7 vectors), separate evidence reinforces rating

### GAP-009 — Orphaned Raspberry Pi
Original: High | Actors: Insider (Negligent), shadow IT | Kill Chains: none directly | Scenarios: none directly
Updated: Same (High) — no new evidence either way

### GAP-010 — Backup single point of failure
Original: Critical | Actors: Ransomware — matches BlackReef's own playbook | Kill Chains: #1, #5 | Scenarios: 1, 3
Updated: Same (Critical) — most threat-validated gap in the project
## Re-prioritized Gap List
Critical: GAP-010, GAP-005, GAP-002, GAP-004, GAP-008 (reinforced), GAP-003 (moved up from High)
High: GAP-007 (moved up from Medium), GAP-001, GAP-009 (unchanged)
Medium: GAP-006 (unchanged)

## The Critical Three
GAP-005, GAP-010, and GAP-002 tie for most frequent across kill chains and scenarios (4 appearances each, alongside GAP-004 — an honest 4-way tie). These three represent: the common entry point (GAP-005), the mechanism every ransomware-pattern attack explicitly targets before deploying (GAP-010, matches BlackReef's own playbook), and the irreversible-loss outcome (GAP-002). Closing GAP-004 alongside them breaks the same attack path just as effectively.

## The Surprise
GAP-007 (security awareness training, Medium in 1x00) should be upgraded to High. In 1x00 it looked like a narrow HR metric (58% completion at Westside). After T4's 7 social-engineering scenarios and T13's Scenario Alpha — where the entire ransomware kill chain started with one successful phishing click — it's clear this gap is a foundational enabler across nearly every human-vector attack path in the project, not an isolated training statistic.
