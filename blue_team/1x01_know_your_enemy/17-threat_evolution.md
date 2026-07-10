# The What-If — MedDefense Threat Evolution

## Scenario A — University Clinical Trial Partnership
New Threat Actors: Nation-state APT activates (T6 flagged this as the trigger); increased organized-crime interest in trial IP theft
Changed Vectors: Supply Chain Compromise rises (3 new international institutions); Vulnerable Software Exploit on the new dedicated server; Pretexting easier against unfamiliar researchers
Shifted Priorities: Nation-state enters Top 5 for the first time; Supply Chain (Rank 2) rises further given 3 new external institutions
New Gaps: New trial server likely lands on the flat network, inheriting GAP-005/GAP-010 patterns; no security review process for the 3 international institutions; cross-border data transfer/compliance exposure beyond HIPAA
Net Assessment: Increases — introduces an entirely new actor class (nation-state) with near-zero prior likelihood, while every existing flat-network gap remains unresolved and now guards higher-value data.

## Scenario B — EHR Migration to MedTech Cloud SaaS
New Threat Actors: No new actor type, but weight shifts — Ransomware/Organized crime now targets MedTech's environment instead of MedDefense's own
Changed Vectors: VPN Exploit → EHR drops (server decommissioned); Open Service Ports (PostgreSQL 5432) disappears from MedDefense's side; Supply Chain Compromise becomes dominant — MedTech IS the EHR now
Shifted Priorities: Rank 2 (Supply chain via MedTech) surges toward #1; GAP-002/GAP-010 (PACS/backup) become relatively more prominent as the largest remaining on-prem assets
New Gaps: Loss of direct visibility/control over EHR security controls; no confirmed security-requirements review of MedTech's SaaS platform; T5's hypothetical "MedTech breach = most damage" becomes literal reality
Net Assessment: Shifts rather than simply rising or falling — clinical data risk moves from MedDefense's own flat network to a single external vendor MedDefense has no visibility into.
## Scenario C — Public Breach Disclosure (News Article)
New Threat Actors: Increased RaaS affiliate interest — public confirmation of a prior successful compromise signals MedDefense as a validated soft target; some hacktivist/opportunistic copycat risk
Changed Vectors: Patient-facing phishing/smishing referencing the breach becomes newly viable; BEC/vishing pretexts against staff become far more credible ("calling about the January breach")
Shifted Priorities: Rank 1 (Ransomware) rises further — public validation attracts other affiliates; Rank 5 (Social engineering/BEC) rises since breach-themed pretexting is now credible
New Gaps: No process for monitoring/takedown of breach-themed phishing targeting patients; no crisis-communications/security coordination plan evident; leadership pressure risks rushed, under-secured decisions
Net Assessment: Increases — public disclosure hands other threat actors validated targeting information without any of the underlying gaps that caused the original incident having been closed.
