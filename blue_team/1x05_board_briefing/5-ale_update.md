# Task 5 — The ALE Update

## Part 1: Original vs. Updated ALE

**Original calculation (1x03 T6, Risk 3 — Ransomware encrypts EHR via flat network):**
- AV: $1,236,000 (recovery $150k + 21 days downtime $336k + regulatory $150k + reputation $600k)
- EF: 100% (encryption denies all EHR access until restored/paid)
- SLE = AV × EF = $1,236,000
- Original ARO: 0.3 — reasoning: "1 attack every 3–4 years for similar hospitals" (sector base rate from 1x01)
- Original ALE = SLE × ARO = **$370,800**

**Updated ARO using the Crimson Tide advisory:**
The 0.3 figure was a multi-year sector average — background risk, not evidence of an active campaign. The advisory changes the input entirely: 5 confirmed compromises in 10 days, 3 in MedDefense's own region, and all 5 victims share MedDefense's exact profile (unpatched FortiGate SSL-VPN, flat network, unencrypted backups). This isn't a base rate anymore — it's a live, targeted campaign against organizations matching MedDefense specifically.

Updated ARO: **0.9** — this is a judgment call, not a sector statistic (the sample is small and the campaign is still ongoing, so a precise probability model isn't defensible). It reflects near-certain compromise within the year if the exposure isn't closed, given MedDefense matches every element of the victim profile and sits inside the same active campaign's geographic cluster.

- Updated SLE: unchanged at $1,236,000 (asset value assumptions haven't changed, only likelihood)
- Updated ALE = SLE × ARO = $1,236,000 × 0.9 = **$1,112,400**

**What changed and why:** the asset value and impact assumptions (SLE) are untouched — this is purely a likelihood update. New threat intelligence replaced a static multi-year sector average with a real-time, profile-matched campaign rate, roughly tripling the ALE.
## Part 2: Budget Impact

**FortiGate support contract renewal ($2,400):** Clear positive ROI. Against the updated $1,112,400 ALE, this is the cheapest possible action in the entire program and unlocks the fix for the exact CVE named in the advisory. Cost-benefit isn't close.

**24/7 outsourced SOC ($150,000/yr, "Not Justified" in T7):** The original verdict was based on the sector-rate ALE ($370,800) — at that level, the SOC's cost exceeded what cheaper controls already delivered. With the ransomware ALE now roughly tripled, the case is stronger, since a SOC's main value is faster detection of exactly this kind of dwell-time/lateral-movement activity. I don't have T7's original risk-reduction percentage for the SOC option, so I can't recalculate its net benefit precisely — but the gap it needs to close to flip from "Not Justified" to "Justified" is now much smaller than before, and this should be re-evaluated with real numbers rather than assumed either way.

**Emergency spending beyond $120,000:** Yes, recommended. The updated ALE for this single risk now exceeds MedDefense's entire original annual security budget by roughly 9x, and the threat is active with a 72-hour operational window (Task 3), not a future-year planning item. Waiting for the next budget cycle no longer matches the actual risk in front of the Board tonight.
