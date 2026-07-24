# Task 9 — The Board Presentation

## Part 1: Board Security Brief

**Current threat status:** CISA issued an emergency advisory 4 hours ago naming "Crimson Tide," a ransomware group that has compromised 5 regional hospitals in 10 days, 3 in our region, one 45 miles away. MedDefense matches the exact victim profile: unpatched FortiGate VPN, flat network, unencrypted backups.

**Security posture verdict:** MedDefense entered this advisory exposed on all 7 phases of the attack chain. Even our funded $120,000 security strategy, fully implemented, would only fully block 2 of those 7 phases — the entry point itself stays open.

**Emergency response summary:** Tonight, we isolated backups, reviewed FortiGate logs, disabled dormant accounts, and blocked known attacker infrastructure. Tomorrow requires a $2,400 support contract renewal to unlock the FortiGate patch. This week requires emergency network segmentation and a Kerberos hardening window. A full 72-hour plan with named owners is in place.

**Investment summary:** $87,500 of the original $120,000 is already funded across MFA, backup replication, segmentation, EDR, medical device isolation, and a clinic firewall — none of it deployed yet. Tonight's advisory raised our ransomware risk (ALE) from $370,800 to $1,112,400, and identified a new $965,700 risk on the FortiGate itself. The $2,400 patch has a projected net benefit of $915,015. We are asking the Board to approve that spend tonight, and to consider funding beyond $120,000 given the scale of what just changed.

**Recommendation:** Approve the $2,400 FortiGate renewal tonight and authorize acceleration of the funded strategy into a 30-day window instead of 6 months. This buys real protection fast; it does not make us fully safe — that requires the SIEM, incident response plan, and vendor risk work that remain unfunded.
## Part 2: Stakeholder Map

**Dr. Morales (CEO) — Patient safety:** Crimson Tide's real-world pattern includes ambulance diversions and paper-record fallback at Hospital C right now, 45 miles from us. If we're hit, EHR and PACS both go down — this is a direct patient-care risk, not just an IT problem, and it's why the 72-hour plan starts tonight, not Monday.

**Robert Kim (CFO) — Financial exposure and ROI:** The updated ransomware ALE is $1,112,400/year, against a $2,400 patch with a $915,015 net benefit — the clearest ROI in the entire program. The bigger financial exposure is doing nothing: a single incident at a peer hospital cost $1.1M in ransom alone, before recovery and reputational cost.

**Dr. Reeves (Board Chair) — Professional recommendation and confidence:** I recommend approving the emergency spend tonight with high confidence — the FortiGate CVE is confirmed, in CISA's exploited-vulnerability catalog, and is the exact mechanism used against all 5 recent hospital victims. My lower-confidence area is the segmentation and Kerberos work this week, which carries real outage risk and needs a tested maintenance window, not a rushed one.

**Thomas Wright (Former banker) — Industry comparison:** Financial sector security assumes active, sophisticated adversaries by default — segmented networks, mandatory MFA, and 24/7 monitoring are baseline, not aspirational. MedDefense currently has none of those three in place; tonight's advisory is the kind of live-fire event that would trigger an immediate incident response drill at any bank, not a 6-month roadmap.

**Maria Santos (Legal counsel) — HIPAA liability and insurance:** Our patient database and backups are unencrypted at rest — a direct HIPAA Security Rule gap that increases both breach-notification exposure and potential penalty tier if Crimson Tide successfully exfiltrates data, which is the campaign's confirmed first move before encryption. I'd recommend confirming our cyber insurance policy's active-exploitation and unpatched-vulnerability clauses before, not after, any incident.
