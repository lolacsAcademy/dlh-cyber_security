# Task 8 — The Budget Game

MedDefense Health Systems — final $120,000 allocation across the 8 Task 7 controls.

## Part 1 — The Selection

**Funded (6 controls, ranked by Net Value):**

| Control | Cost | Net Value |
|---|---|---|
| MFA deployment | $4,000 | $317,900 |
| Offsite backup replication | $14,400 | $407,070 |
| Network segmentation | $25,500 | $234,060 |
| EDR upgrade | $22,000 | $49,640 |
| Medical device isolation + monitoring | $20,000 | $35,890 |
| Westside Clinic firewall | $1,600 | $5,900 |
| **Total** | **$87,500** | |

**Deferred to next fiscal year (1 control):**

- **Enterprise SIEM (Wazuh) — $30,000.** Weakest positive Net Value in the set ($23,400, "Marginal" verdict in Task 7). It also needs roughly 0.4 FTE of analyst time to deploy and tune — the same 2-person team (Task 4) is already stretched funding and rolling out the 6 controls above. Deferring frees labor bandwidth this cycle without losing the investment; revisit once MFA, segmentation, and backup isolation are stable.

**Rejected outright (1 control):**

- **24/7 Outsourced SOC — $150,000.** Not a timing problem, a math problem: negative Net Value (-$107,706, Task 7). Costs more than the entire budget by itself for a fraction of the risk reduction the cheaper controls already deliver. Reject, don't defer — nothing changes next year that makes this cost-justified at MedDefense's current scale.

**Total spend vs. budget:** $87,500 spent of $120,000. **$32,500 budget remaining.** This is not unspent slack — it is reserved for the four remaining Critical gaps (GAP-002, GAP-004, GAP-005, GAP-008) identified in Task 3 but not quantified in Task 6/7's top-5 risk set (backup coverage for ad-dc-02 and PACS, the shared PACS login, and the network closet's physical security).

## Part 2 — The Opportunity Cost

**By deferring Enterprise SIEM (Wazuh), MedDefense accepts an estimated $53,400 in annual risk exposure** — the ALE reduction Task 7 attributed specifically to this control against Risk 4 (undetected malware dwell time, GAP-014). One caveat: EDR (funded) already claims a partial 15% reduction on this same risk (~$16,020 of the $106,800 before-ALE), so the deferral is not a full return to the unmitigated baseline — but the remaining gap SIEM would have closed stays open until next cycle.

The 24/7 SOC's opportunity cost is not calculated here — it was rejected, not deferred, so there is no "next year" figure to track against it.

## Part 3 — The Alternative

**Alternative: swap EDR for the deferred SIEM.** Drop EDR upgrade ($22,000) — its benefit overlaps heavily with segmentation and SIEM rather than closing a gap those don't already touch (flagged directly in Task 7's own recommendation for Control 5). Fund SIEM ($30,000) instead.

| | Primary (this task) | Alternative (SIEM instead of EDR) |
|---|---|---|
| Controls funded | MFA, Backup, Segmentation, EDR, Medical device, Westside | MFA, Backup, Segmentation, SIEM, Medical device, Westside |
| Total cost | $87,500 | $95,500 |
| Total ALE reduction | $1,137,960 | $1,119,720 |

**Result: the primary selection wins on both dimensions** — more total risk reduction ($1,137,960 vs. $1,119,720) at a lower cost ($87,500 vs. $95,500). The alternative is not actually a better use of the budget; it costs $8,000 more for $18,240 less risk reduction. This confirms EDR, despite its overlap with other controls, still earns its place ahead of SIEM in the funded set — the original Task 7 Net Value ranking holds up under a direct swap test.
