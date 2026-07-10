# MedDefense — Risk Decisions

Top 7 gaps selected: all 7 Critical-rated gaps (Task 12 + Task 13). Critical patient-safety/Restricted-data risks get treated, not accepted — the decision is how and when.

## GAP-011 — Flat network, no segmentation (Critical)
- Treatment: Mitigate
- Why: Root cause of Breach 1's 3-hour domain takeover.
- Controls: Technical/Preventive — VLAN segmentation, Central first.
- Cost: $50K+ full scope; Phase 1 (Central) funded now, Westside deferred.
- Effort: Long-term (>1 month).
- Risk Reduction: Removes the biggest lateral-movement path org-wide.
- Trade-off: Westside stays exposed until next FY.

## GAP-001 — Infusion pumps, zero controls (Critical)
- Treatment: Mitigate
- Why: Direct patient-safety risk; cheap win using existing firewall.
- Controls: Technical/Compensating — isolate medical IoT VLAN.
- Cost: $1-10K.
- Effort: Short-term (<1 month).
- Risk Reduction: Blocks the exact pivot path used in Breach 3.
- Trade-off: Doesn't patch device firmware, just isolates it.

## GAP-002 — PACS, no backup (Critical)
- Treatment: Mitigate
- Why: Only Critical asset with zero corrective control.
- Controls: Technical/Corrective — add to existing Veeam job.
- Cost: $10-50K (storage expansion needed).
- Effort: Short-term (<1 month).
- Risk Reduction: Closes the one Critical asset with no recovery path.
- Trade-off: Still co-located with production, same room.

## GAP-010 — Backup single point of failure (Critical)
- Treatment: Mitigate
- Why: Breach 1 proves an untested, co-located backup isn't real protection.
- Controls: Technical/Corrective — offsite/cloud backup (previously denied).
- Cost: $10-50K (~$14,400/yr per existing quote).
- Effort: Short-term (<1 month, vendor-managed).
- Risk Reduction: Removes the "lose both at once" scenario.
- Trade-off: Recurring annual cost.
## GAP-004 — ad-dc-02, no backup (Critical)
- Treatment: Mitigate
- Why: Cheapest fix here — small VM, easy add to existing job.
- Controls: Technical/Corrective — add ad-dc-02 to Veeam job.
- Cost: $0-1K.
- Effort: Quick Win (<1 week).
- Risk Reduction: Restores real DC redundancy for disaster recovery.
- Trade-off: None significant.

## GAP-005 — Network closet exposure (Critical)
- Treatment: Mitigate
- Why: Cheap fix for the single worst data-exposure finding (Task 9).
- Controls: Physical/Preventive (lock) + Physical/Detective (camera).
- Cost: $1-10K.
- Effort: Quick Win (lock) / Short-term (camera).
- Risk Reduction: Removes walk-in access to full network admin control.
- Trade-off: Doesn't fix the underlying habit of writing credentials on paper — needs a policy fix too.

## GAP-008 — Shared PACS login (Critical)
- Treatment: Mitigate
- Why: Pure process fix, near-zero cost, already flagged once and ignored.
- Controls: Administrative/Preventive — individual radiology accounts via existing AD.
- Cost: $0-1K.
- Effort: Quick Win (<1 week).
- Risk Reduction: Restores individual accountability for PACS access.
- Trade-off: Needs management enforcement — past attempts were ignored.

## Budget Summary

| Gap | Item | Cost | Effort |
|---|---|---|---|
| GAP-008 | Individual PACS accounts | $500 | Quick Win |
| GAP-004 | Add ad-dc-02 to backup | $500 | Quick Win |
| GAP-005 | Closet lock + camera | $5,000 | Quick Win/Short-term |
| GAP-001 | Medical IoT VLAN isolation | $8,000 | Short-term |
| GAP-010 | Offsite/cloud backup | $14,400 | Short-term |
| GAP-002 | PACS backup + storage | $15,000 | Short-term |
| GAP-011 | Network segmentation, Phase 1 (Central) | $76,600 | Long-term |
| **Total** | | **$120,000** | |

Fits exactly within budget. Deferred to next fiscal year: Westside's network hardware overhaul, GAP-011's remaining scope beyond Central, and a SIEM ($80K alone can't fit alongside the above).
