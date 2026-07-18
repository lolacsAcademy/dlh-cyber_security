# Task 7 — The Cost-Benefit Analysis

MedDefense Health Systems — 8 proposed controls evaluated by ALE reduction vs. annual cost. Controls 1, 2, 4 reuse Task 6 figures directly. Others are new estimates with stated assumptions.

## Control 1: Network Segmentation

```yaml
Control 1: "Network Segmentation (VLAN: server, workstation, medical device, guest)"
CIS Control Reference: "12"
Annual Cost: "$25,500 (Phase-1 labor, 3-year amortized estimate — no separate license/maintenance line, internal build)"
Risk(s) Addressed: "Risk 3 — Ransomware encrypts EHR (GAP-011)"
ALE Reduction: "$370,800 - $111,240 = $259,560"
Net Value: "$259,560 - $25,500 = $234,060"
Verdict: "Justified"
Recommendation: "Implement — highest structural fix in the whole program, breaks lateral movement for every other risk too."
```

## Control 2: MFA Deployment

```yaml
Control 2: "MFA on VPN and administrative accounts (existing O365 E3 licenses)"
CIS Control Reference: "6"
Annual Cost: "$4,000 (labor/rollout only, no license cost — already owned)"
Risk(s) Addressed: "Risk 2 — VPN compromise, no MFA (GAP-012)"
ALE Reduction: "$375,550 - $53,650 = $321,900"
Net Value: "$321,900 - $4,000 = $317,900"
Verdict: "Justified"
Recommendation: "Implement — best return in the entire set for the lowest cost."
```

## Control 3: Enterprise SIEM (Wazuh, open-source)

```yaml
Control 3: "Enterprise SIEM deployment (Wazuh, open-source, labor cost only)"
CIS Control Reference: "8 / 13"
Annual Cost: "$30,000 (assumption: ~0.4 FTE analyst time to deploy, tune, and maintain org-wide, plus $2,000 hosting — no license fee)"
Risk(s) Addressed: "Risk 4 — Undetected malware dwell time (GAP-014)"
ALE Reduction: "$106,800 - $53,400 = $53,400"
Net Value: "$53,400 - $30,000 = $23,400"
Verdict: "Marginal"
Recommendation: "Implement, but treat as a cost-efficiency test — org-wide Wazuh costs more in labor than Task 6's top-3-asset logging estimate for the same ALE reduction; scope to critical assets first if labor is tight."
```

## Control 4: Offsite Backup Replication (AWS S3 Glacier)

```yaml
Control 4: "Offsite backup replication (cloud immutable storage, AWS S3 Glacier)"
CIS Control Reference: "11"
Annual Cost: "$14,400 (storage + replication, matches the Task 6 backup isolation estimate — this is the concrete implementation of that control)"
Risk(s) Addressed: "Risk 1 — Backup destroyed with production (GAP-010)"
ALE Reduction: "$468,300 - $46,830 = $421,470"
Net Value: "$421,470 - $14,400 = $407,070"
Verdict: "Justified"
Recommendation: "Implement — single highest net value in the program."
```

## Control 5: EDR Upgrade (Sophos Intercept X, all endpoints)

```yaml
Control 5: "EDR upgrade — Sophos basic to Intercept X, all endpoints including servers"
CIS Control Reference: "10"
Annual Cost: "$22,000 (assumption: ~330 endpoints/servers x ~$60/endpoint/year license = $19,800, plus $2,000 labor)"
Risk(s) Addressed: "Partial reduction to Risk 3 (EHR ransomware) and Risk 4 (dwell time) — incremental, since segmentation and SIEM already cover most of both"
ALE Reduction: "Assumption: EDR cuts remaining malware-execution probability ~15% on both risks. 15% x $370,800 + 15% x $106,800 = $71,640"
Net Value: "$71,640 - $22,000 = $49,640"
Verdict: "Justified"
Recommendation: "Implement — solid return, though its benefit overlaps with Controls 1 and 3 rather than closing a new gap."
```

## Control 6: Dedicated Firewall for Westside Clinic

```yaml
Control 6: "Dedicated firewall for Westside Clinic (replacing the consumer router)"
CIS Control Reference: "12"
Annual Cost: "$1,600 (assumption: ~$1,500 hardware amortized over 3 years = $500, plus $600 subscription, plus $500 labor)"
Risk(s) Addressed: "Site-specific perimeter weakness, not one of Task 6's top 5 — new estimate: AV $50,000 (recovery $15,000 + 3 days site downtime at $5,000/day + $10,000 regulatory + $10,000 reputation), EF 100%, ARO 0.2 (consumer-grade router at a smaller site)"
ALE Reduction: "Before: $50,000 x 0.2 = $10,000. After (ARO falls to 0.05 with a real firewall): $50,000 x 0.05 = $2,500. Reduction = $7,500"
Net Value: "$7,500 - $1,600 = $5,900"
Verdict: "Justified"
Recommendation: "Implement — small dollar figure, but cheap and closes an obvious, avoidable weak point."
```

## Control 7: 24/7 Outsourced SOC

```yaml
Control 7: "24/7 Security Operations Center staffing (outsourced managed SOC)"
CIS Control Reference: "13 / 17"
Annual Cost: "$150,000 (assumption: industry-typical outsourced 24/7 SOC/MDR pricing for an org this size)"
Risk(s) Addressed: "Marginal additional detection speed across Risks 1, 3, and 4 — but Controls 1, 3, and 4 already address the underlying gaps"
ALE Reduction: "Assumption: SOC adds ~20% further reduction on top of the already-reduced post-control ALE for Risks 1, 3, 4 ($46,830 + $111,240 + $53,400 = $211,470 remaining). 20% x $211,470 = $42,294"
Net Value: "$42,294 - $150,000 = -$107,706"
Verdict: "Not Justified"
Recommendation: "Reject — costs more than the entire $120,000 budget on its own, for a fraction of the ALE reduction the cheaper controls already deliver."
```

## Control 8: Full Medical Device Network Isolation with Dedicated Monitoring

```yaml
Control 8: "Full medical device network isolation with dedicated monitoring"
CIS Control Reference: "4 / 13"
Annual Cost: "$20,000 (Task 6's $8,000 isolation cost, plus $12,000 assumption for dedicated medical-IoT monitoring)"
Risk(s) Addressed: "Risk 5 — Infusion pump compromise (GAP-001)"
ALE Reduction: "Before: $62,100 (Task 6). After (ARO falls further to 0.002 with monitoring added on top of isolation): $3,105,000 x 0.002 = $6,210. Reduction = $55,890"
Net Value: "$55,890 - $20,000 = $35,890"
Verdict: "Justified"
Recommendation: "Implement — patient-safety risk category, worth the added monitoring cost beyond isolation alone."
```

---

## Cost-Benefit Summary Table (ranked by Net Value)

| Rank | Control | Annual Cost | ALE Reduction | Net Value | Verdict |
|---|---|---|---|---|---|
| 1 | Offsite backup replication | $14,400 | $421,470 | $407,070 | Justified |
| 2 | MFA deployment | $4,000 | $321,900 | $317,900 | Justified |
| 3 | Network segmentation | $25,500 | $259,560 | $234,060 | Justified |
| 4 | EDR upgrade | $22,000 | $71,640 | $49,640 | Justified |
| 5 | Medical device isolation + monitoring | $20,000 | $55,890 | $35,890 | Justified |
| 6 | Enterprise SIEM (Wazuh) | $30,000 | $53,400 | $23,400 | Marginal |
| 7 | Westside Clinic firewall | $1,600 | $7,500 | $5,900 | Justified |
| 8 | 24/7 outsourced SOC | $150,000 | $42,294 | -$107,706 | Not Justified |

**Budget fit:** Controls 1-6 (excluding the SOC) total $14,400 + $4,000 + $25,500 + $22,000 + $20,000 + $30,000 + $1,600 = **$117,500** — fits inside the $120,000 budget with $2,500 to spare. The 24/7 SOC alone ($150,000) would exceed the entire annual budget by itself and delivers the lowest, negative net value in the set — it is deferred, not funded, this cycle.
