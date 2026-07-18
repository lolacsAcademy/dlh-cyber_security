# Task 6 — The ALE Workshop

MedDefense Health Systems — ALE for the 5 highest-priority risks. Built from 1x00 assets, 1x02 findings, 1x01 threat intel.

## Risk 1: Backup destroyed alongside production

```yaml
Risk: "Backup destroyed alongside production during a ransomware event"
Source: "GAP-010 (1x00) + Breach 1/Alpha case study (1x01) + Ransomware/RaaS"

Asset: "Backup & Storage (NAS-01, backup-srv-01) — Critical"
Asset Value (AV): "$1,561,000"
  Replacement/recovery cost: "$235,000 (from-scratch rebuild, no backup to restore from)"
  Revenue loss during downtime: "$576,000 (36 days x $16,000/day — doubled, since no backup extends recovery)"
  Regulatory penalties: "$150,000 (severe tier — data is permanently lost, not just breached)"
  Reputation/patient trust impact: "$600,000 (5% patient attrition over 2 years)"

Exposure Factor (EF): "100%"
  Reasoning: "This AV is already the marginal cost of the backup failing. Full amount hits every time."

SLE: AV x EF = "$1,561,000"

ARO: "0.3"
  Reasoning: "Only fires during a ransomware event. Uses the same 1-in-~3.3-year rate as the ransomware risk."

ALE: SLE x ARO = "$468,300"

Proposed Control: "Isolate backups offline/immutable (GAP-010, CIS Control 11)"
Control Annual Cost: "$14,400"
Estimated ALE After Control: "$46,830 (backup survives the incident, ~90% drop)"
Net Benefit: "$468,300 - $46,830 - $14,400 = $407,070"
```

## Risk 2: VPN compromise, no MFA

```yaml
Risk: "Credential-based VPN compromise leading to full network breach"
Source: "GAP-012 (1x00) + FortiGate OSINT (1x02) + Ransomware/RaaS, Kill Chain 1 (1x01)"

Asset: "VPN / Remote Access (FortiGate) — Critical, entry point to entire network"
Asset Value (AV): "$1,073,000"
  Replacement/recovery cost: "$85,000"
  Revenue loss during downtime: "$288,000 (18 days x $16,000/day)"
  Regulatory penalties: "$100,000"
  Reputation/patient trust impact: "$600,000"

Exposure Factor (EF): "100%"
  Reasoning: "Flat network means one compromised credential reaches everything."

SLE: AV x EF = "$1,073,000"

ARO: "0.35"
  Reasoning: "VPN is the #1 access vector in 38% of healthcare ransomware. No MFA makes it easier than average."

ALE: SLE x ARO = "$375,550"

Proposed Control: "Deploy MFA org-wide, existing O365 licenses (GAP-012, CIS Control 6)"
Control Annual Cost: "$4,000"
Estimated ALE After Control: "$53,650 (ARO falls to 0.05 — breaks the attack at step 1)"
Net Benefit: "$375,550 - $53,650 - $4,000 = $317,900"
```

## Risk 3: Ransomware encrypts EHR via flat network

```yaml
Risk: "Ransomware encrypts the EHR system via the flat network"
Source: "GAP-011 (1x00) + Finding 003, 031 (1x02) + Ransomware/RaaS, Kill Chain 1 (1x01)"

Asset: "EHR system (ehr-srv-01 + ehr-db-01) — Critical"
Asset Value (AV): "$1,236,000"
  Replacement/recovery cost: "$150,000"
  Revenue loss during downtime: "$336,000 (21 days x $16,000/day)"
  Regulatory penalties: "$150,000 (higher tier — PHI involved)"
  Reputation/patient trust impact: "$600,000"

Exposure Factor (EF): "100%"
  Reasoning: "Encryption denies all EHR access until restored or paid."

SLE: AV x EF = "$1,236,000"

ARO: "0.3"
  Reasoning: "1 attack every 3-4 years for similar hospitals (1x01), midpoint used."

ALE: SLE x ARO = "$370,800"

Proposed Control: "Segment the flat network, Phase 1 (GAP-011, CIS Control 12)"
Control Annual Cost: "$25,500 (3-year amortized labor estimate)"
Estimated ALE After Control: "$111,240 (EF falls to ~30% — blast radius contained)"
Net Benefit: "$370,800 - $111,240 - $25,500 = $234,060"
```

## Risk 4: Undetected malware dwell time

```yaml
Risk: "Undetected malware dwell time on billing-srv-01"
Source: "GAP-014 (1x00) + billing-srv-01 findings 001,002,006,009,011,026 (1x02) + Ransomware/cryptomining actors (1x01)"

Asset: "billing-srv-01 — High. Already compromised twice: ransomware, then a cryptominer."
Asset Value (AV): "$89,000"
  Replacement/recovery cost: "$40,000"
  Revenue loss during downtime: "$24,000 (3 days, 50% impact — degraded, not fully down)"
  Regulatory penalties: "$10,000 (no confirmed PHI exposure)"
  Reputation/patient trust impact: "$15,000 (internal cost only)"

Exposure Factor (EF): "60%"
  Reasoning: "Both real incidents on this asset were partial, not full-impact."

SLE: AV x EF = "$53,400"

ARO: "2"
  Reasoning: "Already happened twice in a year, with zero detection in place."

ALE: SLE x ARO = "$106,800"

Proposed Control: "Centralized logging on top 3 critical assets (GAP-014, CIS Control 8)"
Control Annual Cost: "$18,000"
Estimated ALE After Control: "$53,400 (dwell time drops from weeks to hours)"
Net Benefit: "$106,800 - $53,400 - $18,000 = $35,400"
```

## Risk 5: Infusion pump compromise

```yaml
Risk: "Infusion pump compromise via default credentials and flat network"
Source: "GAP-001 (1x00) + BD Alaris CVE (1x00 T7) + Breach 3/Gamma correlation (1x01)"

Asset: "BD Alaris infusion pumps (7 units) — Critical"
Asset Value (AV): "$3,105,000"
  Replacement/recovery cost: "$105,000 (7 x $15,000)"
  Revenue loss during downtime: "$100,000 (5 days manual dosing at $20,000/day)"
  Regulatory penalties: "$150,000 (FDA investigation)"
  Reputation/patient trust impact: "$2,750,000 (midpoint of $500K-$5M liability range)"

Exposure Factor (EF): "100%"
  Reasoning: "A confirmed patient-safety event triggers the full cost stack."

SLE: AV x EF = "$3,105,000"

ARO: "0.02"
  Reasoning: "1-in-50-years for a patient-safety-level event specifically."

ALE: SLE x ARO = "$62,100"

Proposed Control: "Replace default credentials, isolate devices on own segment (GAP-001, CIS Control 4)"
Control Annual Cost: "$8,000"
Estimated ALE After Control: "$15,525 (ARO falls to 0.005)"
Net Benefit: "$62,100 - $15,525 - $8,000 = $38,575"
```

---

## Risk Prioritization by ALE

| Rank | Risk | Gap | ALE Before | Control Cost | ALE After | Net Benefit |
|---|---|---|---|---|---|---|
| 1 | Backup destroyed with production | GAP-010 | $468,300 | $14,400 | $46,830 | $407,070 |
| 2 | VPN compromise, no MFA | GAP-012 | $375,550 | $4,000 | $53,650 | $317,900 |
| 3 | Ransomware encrypts EHR | GAP-011 | $370,800 | $25,500 | $111,240 | $234,060 |
| 4 | Undetected malware dwell time | GAP-014 | $106,800 | $18,000 | $53,400 | $35,400 |
| 5 | Infusion pump compromise | GAP-001 | $62,100 | $8,000 | $15,525 | $38,575 |

**Budget check:** Total control cost = $69,900. Within the $120,000 budget. ~$50,100 remains for the other Critical gaps not costed here. MFA (Risk 2) has the best ROI — $317,900 net benefit for a $4,000 spend.
