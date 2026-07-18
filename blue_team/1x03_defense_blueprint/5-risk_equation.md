# Task 5 — The Risk Equation

MedDefense Health Systems — quantitative risk analysis for 5 scenarios. All work shown.

## Scenario 1: Ransomware Attack on Billing Server

**1. Asset Value (AV):** $4,200,000 — the annual revenue billing-srv-01 processes. This represents the value of the function being protected, not the server's hardware cost.

**2. Exposure Factor (EF):** The real loss in a ransomware event is not the server's replacement cost — it is downtime, recovery, and penalties. Adding those:
- Downtime: 18 days × $16,000/day = $288,000
- Recovery: $85,000
- HIPAA penalty (mid-range): $100,000
- Total one-incident cost = $288,000 + $85,000 + $100,000 = $473,000

EF = $473,000 / $4,200,000 ≈ **11.3%**

**3. SLE = AV × EF:** $4,200,000 × 0.113 = **$473,000** (matches the summed cost above — consistency check passes)

**4. ARO:** Sector rate is "1 attack every 3-4 years" for similar-profile hospitals. Midpoint = 3.5 years → ARO = 1 / 3.5 ≈ **0.3**

**5. ALE = SLE × ARO:** $473,000 × 0.3 = **$141,900** (~$142,000/year)

**6. Confidence: Medium.** The single biggest swing variable is the 18-day downtime assumption. That figure is a national CISA average, not MedDefense-specific — and GAP-010 (backup co-located with production) means MedDefense's actual downtime could run far longer than average if the backup itself is destroyed alongside production. If downtime doubled to 36 days, ALE would jump to roughly $250,000/year.

## Scenario 2: Patient Data Breach via EHR System

**1. Asset Value (AV):** The full cost of one breach event, not the server's replacement cost:
- Record cost: 50,000 records × $165/record = $8,250,000
- HIPAA notification: $25,000
- Litigation exposure: $200,000
- Reputational (5% attrition, 2 years): $600,000
- **AV = $9,075,000**

**2. Exposure Factor (EF):** Per the hint, a breach event triggers all associated costs at once — **EF = 100% (1.0)**.

**3. SLE = AV × EF:** $9,075,000 × 1.0 = **$9,075,000**

**4. ARO:** Sector data estimates breach probability at "1 in 3 years" for a hospital with no SIEM, a flat network, and unpatched systems — a profile that matches MedDefense (GAP-014, GAP-011, and the 1x02 findings) exactly. ARO = 1 / 3 ≈ **0.33**

**5. ALE = SLE × ARO:** $9,075,000 × 0.33 = **$2,994,750** (~$3,000,000/year)

**6. Confidence: Low.** The ARO of "1 in 3 years" is a sector base rate subjectively adjusted upward for MedDefense's specific weaknesses — there is no MedDefense-specific breach history to calibrate it against. The reputational attrition figure ($600,000) is also a soft estimate. A halved ARO (1 in 6 years instead of 1 in 3) would cut this ALE to roughly $1,500,000 — the number is highly sensitive to an assumption nobody can currently verify.

## Scenario 3: Insider Data Theft (Negligent)

**1. Asset Value (AV):** $120,000 — the average fully-loaded cost of one negligent insider incident (investigation $30,000 + containment $25,000 + remediation $40,000 + regulatory reporting $25,000 = $120,000, confirming the total).

**2. Exposure Factor (EF):** The $120,000 figure already represents the full cost of one incident, not a larger asset value being partially lost — **EF = 100% (1.0)**.

**3. SLE = AV × EF:** $120,000 × 1.0 = **$120,000**

**4. ARO:** Sector averages plus MedDefense's specific lack of controls (no DLP, no USB restriction, shared accounts, no training program — CIS Controls 3, 14 both Not Implemented per Task 2) support an estimate of 2-3 incidents per year. Midpoint = **2.5**

**5. ALE = SLE × ARO:** $120,000 × 2.5 = **$300,000/year**

**6. Confidence: Medium.** The ARO of 2-3/year is itself an estimate MedDefense cannot currently verify — GAP-014 (no monitoring) means negligent incidents that already happened may never have been detected or counted. The real number could be higher, not lower, which would make this ALE a floor rather than a ceiling.

## Scenario 4: Medical Device Compromise

Two separate ALEs, as the hint specifies — a low-impact DoS scenario and a low-probability/high-impact patient-safety scenario.

### 4a. Denial-of-Service Scenario

**1. AV:** $100,000 — operational disruption from switching to manual dosing (5 days × $20,000/day) while pumps are quarantined. Device replacement cost ($105,000) does not apply here since a DoS event takes pumps offline, it doesn't destroy them.

**2. EF:** 100% — the full disruption cost is realized in a DoS event.

**3. SLE:** $100,000 × 1.0 = **$100,000**

**4. ARO:** Given as 1-in-10 years → **0.1**

**5. ALE:** $100,000 × 0.1 = **$10,000/year**

### 4b. Patient Safety Scenario

**1. AV:** Liability ($500,000–$5,000,000, midpoint $2,750,000) + FDA investigation ($150,000) + operational disruption ($100,000) = **$3,000,000**

**2. EF:** 100% — a confirmed patient safety event triggers the full cost stack.

**3. SLE:** $3,000,000 × 1.0 = **$3,000,000**

**4. ARO:** Given as 1-in-50 years → **0.02**

**5. ALE:** $3,000,000 × 0.02 = **$60,000/year**

**6. Confidence (both): Low.** The liability range spans a 10x factor ($500,000 to $5,000,000) — using the low end instead of the midpoint would cut the patient-safety ALE roughly in half, to about $31,000/year; using the high end would push it to about $105,000/year. Neither the 1-in-10 nor 1-in-50 ARO has MedDefense-specific incident history behind it (GAP-001 confirms zero detective controls on infusion pumps — MedDefense could not currently detect a DoS or safety event even if one had already occurred).

## Scenario 5: VPN Compromise Leading to Full Network Access

**1. Asset Value (AV):** The hint frames this as the aggregate of Scenarios 1 and 2, since a flat network (GAP-011) means VPN compromise opens a path to both:
- Scenario 1 SLE (billing ransomware): $473,000
- Scenario 2 SLE (EHR breach): $9,075,000
- **AV = $473,000 + $9,075,000 = $9,548,000**

**2. Exposure Factor (EF):** Because MedDefense's network is flat with no segmentation, an attacker who compromises the VPN can reach EHR, billing, AD, and the non-isolated backups in one continuous path — **EF = 100% (1.0)**.

**3. SLE = AV × EF:** $9,548,000 × 1.0 = **$9,548,000**

**4. ARO:** Given directly, based on VPN being the #1 initial access vector at 38% of healthcare ransomware attacks — **0.3**

**5. ALE = SLE × ARO:** $9,548,000 × 0.3 = **$2,864,400** (~$2,864,000/year)

**6. Confidence: Low.** This is the most compounded calculation in the set — it stacks Scenario 1's and Scenario 2's own already-uncertain figures. The single biggest swing variable is EF, not ARO: EF is only ~100% *because* GAP-011 (flat network) exists. If network segmentation (the Task 2/3 top recommendation) were implemented, an attacker entering via VPN would no longer automatically reach every system — EF could fall sharply, which would cut this ALE by a proportional amount. This is the clearest quantitative argument in the entire risk register for prioritizing segmentation first.
