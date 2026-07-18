# Task 11 — The Control Selection

MedDefense Health Systems — controls for each "Mitigate" risk in the Task 10 register. RISK-004 (Accept) excluded.

## RISK-001

Risk: RISK-001 — Backup destroyed with production
Selected Control: Offsite backup replication (AWS S3 Glacier)
CIS Control Mapping: Control 11, Safeguard 11.4 (isolated instance of recovery data)
NIST CSF Mapping: RC.RP
Control Type: Corrective
Control Category: Technical
Implementation Cost: $14,400/year
Expected Risk Reduction: ALE $468,300 to $46,830 (~90%)
Dependencies: None — standalone; other backup fixes below build on this.

## RISK-002

Risk: RISK-002 — VPN compromise, no MFA
Selected Control: MFA on VPN and admin accounts
CIS Control Mapping: Control 6, Safeguards 6.3, 6.4, 6.5
NIST CSF Mapping: PR.AA
Control Type: Preventive
Control Category: Technical
Implementation Cost: $4,000/year
Expected Risk Reduction: ALE $375,550 to $53,650
Dependencies: None — O365 E3 licenses already owned; account inventory already exists (1x00).

## RISK-003

Risk: RISK-003 — Ransomware encrypts EHR
Selected Control: Network segmentation, Phase 1 (VLANs)
CIS Control Mapping: Control 12, Safeguard 12.2
NIST CSF Mapping: PR.IR
Control Type: Preventive
Control Category: Technical
Implementation Cost: $25,500/year
Expected Risk Reduction: ALE $370,800 to $111,240
Dependencies: None to start — but foundational for RISK-005 and RISK-006 below.

## RISK-005

Risk: RISK-005 — Undetected malware dwell time
Selected Control: SIEM (Wazuh) — deferred to next fiscal year
CIS Control Mapping: Control 8, Safeguard 8.2; Control 13, Safeguard 13.1
NIST CSF Mapping: DE.CM
Control Type: Detective
Control Category: Technical
Implementation Cost: $30,000/year
Expected Risk Reduction: ALE $106,800 to $53,400
Dependencies: Network segmentation (RISK-003) should land first — defines log zones and scope.

## RISK-006

Risk: RISK-006 — Infusion pump compromise
Selected Control: Default credential reset + medical device network isolation + monitoring
CIS Control Mapping: Control 4, Safeguard 4.7; Control 12, Safeguard 12.2
NIST CSF Mapping: PR.PS
Control Type: Preventive (credentials/isolation), Detective (monitoring)
Control Category: Technical
Implementation Cost: $20,000/year
Expected Risk Reduction: ALE $62,100 to $15,525
Dependencies: Requires network segmentation (RISK-003) — device isolation is a specific case of the same VLAN architecture.

## RISK-007

Risk: RISK-007 — ad-dc-02 no backup
Selected Control: Extend existing backup job to ad-dc-02
CIS Control Mapping: Control 11, Safeguard 11.2
NIST CSF Mapping: RC.RP
Control Type: Corrective
Control Category: Technical
Implementation Cost: ~$2,000/year (from $32,500 reserve)
Expected Risk Reduction: Closes single point of failure in domain auth recovery
Dependencies: Requires the isolated backup infrastructure from RISK-001 — extend to the new isolated target, not the old co-located one.

## RISK-008

Risk: RISK-008 — PACS excluded from backup
Selected Control: Add pacs-srv-01 to backup schedule
CIS Control Mapping: Control 11, Safeguard 11.2
NIST CSF Mapping: RC.RP
Control Type: Corrective
Control Category: Technical
Implementation Cost: ~$2,000/year (from $32,500 reserve)
Expected Risk Reduction: Closes backup gap for imaging data
Dependencies: Requires the isolated backup infrastructure from RISK-001, same as RISK-007.

## RISK-009

Risk: RISK-009 — Shared PACS login
Selected Control: Individual accounts replace shared login
CIS Control Mapping: Control 5, Safeguards 5.1, 5.2
NIST CSF Mapping: PR.AA
Control Type: Preventive
Control Category: Technical
Implementation Cost: ~$3,000/year (from $32,500 reserve)
Expected Risk Reduction: Restores individual accountability for imaging access
Dependencies: None — pairs efficiently with the MFA rollout (RISK-002) but doesn't require it.

## RISK-010

Risk: RISK-010 — Network closet exposure
Selected Control: Camera + keycard audit trail
CIS Control Mapping: No dedicated physical-security control in the 18 CIS Controls provided; closest is Control 12 (network core equipment housed there)
NIST CSF Mapping: PR.AA
Control Type: Preventive (keycard), Detective (camera)
Control Category: Physical
Implementation Cost: $1,600/year (from $32,500 reserve)
Expected Risk Reduction: Closes physical access gap to network core
Dependencies: None — fully independent of every technical control.

---

## Control Dependency Map

Independent — implement anytime, no prerequisites:
  MFA (RISK-002)
  Individual PACS accounts (RISK-009)
  Closet camera + keycard (RISK-010)

Backup infrastructure chain:
  Offsite Backup Replication (RISK-001)
    then Extend backup to ad-dc-02 (RISK-007)
    then Add pacs-srv-01 to backup schedule (RISK-008)

Network architecture chain:
  Network Segmentation, Phase 1 (RISK-003)
    then Medical Device Isolation + Monitoring (RISK-006)
    then SIEM / Wazuh (RISK-005)

Two controls anchor everything else: RISK-001 (backup) must land before its two dependents, and RISK-003 (segmentation) must land before its two dependents. The three independent controls can run in parallel with either chain.
