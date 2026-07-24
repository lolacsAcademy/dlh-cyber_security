# Task 3 — The 72-Hour Plan

## Tier 1 — Tonight (0–12 hours)

**Action:** Physically disconnect NAS-01 from the network (backup isolation)
Phase Blocked: Phase 5 — Backup Destruction
Owner: IT staff member 1
Prerequisites: None
Risk of Action: Brief interruption to the current backup job
Risk of Inaction: Backups destroyed alongside production — total data loss if compromised tonight

**Action:** Review FortiGate logs for IOCs (unusual CLI commands, VPN session anomalies)
Phase Blocked: Phase 1/2 — Initial Access, Internal Recon (detection)
Owner: Sarah
Prerequisites: None
Risk of Action: Minimal — read-only
Risk of Inaction: Ongoing compromise stays undetected

**Action:** Disable all dormant/inactive VPN and AD accounts
Phase Blocked: Phase 2/3 — Recon, Lateral Movement (attack surface reduction)
Owner: IT staff member 2
Prerequisites: None
Risk of Action: Could disable a rarely-used but legitimate account
Risk of Inaction: Retained accounts remain usable credentials for the attacker

**Action:** Enable MFA on all available admin/VPN accounts using existing O365 licenses
Phase Blocked: Phase 2/3 — credential-based recon and lateral movement (does not stop Phase 1 itself — CVE-2023-27997 is pre-auth)
Owner: IT staff member 2
Prerequisites: Dormant account cleanup (above) done first
Risk of Action: Admin lockout risk if misconfigured overnight
Risk of Inaction: Credential-based lateral movement path stays open

**Action:** Block outbound traffic to known Crimson Tide IOCs (Tor C2 IP, mega.nz if not business-critical) at the firewall
Phase Blocked: Phase 4 — Data Exfiltration
Owner: Sarah
Prerequisites: None
Risk of Action: Minimal — may affect mega.nz if used for legitimate business (unlikely)
Risk of Inaction: Exfiltration path via Rclone/cloud storage stays open
## Tier 2 — Tomorrow (12–36 hours)

**Action:** Board approves FortiGate support contract renewal ($2,400)
Phase Blocked: Phase 1 — Initial Access (unlocks the fix)
Owner: James / Board
Prerequisites: 9:00 AM Board meeting
Risk of Action: None — budget approval only
Risk of Inaction: FortiGate stays unpatchable; the entry point for the entire chain remains open

**Action:** Patch FortiOS off 7.0.9, or disable SSL-VPN entirely as an interim stopgap if patching can't complete same-day
Phase Blocked: Phase 1 — Initial Access
Owner: External vendor (Fortinet support) + Sarah
Prerequisites: Contract renewal approved (above)
Risk of Action: VPN downtime for all 3 sites during the patch/reboot window; disabling SSL-VPN cuts remote access entirely
Risk of Inaction: The single entry point every other phase depends on stays exploitable

**Action:** Verify integrity of the last known-good backup on the now-isolated NAS-01
Phase Blocked: Phase 5 — Backup Destruction (residual risk — confirms the isolated backup is actually usable)
Owner: IT staff
Prerequisites: Tier 1 physical disconnect complete
Risk of Action: Minimal
Risk of Inaction: False confidence in an untested or incomplete backup

**Action:** Present the 72-hour plan and Security Strategy acceleration ask to the Board
Phase Blocked: N/A — governance action enabling Tier 2/3 budget
Owner: James / You
Prerequisites: Tier 1 status confirmed
Risk of Action: None
Risk of Inaction: No funded path to Tier 3 actions
## Tier 3 — This Week (36–72 hours)

**Action:** Begin emergency segmentation — isolate the Server VLAN from Workstation/Medical Device zones as a rushed partial version of the planned architecture (T14)
Phase Blocked: Phase 3 — Lateral Movement (partially addresses Phase 6, per 1x03's own Management Zone caveat)
Owner: External vendor + Sarah
Prerequisites: Board budget approval (Tier 2), switch procurement/configuration (2–3 days minimum)
Risk of Action: Misconfigured VLANs could break clinical device connectivity; needs testing
Risk of Inaction: The flat network — root cause behind 4 of 5 of MedDefense's original kill chains — stays fully open

**Action:** AD Kerberos hardening — disable RC4/DES, enforce AES-only, during a scheduled maintenance window
Phase Blocked: Phase 3 — Lateral Movement (Kerberoasting)
Owner: Sarah + James sign-off
Prerequisites: Dedicated maintenance window, communicated downtime, tested rollback plan
Risk of Action: Hospital-wide authentication outage if misconfigured — the highest-risk single action in this plan
Risk of Inaction: Kerberoasting via RC4 stays viable for DC compromise

**Action:** Deploy EDR to highest-priority assets first (DCs, FortiGate management host, ehr-db-01, billing-srv-01) instead of the full ~330-endpoint rollout
Phase Blocked: Phase 4/6 — partial detection on exfiltration and deployment
Owner: Sarah + IT staff, vendor-assisted
Prerequisites: EDR licensing already funded (T8); accelerated partial deployment vs. original Month-4 target
Risk of Action: Minimal — mainly staff time
Risk of Inaction: No endpoint-level detection during the highest-risk window
## Resource Conflict Assessment

With only 3 people covering Tier 1 tonight, the 5 actions cannot all run in parallel. Resolution: one IT staffer handles the NAS-01 disconnect alone (fast, no coordination needed); Sarah takes FortiGate log review and the firewall block; the second staffer handles dormant-account cleanup then MFA rollout, in that order, since both touch AD and should not run simultaneously without coordination.

Sarah is also the single point of contact for both the Tier 1 FortiGate log review tonight and the Tier 2 FortiGate patch/SSL-VPN decision tomorrow — she cannot do that and present to the Board at the same time, so James presents at 9:00 AM while Sarah stays on the technical response.

The Tier 1 AD changes (dormant accounts, MFA) and the Tier 3 AD Kerberos hardening both touch the same authentication system. They are intentionally not scheduled together — Kerberos changes wait for a dedicated maintenance window specifically to avoid stacking two authentication-breaking risks in the same night.
