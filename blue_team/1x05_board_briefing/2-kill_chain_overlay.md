# Task 2 — The Kill Chain Overlay

## Part 1: The Overlay — Kill Chain #1 vs. Crimson Tide

| MedDefense Kill Chain #1 (1x01 T10) | Crimson Tide Phase (Advisory) | Match? |
|---|---|---|
| Step 1 — Initial Access: VPN exploit via permissive FortiGate 100F rules | Phase 1 — Initial Access: CVE-2023-27997 on the FortiGate | Accurate. We correctly named the FortiGate/VPN as the top access vector before this CVE existed. |
| Step 2 — Foothold: recon of AD/backups, enabled by no SIEM/EDR and a flat network | Phase 2 — Internal Recon: VPN credential capture + routing table dump from the compromised FortiGate itself | Partially accurate. We predicted the *outcome* (recon reaching AD/backups) but not the specific mechanism — Crimson Tide recons from inside the FortiGate device before ever touching AD. |
| Step 3 — Lateral Movement: credential harvest (LSASS), targets DCs, enabled by flat network | Phase 3 — Lateral Movement: RDP/SSH/WMI with captured creds, Kerberoasting (RC4 tickets), flat network | Accurate on the enabler (flat network), inaccurate on technique. We modeled LSASS dumping; the real chain also uses Kerberoasting — a credential-theft path we didn't name. |
| Step 4 — Objective Execution: neutralize backups, deploy ransomware via GPO | Phase 5 — Backup Destruction + Phase 6 — Ransomware Deployment via GPO | Accurate — this step matches almost exactly, including the GPO deployment mechanism. |
| (not modeled as a distinct step) | Phase 4 — Data Exfiltration (15–65GB before encryption) | **Gap.** Our model treated data loss as a byproduct of encryption (an availability-first view). Crimson Tide exfiltrates first, deliberately, for double extortion — a distinct confidentiality-breach action our kill chain never separated out. |
| Step 5 — Impact: clinical, financial, regulatory, reputational | Phase 7 — Extortion: ransom demand + leak-site threat, direct exec contact, 96-hour deadline | Partially accurate. Our impact categories are correct, but we modeled impact as a passive consequence, not as an active, timed adversary phase with its own tactics (leak site, executive contact channels). |

**Summary:** 3 of 5 steps landed close to the real chain. The clearest miss is that our model was encryption-centric (single extortion) while Crimson Tide is exfiltration-first (double extortion) — that's a structural gap in the threat model, not just a missed detail.

## Part 2: Control Interception Map

Phase 1 (Initial Access) | MFA on VPN/admin accounts (T8) | Funded, rollout target Month 2 | No — CVE-2023-27997 is pre-authentication; MFA is never reached
Phase 2 (Internal Recon) | SIEM / log monitoring | Deferred, not funded this cycle | No — no detection layer currently funded
Phase 3 (Lateral Movement) | Network segmentation, 5 VLANs (T14) | Funded, target Month 4 | Yes — explicitly named in 1x03 as breaking Kill Chain 1 at this step, once deployed
Phase 4 (Data Exfiltration) | EDR upgrade, all endpoints (T8) | Funded, target Month 4 | Partially — may flag Rclone as anomalous behavior, but no dedicated DLP/DB-egress control is funded
Phase 5 (Backup Destruction) | Isolated/immutable backup replication (T8) | Funded, first in dependency chain | Yes — directly counters shadow-copy/NAS deletion, once live
Phase 6 (Ransomware Deploy) | Network segmentation (Management Zone) | Funded, but flagged incomplete | Partially — 1x03's own Red Team finding (T15) states this chain stays viable through the Management Zone even with full deployment
Phase 7 (Extortion) | None | Not funded / not addressed | No — no technical control in the strategy targets extortion; this needs the not-yet-written Incident Response Plan

## Part 3: The Gap Between Plan and Reality

Even with the 1x03 Security Strategy fully implemented, only 2 of the 7 Crimson Tide phases would be fully blocked (Lateral Movement via segmentation, Backup Destruction via isolated backups); 2 more would be partially disrupted (Data Exfiltration, Ransomware Deployment); and 3 would still succeed outright — critically, Phase 1 itself, since MFA (the strategy's #1 priority control) cannot stop a pre-authentication RCE that never reaches a login prompt. This means the fully-funded strategy would not have prevented this specific advisory from playing out at MedDefense; it would have contained the blast radius and protected recovery capability, but the attacker still gets in, still recons, and still has a viable extortion path. The residual risk isn't hypothetical — it's the same gap 1x03's own Red Team assessment (T15) already flagged: segmentation controls lateral spread but doesn't close initial access or the Management Zone, and nothing in the funded control set touches detection (deferred SIEM) or extortion response (no IR plan yet). Full strategy implementation buys resilience, not prevention, against this specific advisory.
