# Task 17 — Certificate Lifecycle Management

MedDefense Health Systems — 1x04 Task 17

## 1. Certificate Inventory

| Certificate | Current Issuer | Expiration (Estimate) | Responsible Owner |
|---|---|---|---|
| Patient portal (portal.meddefense.local) | Let's Encrypt (T0 audit notes) | ~18 days from current point (Finding 013), 90-day cert, auto-renewal not configured | IT/Sysadmin (James Chen's team) |
| EHR internal (ehr-srv-01 to ehr-db-01) | None currently — ssl=on but not consistently enforced (T0) | N/A — no dedicated certificate in place | DBA / IT |
| VPN tunnels (Central-Westside, Central-HQ) | FortiGate device-managed | Unknown — not yet inventoried | Network admin |
| Email signing (S/MIME) | Not yet implemented (T0/T7 gap) | N/A — not yet issued | IT/Compliance |
| Code signing | Not currently in use at MedDefense | N/A | DevOps, if introduced |

## 2. Auto-Renewal Strategy

Recommendation for the patient portal: commercial OV CA (per T8/T10 profile), automated via ACME where the CA supports it, not free Let's Encrypt.

Justification: Let's Encrypt only offers DV — confirms domain control, not MedDefense's legal identity, insufficient for a healthcare portal handling PHI/payment data. At 800 patient connections/day, an expired cert directly blocks patient access — automation is non-negotiable regardless of CA. Commercial CAs (Sectigo, DigiCert) now support ACME, giving OV validation with the same renewal automation Let's Encrypt is known for.

## 3. Monitoring and Alerting

System: MedDefense has no SIEM/centralized monitoring yet — start with a scheduled cron job checking cert expiry across the inventory, feeding email/calendar alerts, with a path to full CLM tooling as the program matures.

| Threshold | Recipients |
|---|---|
| 90 days | IT/Sysadmin team — routine awareness, begin renewal planning |
| 60 days | IT/Sysadmin + James Chen (Deputy CISO) — confirm renewal in progress |
| 30 days | IT/Sysadmin + James Chen + Sarah Park (IT Director) — escalated priority |
| 7 days | All above, incident-level urgency — immediate action required |

## 4. Certificate Policy (5 rules)

1. All internal services must use certificates signed by the MedDefense internal CA or a trusted public CA. Self-signed certificates are prohibited in production.
2. All publicly-facing certificates handling PHI (e.g. the patient portal) must be OV or higher validation. DV-only certificates are prohibited for these systems.
3. Certificate validity must not exceed the current CA/Browser Forum maximum (200 days as of 2026) — no certificate may be manually issued for a longer period.
4. Every certificate must be recorded in the central certificate inventory before deployment, with a named responsible owner and monitored expiration date.
5. Private keys must never be stored in source control repositories or transmitted over unencrypted channels — directly addressing the key-exposure scenario referenced in Task 9 (1x03 T25).
