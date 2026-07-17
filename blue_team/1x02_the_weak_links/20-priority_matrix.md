# Task 20 — The Priority Matrix

## Immediate (24-48 hours)

| Finding | Description | Action | Owner | Cost |
|---|---|---|---|---|
| 031 | Ghostcat, weaponized KEV RCE on EHR server | Disable/restrict AJP connector | IT | $0-1K |
| 004 | 3 weaponized KEV exploits, EOL MRI workstation | Deploy VLAN + IDS compensating controls | Security | $10-50K |
| 010 | Trivial default credentials on infusion pumps | Change credentials + start isolation | IT | $1-10K |
| 029 | Weaponized public exploit on undocumented device | Patch or remove the shadow IT device | Security | $0-1K |
| 003 | PostgreSQL reachable network-wide, no exploit needed | Restrict pg_hba.conf + firewall rule | IT | $0-1K |

## Short-term (7 days)

| Finding | Description | Action | Owner | Cost |
|---|---|---|---|---|
| 001 | Apache RCE, billing server | Upgrade Apache to 2.4.52+ | IT | $0-1K |
| 002 | Apache privesc, billing server | Bundled with Finding 001's upgrade | IT | $0 |
| 015 | NAS RCE, backup server | Update DSM to fixed build | IT | $0-1K |
| 009 | SSH password auth, repeat-compromised host | Enforce key-based auth | IT | $0-1K |
| 006 | MySQL bound network-wide | Bind to localhost/restrict IPs | IT | $0-1K |
| 011 | No ESM on billing server | Enroll in Ubuntu Pro/ESM | IT | $1-10K |

## Medium-term (30 days)

| Finding | Description | Action | Owner | Cost |
|---|---|---|---|---|
| 007 | LDAP relay/SMBv1 on domain controller | Enable LDAP signing, disable SMBv1 | IT | $0-1K |
| 017 | Tomcat error pages disclose version info | Harden default error pages | IT | $0-1K |
| 018 | Weak Kerberos encryption on DCs | Disable DES/RC4 | IT | $0-1K |
| 016 | Patient monitors exposed network-wide | Network isolation for medical IoT | Security | $1-10K |
| 026 | 47 unpatched kernel CVEs | Resolved automatically once Finding 011 completes | IT | $0 |
| 005 | TLS 1.0 on patient portal | Disable TLS 1.0/1.1 | IT | $0-1K |
| 012 | Missing security headers on portal | Add CSP/HSTS/X-Frame-Options | IT | $0-1K |
| 013 | SSL cert expiring in 23 days | Renew + automate future renewal | IT | $0-1K |
| 021 | HTTP TRACE enabled | Disable TRACE method | IT | $0-1K |
| 019 | RDP enabled unnecessarily on 5 hosts | Disable or restrict RDP | IT | $0-1K |
| 025 | DNS zone transfer open to anyone | Restrict to authorized secondaries | IT | $0-1K |
| 024 | DICOM traffic unencrypted | Enable TLS on DICOM (vendor coordination) | IT | $1-10K |
| 023 | USB mass storage unrestricted, 280 endpoints | Apply GPO restriction | IT | $0-1K |
| 028 | Undocumented device on server subnet | Investigate and formally inventory | Security | $0-1K |

## Long-term (90 days)

| Finding | Description | Action | Owner | Cost |
|---|---|---|---|---|
| 008 | Windows Server 2012 R2, print server | Migrate off EOL OS | IT | $10-50K |
| 014 | Consumer router as Westside perimeter/VPN device | Replace with enterprise firewall | IT | $1-10K |
| 001/002/006/009/011/026 (collectively) | Ubuntu 18.04 EOL root cause on billing-srv-01 | Full OS migration to a supported release (per Task 12's Business Decision) | IT | $10-50K |

## Budget Summary

Using the midpoint of each cost bracket, the total estimated remediation cost across all four horizons is approximately **$120,000-$130,000** — Immediate (~$36.5K), Short-term (~$7K), Medium-term (~$16K), and Long-term (~$65K, dominated by the two EOL migrations). This consumes essentially the entire **$120,000 annual security budget** from 1x00 on its own, leaving no room for other operational security needs across the rest of the year.

Given this, the two Long-term systemic migrations — the Windows Server 2012 R2 print server migration and the full Ubuntu 18.04 billing-srv-01 migration, together roughly $20-100K — should be deferred and spread into next fiscal year's budget rather than funded all at once. Neither meets the Immediate urgency bar (no weaponized exploit currently reaching either fully), and funding them now would crowd out the cheaper, higher-urgency Immediate and Short-term fixes that deliver more risk reduction per dollar. The Immediate and Short-term items together cost only about $43.5K and address every weaponized, KEV-listed, or actively-reachable finding in the report — that tranche should be funded first and in full within this budget cycle.
