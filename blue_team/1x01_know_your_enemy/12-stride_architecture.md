# STRIDE Across the Architecture — MedDefense

## System: PACS / Medical Imaging
Architecture Notes: pacs-srv-01 (Windows Server 2016, ports 135/445/4242/11112) + WS-RAD-01 (Windows XP, EOL) + radiology workstations, all on flat 10.10.1-2.0/24. Shared login raduser/radiology1.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| S | Shared login lets anyone spoof any technician with zero attribution | No accountability for who viewed/altered studies | C |
| T | Unpatched XP MRI workstation tampered with (firmware/output) | Falsified/corrupted imaging data used for diagnosis | H |
| R | Shared login means no action can be proven to one person | Legal/clinical accountability failure | H |
| I | SMB/DICOM reachable network-wide, unencrypted image data exposed | Mass exposure of Restricted medical imaging data | C |
| D | pacs-srv-01 excluded from all backups (GAP-002) | Diagnostic capability halted, no recovery path | C |
| E | Shared account has fixed privilege regardless of actual user role | Over-privileged access by design | H |

Top Threat: Denial of Service — pacs-srv-01 has zero corrective control (GAP-002), so an outage isn't downtime, it's permanent unrecoverable loss of imaging data.

## System: Active Directory
Architecture Notes: ad-dc-01 (primary) + ad-dc-02 (secondary, no backup — GAP-004), ports 53/88/135/389/636, no MFA confirmed.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| S | Harvested creds (LSASS dump/Kerberoasting) used to impersonate a trusted account | Unauthorized org-wide access under a trusted identity | C |
| T | Domain Admin used to tamper with GPOs (BlackReef's own ransomware-push method) | Malicious changes pushed to every managed endpoint at once | C |
| R | No MFA — a compromised account's actions can't be told apart from the real user's | Unclear attribution during incident response | H |
| I | LDAP (389, unencrypted) sniffable on flat network | Credential/org-structure disclosure | H |
| D | ad-dc-02 has no backup (GAP-004) | Org-wide authentication outage if both DCs lost | C |
| E | Weak MFA + flat network = easy path from one workstation to Domain Admin | Full administrative control of the organization | C |

Top Threat: Elevation of Privilege — AD is the single highest-value pivot (T6/T9); once Domain Admin is reached, every other threat across the org becomes trivial.
## System: Network Infrastructure
Architecture Notes: FortiGate 100F (sole perimeter, VPN rules too permissive) + Westside consumer Netgear router (also runs site-to-site VPN) + zero internal segmentation.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| S | VPN client/endpoint impersonated using stolen creds — rules documented as too permissive | Unauthorized entry indistinguishable from legit remote access | C |
| T | Westside consumer router firmware tampered with/backdoored | Persistent, invisible compromise of the Westside VPN tunnel | H |
| R | Consumer router likely lacks enterprise logging | Undetectable network-level compromise at Westside | M |
| I | FortiGate is the sole boundary device — misconfig exposes full network topology | Full network blueprint exposure to an attacker | H |
| D | FortiGate is a single point of failure for all connectivity org-wide | Total loss of network availability across every site | C |
| E | Zero internal segmentation means any foothold has admin-level reach already | Privilege escalation is effectively unnecessary — flat access = full access | C |

Top Threat: Elevation of Privilege (via absent segmentation) — in a flat network no real "elevation" is needed; one foothold anywhere already has full reach, the root cause behind nearly every other finding in this project.
