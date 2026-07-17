# Task 13 — The Web Exposure

## Host 1: web-srv-01 (10.10.2.50)

Host: web-srv-01, 10.10.2.50
Exposure: Internet-facing — public website and patient portal, sits in the DMZ (A-11)
Findings: Finding 005 (TLS 1.0 supported, BEAST/POODLE), Finding 012 (missing security headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, X-XSS-Protection), Finding 013 (SSL certificate expires in 23 days), Finding 021 (HTTP TRACE method enabled)
Combined Risk: No single finding here is Critical, but together they strip away nearly every layer of defense-in-depth a public web app normally relies on: weak transport encryption, no clickjacking/XSS/MIME-sniffing protection, an expiring cert, and a TRACE method that enables credential theft via Cross-Site Tracing when paired with any XSS bug.
Attack Scenario: An attacker intercepts a patient's session over TLS 1.0, or exploits an XSS flaw (easier without CSP) combined with HTTP TRACE to steal session cookies directly from patient browsers — full account takeover on the portal, entirely from the outside. None of the five 1x01 kill chains name this host directly, which is itself worth flagging as a gap in the existing threat model.
Priority: Highest of this group — the only truly internet-facing host, directly touching patient data and login credentials, with four weaknesses stacking simultaneously.

## Host 2: ehr-srv-01 (10.10.2.10)

Host: ehr-srv-01, 10.10.2.10
Exposure: Internal but flat network accessible — no segmentation from the rest of 10.10.2.0/24
Findings: Finding 017 (Tomcat default error page info disclosure), Finding 031 (Ghostcat, CVE-2020-1938, CVSS 9.8, KEV-listed)
Combined Risk: Critical — Finding 017 is what revealed the exact Tomcat version and AJP port that led directly to confirming Finding 031, a weaponized file-read vulnerability on the organization's Critical-rated EHR application server.
Attack Scenario: Matches Kill Chain 1 and Kill Chain 5's "reach EHR" step (from Task 10): an attacker reads the exposed error pages to fingerprint the Tomcat version, exploits Ghostcat to pull configuration files, extracts database credentials, and pivots directly into Finding 003's exposed PostgreSQL database.
Priority: Second — not internet-facing, but the flat network means any other compromised host reaches it instantly, and the payoff (full EHR data access) is the single highest-value target in the report.

## Host 3: billing-srv-01 (10.10.2.15)

Host: billing-srv-01, 10.10.2.15
Exposure: Internal but flat network accessible
Findings: Finding 001 (Apache mod_lua buffer overflow, CVE-2021-44790, CVSS 9.8), Finding 002 (Apache privilege escalation, CVE-2019-0211, CVSS 7.8)
Combined Risk: Critical — the scan report itself confirms these chain together: remote code execution as www-data via Finding 001, then privilege escalation to root via Finding 002, full system compromise from one web flaw.
Attack Scenario: This is Kill Chain 3 exactly ("Vulnerable Software → billing-srv-01 Compromise," actor Unskilled/Opportunistic, GAP-003) — a pattern that has already played out twice on this exact host per the Asset Registry.
Priority: Third — the chain is fully weaponizable and reaches root, but Billing's asset criticality (High) ranks below the EHR system (Critical), placing it just behind Host 2.

## Host 4: NAS-01 (10.10.2.41)

Host: NAS-01, 10.10.2.41
Exposure: Internal but flat network accessible
Findings: Finding 015 (Synology DSM web interface reachable network-wide, backups stored unencrypted)
Combined Risk: High — on its own a network-exposure issue, but combined with CVE-2024-10441 (found separately via Task 9 OSINT, not in the original scan), this internal web interface is a real path to remote code execution on the backup server.
Attack Scenario: Ties to the "immutable backup" break point named in Kill Chain 1 and Kill Chain 5 — an attacker reaching this interface from any compromised internal host could destroy backups to block recovery from a ransomware event elsewhere.
Priority: Fourth — high potential impact given Backup's Critical asset rating, but the scan's own finding alone is exposure, not a confirmed exploit path without the separately-sourced CVE.

## Host 5: Philips IntelliVue Monitors (10.10.3.10-32)

Host: Philips IntelliVue monitors, 10.10.3.10-32 (13 devices)
Exposure: Internal but flat network accessible — medical device subnet with no VLAN isolation
Findings: Finding 016 (HTTP/HL7 management interfaces exposed network-wide, no authentication beyond the network layer)
Combined Risk: High — a standalone finding, but on patient-safety-critical devices; unauthorized access to monitor configuration could affect vital sign monitoring.
Attack Scenario: No CVE is attached, and no kill chain names this host directly, but it fits the same flat-network exploitation pattern as the rest of the report — 13 monitors exposed at once from a single foothold anywhere on that subnet.
Priority: Fifth — a genuine patient-safety concern, but ranked below the hosts above since there's no confirmed exploit path, only exposed interfaces.

## Host 6: Unknown Device — Westside Clinic (10.10.10.200)

Host: Unidentified Linux host, 10.10.10.200 (Grafana)
Exposure: Internal but flat network accessible — sitting behind Westside's weak consumer-grade perimeter router (Finding 014), which somewhat elevates this host's real-world exposure beyond a typical internal system
Findings: Finding 029 (Grafana 8.2.0, CVE-2021-43798 path traversal, CVSS 7.5, publicly available trivial exploit)
Combined Risk: High — a real, weaponized, unauthenticated file-read CVE on a completely undocumented device.
Attack Scenario: An attacker who compromises Westside's consumer router (Finding 014) or otherwise reaches that site's network finds this undocumented Grafana instance and reads arbitrary files via CVE-2021-43798 — since it's shadow IT, it could go undetected far longer than any inventoried asset.
Priority: Sixth — genuinely dangerous, but lowest priority here only because it sits at the smaller Westside site rather than Central's core infrastructure, and no kill chain names it.

## Why Investigate "Medium" Findings

Finding 017 was rated Medium and, on its own, only revealed a Tomcat version number and flagged that the scanner couldn't confirm whether the AJP connector was active. SecurePoint manually followed up on that uncertainty and found Ghostcat — a CVSS 9.8, KEV-listed vulnerability the automated scan had otherwise missed entirely. This shows that severity ratings measure a finding in isolation, not its investigative value: a low-effort, Medium-rated information disclosure can be the exact clue that unlocks a Critical finding hiding just out of the scanner's reach. Any finding explicitly flagged as "manual verification recommended," like Finding 017, is effectively the scanner telling the analyst where it hit the limit of what it could confirm on its own — dismissing those because of their Medium label means potentially leaving a Critical vulnerability undiscovered.
