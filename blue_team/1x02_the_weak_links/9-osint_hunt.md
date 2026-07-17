# Task 9 — The OSINT Hunt

## 1. FortiGate FortiOS

Source: CISA alert, Jan 28 2026 (cisa.gov/news-events/alerts/2026/01/28), and Fortinet advisory FG-IR-26-060. Also checked on nvd.nist.gov.
CVE: CVE-2026-24858
Affected Product: FortiGate 100F (A-17), our perimeter firewall and VPN
Why the Scan Missed It: The scan never touched the firewall itself, only servers and endpoints. This CVE also came out in January 2026, so it wouldn't show up unless someone checked separately.
CVSS / Severity: 9.8, Critical. On CISA's active exploitation list.
MedDefense Impact: This lets someone log into our firewall without real credentials, through a flaw in FortiCloud SSO. Since the VPN rules on this same device are already too loose (from Task 4), a compromise here could open up the whole network.
Recommendation: Check if FortiCloud SSO is turned on for our FortiGate, patch it now if so, and look for signs of unauthorized admin accounts or config changes.

## 2. Microsoft 365 / Entra ID

Source: The Hacker News, July 2026
CVE: None — this is a technique, not a numbered CVE
Affected Product: Our O365 E3 tenant, org-wide
Why the Scan Missed It: Cloud services were never in scope for this scan (stated in the methodology notes).
CVSS / Severity: No CVSS score. Currently active, and healthcare is one of the sectors being targeted.
MedDefense Impact: Attackers call staff and talk them into registering a fake security "passkey," which then gives the attacker ongoing access to that account, no password needed. With our whole org on O365, any employee's inbox could be at risk this way.
Recommendation: Warn staff about this specific scam (not just generic phishing), check Entra sign-in logs for odd passkey registrations, and think about upgrading to Entra ID P2 for better risk detection.

## 3. Synology DSM 7

Source: GBHackers article, also confirmed on nvd.nist.gov
CVE: CVE-2024-10441
Affected Product: NAS-01 (A-10), our backup storage running DSM 7
Why the Scan Missed It: The scan saw the DSM login page was open (that's Finding 015) but didn't check which exact version it's running, so it couldn't catch this.
CVSS / Severity: 9.8, Critical. No login needed to exploit it.
MedDefense Impact: This is our backup server — the one thing meant to save us if ransomware hits again. If it's on an old DSM build, and the interface is already open network-wide, this is a real path to losing our last line of defense.
Recommendation: Check the exact DSM version on NAS-01 and patch if it's below 7.2.2-72806-1. Also fix the network exposure from Finding 015 either way.
