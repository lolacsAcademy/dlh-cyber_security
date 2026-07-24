# Task 1 — The CVE Deep Dive

## Part 1: NVD Research — CVE-2023-27997

**Full Description:** A heap-based buffer overflow vulnerability (CWE-122) in FortiOS and FortiProxy SSL-VPN. An unauthenticated, remote attacker can execute arbitrary code or commands via specifically crafted requests to the SSL-VPN portal (pre-authentication, no user interaction required).

**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**CVSS v3.1 Base Score:** 9.8 (Critical)

**CWE Classification:** CWE-122 (Heap-based Buffer Overflow); also tagged CWE-787 (Out-of-bounds Write)

**Affected Products and Versions:**
- FortiOS: 7.2.0–7.2.4, 7.0.0–7.0.11, 6.4.0–6.4.12, 6.0.0–6.0.16
- FortiProxy: 7.2.0–7.2.3, 7.0.0–7.0.9, 2.0.0–2.0.12, 1.2 (all), 1.1 (all)
- MedDefense runs FortiOS 7.0.9 — within the affected 7.0.0–7.0.11 range.

**References:**
- Fortinet PSIRT advisory FG-IR-23-097 (vendor advisory + patches, released June 12, 2023)
- CISA Known Exploited Vulnerabilities (KEV) catalog — listed, named "XORtigate"
- NVD/MITRE CVE record, published June 13, 2023
## Part 2: Exploit Assessment

- **Public Exploit:** Yes. Public PoC/exploit code is available on GitHub (e.g. lexfo/xortigate-cve-2023-27997, delsploit/CVE-2023-27997). No officially merged Metasploit module was confirmed at time of research (a module request was opened but weaponized PoCs already circulate independently).
- **CISA KEV:** Yes — actively exploited in the wild; over 330,000 unpatched internet-facing instances were reported shortly after disclosure.
- **Exploitability Score (1x02 T4 scale):** **5** — weaponized public PoC exists, listed in CISA KEV, confirmed active exploitation (matches this advisory's Crimson Tide campaign).
## Part 3: MedDefense CVSS Contextualization

**Environmental inputs applied:**
- Confidentiality Requirement (CR): High — FortiGate terminates all VPN tunnels (all 3 sites depend on it)
- Integrity Requirement (IR): High — sits on kill chain steps #1–#3 (1x01)
- Availability Requirement (AR): High — sole perimeter defense, no redundancy
- Modified Base Metrics (MAV/MAC/MPR/MUI/MS/MC/MI/MA): unchanged from base — nothing about MedDefense's environment reduces technical exploitability or impact.

**Environmental Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H`

**Adjusted CVSS Score: 9.8 — same as the base score, not higher.**

This is a documented CVSS behavior, not an oversight: per the FIRST CVSS v3.1 specification, raising CR/IR/AR to High cannot increase the Environmental score once the Modified Impact metrics (C/I/A) are already High — the Modified Impact Sub-Score is mathematically capped at its maximum (0.915). MedDefense's base impact was already H/H/H, so the ceiling was already hit.

**What the CVSS number does not capture:** the expired support contract is not an Environmental input — it affects the Remediation Level (a Temporal metric). Practically, it means patching is blocked until the contract is renewed, so MedDefense cannot execute the advisory's #1 recommended action (patch immediately) without an unplanned procurement step first. Combined with zero redundancy on the only perimeter device, this is a 9.8 that MedDefense currently has no fast legitimate path to closing — which is the real business risk, separate from the number itself.
