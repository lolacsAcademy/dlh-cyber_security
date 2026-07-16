# Task 1 — The CVE Ecosystem

## CVE 1 — Critical (Finding 001)

CVE ID: CVE-2021-44790
NVD URL: https://nvd.nist.gov/vuln/detail/CVE-2021-44790
Description: A buffer overflow in Apache's mod_lua module. When mod_lua is loaded, a specially crafted request body sent to the server can overflow a buffer in the multipart body parser, which could let an attacker run their own code on the server without logging in.
Affected Products: Apache HTTP Server (versions up to and including 2.4.51), Debian Linux 10 and 11, Fedora 34/35/36
CVSS v3.1 Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS Base Score: 9.8 (Critical)
CWE: CWE-787 — Out-of-bounds Write
References:
  - http://httpd.apache.org/security/vulnerabilities_24.html — Vendor Advisory
  - http://packetstormsecurity.com/files/171631/Apache-2.4.x-Buffer-Overflow.html — Exploit
  - https://www.debian.org/security/2022/dsa-5035 — Third Party Advisory
Published Date: 12/20/2021
Last Modified: 05/01/2025
## CVE 2 — High (Finding 008)

CVE ID: CVE-2021-34527
NVD URL: https://nvd.nist.gov/vuln/detail/CVE-2021-34527
Description: Known as PrintNightmare. The Windows Print Spooler service does not properly check privileges when performing certain file operations, so an attacker able to reach it can get the service to run their own code with full SYSTEM rights.
Affected Products: Windows 10 (multiple builds), Windows Server 2019, Windows Server 2016, Windows 7, Windows 8.1
CVSS v3.1 Vector String: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
CVSS Base Score: 8.8 (High)
CWE: NVD-CWE-noinfo (Insufficient Information — NVD did not assign a specific CWE)
References:
  - https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-34527 — Vendor Advisory / Patch / Mitigation
  - http://packetstormsecurity.com/files/167261/Print-Spooler-Remote-DLL-Injection.html — Exploit
  - https://www.kb.cert.org/vuls/id/383432 — Third Party Advisory / US Government Resource
Published Date: 07/02/2021
Last Modified: 12/17/2025
Note: This CVE is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog, added 11/03/2021.
## CVE 3 — Medium in this scan (Finding 020)

CVE ID: CVE-2023-38408
NVD URL: https://nvd.nist.gov/vuln/detail/CVE-2023-38408
Description: A flaw in OpenSSH's ssh-agent PKCS#11 feature. If a user forwards their SSH agent to a system controlled by an attacker, that attacker can trick the agent into loading a malicious library from the local system, resulting in code execution on the user's machine.
Affected Products: OpenSSH (versions before 9.3), Fedora 37, Fedora 38
CVSS v3.1 Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS Base Score: 9.8 (Critical, per NIST and CISA-ADP on NVD)
CWE: CWE-428 — Unquoted Search Path or Element
References:
  - https://www.openssh.com/security.html — Vendor Advisory
  - https://blog.qualys.com/vulnerabilities-threat-research/2023/07/19/cve-2023-38408-remote-code-execution-in-opensshs-forwarded-ssh-agent — Exploit / Third Party Advisory
  - https://github.com/openbsd/src/commit/f03a4faa55c4ce0818324701dadbf91988d7351d — Patch
Published Date: 07/19/2023
Last Modified: 11/21/2024
Note: The scan report rated this finding Medium and flagged it as a possible false positive requiring manual
## Questions

### 1. What is the structure of a CVE ID?
Format: CVE-YYYY-NNNNN. YYYY is the year the ID was assigned by a CNA (not necessarily the year the flaw was discovered or published — an ID can be reserved in one year and published later). NNNNN is a sequence number with a minimum of 4 digits, which can extend to more digits as needed; it does not indicate severity or order of discovery, only assignment order.

### 2. What is a CNA (CVE Numbering Authority) and what role does it play?
A CNA is an organization authorized by the CVE Program to assign official CVE IDs to vulnerabilities and publish the initial CVE record for products within its scope. CNAs include software vendors (e.g., Microsoft, Apache Software Foundation), security researchers, and MITRE itself, which acts as the CNA of last resort when no other CNA covers a product.

### 3. What lifecycle states can a CVE have?
- Reserved: A CNA has allocated the ID, but no public details exist yet. Reserved records do not appear in the NVD dataset.
- Published: A CNA has filled in the CVE record (description, references) and it is now public.
- Rejected: The CVE ID is withdrawn and should no longer be used — reasons include being a duplicate of another CVE, being withdrawn by the requester, or being assigned incorrectly. The record stays visible so people know the ID is invalid.

### 4. One CVE with status "Rejected"
CVE ID: CVE-2021-44575
NVD URL: https://nvd.nist.gov/vuln/detail/CVE-2021-44575
Why it was rejected: It is a duplicate of CVE-2021-3200. NVD's rejected-reason text states this candidate should not be used and that all references and the original description were removed to prevent accidental use; users are told to reference CVE-2021-3200 instead.
