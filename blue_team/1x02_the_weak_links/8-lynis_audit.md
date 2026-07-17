# Task 8 — The Self-Audit

## Part 1: Install and Run

Lynis 3.1.6 was already installed on the Kali machine (confirmed via `sudo apt install lynis -y`). Full audit run via `sudo lynis audit system` — 269 tests performed.

## Part 2: Analyze Results

### 1. Hardening Index

**60 / 100**

### 2. Warnings

A note on accuracy first: Lynis's own final summary read "Great, no warnings" — the formal Warnings section returned zero items. Only two individual checks were flagged WARNING inline during the scan, and neither was escalated into the final Warnings list. Rather than inventing three more to reach five, here are the two real ones, followed by three high-value Suggestions substituted in transparently (clearly labeled as Suggestions, not Warnings):

1. **Permissions for /etc/sudoers.d [WARNING]** — Lynis checks that the directory holding sudo privilege files is tightly restricted. Loose permissions here could let a non-privileged user read or tamper with sudo rules. Remediation: chmod 750 /etc/sudoers.d and confirm root:root ownership.
2. **Permissions of home directories [WARNING]** — Home directories often contain SSH keys and shell history; if too permissive, other local users can read them. Remediation: chmod 700 on each user's home directory.
3. **(Suggestion, substituted) No active firewall [FIRE-4590]** — host-based firewall was NOT ACTIVE and no iptables module was found. On a machine running an exposed web server, this is a meaningful gap.
4. **(Suggestion, substituted) No malware scanner installed [HRDN-7230]** — no tool like rkhunter/chkrootkit/OSSEC present, so no periodic detection of rootkits or malware.
5. **(Suggestion, substituted) auditd not enabled [ACCT-9628]** — no audit logging framework running, meaning file access/change auditing isn't happening at the OS level.

### 3. Top 5 Suggestions

1. **Install fail2ban [DEB-0880]** — automatically bans hosts after repeated authentication failures, mitigating brute-force attacks.
2. **Install a PAM password-strength module (pam_cracklib/pam_passwdqc) [AUTH-9262]** — currently no enforcement of password complexity at the PAM layer.
3. **Configure password aging (min/max) in /etc/login.defs [AUTH-9286]** — passwords currently never expire or rotate.
4. **Set a GRUB bootloader password [BOOT-5122]** — without one, anyone with physical/console access can boot into single-user mode with no authentication.
5. **Install Apache mod_security / mod_evasive [HTTP-6643 / HTTP-6640]** — the running Apache instance has no web application firewall or anti-brute-force module loaded.

### 4. Category Breakdown

**Strongest categories:** Users/Groups/Authentication (mostly OK — unique UIDs, password file consistency, no locked/expired-password issues) and Memory/Processes (fully clean, no zombie processes).

**Weakest categories:**
- **Kernel Hardening** — over a dozen sysctl values marked DIFFERENT from the hardened baseline (dmesg_restrict, kptr_restrict, modules_disabled, sysrq, bpf_jit_harden, several IPv4/IPv6 redirect and rp_filter settings).
- **Security frameworks** — both AppArmor and SELinux are present but DISABLED; no Mandatory Access Control framework active at all.
- **Software: firewalls** — no active host firewall.
- **Software: file integrity / malware** — no integrity-checking tool, no malware scanner.
- **Accounting** — auditd not installed, sysstat disabled.

This tells a consistent story: basic OS/user hygiene is solid, but every proactive defensive layer — kernel hardening, MAC enforcement, firewall, malware detection, audit logging — is either disabled or never installed. That pattern (clean defaults, no hardening applied on top) matches a Hardening Index of 60: functional but not actively defended.

## Part 3: MedDefense Projection — billing-srv-01

Without direct access, based on what's already confirmed about this host (Ubuntu 18.04 EOL, Apache 2.4.29, MySQL bound 0.0.0.0, SSH password auth enabled, prior ransomware + cryptominer compromise per the Asset Registry), Lynis would likely flag:

1. **SSH password authentication enabled** — this is already confirmed as Finding 009 in the scan report; Lynis's AUTH checks would flag this directly, along with likely missing MaxAuthTries limits.
2. **Large volume of outdated/vulnerable packages** — Ubuntu 18.04 is past standard support with ESM not enrolled (Finding 011); Lynis's package checks would likely surface many more unpatched packages than a supported system.
3. **No malware scanner installed [HRDN-7230]** — given this host was compromised twice before (ransomware, then a cryptominer per the Asset Registry), the absence of any listed remediation suggests this gap likely still exists.
4. **No active host firewall [FIRE-4590]** — consistent with Finding 006 (MySQL bound to 0.0.0.0) and Finding 003-style exposures already found network-wide on this host.
5. **Suspicious cron entries or unusual file permissions** — Lynis frequently flags cron and file-permission anomalies on previously-compromised hosts; given two prior compromises, remnants of that history (leftover cron jobs, altered permissions) are a reasonable expectation here.
