# 2x00 - Locking the Gates

## Task 0
`0-baseline_snapshot.sh` - baseline system state.
Usage: `sudo ./0-baseline_snapshot.sh`

## Task 1
`1-cis_profile.sh` - generates `cis_profile.json`, 15 CIS controls.
Usage: `./1-cis_profile.sh`
## Task 2
`2-lynis_parse.sh` - parses lynis-report.dat into JSON (hardening_index + findings).
Usage: `sudo ./2-lynis_parse.sh /var/log/lynis-report.dat | jq '.' > lynis_findings.json`
## Task 3
`3-remediation_queue.sh` - builds gap_analysis.json (15 controls status) and remediation_queue.json (12 items, priority sorted).
Usage: `./3-remediation_queue.sh`
## Task 4
`4-ssh_hardening.sh` - hardens sshd_config (11 settings), creates banner, validates with sshd -t, restarts SSH.
Usage: `sudo ./4-ssh_hardening.sh`
## Task 5
`5-sysctl_hardening.sh` - applies 14 kernel/network sysctl hardening params, verifies each via /proc/sys.
Usage: `sudo ./5-sysctl_hardening.sh`
## Task 6
`6-filesystem_hardening.sh` - audits SUID/SGID vs whitelist, fixes world-writable files, hardens /tmp /var/tmp /dev/shm mounts, restricts cron.
Usage: `sudo ./6-filesystem_hardening.sh`
## Task 7
`7-service_minimization.sh` - compares enabled services against MedDefense whitelist. Runs dry-run by default for safety; --apply enforces.
Usage: `sudo ./7-service_minimization.sh`
## Task 8
`8-pam_hardening.sh` - configures pwquality (minlen 14), pam_faillock lockout (5/900s), password history (remember 12). Backs up PAM files first.
Usage: `sudo ./8-pam_hardening.sh`
## Task 9
`9-apparmor_config.sh` - checks AppArmor status, switches Apache/MySQL to enforce, creates custom billing-app profile, reports unconfined processes.
Usage: `sudo ./9-apparmor_config.sh`
## Task 10
`10-auditd_config.sh` - enables auditd, deploys 14 MedDefense audit rules, verifies load, tests with a live event.
Usage: `sudo ./10-auditd_config.sh`
