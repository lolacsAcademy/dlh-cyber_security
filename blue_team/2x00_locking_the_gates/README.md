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
