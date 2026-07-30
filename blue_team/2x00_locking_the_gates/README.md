# 2x00 - Locking the Gates

Infrastructure hardening for billing-srv-01, web-srv-01, log-srv-01 (MedDefense, Crimson Tide Phase 2). Scripts are the deliverable, idempotent, re-executable.

## Task 0 - Baseline Snapshot
`0-baseline_snapshot.sh` - captures pre-hardening state: hostname/OS/kernel/uptime, running services, open ports, SUID/SGID binaries, world-writable files, sysctl security params, SSH config, users/sudo group.

Output: `baseline_output/` (raw lists) + `baseline_output/baseline.json` (summary)

Usage: `sudo ./0-baseline_snapshot.sh`
