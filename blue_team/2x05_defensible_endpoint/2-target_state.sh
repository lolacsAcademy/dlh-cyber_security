#!/bin/bash
# apparmor
# overwrite
set -euo pipefail

OUT="capstone/target_state.json"
TMP="${OUT}.tmp"
FORCE=0

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required" >&2
    exit 2
fi

case "${1:-}" in
    "")
        ;;
    --force)
        FORCE=1
        ;;
    *)
        echo "Usage: $0 [--force]" >&2
        exit 1
        ;;
esac

if [ -e "$OUT" ] && [ "$FORCE" -ne 1 ]; then
    echo "ERROR: $OUT already exists." >&2
    echo "Use --force to replace it." >&2
    exit 1
fi

mkdir -p "capstone"

jq -n \
    --arg schema_version "1.0" \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
        schema_version: $schema_version,
        generated_at: $generated_at,

        controls: [

            {
                id: "LNX-SSH-01",
                platform: "linux",
                family: "hardening",
                description: "SSH must prohibit direct root login.",
                check_type: "grep_match",
                check_target: "/etc/ssh/sshd_config",
                expected_value: "^[[:space:]]*PermitRootLogin[[:space:]]+no",
                source_project: "2x05_defensible_endpoint",
                severity: "critical"
            },

            {
                id: "LNX-SSH-02",
                platform: "linux",
                family: "hardening",
                description: "SSH must refuse password authentication.",
                check_type: "grep_match",
                check_target: "/etc/ssh/sshd_config",
                expected_value: "^[[:space:]]*PasswordAuthentication[[:space:]]+no",
                source_project: "2x05_defensible_endpoint",
                severity: "critical"
            },

            {
                id: "LNX-SYSCTL-01",
                platform: "linux",
                family: "hardening",
                description: "IPv4 forwarding must be disabled.",
                check_type: "command_exit_zero",
                check_target: "test \"$(sysctl -n net.ipv4.ip_forward)\" = \"0\"",
                expected_value: 0,
                source_project: "2x00_system_hardening",
                severity: "high"
            },

            {
                id: "LNX-SYSCTL-02",
                platform: "linux",
                family: "hardening",
                description: "Address space layout randomization must be fully enabled.",
                check_type: "command_exit_zero",
                check_target: "test \"$(sysctl -n kernel.randomize_va_space)\" = \"2\"",
                expected_value: 0,
                source_project: "2x00_system_hardening",
                severity: "high"
            },

            {
                id: "LNX-AUDITD-01",
                platform: "linux",
                family: "telemetry",
                description: "The auditd service must be active.",
                check_type: "command_exit_zero",
                check_target: "systemctl is-active --quiet auditd",
                expected_value: 0,
                source_project: "2x02_eyes_on_endpoint",
                severity: "high"
            },

            {
                id: "LNX-APPARMOR-01",
                platform: "linux",
                family: "hardening",
                description: "AppArmor must have profiles operating in enforce mode.",
                check_type: "command_exit_zero",
                check_target: "aa-status --enforced >/dev/null",
                expected_value: 0,
                source_project: "2x00_system_hardening",
                severity: "high"
            },

            {
                id: "LNX-LYNIS-01",
                platform: "linux",
                family: "hardening",
                description: "The Lynis hardening index must be at least 80.",
                check_type: "json_field_gte",
                check_target: "capstone/post_hardening/post_hardening_linux.json:.hardening_index",
                expected_value: 80,
                source_project: "2x05_defensible_endpoint",
                severity: "high"
            },

            {
                id: "WIN-FW-01",
                platform: "windows",
                family: "hardening",
                description: "Windows Firewall must default-deny inbound traffic on every profile.",
                check_type: "json_field_equals",
                check_target: "capstone/post_hardening/post_hardening_windows.json:.windows_firewall.default_inbound_all_profiles",
                expected_value: "Block",
                source_project: "2x05_defensible_endpoint",
                severity: "critical"
            },

            {
                id: "WIN-PSLOG-01",
                platform: "windows",
                family: "telemetry",
                description: "PowerShell Script Block Logging must be enabled.",
                check_type: "json_field_equals",
                check_target: "capstone/post_hardening/post_hardening_windows.json:.powershell_logging.script_block_logging_enabled",
                expected_value: true,
                source_project: "2x02_eyes_on_endpoint",
                severity: "high"
            },

            {
                id: "WIN-SYSMON-01",
                platform: "windows",
                family: "telemetry",
                description: "The Sysmon service must be installed and running.",
                check_type: "json_field_equals",
                check_target: "capstone/post_hardening/post_hardening_windows.json:.sysmon.running",
                expected_value: true,
                source_project: "2x02_eyes_on_endpoint",
                severity: "critical"
            },

            {
                id: "WIN-AUDIT-01",
                platform: "windows",
                family: "telemetry",
                description: "Windows audit policy must cover Account Logon, Logon, Object Access and Privilege Use.",
                check_type: "grep_match",
                check_target: "capstone/post_hardening/windows_audit_policy.log",
                expected_value: "Account Logon|Logon|Object Access|Privilege Use",
                source_project: "2x02_eyes_on_endpoint",
                severity: "high"
            },

            {
                id: "WIN-CIS-01",
                platform: "windows",
                family: "hardening",
                description: "The Windows CIS Level 1 pass rate must be at least 85 percent.",
                check_type: "json_field_gte",
                check_target: "capstone/post_hardening/post_hardening_windows.json:.pass_rate_percent",
                expected_value: 85,
                source_project: "2x05_defensible_endpoint",
                severity: "high"
            },

            {
                id: "TEL-LNX-01",
                platform: "linux",
                family: "telemetry",
                description: "The Linux auditd persistent rules file must exist.",
                check_type: "file_exists",
                check_target: "/etc/audit/rules.d/99-detection-refine.rules",
                expected_value: true,
                source_project: "2x02_eyes_on_endpoint",
                severity: "high"
            },

            {
                id: "TEL-LNX-02",
                platform: "linux",
                family: "telemetry",
                description: "The Linux auditd persistent rules must be loaded.",
                check_type: "command_exit_zero",
                check_target: "auditctl -l | grep -q .",
                expected_value: 0,
                source_project: "2x02_eyes_on_endpoint",
                severity: "high"
            },

            {
                id: "TEL-EXPORT-01",
                platform: "both",
                family: "telemetry",
                description: "The structured telemetry JSON export path must exist.",
                check_type: "file_exists",
                check_target: "capstone/telemetry",
                expected_value: true,
                source_project: "2x05_defensible_endpoint",
                severity: "high"
            },

            {
                id: "TEL-WIN-01",
                platform: "windows",
                family: "telemetry",
                description: "Sysmon must record more than zero events during the last ten minutes.",
                check_type: "json_field_gte",
                check_target: "capstone/telemetry/windows_telemetry.json:.sysmon_events_last_10_minutes",
                expected_value: 1,
                source_project: "2x02_eyes_on_endpoint",
                severity: "high"
            },

            {
                id: "TEL-WIN-02",
                platform: "windows",
                family: "telemetry",
                description: "The PowerShell Script Block Logging event channel must contain data.",
                check_type: "json_field_gte",
                check_target: "capstone/telemetry/windows_telemetry.json:.script_block_log_channel_size",
                expected_value: 1,
                source_project: "2x02_eyes_on_endpoint",
                severity: "high"
            },

            {
                id: "PATCH-INV-01",
                platform: "linux",
                family: "patching",
                description: "The vulnerability inventory artifact must exist.",
                check_type: "file_exists",
                check_target: "vulnerability_inventory.json",
                expected_value: true,
                source_project: "2x03_patch_equation",
                severity: "critical"
            },

            {
                id: "PATCH-PLAN-01",
                platform: "linux",
                family: "patching",
                description: "The patch plan artifact must exist.",
                check_type: "file_exists",
                check_target: "patch_plan.json",
                expected_value: true,
                source_project: "2x03_patch_equation",
                severity: "high"
            },

            {
                id: "PATCH-EXEC-01",
                platform: "linux",
                family: "patching",
                description: "The patch execution log must exist.",
                check_type: "file_exists",
                check_target: "patch_execution_log.json",
                expected_value: true,
                source_project: "2x03_patch_equation",
                severity: "critical"
            },

            {
                id: "PATCH-EXEC-02",
                platform: "linux",
                family: "patching",
                description: "The patch execution log must contain zero failed entries.",
                check_type: "json_field_equals",
                check_target: "patch_execution_log.json:.failed_count",
                expected_value: 0,
                source_project: "2x03_patch_equation",
                severity: "critical"
            },

            {
                id: "PATCH-AUTO-01",
                platform: "linux",
                family: "patching",
                description: "Unattended upgrades must be configured with the mandated package blacklist.",
                check_type: "grep_match",
                check_target: "/etc/apt/apt.conf.d/50unattended-upgrades",
                expected_value: "Package-Blacklist",
                source_project: "2x03_patch_equation",
                severity: "high"
            },

            {
                id: "NET-NFT-01",
                platform: "network",
                family: "network",
                description: "The nftables input chain must use a default-deny policy.",
                check_type: "command_exit_zero",
                check_target: "nft list ruleset | grep -Eq \"hook input.*policy drop|policy drop\"",
                expected_value: 0,
                source_project: "2x04_perimeter_defense",
                severity: "critical"
            },

            {
                id: "NET-SEG-01",
                platform: "network",
                family: "network",
                description: "The segmentation rules artifact must exist.",
                check_type: "file_exists",
                check_target: "segmentation_rules.json",
                expected_value: true,
                source_project: "2x04_perimeter_defense",
                severity: "critical"
            },

            {
                id: "NET-SURI-01",
                platform: "network",
                family: "network",
                description: "The Suricata custom rule file must contain at least six rules.",
                check_type: "command_exit_zero",
                check_target: "test \"$(grep -Ec \"^[[:space:]]*(alert|drop|reject|pass)[[:space:]]\" suricata_custom.rules)\" -ge 6",
                expected_value: 0,
                source_project: "2x04_perimeter_defense",
                severity: "high"
            },

            {
                id: "NET-SURI-02",
                platform: "network",
                family: "network",
                description: "The Suricata validation report must show every custom rule firing against its target PCAP.",
                check_type: "json_field_equals",
                check_target: "suricata_rule_validation.json:.all_rules_fired",
                expected_value: true,
                source_project: "2x04_perimeter_defense",
                severity: "high"
            },

            {
                id: "NET-DNS-01",
                platform: "network",
                family: "network",
                description: "The DNS filtering control must be active.",
                check_type: "json_field_equals",
                check_target: "dns_filter_validation.json:.active",
                expected_value: true,
                source_project: "2x04_perimeter_defense",
                severity: "high"
            },

            {
                id: "HANDOFF-COMP-01",
                platform: "both",
                family: "handoff",
                description: "The final compliance artifact must exist.",
                check_type: "file_exists",
                check_target: "capstone/compliance.json",
                expected_value: true,
                source_project: "2x05_defensible_endpoint",
                severity: "critical"
            },

            {
                id: "HANDOFF-MANIFEST-01",
                platform: "both",
                family: "handoff",
                description: "The handoff manifest must exist.",
                check_type: "file_exists",
                check_target: "capstone/manifest.json",
                expected_value: true,
                source_project: "2x05_defensible_endpoint",
                severity: "critical"
            },

            {
                id: "HANDOFF-MANIFEST-02",
                platform: "both",
                family: "handoff",
                description: "The handoff manifest must contain SHA-256 hashes for packaged files.",
                check_type: "grep_match",
                check_target: "capstone/manifest.json",
                expected_value: "sha256|sha256sum|SHA-256",
                source_project: "2x05_defensible_endpoint",
                severity: "critical"
            },

            {
                id: "HANDOFF-TEL-01",
                platform: "both",
                family: "handoff",
                description: "The telemetry export package directory must exist.",
                check_type: "file_exists",
                check_target: "capstone/telemetry",
                expected_value: true,
                source_project: "2x05_defensible_endpoint",
                severity: "critical"
            },

            {
                id: "HANDOFF-TAR-01",
                platform: "both",
                family: "handoff",
                description: "The telemetry export package must be archived as a tarball.",
                check_type: "file_exists",
                check_target: "capstone/telemetry_handoff.tar.gz",
                expected_value: true,
                source_project: "2x05_defensible_endpoint",
                severity: "high"
            },

            {
                id: "HANDOFF-RUNBOOK-01",
                platform: "both",
                family: "handoff",
                description: "The handoff runbook script must exist.",
                check_type: "file_exists",
                check_target: "capstone/runbook.sh",
                expected_value: true,
                source_project: "2x05_defensible_endpoint",
                severity: "high"
            },

            {
                id: "HANDOFF-RUNBOOK-02",
                platform: "both",
                family: "handoff",
                description: "The handoff runbook script must be executable.",
                check_type: "command_exit_zero",
                check_target: "test -x capstone/runbook.sh",
                expected_value: 0,
                source_project: "2x05_defensible_endpoint",
                severity: "high"
            }
        ]
    }' > "$TMP"

if ! jq -e '
    (.schema_version | type == "string") and
    (.generated_at | type == "string") and
    (.controls | type == "array") and
    (.controls | length > 0) and
    (
        all(
            .controls[];
            (.id | type == "string") and
            (
                .platform == "linux" or
                .platform == "windows" or
                .platform == "network" or
                .platform == "both"
            ) and
            (
                .family == "hardening" or
                .family == "telemetry" or
                .family == "patching" or
                .family == "network" or
                .family == "handoff"
            ) and
            (
                .check_type == "file_exists" or
                .check_type == "json_field_equals" or
                .check_type == "json_field_gte" or
                .check_type == "command_exit_zero" or
                .check_type == "grep_match"
            ) and
            (.check_target | type == "string") and
            has("expected_value") and
            (.source_project | type == "string") and
            (
                .severity == "critical" or
                .severity == "high" or
                .severity == "medium" or
                .severity == "low"
            )
        )
    )
' "$TMP" >/dev/null; then
    rm -f "$TMP"
    echo "ERROR: generated target_state.json failed validation" >&2
    exit 1
fi

mv "$TMP" "$OUT"

echo "Target state written to: $OUT"
echo "Controls: $(jq '.controls | length' "$OUT")"

exit 0
