#!/bin/bash
# capstone
# Sysmon
set -uo pipefail

OUT="environment_intake_linux.json"
TMP="${OUT}.tmp"

# Exit codes:
# 0 = success
# 1 = controlled collection failure
# 2 = environment error

for cmd in jq dpkg-query ss systemctl find uname hostname; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: missing dependency: $cmd" >&2
        exit 2
    fi
done

HOSTNAME_VALUE=$(hostname)
KERNEL=$(uname -r)

if [ -r /etc/os-release ]; then
    DISTRIBUTION=$(
        . /etc/os-release
        printf '%s' "${PRETTY_NAME:-unknown}"
    )
else
    DISTRIBUTION="unknown"
fi

PATCH_LEVEL=$(
    dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null |
        sort |
        sha256sum |
        awk '{print $1}'
)

PACKAGE_COUNT=$(dpkg-query -W 2>/dev/null | wc -l)

LISTENING_SOCKETS=$(
    ss -tulnpH 2>/dev/null || true
)

ACTIVE_SERVICES=$(
    systemctl list-units \
        --type=service \
        --state=active \
        --no-legend \
        --no-pager 2>/dev/null |
        awk '{print $1}' |
        sort
)

SSHD_JSON='{}'

if [ -r /etc/ssh/sshd_config ]; then
    SSHD_JSON=$(
        awk '
            /^[[:space:]]*#/ {next}
            /^[[:space:]]*$/ {next}
            {
                key=$1
                $1=""
                sub(/^[[:space:]]+/, "", $0)
                print key "\t" $0
            }
        ' /etc/ssh/sshd_config |
            jq -Rn '
                reduce inputs as $line ({};
                    ($line | split("\t")) as $parts
                    | .[$parts[0]] = ($parts[1:] | join("\t"))
                )
            '
    )
fi

SYSCTL_JSON=$(
    jq -n \
        --arg ip_forward "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)" \
        --arg syn_cookies "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo unknown)" \
        --arg accept_redirects "$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo unknown)" \
        --arg send_redirects "$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null || echo unknown)" \
        --arg rp_filter "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo unknown)" \
        --arg randomize_va_space "$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo unknown)" \
        --arg suid_dumpable "$(sysctl -n fs.suid_dumpable 2>/dev/null || echo unknown)" \
        '{
            "net.ipv4.ip_forward": $ip_forward,
            "net.ipv4.tcp_syncookies": $syn_cookies,
            "net.ipv4.conf.all.accept_redirects": $accept_redirects,
            "net.ipv4.conf.all.send_redirects": $send_redirects,
            "net.ipv4.conf.all.rp_filter": $rp_filter,
            "kernel.randomize_va_space": $randomize_va_space,
            "fs.suid_dumpable": $suid_dumpable
        }'
)

SUID_SGID_COUNT=$(
    find / -perm /6000 -type f \
        -not -path '/proc/*' \
        -not -path '/sys/*' \
        2>/dev/null |
        wc -l
)

WORLD_WRITABLE_COUNT=$(
    find / -perm -0002 -type f \
        -not -path '/proc/*' \
        -not -path '/sys/*' \
        2>/dev/null |
        wc -l
)

if command -v nft >/dev/null 2>&1; then
    NFT_RULESET_LENGTH=$(
        nft list ruleset 2>/dev/null |
            wc -l
    )
else
    NFT_RULESET_LENGTH=0
fi

AUDITD_RUNNING=false
RSYSLOG_RUNNING=false
SYSMON_LINUX_PRESENT=false

if systemctl is-active --quiet auditd 2>/dev/null; then
    AUDITD_RUNNING=true
fi

if systemctl is-active --quiet rsyslog 2>/dev/null; then
    RSYSLOG_RUNNING=true
fi

if command -v sysmon >/dev/null 2>&1 ||
    command -v sysmonforlinux >/dev/null 2>&1; then
    SYSMON_LINUX_PRESENT=true
fi

jq -n \
    --arg captured_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$HOSTNAME_VALUE" \
    --arg kernel "$KERNEL" \
    --arg distribution "$DISTRIBUTION" \
    --arg patch_level "$PATCH_LEVEL" \
    --argjson package_count "$PACKAGE_COUNT" \
    --arg sockets "$LISTENING_SOCKETS" \
    --arg services "$ACTIVE_SERVICES" \
    --argjson sshd "$SSHD_JSON" \
    --argjson sysctl_security "$SYSCTL_JSON" \
    --argjson suid_sgid_count "$SUID_SGID_COUNT" \
    --argjson world_writable_count "$WORLD_WRITABLE_COUNT" \
    --argjson nft_ruleset_length "$NFT_RULESET_LENGTH" \
    --argjson auditd_running "$AUDITD_RUNNING" \
    --argjson rsyslog_running "$RSYSLOG_RUNNING" \
    --argjson sysmon_linux_present "$SYSMON_LINUX_PRESENT" \
    '{
        captured_at: $captured_at,
        hostname: $hostname,
        kernel_release: $kernel,
        distribution: $distribution,
        patch_level: $patch_level,
        installed_package_count: $package_count,
        listening_sockets: ($sockets | split("\n") | map(select(length > 0))),
        active_systemd_services: ($services | split("\n") | map(select(length > 0))),
        sshd_config: $sshd,
        sysctl_security_parameters: $sysctl_security,
        suid_sgid_binary_count: $suid_sgid_count,
        world_writable_file_count: $world_writable_count,
        firewall: {
            nft_ruleset_length: $nft_ruleset_length
        },
        telemetry: {
            auditd_running: $auditd_running,
            rsyslog_running: $rsyslog_running,
            sysmon_for_linux_present: $sysmon_linux_present
        }
    }' > "$TMP"

if ! jq empty "$TMP" >/dev/null 2>&1; then
    rm -f "$TMP"
    echo "ERROR: failed to create valid JSON" >&2
    exit 1
fi

mv "$TMP" "$OUT"

echo "Environment intake saved to: $OUT"
exit 0
