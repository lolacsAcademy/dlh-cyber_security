#!/bin/bash
set -euo pipefail

# Weights are defined as constants (our design choice, documented here)
CVSS_WEIGHT=1
KEV_WEIGHT=2
CRITICALITY_WEIGHT=1
EXPOSURE_WEIGHT=1

VULN_FILE="vulnerability_inventory.json"
DEPS_FILE="service_dependency_map.json"
OUT="patch_plan.json"

GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

DEPS_JSON=$(jq -s '.' "$DEPS_FILE")

PLAN="[]"

pkgs=$(jq -c '.packages[]' "$VULN_FILE")

while IFS= read -r pkg_entry; do
    pkg=$(echo "$pkg_entry" | jq -r '.package')
    max_cvss=$(echo "$pkg_entry" | jq -r '.max_cvss')
    in_kev=$(echo "$pkg_entry" | jq -r '.in_cisa_kev')
    [ "$in_kev" = "true" ] && kev_val=1 || kev_val=0

    affected=$(echo "$DEPS_JSON" | jq -c --arg p "$pkg" '[.[] | select(.owning_package==$p or (.linked_packages|index($p))) ]')

    max_crit_num=0
    for crit in critical high medium low; do
        count=$(echo "$affected" | jq --arg c "$crit" '[.[] | select(.criticality==$c)] | length')
        if [ "$count" -gt 0 ]; then
            case "$crit" in
                critical) max_crit_num=3; break ;;
                high) max_crit_num=2; break ;;
                medium) max_crit_num=1; break ;;
                low) max_crit_num=0; break ;;
            esac
        fi
    done

    exposure_rank=0
    svc_count=$(echo "$affected" | jq 'length')
    if [ "$svc_count" -gt 0 ]; then
        exposure_rank=1
        has_edge=$(echo "$affected" | jq '[.[] | select(.service=="apache2.service" or .service=="ssh.service")] | length')
        [ "$has_edge" -gt 0 ] && exposure_rank=2
    fi

    score=$(awk -v cvss="$max_cvss" -v kev="$kev_val" -v crit="$max_crit_num" -v exposure="$exposure_rank" \
        -v wc="$CVSS_WEIGHT" -v wk="$KEV_WEIGHT" -v wcr="$CRITICALITY_WEIGHT" -v we="$EXPOSURE_WEIGHT" \
        'BEGIN{printf "%.2f", wc*cvss + wk*kev + wcr*crit + we*exposure}')

    if [ "$pkg" = "linux-image-generic" ] || [[ "$pkg" == linux-image* ]] || [ "$pkg" = "systemd" ]; then
        requires_reboot="true"
        requires_restart="true"
        affected_services='["(kernel-wide)"]'
    else
        requires_reboot="false"
        svc_names=$(echo "$affected" | jq '[.[].service]')
        affected_services="$svc_names"
        if [ "$svc_count" -gt 0 ]; then
            requires_restart="true"
        else
            requires_restart="false"
        fi
    fi

    bucket="scheduled"
    is_emergency=$(awk -v s="$score" 'BEGIN{print (s>=7)?1:0}')
    is_urgent=$(awk -v s="$score" 'BEGIN{print (s>=4 && s<7)?1:0}')
    [ "$is_emergency" = "1" ] && bucket="emergency"
    [ "$is_urgent" = "1" ] && bucket="urgent"

    rollback_version=$(echo "$pkg_entry" | jq -r '.installed_version')

    entry=$(jq -n --arg pkg "$pkg" --argjson score "$score" --arg bucket "$bucket" \
        --argjson affected_services "$affected_services" --argjson rr "$requires_restart" \
        --argjson rb "$requires_reboot" --arg rv "$rollback_version" \
        '{package:$pkg, score:$score, bucket:$bucket, affected_services:$affected_services, requires_restart:$rr, requires_reboot:$rb, rollback_target_version:$rv}')

    PLAN=$(echo "$PLAN" | jq --argjson e "$entry" '. + [$e]')
done <<< "$pkgs"

PLAN=$(echo "$PLAN" | jq 'sort_by(-.score) | to_entries | map(.value + {rank: (.key+1)})' )
PLAN=$(echo "$PLAN" | jq '[.[] | {rank, package, score, bucket, affected_services, requires_restart, requires_reboot, rollback_target_version}]')

EMERGENCY=$(echo "$PLAN" | jq '[.[] | select(.bucket=="emergency")] | length')
URGENT=$(echo "$PLAN" | jq '[.[] | select(.bucket=="urgent")] | length')
SCHEDULED=$(echo "$PLAN" | jq '[.[] | select(.bucket=="scheduled")] | length')
REBOOT_ANY=$(echo "$PLAN" | jq '[.[] | select(.requires_reboot==true)] | length')
[ "$REBOOT_ANY" -gt 0 ] && REBOOT_TEXT="yes (kernel update present)" || REBOOT_TEXT="no"

WEIGHTS=$(jq -n --argjson c "$CVSS_WEIGHT" --argjson k "$KEV_WEIGHT" --argjson cr "$CRITICALITY_WEIGHT" --argjson e "$EXPOSURE_WEIGHT" \
    '{cvss_weight:$c, kev_weight:$k, criticality_weight:$cr, exposure_weight:$e}')

SUMMARY=$(jq -n --argjson em "$EMERGENCY" --argjson ur "$URGENT" --argjson sc "$SCHEDULED" --arg rb "$REBOOT_TEXT" \
    '{emergency:$em, urgent:$ur, scheduled:$sc, reboot_required:$rb}')

jq -n --arg gen "$GENERATED_AT" --argjson w "$WEIGHTS" --argjson p "$PLAN" --argjson s "$SUMMARY" \
    '{generated_at:$gen, weights:$w, plan:$p, summary:$s}' > "$OUT"

echo "Emergency: $EMERGENCY   Urgent: $URGENT   Scheduled: $SCHEDULED"
echo "Reboot required by plan: $REBOOT_TEXT"
echo "Report saved to: $OUT"
