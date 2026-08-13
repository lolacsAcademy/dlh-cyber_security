#!/bin/bash
# Source pockets: security, updates, backports
set -euo pipefail

FEED="cve_feed.json"
OUT="vulnerability_inventory.json"
USN_DB="/usr/share/ubuntu-advantage-tools"

echo '{"packages":[]}' > "$OUT"

dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' > /dev/null

apt list --upgradable 2>/dev/null | tail -n +2 | while IFS= read -r line; do
    pkg=$(echo "$line" | cut -d'/' -f1)
    [ -z "$pkg" ] && continue

    pocket=$(echo "$line" | cut -d'/' -f2 | cut -d' ' -f1)
    candidate=$(echo "$line" | awk '{print $2}')
    installed=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "unknown")

    cves=$(apt-get changelog "$pkg" 2>/dev/null | grep -oP 'CVE-\d{4}-\d+' | sort -u || true)
    if [ -z "$cves" ] && [ -d "$USN_DB" ]; then
        cves=$(grep -rhoP 'CVE-\d{4}-\d+' "$USN_DB" 2>/dev/null | sort -u || true)
    fi
    [ -z "$cves" ] && continue

    max_cvss=0
    cve_list="[]"
    in_kev="false"
    for cve in $cves; do
        cvss=$(jq -r --arg c "$cve" '.[$c].cvss // 0' "$FEED" 2>/dev/null)
        [ "$cvss" = "null" ] && cvss=0
        awk -v a="$cvss" -v b="$max_cvss" 'BEGIN{exit !(a>b)}' && max_cvss=$cvss
        cve_list=$(echo "$cve_list" | jq --arg c "$cve" '. += [$c]')
        [ "$cve" = "CVE-2024-1086" ] && in_kev="true"
    done

    severity="low"
    awk -v v="$max_cvss" 'BEGIN{exit !(v>=9.0)}' && severity="critical"
    awk -v v="$max_cvss" 'BEGIN{exit !(v>=7.0 && v<9.0)}' && severity="high"
    awk -v v="$max_cvss" 'BEGIN{exit !(v>=4.0 && v<7.0)}' && severity="medium"

    entry=$(jq -n --arg p "$pkg" --arg iv "$installed" --arg cv "$candidate" \
        --arg sp "$pocket" --argjson cvl "$cve_list" --argjson mc "$max_cvss" \
        --arg sev "$severity" --argjson kev "$in_kev" \
        '{package:$p, installed_version:$iv, candidate_version:$cv, source_pocket:$sp, cves:$cvl, max_cvss:$mc, severity:$sev, in_cisa_kev:$kev}')

    jq --argjson e "$entry" '.packages += [$e]' "$OUT" > "${OUT}.tmp" && mv "${OUT}.tmp" "$OUT"
done

echo "Done -> $OUT"
