#!/bin/bash

# Task 1 - Signal vs Noise

FEED="commercial_feed_extract.json"
INTAKE="0-intel_intake.md"

if [[ ! -f "$FEED" || ! -f "$INTAKE" ]]; then
    echo "Error: required material missing."
    exit 1
fi

actionable=0
contextual=0
noise=0
total=0

triage() {
    local type="$1"
    local value="$2"
    local sources="$3"
    local category="$4"
    local reason="$5"
    local confidence="$6"
    local uncertainty="$7"

    printf '%s | %s | %s | %s | %s | %s | %s\n' \
        "$type" "$value" "$sources" "$category" \
        "$reason" "$confidence" "$uncertainty"

    total=$((total + 1))

    case "$category" in
        ACTIONABLE) actionable=$((actionable + 1)) ;;
        CONTEXTUAL) contextual=$((contextual + 1)) ;;
        NOISE) noise=$((noise + 1)) ;;
    esac
}

echo "Type | Value | Sources | Category | Justification | Confidence | Uncertainty"
echo "-----|-------|---------|----------|---------------|------------|------------"

while IFS=$'\t' read -r type value confidence tags note; do
    category="CONTEXTUAL"
    reason="Commercial-feed indicator needs corroboration."
    level="MEDIUM"
    uncertainty="YES"

    if [[ "$note" == *"DO NOT BLOCK"* ||
          "$note" == *"LIKELY NOISE"* ||
          "$tags" == *"shared-hosting"* ||
          "$tags" == *"cdn-shared"* ||
          "$tags" == *"microsoft-cloud"* ||
          "$tags" == *"cloudflare"* ]]; then
        category="NOISE"
        reason="Shared infrastructure is unsafe for blocking."
        level="HIGH"
        uncertainty="NO"
    elif [[ "$tags" == *"clustered_by_similarity"* &&
            "$confidence" -lt 50 ]]; then
        category="NOISE"
        reason="Weak ML similarity provides insufficient evidence."
        level="MEDIUM"
        uncertainty="YES"
    elif [[ "$tags" == *"POSSIBLE_VITALSCORE_PRIOR"* ]]; then
        category="CONTEXTUAL"
        reason="Historical association is useful for correlation only."
        level="MEDIUM"
        uncertainty="YES"
    elif [[ "$confidence" -ge 80 ]]; then
        category="ACTIONABLE"
        reason="High-confidence campaign indicator supports detection."
        level="HIGH"
        uncertainty="NO"
    fi

    triage "$type" "$value" "commercial_feed_extract.json" \
        "$category" "$reason" "$level" "$uncertainty"

done < <(
    jq -r '.indicators[] |
        [.type, .value, (.acme_confidence | tostring),
        (.tags | join(",")), (.acme_note // "")] | @tsv' "$FEED"
)

# HC3 indicators recorded during Task 0 intake.

triage domain meddefense-portal.com "HC3; commercial" ACTIONABLE \
    "Corroborated phishing domain." HIGH NO
triage domain medequip-supplies.net "HC3; commercial" ACTIONABLE \
    "Corroborated phishing domain." HIGH NO
triage domain meddefense-benefits.org "HC3; commercial" ACTIONABLE \
    "Corroborated phishing domain." HIGH NO
triage domain outlook-protection.com "HC3; commercial" ACTIONABLE \
    "Corroborated phishing domain." HIGH NO
triage domain portal-secure-meddefense.com "HC3" CONTEXTUAL \
    "HC3 reports this domain with MEDIUM confidence." MEDIUM YES
triage domain healthbane-c2.net "HC3; commercial" ACTIONABLE \
    "Corroborated C2 domain." HIGH NO
triage domain data-sync.healthbane-c2.net "HC3; commercial" ACTIONABLE \
    "Corroborated DNS tunneling domain." HIGH NO
triage domain update-healthbane.net "HC3; commercial" CONTEXTUAL \
    "HC3 assigns MEDIUM confidence." MEDIUM YES

triage ip 91.234.99.107 "HC3; commercial" ACTIONABLE \
    "Corroborated campaign IP." HIGH NO
triage ip 185.176.43.22 "HC3; commercial" ACTIONABLE \
    "Corroborated campaign IP." HIGH NO
triage ip 164.90.218.73 "HC3; commercial" ACTIONABLE \
    "Corroborated campaign IP." HIGH NO
triage ip 51.38.42.17 "HC3; commercial" ACTIONABLE \
    "Corroborated campaign IP." HIGH NO
triage ip 51.38.42.191 "HC3; commercial" ACTIONABLE \
    "Corroborated C2 IP." HIGH NO
triage ip 45.77.218.9 "HC3; commercial" CONTEXTUAL \
    "HC3 assigns MEDIUM confidence." MEDIUM YES

triage sha256 a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456 \
    "HC3; commercial" ACTIONABLE "Corroborated malicious document hash." HIGH NO
triage sha256 b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654 \
    "HC3; commercial" ACTIONABLE "Corroborated malware hash." HIGH NO
triage sha256 c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 \
    "HC3; commercial" ACTIONABLE "Corroborated malicious script hash." HIGH NO
triage sha256 2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f \
    "HC3" CONTEXTUAL "Lure hash reported with MEDIUM confidence." MEDIUM YES
triage sha256 dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678 \
    "HC3; commercial" CONTEXTUAL "Dropper variant has MEDIUM confidence." MEDIUM YES

triage url 'https://meddefense-portal.com/verify/staff?id=<user>&token=<8hex>' \
    "HC3" ACTIONABLE "High-confidence credential capture URL." HIGH NO
triage url 'https://medequip-supplies.net/invoices/pay?id=INV-<YYYY-NNNNN>' \
    "HC3; commercial" ACTIONABLE "High-confidence credential capture URL." HIGH NO
triage url 'https://meddefense-benefits.org/enroll' \
    "HC3; commercial" ACTIONABLE "High-confidence credential capture URL." HIGH NO
triage url 'https://healthbane-c2.net/update/svchost_update.exe' \
    "HC3; commercial" ACTIONABLE "High-confidence malware download URL." HIGH NO

echo
echo "Summary"
echo "======="
echo "Total indicators reviewed: $total"
echo "ACTIONABLE: $actionable ($((actionable * 100 / total))%)"
echo "CONTEXTUAL: $contextual ($((contextual * 100 / total))%)"
echo "NOISE: $noise ($((noise * 100 / total))%)"

echo
echo "Top reasons indicators were downgraded:"
echo "- Shared hosting or cloud infrastructure"
echo "- Weak ML similarity"
echo "- Historical indicators"
echo "- Low confidence or missing corroboration"

echo
echo "Top indicators for immediate detection:"
echo "- meddefense-portal.com"
echo "- healthbane-c2.net"
echo "- data-sync.healthbane-c2.net"
echo "- 91.234.99.107"
echo "- 51.38.42.191"

echo
echo "Assessment: Not all 64 indicators are operationally safe to block."
