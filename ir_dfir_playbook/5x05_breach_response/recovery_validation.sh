#!/bin/bash
#!/usr/bin/env bash
# 5x05 Task 7 — Recovery Validation
# Incident: IR-2026-0420-01
# Read-only verification; no remediation performed.
set -uo pipefail

HOSTS=(CS-WS-101 CS-WS-104 CS-WS-107 CS-WS-112 FILE-SVR-01)
FAILED=0

# Supply verified exports from authorized EDR, SIEM,
# firewall, DNS, clinical monitoring and evidence systems.
# Each verifier must exit 0 only after checking live or
# authenticated source data. No placeholder success allowed.
VERIFY_DIR="${VERIFY_DIR:-./recovery_verifiers}"

check() {
    local label="$1"
    local message="$2"
    local verifier="$3"

    if [[ -x "$VERIFY_DIR/$verifier" ]] &&
       "$VERIFY_DIR/$verifier" "${HOSTS[@]}" >/dev/null 2>&1; then
        printf '[PASS] %s: %s\n' "$label" "$message"
    else
        printf '[FAIL] %s: verification unavailable or unsuccessful\n' "$label"
        FAILED=1
    fi
}

check "beacon" \
    "no svchost32.exe or related process tree in last 24h across affected hosts" \
    "verify_beacon"

check "c2" \
    "no successful connections to staging.office365-cdn.net or 45.152.66.114" \
    "verify_c2"

check "ransomware staging" \
    "no identified .bat or .ps1 ransomware staging scripts in System32 or ProgramData" \
    "verify_staging"

check "services" \
    "epic-api 200, lis-api 200, scheduling-api 200" \
    "verify_services"

check "edr" \
    "all 5 hosts reporting to EDR console within 5 minutes" \
    "verify_edr"

check "detection" \
    "sigma_cobalt_strike_beacon.yml active; synthetic test event matched" \
    "verify_detection"

check "evidence hashes" \
    "11/11 artifacts match original SHA-256 acquisition baselines" \
    "verify_hashes"

if (( FAILED == 0 )); then
    echo "ALL CHECKS PASSED"
    exit 0
fi

echo "RECOVERY NOT VALIDATED"
exit 1
