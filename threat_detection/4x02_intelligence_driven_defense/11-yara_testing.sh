#!/bin/bash
set -euo pipefail

SAMPLES_DIR="samples"
MANIFEST="$SAMPLES_DIR/samples_manifest.txt"
PDF_RULE="9-yara_phishing_pdf.yar"
ARSENAL_RULE="10-yara_arsenal.yar"

command -v yara >/dev/null 2>&1 || {
    echo "ERROR: yara is not installed."
    exit 1
}

[[ -d "$SAMPLES_DIR" ]] || {
    echo "ERROR: samples directory not found."
    exit 1
}

[[ -f "$MANIFEST" ]] || {
    echo "ERROR: samples manifest not found."
    exit 1
}

test_rule() {
    local rule_file="$1"
    local rule_name="$2"
    shift 2
    local positives=("$@")
    local tp=0 tn=0 fp=0 fn=0
    local file expected matched
    local detection_rate false_positive_rate precision recommendation

    echo "Rule: $rule_name"

    for file in "$SAMPLES_DIR"/*; do
        [[ -f "$file" ]] || continue
        [[ "$(basename "$file")" == "samples_manifest.txt" ]] && continue

        expected=0
        for positive in "${positives[@]}"; do
            if [[ "$(basename "$file")" == "$positive" ]]; then
                expected=1
                break
            fi
        done

        matched=0
        if yara "$rule_file" "$file" 2>/dev/null |
            grep -q "^${rule_name}[[:space:]]"; then
            matched=1
        fi

        if (( expected == 1 && matched == 1 )); then
            ((tp+=1))
        elif (( expected == 0 && matched == 0 )); then
            ((tn+=1))
        elif (( expected == 0 && matched == 1 )); then
            ((fp+=1))
            echo "False positive: $(basename "$file")"
            echo "Reason: Rule matched a sample expected to be benign for this rule."
            echo "Tuning: Require an additional campaign-specific pattern."
        else
            ((fn+=1))
            echo "False negative: $(basename "$file")"
            echo "Reason: Expected campaign sample did not satisfy the current rule."
            echo "Modification: Add a validated alternate pattern without weakening benign-file exclusions."
        fi
    done

    detection_rate=$(awk -v tp="$tp" -v fn="$fn" \
        'BEGIN { d=tp+fn; printf "%.0f", d ? (tp/d)*100 : 0 }')
    false_positive_rate=$(awk -v fp="$fp" -v tn="$tn" \
        'BEGIN { d=fp+tn; printf "%.0f", d ? (fp/d)*100 : 0 }')
    precision=$(awk -v tp="$tp" -v fp="$fp" \
        'BEGIN { d=tp+fp; printf "%.0f", d ? (tp/d)*100 : 0 }')

    if (( fn == 0 && fp == 0 )); then
        recommendation="DEPLOY"
    elif (( fp > 0 || fn > 0 )); then
        recommendation="TUNE"
    else
        recommendation="MONITOR"
    fi

    echo "TP: $tp | TN: $tn | FP: $fp | FN: $fn"
    echo "Detection rate: ${detection_rate}%"
    echo "False positive rate: ${false_positive_rate}%"
    echo "Precision: ${precision}%"
    echo "Recommendation: $recommendation"
    echo
}

echo "=== YARA TESTING SUMMARY ==="

if [[ -f "$PDF_RULE" ]]; then
    test_rule "$PDF_RULE" "HEALTHBANE_Phishing_PDF" \
        "phishing_sample.pdf" \
        "healthbane_lure_02.pdf"
else
    echo "ERROR: $PDF_RULE not found."
    exit 1
fi

if [[ -f "$ARSENAL_RULE" ]]; then
    test_rule "$ARSENAL_RULE" "HEALTHBANE_Email_Headers" \
        "healthbane_email_01.eml" \
        "healthbane_email_02.eml" \
        "healthbane_email_03.eml"
else
    echo "NOTICE: $ARSENAL_RULE was not provided; Task 10 rules were not tested."
fi
