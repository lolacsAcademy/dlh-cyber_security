
#!/bin/bash

# The Evidence Trail - Task 2

files=("wst-ws-031.dd" "wst-ws-031.mem" "wst-ws-017.mem")
ids=("ART-001" "ART-002" "ART-003")

actor="Forensic Analyst"
timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
failed=0

# Stop if any artifact is missing.
for file in "${files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "[FAIL] Missing artifact: $file"
        exit 1
    fi
done

# First run: establish baseline.
if [ ! -f hashes.txt ]; then
    for i in "${!files[@]}"; do
        file="${files[$i]}"
        id="${ids[$i]}"
        hash=$(sha256sum "$file" | awk '{print $1}')

        echo "$hash  $file" >> hashes.txt
        echo "[BASELINE_SET] $id $file sha256=$hash"
        echo "$timestamp | $actor | $id | BASELINE_SET | expected=N/A | computed=$hash" >> verification_log.txt
    done

    echo "Baseline written to hashes.txt. Run again to verify."
    exit 0
fi

# Subsequent runs: verify against baseline.
for i in "${!files[@]}"; do
    file="${files[$i]}"
    id="${ids[$i]}"

    expected=$(awk -v name="$file" '$2 == name {print $1}' hashes.txt)
    computed=$(sha256sum "$file" | awk '{print $1}')

    if [ -n "$expected" ] && [ "$expected" = "$computed" ]; then
        result="PASS"
    else
        result="FAIL"
        failed=1
    fi

    echo "[$result] $id $file expected=$expected computed=$computed"
    echo "$timestamp | $actor | $id | $result | expected=$expected | computed=$computed" >> verification_log.txt
done

if [ "$failed" -eq 0 ]; then
    echo "ALL ARTIFACTS VERIFIED"
    exit 0
else
    echo "ARTIFACT VERIFICATION FAILED"
    exit 1
fi

