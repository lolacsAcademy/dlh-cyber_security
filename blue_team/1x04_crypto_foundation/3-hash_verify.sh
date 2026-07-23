#!/bin/bash
# 3-hash_verify.sh
# Usage: ./3-hash_verify.sh file_path expected_sha256_hash

FILE=$1
EXPECTED=$2

ACTUAL=$(sha256sum "$FILE" | awk '{print $1}')

if [ "$ACTUAL" == "$EXPECTED" ]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected $EXPECTED got $ACTUAL"
    exit 1
fi
