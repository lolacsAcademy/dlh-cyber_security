#!/bin/bash
# 1-symmetric_encrypt.sh
# Usage: ./1-symmetric_encrypt.sh input_file output_file mode

INPUT=$1
OUTPUT=$2
MODE=$3

if [ "$MODE" == "cbc" ]; then
    openssl enc -aes-256-cbc -pbkdf2 -in "$INPUT" -out "$OUTPUT" -pass pass:MedDefense2026!
elif [ "$MODE" == "gcm" ]; then
    python3 -c "
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = os.urandom(32)
nonce = os.urandom(12)
data = open('$INPUT','rb').read()
ct = AESGCM(key).encrypt(nonce, data, None)
open('$OUTPUT','wb').write(nonce + ct)
"
else
    echo "mode must be cbc or gcm"
    exit 1
fi
