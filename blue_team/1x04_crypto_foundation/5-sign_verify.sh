#!/bin/bash
# 5-sign_verify.sh
# Usage:
#   ./5-sign_verify.sh sign file_path private_key_path
#   ./5-sign_verify.sh verify file_path signature_path public_key_path

MODE=$1

if [ "$MODE" == "sign" ]; then
    FILE=$2
    KEY=$3
    openssl dgst -sha256 -sign "$KEY" -out "$FILE.sig" "$FILE"
    echo "Signature written to $FILE.sig"
elif [ "$MODE" == "verify" ]; then
    FILE=$2
    SIG=$3
    PUBKEY=$4
    openssl dgst -sha256 -verify "$PUBKEY" -signature "$SIG" "$FILE"
else
    echo "mode must be sign or verify"
    exit 1
fi
