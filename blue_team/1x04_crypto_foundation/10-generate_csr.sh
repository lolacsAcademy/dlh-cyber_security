#!/bin/bash
# 10-generate_csr.sh
# Automates steps 1-3: key generation, CSR creation, CSR inspection
# Usage: ./10-generate_csr.sh

KEY_FILE="portal_key.pem"
CSR_FILE="portal.csr"
CONFIG_FILE="openssl.cnf"

# Step 1: Generate ECC P-256 private key
openssl ecparam -genkey -name prime256v1 -out "$KEY_FILE"
echo "Private key generated: $KEY_FILE"

# Step 2: Generate CSR using existing openssl.cnf
openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -config "$CONFIG_FILE"
echo "CSR generated: $CSR_FILE"

# Step 3: Inspect the CSR
echo "--- CSR Details ---"
openssl req -text -noout -in "$CSR_FILE"
