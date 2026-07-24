#!/bin/bash
# 10-generate_csr.sh
# Automates steps 1-3: key generation, CSR creation, CSR inspection
# Usage: ./10-generate_csr.sh

KEY_FILE="portal_key.pem"
CSR_FILE="portal.csr"
CONFIG_FILE="openssl_generated.cnf"

# Embed MedDefense field values directly for this script's own CSR config
cat > "$CONFIG_FILE" << CONF
[ req ]
default_bits       = 256
prompt             = no
distinguished_name = req_dn
req_extensions     = req_ext

[ req_dn ]
C  = US
ST = California
L  = San Francisco
O  = MedDefense Health Systems
OU = Information Technology
CN = portal.meddefense.local

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = portal.meddefense.local
DNS.2 = www.portal.meddefense.local
DNS.3 = patientportal.meddefense.local
CONF

# Step 1: Generate ECC P-256 private key
openssl ecparam -genkey -name prime256v1 -out "$KEY_FILE"
echo "Private key generated: $KEY_FILE"

# Step 2: Generate CSR for portal.meddefense.local
openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -config "$CONFIG_FILE"
echo "CSR generated: $CSR_FILE"

# Step 3: Inspect the CSR
echo "--- CSR Details ---"
openssl req -text -noout -in "$CSR_FILE"
