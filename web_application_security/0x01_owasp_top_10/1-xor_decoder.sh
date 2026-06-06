#!/bin/bash
# Decodes a XOR WebSphere encoded hash
# Usage: ./1-xor_decoder.sh {xor}KzosKw==
python3 -c "
from base64 import b64decode
data = '$1'.replace('{xor}', '')
decoded = bytes(byte ^ 0x5f for byte in b64decode(data))
print(decoded.decode('utf-8'))
"
