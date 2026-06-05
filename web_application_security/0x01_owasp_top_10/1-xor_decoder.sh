#!/bin/bash
encoded=$(echo "$1" | sed 's/{xor}//')
decoded=$(echo "$encoded" | base64 -d | python3 -c "import sys; print(''.join(chr(b^95) for b in sys.stdin.buffer.read()))")
echo "$decoded"
