#!/bin/bash
# 12-luks_manager.sh
# Usage:
#   sudo ./12-luks_manager.sh create <file> <size_MB>
#   sudo ./12-luks_manager.sh open <file> <mapper_name>
#   sudo ./12-luks_manager.sh close <mapper_name>

MODE=$1

if [ "$MODE" == "create" ]; then
    FILE=$2
    SIZE=$3
    dd if=/dev/zero of="$FILE" bs=1M count="$SIZE"
    cryptsetup luksFormat "$FILE"
    cryptsetup luksOpen "$FILE" tmp_format_vol
    mkfs.ext4 /dev/mapper/tmp_format_vol
    cryptsetup luksClose tmp_format_vol
    echo "Encrypted volume created and formatted: $FILE"

elif [ "$MODE" == "open" ]; then
    FILE=$2
    NAME=$3
    cryptsetup luksOpen "$FILE" "$NAME"
    mkdir -p "/mnt/$NAME"
    mount "/dev/mapper/$NAME" "/mnt/$NAME"
    echo "Volume opened and mounted at /mnt/$NAME"

elif [ "$MODE" == "close" ]; then
    NAME=$2
    umount "/mnt/$NAME"
    cryptsetup luksClose "$NAME"
    echo "Volume unmounted and closed: $NAME"

else
    echo "mode must be create, open, or close"
    exit 1
fi
