#!/bin/bash
# Accepts a single positional argument $1: the package name
set -uo pipefail

PRE_FILE="pre_patch_state.json"
DEPS_FILE="service_dependency_map.json"
PROBES_FILE="service_probes.json"

PKG="${1:-}"
if [ -z "$PKG" ]; then
    echo "Usage: $0 <package>"
    exit 1
fi

# 2 & 3. Load target version from pre_patch_state.json (handle :amd64 suffix)
TARGET_VERSION=$(jq -r --arg p "$PKG" '.packages[] | select(.package==$p or .package==($p+":amd64")) | .version' "$PRE_FILE")

if [ -z "$TARGET_VERSION" ]; then
    echo "ERROR: package '$PKG' not found in $PRE_FILE"
    exit 1
fi
echo "[*] Target version from pre_patch_state.json: $TARGET_VERSION"

CURRENT_VERSION=$(dpkg-query -W -f='${Version}' "$PKG" 2>/dev/null || echo "not_installed")

# 4. Confirm version available via apt-cache madison
AVAILABLE="no"
if apt-cache madison "$PKG" 2>/dev/null | grep -qF "$TARGET_VERSION"; then
    AVAILABLE="yes"
fi
echo "[*] Version available in cache or repository: $AVAILABLE"

if [ "$AVAILABLE" != "yes" ]; then
    echo "ERROR: target version $TARGET_VERSION not available for $PKG"
    echo "ROLLBACK: failed"
    exit 1
fi

# 5. Execute rollback
echo -n "[*] Downgrading $PKG...                              "
DOWNGRADE_OK="no"
if DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "${PKG}=${TARGET_VERSION}" >/tmp/rollback_stdout.txt 2>&1; then
    echo "OK"
    DOWNGRADE_OK="yes"
else
    echo "FAILED"
    cat /tmp/rollback_stdout.txt
fi

if [ "$DOWNGRADE_OK" != "yes" ]; then
    echo "ROLLBACK: failed"
    exit 1
fi

# 6. Apply hold
echo -n "[*] apt-mark hold $PKG                               "
HOLD_OK="no"
if apt-mark hold "$PKG" >/dev/null 2>&1; then
    echo "OK"
    HOLD_OK="yes"
else
    echo "FAILED"
fi

# 7. Re-run probes for affected services
echo "[*] Re-running probes for affected services..."
AFFECTED_SERVICES=$(jq -s -r --arg p "$PKG" '.[] | select(.linked_packages | index($p)) | .service' "$DEPS_FILE")

ALL_PROBES_PASS="yes"
if [ -n "$AFFECTED_SERVICES" ]; then
    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        probe=$(jq -c --arg s "$svc" '.[$s] // empty' "$PROBES_FILE")
        result="PASS"
        if [ -n "$probe" ]; then
            ptype=$(echo "$probe" | jq -r '.type')
            target=$(echo "$probe" | jq -r '.target')
            ok=0
            case "$ptype" in
                curl)
                    curl -sf -o /dev/null "$target" && ok=1
                    ;;
                mysqladmin_ping)
                    sudo mysqladmin ping -h "$target" >/dev/null 2>&1 && ok=1
                    ;;
                ssh_batchmode)
                    ssh -o BatchMode=yes -o ConnectTimeout=3 "$target" true 2>/dev/null
                    rc=$?
                    [ $rc -eq 0 ] || [ $rc -eq 255 ] && ok=1
                    ;;
                *)
                    ok=1
                    ;;
            esac
            if [ "$ok" -ne 1 ]; then
                result="FAIL"
                ALL_PROBES_PASS="no"
            fi
        else
            state=$(systemctl show -p ActiveState --value "$svc" 2>/dev/null)
            [ "$state" != "active" ] && result="FAIL" && ALL_PROBES_PASS="no"
        fi
        printf "    %-40s probe                                  %s\n" "$svc" "$result"
    done <<< "$AFFECTED_SERVICES"
fi

if [ "$DOWNGRADE_OK" = "yes" ] && [ "$HOLD_OK" = "yes" ] && [ "$ALL_PROBES_PASS" = "yes" ]; then
    echo "ROLLBACK: success"
    echo "from $CURRENT_VERSION to $TARGET_VERSION"
    exit 0
else
    echo "ROLLBACK: failed"
    echo "from $CURRENT_VERSION to $TARGET_VERSION"
    exit 1
fi
