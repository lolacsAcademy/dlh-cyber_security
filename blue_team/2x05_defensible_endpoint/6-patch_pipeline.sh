#!/bin/bash
set -uo pipefail

MODE="${1:-}"

ARTIFACT_DIR="capstone/patch"
SUMMARY="$ARTIFACT_DIR/patch_pipeline_summary.json"

CVE_FEED="/home/analyst/MedDefense_Lab/capstone/cve_feed.json"
BLACKLIST="/home/analyst/MedDefense_Lab/capstone/blacklist.json"

PIPELINE="${PATCH_PIPELINE_SCRIPT:-./13-patch_pipeline.sh}"

UNATTENDED_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
BACKUP_CONF="$ARTIFACT_DIR/50unattended-upgrades.before"

# Checker-required environment redirection.
export CAPSTONE_ARTIFACTS_DIR="capstone/patch/"

# Provide the capstone CVE feed to downstream scripts.
export CVE_FEED="$CVE_FEED"

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

for cmd in jq find; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: missing dependency: $cmd" >&2
        exit 2
    fi
done

echo "Capstone patch pipeline wrapper"

# ------------------------------------------------------------
# Validate required inputs
# ------------------------------------------------------------
if [ ! -s "$CVE_FEED" ]; then
    echo "ERROR: missing CVE feed: $CVE_FEED" >&2
    exit 2
fi

if ! jq empty "$CVE_FEED" >/dev/null 2>&1; then
    echo "ERROR: invalid CVE feed JSON" >&2
    exit 2
fi

if [ ! -s "$BLACKLIST" ]; then
    echo "ERROR: missing blacklist: $BLACKLIST" >&2
    exit 2
fi

if ! jq empty "$BLACKLIST" >/dev/null 2>&1; then
    echo "ERROR: invalid blacklist JSON" >&2
    exit 2
fi

if [ ! -f "$PIPELINE" ]; then
    echo "ERROR: missing previous-project pipeline: $PIPELINE" >&2
    exit 2
fi

# ------------------------------------------------------------
# SAFE DEFAULT
# ------------------------------------------------------------
if [ "$MODE" != "--apply" ]; then
    echo
    echo "SAFE MODE: no patches or unattended-upgrades changes will be applied."
    echo "[OK] Pipeline: $PIPELINE"
    echo "[OK] CVE feed: $CVE_FEED"
    echo "[OK] Blacklist: $BLACKLIST"
    echo "[OK] CAPSTONE_ARTIFACTS_DIR=$CAPSTONE_ARTIFACTS_DIR"
    echo
    echo "Real patch deployment requires:"
    echo "$0 --apply"
    exit 0
fi

# ------------------------------------------------------------
# APPLY MODE
# Everything below here can modify the endpoint.
# ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: --apply requires root privileges" >&2
    exit 2
fi

mkdir -p "$ARTIFACT_DIR"

# ------------------------------------------------------------
# Parse mandated blacklist.
#
# Supports either:
# ["package1","package2"]
#
# or:
# {"packages":["package1","package2"]}
# ------------------------------------------------------------
BLACKLIST_PACKAGES=$(
    jq -r '
        if type == "array" then
            .[]
        elif (.packages? | type) == "array" then
            .packages[]
        else
            empty
        end
    ' "$BLACKLIST"
)

if [ -z "$BLACKLIST_PACKAGES" ]; then
    echo "ERROR: blacklist.json contains no package list" >&2
    exit 2
fi

# ------------------------------------------------------------
# Configure unattended-upgrades idempotently.
# Preserve original config for evidence/recovery.
# ------------------------------------------------------------
if [ -f "$UNATTENDED_CONF" ] &&
    [ ! -f "$BACKUP_CONF" ]; then
    cp -a "$UNATTENDED_CONF" "$BACKUP_CONF"
fi

BLACKLIST_BLOCK="$ARTIFACT_DIR/unattended-blacklist.conf"

{
    echo 'Unattended-Upgrade::Package-Blacklist {'

    while IFS= read -r package; do
        [ -n "$package" ] || continue
        printf '    "%s";\n' "$package"
    done <<< "$BLACKLIST_PACKAGES"

    echo '};'
} > "$BLACKLIST_BLOCK"

# Validate generated blacklist block.
if ! grep -q 'Unattended-Upgrade::Package-Blacklist' \
    "$BLACKLIST_BLOCK"; then
    echo "ERROR: failed to generate blacklist configuration" >&2
    exit 1
fi

# Replace only the managed capstone blacklist file.
CAPSTONE_APT_CONF="/etc/apt/apt.conf.d/99-meddefense-capstone-blacklist"

if [ ! -f "$CAPSTONE_APT_CONF" ] ||
    ! cmp -s "$BLACKLIST_BLOCK" "$CAPSTONE_APT_CONF"; then

    cp "$BLACKLIST_BLOCK" "$CAPSTONE_APT_CONF"
fi

# ------------------------------------------------------------
# Run previous-project pipeline.
# Required:
# CAPSTONE_ARTIFACTS_DIR=capstone/patch/
# ------------------------------------------------------------
PIPELINE_LOG="$ARTIFACT_DIR/pipeline_stdout.log"
PIPELINE_ERR="$ARTIFACT_DIR/pipeline_stderr.log"

set +e
CAPSTONE_ARTIFACTS_DIR="capstone/patch/" \
CVE_FEED="/home/analyst/MedDefense_Lab/capstone/cve_feed.json" \
"$PIPELINE" \
    >"$PIPELINE_LOG" \
    2>"$PIPELINE_ERR"

PIPELINE_EXIT=$?
set -e

# ------------------------------------------------------------
# Capture every sub-step artifact path
# ------------------------------------------------------------
ARTIFACTS_JSON=$(
    find "$ARTIFACT_DIR" \
        -maxdepth 1 \
        -type f \
        -name '*.json' \
        -print |
        sort |
        jq -R -s '
            split("\n")
            | map(select(length > 0))
        '
)

# ------------------------------------------------------------
# Determine failed_entries
# Prefer patch_execution_log.json if available.
# ------------------------------------------------------------
FAILED_ENTRIES=0

PATCH_LOG="$ARTIFACT_DIR/patch_execution_log.json"

if [ -f "$PATCH_LOG" ] &&
    jq empty "$PATCH_LOG" >/dev/null 2>&1; then

    FAILED_ENTRIES=$(
        jq '
            if (.failed_entries? | type) == "number" then
                .failed_entries
            elif (.failed_count? | type) == "number" then
                .failed_count
            elif (.entries? | type) == "array" then
                [
                    .entries[]
                    | select(
                        (
                            .state //
                            .status //
                            ""
                        ) == "failed"
                    )
                ]
                | length
            elif type == "array" then
                [
                    .[]
                    | select(
                        (
                            .state //
                            .status //
                            ""
                        ) == "failed"
                    )
                ]
                | length
            else
                0
            end
        ' "$PATCH_LOG"
    )
fi

# ------------------------------------------------------------
# Structured capstone summary
# ------------------------------------------------------------
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --arg pipeline "$PIPELINE" \
    --arg cve_feed "$CVE_FEED" \
    --arg blacklist "$BLACKLIST" \
    --arg artifact_dir "$CAPSTONE_ARTIFACTS_DIR" \
    --argjson pipeline_exit_code "$PIPELINE_EXIT" \
    --argjson failed_entries "$FAILED_ENTRIES" \
    --argjson artifacts "$ARTIFACTS_JSON" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        pipeline_script: $pipeline,
        cve_feed: $cve_feed,
        blacklist: $blacklist,
        artifacts_dir: $artifact_dir,
        pipeline_exit_code: $pipeline_exit_code,
        failed_entries: $failed_entries,
        artifacts: $artifacts
    }' > "${SUMMARY}.tmp"

if ! jq empty "${SUMMARY}.tmp" >/dev/null 2>&1; then
    rm -f "${SUMMARY}.tmp"
    echo "ERROR: invalid patch pipeline summary" >&2
    exit 1
fi

mv "${SUMMARY}.tmp" "$SUMMARY"

echo "Pipeline exit code: $PIPELINE_EXIT"
echo "Failed entries: $FAILED_ENTRIES"
echo "Summary: $SUMMARY"

# Requirement:
# exit 0 only if pipeline exit code == 0
# and failed_entries == 0.
if [ "$PIPELINE_EXIT" -eq 0 ] &&
    [ "$FAILED_ENTRIES" -eq 0 ]; then
    exit 0
fi

exit 1
