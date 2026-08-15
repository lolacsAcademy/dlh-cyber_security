#!/bin/bash
# Bash shebang: #!/bin/bash
set -euo pipefail

TARGET_STATE="capstone/target_state.json"
OUT="capstone/validation.json"
TMP_OUT="${OUT}.tmp"

# Exit codes:
# 0 = all controls passed
# 1 = one or more controls failed/errored
# 2 = environment error

for cmd in jq grep bash; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: missing dependency: $cmd" >&2
        exit 2
    fi
done

if [ ! -s "$TARGET_STATE" ]; then
    echo "ERROR: missing target state: $TARGET_STATE" >&2
    exit 2
fi

if ! jq empty "$TARGET_STATE" >/dev/null 2>&1; then
    echo "ERROR: corrupted target_state.json" >&2
    exit 2
fi

if ! jq -e '
    (.controls | type == "array") and
    (.controls | length > 0)
' "$TARGET_STATE" >/dev/null; then
    echo "ERROR: target_state.controls missing or invalid" >&2
    exit 2
fi

mkdir -p "capstone"

RESULTS='[]'
PASS_COUNT=0
FAIL_COUNT=0
ERROR_COUNT=0

get_json_parts() {
    local target="$1"

    JSON_FILE=${target%%:*}
    JSON_FIELD=${target#*:}

    if [ "$JSON_FILE" = "$JSON_FIELD" ]; then
        return 1
    fi

    return 0
}

record_result() {
    local id="$1"
    local platform="$2"
    local family="$3"
    local description="$4"
    local check_type="$5"
    local check_target="$6"
    local expected_json="$7"
    local verdict="$8"
    local evidence="$9"

    local entry

    entry=$(
        jq -n \
            --arg id "$id" \
            --arg platform "$platform" \
            --arg family "$family" \
            --arg description "$description" \
            --arg check_type "$check_type" \
            --arg check_target "$check_target" \
            --arg verdict "$verdict" \
            --arg evidence "$evidence" \
            --argjson expected_value "$expected_json" \
            '{
                id: $id,
                platform: $platform,
                family: $family,
                description: $description,
                check_type: $check_type,
                check_target: $check_target,
                expected_value: $expected_value,
                verdict: $verdict,
                evidence: $evidence
            }'
    )

    RESULTS=$(
        printf '%s\n' "$RESULTS" |
            jq --argjson entry "$entry" '. + [$entry]'
    )

    case "$verdict" in
        pass)
            PASS_COUNT=$((PASS_COUNT + 1))
            ;;
        fail)
            FAIL_COUNT=$((FAIL_COUNT + 1))
            ;;
        error)
            ERROR_COUNT=$((ERROR_COUNT + 1))
            ;;
    esac
}

CONTROL_COUNT=$(jq '.controls | length' "$TARGET_STATE")

for ((i = 0; i < CONTROL_COUNT; i++)); do

    ID=$(jq -r \
        --argjson i "$i" \
        '.controls[$i].id' \
        "$TARGET_STATE")

    PLATFORM=$(jq -r \
        --argjson i "$i" \
        '.controls[$i].platform' \
        "$TARGET_STATE")

    FAMILY=$(jq -r \
        --argjson i "$i" \
        '.controls[$i].family' \
        "$TARGET_STATE")

    DESCRIPTION=$(jq -r \
        --argjson i "$i" \
        '.controls[$i].description' \
        "$TARGET_STATE")

    CHECK_TYPE=$(jq -r \
        --argjson i "$i" \
        '.controls[$i].check_type' \
        "$TARGET_STATE")

    CHECK_TARGET=$(jq -r \
        --argjson i "$i" \
        '.controls[$i].check_target' \
        "$TARGET_STATE")

    EXPECTED_JSON=$(jq -c \
        --argjson i "$i" \
        '.controls[$i].expected_value' \
        "$TARGET_STATE")

    VERDICT="error"
    EVIDENCE=""

    case "$CHECK_TYPE" in

        # ----------------------------------------------------
        # file_exists
        # ----------------------------------------------------
        file_exists)
            if [ -e "$CHECK_TARGET" ]; then
                VERDICT="pass"
                EVIDENCE="$CHECK_TARGET exists"
            else
                VERDICT="fail"
                EVIDENCE="$CHECK_TARGET does not exist"
            fi
            ;;

        # ----------------------------------------------------
        # json_field_equals
        # check_target format:
        # file.json:.field.path
        # ----------------------------------------------------
        json_field_equals)

            if ! get_json_parts "$CHECK_TARGET"; then
                VERDICT="error"
                EVIDENCE="invalid JSON check target: $CHECK_TARGET"

            elif [ ! -s "$JSON_FILE" ]; then
                VERDICT="error"
                EVIDENCE="JSON file missing: $JSON_FILE"

            elif ! jq empty "$JSON_FILE" >/dev/null 2>&1; then
                VERDICT="error"
                EVIDENCE="invalid JSON file: $JSON_FILE"

            else
                set +e

                ACTUAL_JSON=$(jq -c "$JSON_FIELD" "$JSON_FILE" 2>/dev/null)
                JQ_RC=$?

                set -e

                if [ "$JQ_RC" -ne 0 ]; then
                    VERDICT="error"
                    EVIDENCE="unable to evaluate $JSON_FIELD in $JSON_FILE"

                elif [ "$ACTUAL_JSON" = "$EXPECTED_JSON" ]; then
                    VERDICT="pass"
                    EVIDENCE="$JSON_FILE $JSON_FIELD = $ACTUAL_JSON"

                else
                    VERDICT="fail"
                    EVIDENCE="$JSON_FILE $JSON_FIELD = $ACTUAL_JSON, expected $EXPECTED_JSON"
                fi
            fi
            ;;

        # ----------------------------------------------------
        # json_field_gte
        # ----------------------------------------------------
        json_field_gte)

            if ! get_json_parts "$CHECK_TARGET"; then
                VERDICT="error"
                EVIDENCE="invalid JSON check target: $CHECK_TARGET"

            elif [ ! -s "$JSON_FILE" ]; then
                VERDICT="error"
                EVIDENCE="JSON file missing: $JSON_FILE"

            elif ! jq empty "$JSON_FILE" >/dev/null 2>&1; then
                VERDICT="error"
                EVIDENCE="invalid JSON file: $JSON_FILE"

            else
                set +e

                ACTUAL=$(jq -r "$JSON_FIELD // empty" "$JSON_FILE" 2>/dev/null)
                JQ_RC=$?

                set -e

                EXPECTED=$(printf '%s\n' "$EXPECTED_JSON" |
                    jq -r '.')

                if [ "$JQ_RC" -ne 0 ] || [ -z "$ACTUAL" ]; then
                    VERDICT="error"
                    EVIDENCE="numeric field unavailable: $JSON_FILE $JSON_FIELD"

                elif ! [[ "$ACTUAL" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
                    VERDICT="error"
                    EVIDENCE="non-numeric value: $ACTUAL"

                elif awk \
                    -v actual="$ACTUAL" \
                    -v expected="$EXPECTED" \
                    'BEGIN {exit !(actual >= expected)}'; then

                    VERDICT="pass"
                    EVIDENCE="$JSON_FILE $JSON_FIELD = $ACTUAL >= $EXPECTED"

                else
                    VERDICT="fail"
                    EVIDENCE="$JSON_FILE $JSON_FIELD = $ACTUAL < $EXPECTED"
                fi
            fi
            ;;

        # ----------------------------------------------------
        # command_exit_zero
        # Commands originate from trusted target_state.json.
        # ----------------------------------------------------
        command_exit_zero)

            set +e

            COMMAND_OUTPUT=$(
                bash -o pipefail -c "$CHECK_TARGET" 2>&1
            )

            COMMAND_RC=$?

            set -e

            if [ "$COMMAND_RC" -eq 0 ]; then
                VERDICT="pass"

                if [ -n "$COMMAND_OUTPUT" ]; then
                    EVIDENCE="$CHECK_TARGET -> $COMMAND_OUTPUT"
                else
                    EVIDENCE="$CHECK_TARGET -> exit 0"
                fi
            else
                VERDICT="fail"

                if [ -n "$COMMAND_OUTPUT" ]; then
                    EVIDENCE="$CHECK_TARGET -> exit $COMMAND_RC: $COMMAND_OUTPUT"
                else
                    EVIDENCE="$CHECK_TARGET -> exit $COMMAND_RC"
                fi
            fi
            ;;

        # ----------------------------------------------------
        # grep_match
        # ----------------------------------------------------
        grep_match)

            EXPECTED_REGEX=$(printf '%s\n' "$EXPECTED_JSON" |
                jq -r '.')

            if [ ! -f "$CHECK_TARGET" ]; then
                VERDICT="error"
                EVIDENCE="grep target missing: $CHECK_TARGET"

            else
                set +e

                MATCH=$(
                    grep -E \
                        -m 1 \
                        "$EXPECTED_REGEX" \
                        "$CHECK_TARGET" 2>/dev/null
                )

                GREP_RC=$?

                set -e

                case "$GREP_RC" in
                    0)
                        VERDICT="pass"
                        EVIDENCE="$CHECK_TARGET -> $MATCH"
                        ;;

                    1)
                        VERDICT="fail"
                        EVIDENCE="$CHECK_TARGET -> no match for $EXPECTED_REGEX"
                        ;;

                    *)
                        VERDICT="error"
                        EVIDENCE="$CHECK_TARGET -> grep error"
                        ;;
                esac
            fi
            ;;

        *)
            VERDICT="error"
            EVIDENCE="unsupported check_type: $CHECK_TYPE"
            ;;
    esac

    record_result \
        "$ID" \
        "$PLATFORM" \
        "$FAMILY" \
        "$DESCRIPTION" \
        "$CHECK_TYPE" \
        "$CHECK_TARGET" \
        "$EXPECTED_JSON" \
        "$VERDICT" \
        "$EVIDENCE"
done

# ------------------------------------------------------------
# Aggregate results
# ------------------------------------------------------------

TOTAL_CONTROLS=$((PASS_COUNT + FAIL_COUNT + ERROR_COUNT))

if [ "$TOTAL_CONTROLS" -gt 0 ]; then
    PASS_PERCENTAGE=$(
        awk \
            -v passed="$PASS_COUNT" \
            -v total="$TOTAL_CONTROLS" \
            'BEGIN {printf "%.2f", (passed / total) * 100}'
    )
else
    PASS_PERCENTAGE="0.00"
fi

FAMILY_SUMMARY=$(
    printf '%s\n' "$RESULTS" |
        jq '
            group_by(.family)
            | map({
                family: .[0].family,
                total: length,
                pass: (
                    [
                        .[]
                        | select(.verdict == "pass")
                    ]
                    | length
                ),
                fail: (
                    [
                        .[]
                        | select(.verdict == "fail")
                    ]
                    | length
                ),
                error: (
                    [
                        .[]
                        | select(.verdict == "error")
                    ]
                    | length
                )
            })
        '
)

if [ "$FAIL_COUNT" -eq 0 ] &&
    [ "$ERROR_COUNT" -eq 0 ]; then
    VERDICT="pass"
else
    VERDICT="fail"
fi

# ------------------------------------------------------------
# Machine-readable report
# ------------------------------------------------------------

jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --arg target_state "$TARGET_STATE" \
    --arg verdict "$VERDICT" \
    --argjson total_controls "$TOTAL_CONTROLS" \
    --argjson pass_count "$PASS_COUNT" \
    --argjson fail_count "$FAIL_COUNT" \
    --argjson error_count "$ERROR_COUNT" \
    --argjson pass_percentage "$PASS_PERCENTAGE" \
    --argjson family_summary "$FAMILY_SUMMARY" \
    --argjson controls "$RESULTS" \
    '{
        generated_at: $generated_at,
        hostname: $hostname,
        target_state: $target_state,
        verdict: $verdict,
        summary: {
            total_controls: $total_controls,
            pass_count: $pass_count,
            fail_count: $fail_count,
            error_count: $error_count,
            pass_percentage: $pass_percentage
        },
        families: $family_summary,
        controls: $controls
    }' > "$TMP_OUT"

if ! jq empty "$TMP_OUT" >/dev/null 2>&1; then
    rm -f "$TMP_OUT"
    echo "ERROR: generated validation JSON is invalid" >&2
    exit 2
fi

mv "$TMP_OUT" "$OUT"

# ------------------------------------------------------------
# Clean family table
# ------------------------------------------------------------

echo
printf '%-15s %8s %8s %8s %8s\n' \
    "FAMILY" "TOTAL" "PASS" "FAIL" "ERROR"

printf '%-15s %8s %8s %8s %8s\n' \
    "---------------" "--------" "--------" "--------" "--------"

printf '%s\n' "$FAMILY_SUMMARY" |
    jq -r '
        .[]
        | [
            .family,
            (.total | tostring),
            (.pass | tostring),
            (.fail | tostring),
            (.error | tostring)
        ]
        | @tsv
    ' |
    while IFS=$'\t' read -r family total passed failed errors; do
        printf '%-15s %8s %8s %8s %8s\n' \
            "$family" \
            "$total" \
            "$passed" \
            "$failed" \
            "$errors"
    done

echo
echo "Total controls:  $TOTAL_CONTROLS"
echo "Pass:            $PASS_COUNT"
echo "Fail:            $FAIL_COUNT"
echo "Error:           $ERROR_COUNT"
echo "Pass percentage: ${PASS_PERCENTAGE}%"
echo "Report saved to: $OUT"

if [ "$VERDICT" = "pass" ]; then
    echo "VERDICT: PASS"
    exit 0
fi

echo "VERDICT: FAIL"

echo
echo "Failing controls:"

printf '%s\n' "$RESULTS" |
    jq -r '
        .[]
        | select(
            .verdict == "fail" or
            .verdict == "error"
        )
        | "\(.id) [\(.verdict)] -> \(.evidence)"
    '

exit 1
