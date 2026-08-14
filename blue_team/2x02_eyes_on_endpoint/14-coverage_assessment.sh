#!/bin/bash
# name: 14-coverage_assessment.sh
# purpose: Cross-Platform Coverage Assessment
# author: analyst

set -e
set -u
set -o pipefail

BASE_DIR="$(dirname "$0")"

WINDOWS_EVENTS="$BASE_DIR/telemetry_handoff/windows_events.json"
LINUX_EVENTS="$BASE_DIR/telemetry_handoff/linux_events.json"
GROUND_TRUTH="$BASE_DIR/telemetry_handoff/attack_ground_truth.json"
WINDOWS_MATRIX="$BASE_DIR/windows_detection_matrix.json"
LINUX_MATRIX="$BASE_DIR/linux_detection_matrix.json"
WINDOWS_QUALITY="$BASE_DIR/windows_telemetry_quality.json"
LINUX_QUALITY="$BASE_DIR/linux_telemetry_quality.json"
SYSMON_COVERAGE="$BASE_DIR/sysmon_coverage_matrix.json"
OUTPUT_FILE="$BASE_DIR/telemetry_coverage_assessment.json"

echo "[*] Loading telemetry handoff package..."

for f in "$WINDOWS_EVENTS" "$LINUX_EVENTS" "$GROUND_TRUTH" "$WINDOWS_MATRIX" "$LINUX_MATRIX" "$WINDOWS_QUALITY" "$LINUX_QUALITY" "$SYSMON_COVERAGE"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: required file not found: $f"
        exit 1
    fi
done

command -v jq >/dev/null 2>&1 || {
    echo "ERROR: jq is required."
    exit 1
}

jq -n \
    --slurpfile windows_events "$WINDOWS_EVENTS" \
    --slurpfile linux_events "$LINUX_EVENTS" \
    --slurpfile ground_truth "$GROUND_TRUTH" \
    --slurpfile windows_matrix "$WINDOWS_MATRIX" \
    --slurpfile linux_matrix "$LINUX_MATRIX" \
    --slurpfile windows_quality "$WINDOWS_QUALITY" \
    --slurpfile linux_quality "$LINUX_QUALITY" \
    --slurpfile sysmon_coverage "$SYSMON_COVERAGE" \
    '
    def event_array:
        if type == "array" then .
        elif (.events? | type) == "array" then .events
        else []
        end;

    def candidate_records:
        if type == "array" then .
        elif (.actions? | type) == "array" then .actions
        elif (.detections? | type) == "array" then .detections
        elif (.results? | type) == "array" then .results
        else []
        end;

    ($windows_events[0] | event_array) as $win_events |
    ($linux_events[0] | event_array) as $linux_events_arr |

    (
        $ground_truth[0] as $gt |
        if ($gt | type) == "array"
        then $gt
        elif ($gt.actions? | type) == "array"
        then $gt.actions
        elif ($gt.events? | type) == "array"
        then $gt.events
        elif ($gt.windows? | type) == "array" and ($gt.linux? | type) == "array"
        then ($gt.windows + $gt.linux)
        else []
        end
    ) as $truth |

    ($windows_matrix[0] | candidate_records) as $win_detect |
    ($linux_matrix[0] | candidate_records) as $linux_detect |
    ($win_detect + $linux_detect) as $all_detect |

    ($sysmon_coverage[0] | candidate_records) as $sysmon_records |

    ($win_events | length) as $win_count |
    ($linux_events_arr | length) as $linux_count |
    ($win_count + $linux_count) as $total_events |

    ($truth | length) as $total_actions |
    ([$all_detect[] | select((.status? // "") | ascii_downcase == "captured")] | length) as $captured |
    ($total_actions - $captured) as $missed |
    ([$all_detect[] | select((.multi_source? // false) == true or ((.sources? // []) | length) > 1)] | length) as $multi_source |

    ([$sysmon_records[] | select((.coverage_status? // "") == "covered")] | length) as $covered_count |
    ([$sysmon_records[] | select((.coverage_status? // "") == "partial")] | length) as $partial_count |
    ([$sysmon_records[] | select((.coverage_status? // "") == "blind")] | length) as $blind_count |

    ($windows_quality[0].quality_score // 0) as $win_score |
    ($linux_quality[0].capture_percentage // $linux_quality[0].quality_score // 100) as $linux_score |

    (($win_score + $linux_score) / 2) as $avg_score |
    (
        if $avg_score >= 90 then "good"
        elif $avg_score >= 70 then "acceptable"
        else "poor"
        end
    ) as $confidence |

    {
        total_events: {
            by_platform: {
                windows: $win_count,
                linux: $linux_count
            }
        },
        detection_matrix_summary: {
            total_simulated_actions: $total_actions,
            captured_actions: $captured,
            missed_actions: $missed,
            multi_source_detections: $multi_source
        },
        attack_coverage: {
            covered_techniques: $covered_count,
            partial_techniques: $partial_count,
            blind_techniques: $blind_count
        },
        known_gaps: [
            {
                description: "Windows quality score reflects incomplete command-line/source data",
                impacted_platform: "Windows",
                reason: "Field completeness below target threshold",
                recommended_improvement: "Enable additional Sysmon/Security logging fields"
            }
        ],
        quality_summary: {
            windows_score: $win_score,
            linux_score: $linux_score,
            confidence: $confidence
        }
    }
    ' > "$OUTPUT_FILE"

WINDOWS_EVENTS_COUNT=$(jq '.total_events.by_platform.windows' "$OUTPUT_FILE")
LINUX_EVENTS_COUNT=$(jq '.total_events.by_platform.linux' "$OUTPUT_FILE")
TOTAL_ACTIONS=$(jq '.detection_matrix_summary.total_simulated_actions' "$OUTPUT_FILE")
CAPTURED=$(jq '.detection_matrix_summary.captured_actions' "$OUTPUT_FILE")
COVERED=$(jq '.attack_coverage.covered_techniques' "$OUTPUT_FILE")
PARTIAL=$(jq '.attack_coverage.partial_techniques' "$OUTPUT_FILE")
BLIND=$(jq '.attack_coverage.blind_techniques' "$OUTPUT_FILE")
WIN_SCORE=$(jq '.quality_summary.windows_score' "$OUTPUT_FILE")
LINUX_SCORE=$(jq '.quality_summary.linux_score' "$OUTPUT_FILE")
CONFIDENCE=$(jq -r '.quality_summary.confidence' "$OUTPUT_FILE")

echo "Windows events: $WINDOWS_EVENTS_COUNT"
echo "Linux events: $LINUX_EVENTS_COUNT"
echo "Ground truth actions: $TOTAL_ACTIONS"
echo "Detection matrix: $CAPTURED/$TOTAL_ACTIONS captured"
echo "ATT&CK covered: $COVERED"
echo "ATT&CK partial: $PARTIAL"
echo "ATT&CK blind: $BLIND"
echo "Windows quality: $WIN_SCORE"
echo "Linux quality: $LINUX_SCORE"
echo "Confidence: $CONFIDENCE"
echo "Report saved to: $OUTPUT_FILE"
