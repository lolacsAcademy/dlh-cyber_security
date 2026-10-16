
# Rule Validation Report: IR-2026-0414-01

## Test Data

- Incident sample: 17 Sysmon events
- Clean baseline: 21 Sysmon events
- Validation tool: Bash and jq
- False positive target: below 0.1%

## Validation Results

| Detection | Incident matches | Clean matches | False positive rate | Result |
|---|---:|---:|---:|---|
| PowerShell to MSBuild | 2 | 0 | 0.000% | PASS |
| MSBuild network activity (initial) | 2 | 14 | 66.667% | FAIL |
| MSBuild network activity (tuned) | 2 | 0 | 0.000% | PASS |

## Findings

The process detection matched two incident events:

- WST-WS-031: PID 8104 at 02:46:58Z
- WST-WS-017: PID 5108 at 03:27:13Z

No clean process events matched.

The initial network detection matched 14 legitimate MSBuild
connections to api.nuget.org in the clean baseline.

## Tuning Decision

Excluded destination hostnames ending in `.nuget.org`
from the provisional network detection.

After tuning:
- Incident matches remained at 2.
- Clean matches decreased from 14 to 0.
- False positive rate decreased to 0.000%.

The process detection required no tuning.

## Limitations

The tests used jq detection patterns against the provided JSONL
samples, not direct Sigma rule execution.

Only one Sigma rule file currently exists. The network detection
is implemented in validate_rules.sh, not in a second Sigma file.

The small samples cannot establish production false positive rates.
Both patterns require further validation before deployment.
