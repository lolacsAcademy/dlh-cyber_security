# MedDefense — Predecessor's Notes Review

## Part 1: Comparative Analysis

| Finding | Marcus's Assessment | My Assessment | Agree/Disagree | Resolution |
|---|---|---|---|---|
| M-01 Segmentation | Critical, $25-40K, 3-6mo | GAP-011, Critical | Agree | Same finding. Cost differs ($76.6K Phase-1 vs his $25-40K full-scope) — his labor-only estimate is likely more accurate; will revise Task 14 budget note. |
| M-02 Backup isolation | Critical, $14,400/yr | GAP-010, Critical | Agree | Identical finding, same quote, same source (Artifact 5). |
| M-03 Medical IoT | High (potentially Critical) | GAP-001, Critical | Partially agree | He hedged; I committed to Critical given the confirmed CVE and patient-safety framing. Keeping Critical. |
| M-04 No monitoring/SIEM | High | Scattered across GAP-001/002/005/011, no own ID | Valid, missed | New gap added: GAP-014. |
| M-05 No MFA | High | GAP-012 (bundled with offboarding) | Agree | Already covered; his version isolates MFA specifically — noted. |
| M-06 Westside security | High | Task 5 G-006 (physical) + GAP-011 (network) | Agree, split | Same substance, split across two of my entries instead of one combined finding. |
| M-07 Shared PACS login | Medium (on-site only) | GAP-008, Critical | Disagree | His on-site-only point is real for external threats, but doesn't remove insider/on-site accountability risk. Keeping Critical. |
| M-08 print-srv-01 EOL | Low | Not in Task 12 | Valid, missed | New gap added: GAP-015, Low, matches his own reasoning. |
## Undocumented items — validity check

- DLP + unrestricted USB: valid, real Restricted-data exfiltration risk. New gap added: GAP-016.
- TLS 1.0 on patient portal: valid but minor, quick fix — noted, not a full gap entry.
- HQ landlord-managed network blind spot: valid, but MedDefense has no control over it — noted as a vendor-risk item, not a control gap.
- No change management process: valid — this caused the 3-week backup cron failure (Task 0). Noted, not a new gap since it's a root cause behind GAP-002 and GAP-010.

## Findings Marcus missed (that I identified)

- Shadow IT (Task 11: Dr. Patel's NAS, Marketing Google Drive, orphaned Pi) — likely discovered after Marcus left; Mike Torres told me directly, no sign Marcus knew.
- Two unidentified network devices (Task 7 scan) — the scan was commissioned after Marcus left; he never had this data.
- ad-dc-02 specifically excluded from backup (GAP-004) — his M-02 covers backups broadly but doesn't call this out individually.

## New Gaps Added From This Review

- GAP-014 — No centralized monitoring/SIEM. Critical. Technical/Detective. Matches M-04; already implicit across other gaps but never had its own entry.
- GAP-015 — print-srv-01 end-of-life. Low. Technical/Preventive. Matches M-08 exactly, including his own low-priority reasoning.
- GAP-016 — No DLP, unrestricted USB ports. High. Technical/Preventive. Restricted data can leave via email, USB, or cloud upload with zero detection.

## Part 2: Reflection

My internal assessment shows a small number of foundational gaps — the flat network (GAP-011), no MFA (GAP-012), and now no monitoring (GAP-014) — feeding almost every other Critical finding, and Task 13's reality check already confirmed this exact combination caused a real hospital breach. Marcus was right that internal posture is only half the picture: it shows what could be exploited, not who is likely to target MedDefense or how. A threat landscape assessment — actor categories, MITRE ATT&CK TTPs, a STRIDE pass over the architecture — would tell us whether to expect opportunistic ransomware-as-a-service (his own hypothesis, and the most likely one) or something more targeted, which changes how urgently the Task 14 remediation plan should be sequenced. This is the natural next phase of the project, picking up exactly where Marcus stopped.
