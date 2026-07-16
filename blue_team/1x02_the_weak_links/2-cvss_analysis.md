# Task 2 — The CVSS Deconstruction

## Exercise 1: Deconstruction

Vector (Finding 001, CVE-2021-44790): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**AV — Attack Vector: N (Network)**
Stands for how remote the attacker can be. Value N means the flaw is exploitable over a network connection, from anywhere the vulnerable service is reachable, without local or physical access.
Other values: A (Adjacent — attacker must be on the same local/logical network segment), L (Local — attacker needs local access, e.g. a shell on the box), P (Physical — attacker must physically touch the device). Moving from N to any other value lowers the score, since fewer attackers can reach the target.
Selected because: this is an HTTP request-based buffer overflow in mod_lua. An attacker anywhere that can reach port 80 can send the crafted request; no local presence is needed.

**AC — Attack Complexity: L (Low)**
Stands for how much extra effort or luck the attack needs. Low means the attacker can succeed reliably, on demand, with no special conditions.
Other value: H (High) — the attacker needs to defeat extra protections or gather specific information first. High lowers the score.
Selected because: a single crafted HTTP request triggers the overflow; no race condition, no bypass of another control, no waiting for a specific state.

**PR — Privileges Required: N (None)**
Stands for what access level the attacker needs before the attack. None means no account or authentication is needed at all.
Other values: L (Low — basic user privileges needed), H (High — admin-level privileges needed). Both lower the score.
Selected because: mod_lua's request parser is reached before any login; the endpoint is public.

**UI — User Interaction: N (None)**
Stands for whether a victim user must do something (click a link, open a file) for the attack to work. None means the attacker alone is enough.
Other value: R (Required) — lowers the score, since a victim must act.
Selected because: the attacker sends the malicious request directly to the server; no other person is involved.
**S — Scope: U (Unchanged)**
Stands for whether the impact stays inside the vulnerable component's own security authority, or spreads to another component with different privileges. Unchanged means the damage is contained to the thing that was attacked.
Other value: C (Changed) — the exploit reaches beyond its own authority (e.g. escapes a sandbox). Changed generally raises the score.
Selected because: the overflow affects the Apache process itself; it doesn't cross into a separate security boundary.

**C — Confidentiality Impact: H (High)**
Stands for how much data exposure results from the attack. High means the attacker can read all data accessible to the compromised component.
Other values: L (Low — partial exposure), N (None). Both lower the score.
Selected because: a successful buffer overflow here enables arbitrary code execution, giving the attacker full read access to whatever the web server process can read.

**I — Integrity Impact: H (High)**
Stands for how much the attacker can modify data. High means the attacker can change any data the component controls.
Other values: L (Low), N (None). Both lower the score.
Selected because: code execution as the server process also allows arbitrary modification of files/data it can write.

**A — Availability Impact: H (High)**
Stands for how much the attacker can deny service. High means the attacker can fully shut the component down.
Other values: L (Low), N (None). Both lower the score.
Selected because: code execution allows the attacker to crash or kill the server process at will.

### If Attack Vector changed from Network (N) to Local (L)

New vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Calculated Base Score: **8.4 (High)** — down from 9.8 (Critical).

Why it changes: Attack Vector feeds directly into the Exploitability sub-score. Network access is scored 0.85 (the highest possible), while Local access is scored 0.55. Lowering this one value shrinks the Exploitability sub-score, which lowers the overall Base Score, because far fewer attackers can reach a target that now requires local access instead of anywhere on the network. The Impact sub-score (confidentiality/integrity/availability) is unaffected, since the damage a successful attack could do doesn't change — only the practical attacker pool does.
## Exercise 2: Construction

Given characteristics:
- Exploitable only from the local network (not the internet) → **AV:A** (Adjacent Network — limited to a shared network segment, not internet-reachable)
- Exploitation is complex, requires specific conditions → **AC:H**
- Attacker needs low-level privileges → **PR:L**
- No user interaction needed → **UI:N**
- Scope unchanged → **S:U**
- Confidentiality completely compromised → **C:H**
- No impact on integrity → **I:N**
- No impact on availability → **A:N**

Constructed vector: CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N

Calculated Base Score: **4.8**
Severity Rating: **Medium** (CVSS v3.1 band: 4.0–6.9)
## Exercise 3: Comparison

The report has no finding scored between 5.0–7.0 (its scores are 9.8, 7.8, 8.1, 9.8, 10.0, 7.5, 8.8, 7.5, 9.8, 9.8). Finding 006 (MySQL unrestricted network binding) has no CVE, so it was scored here using the same NIST Calculator method as Exercise 2.

**Finding 001 — 9.8 (Critical)**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**Finding 006 — 6.5 (Medium, self-scored)**
CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
(AV:A — internal network only; PR:N — binding flaw needs no auth to reach; C:H — financial data exposed; I:N/A:N — no modify/deny capability, read-only exposure)

**Component differences:** Attack Vector (N vs A) and both Integrity/Availability impact (H/H vs N/N). Finding 001 allows remote code execution (full C/I/A); Finding 006 is a network-exposure misconfiguration limited to data disclosure only.

**Biggest impact on score:** the Impact metrics. Dropping Integrity and Availability from High to None removes far more score than the Attack Vector change alone — full RCE vs. read-only exposure is the main driver of the 3.3-point gap, not just how remote the attacker needs to be.

