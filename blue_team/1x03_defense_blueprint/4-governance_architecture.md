# Task 4 — The Governance Architecture

## Part 1 — RACI Matrix

| Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst (You) |
|---|---|---|---|---|---|
| Security budget approval | A | R | C | C | I |
| Vulnerability remediation | I | A | R | I | R |
| Incident response execution | I | A | R | I | R |
| Security policy approval | A | R | C | C | I |
| Risk acceptance decisions | A | R | C | C | I |
| Security awareness training | I | A | C | R | R |
| Vendor risk assessment | I | A | C | C | R |
| Audit coordination | I | A | C | C | R |

**R** = Responsible (does the work) · **A** = Accountable (owns the outcome, signs off) · **C** = Consulted (input sought before action) · **I** = Informed (kept updated after the fact)

Reasoning notes:
- The CEO is Accountable for budget, policy, and risk acceptance because no CISO exists — these are the exact decisions James's own concern describes as currently contested; a single named Accountable owner ends the "whoever shouts loudest" problem.
- Vulnerability remediation and incident response carry two Responsible parties (IT Director + Security Analyst) because technical execution genuinely splits between infrastructure changes (Sarah's team) and security-specific action (you) — this reflects reality rather than forcing an artificial single owner.
- Dept Heads are Responsible for training completion in their own departments (not Consulted) because compliance depends on them enforcing it locally, not just being informed.

## Part 2 — Role Definitions

**Data Owner** — Department Heads (e.g., Dr. Patel for Cardiology data, the CFO for financial data). The Data Owner is the business-side individual accountable for classifying data, deciding who may access it, and approving exceptions. James's own example — Dr. Patel believing he can do "whatever he wants with his data" — is a Data Owner overstepping into decisions (technical control implementation) that belong to the Custodian role instead; the fix is not removing his ownership, but clarifying its boundary.

**Data Controller** — MedDefense Health Systems as the legal organization, represented by the CEO/Board. The Controller is the entity that determines *why* and *how* patient data is processed overall — it holds ultimate legal and regulatory responsibility (the equivalent role a HIPAA Covered Entity holds), which is why risk acceptance in Part 1 sits with the CEO.

**Data Processor** — Third-party vendors who handle MedDefense data under contract (e.g., the vendors reviewed in 1x00: MedTech, Microsoft, Sophos, Siemens, Greenfield). A Processor acts only on the Controller's instructions and has no independent right to decide how the data is used — this is why Part 1 places Vendor Risk Assessment as Security-Analyst-Responsible, CISO-Accountable: someone must verify each Processor is actually staying within that boundary.

**Data Custodian/Steward** — IT Director (Sarah) and the Security Analyst. The Custodian implements the technical safeguards (backups, access controls, encryption) that carry out the Data Owner's classification decisions. This is the exact distinction missing in James's conflict: Sarah manages the endpoints (Custodian function) but that does not make her the Owner of endpoint security policy — that decision authority sits with the Deputy CISO/CEO per Part 1.

## Part 3 — The CISO Question

**Consequences of the vacancy:** The RACI conflict James describes — Sarah, James, and Dr. Patel each claiming ownership of the same function — is a direct, predictable symptom of having no single Accountable executive for security. This same vacancy explains the Task 1 finding that the Govern function is only Partial: without a CISO, MedDefense has never had one person whose job it is to approve policy, own Board-level risk reporting, and resolve exactly this kind of ownership dispute. Left unresolved, it means slower incident response (no clear decision-maker during a crisis), inconsistent risk acceptance (different people making different calls with no accountable check), and continued exposure to the same governance gap that let 1x00's findings go unaddressed for as long as they did.

**Recommendation: vCISO (outsourced/fractional), not a full-time hire.** A full-time CISO in a regulated healthcare environment typically commands a salary well into six figures — a cost that would consume most or all of the $120,000 technical remediation budget on a single hire, leaving little or nothing for the segmentation, backup isolation, MFA, and logging work the gap analysis already identified as urgent. A vCISO engagement costs a small fraction of that annually, provides the same strategic authority to approve policy, own risk acceptance, and resolve exactly the ownership conflicts James is describing, and lets James continue running day-to-day execution as Deputy under that strategic direction — preserving the technical budget for the fixes MedDefense actually needs first. A full-time CISO hire should be revisited once the highest-priority technical gaps are closed and the security program has grown enough to justify a permanent in-house executive.
