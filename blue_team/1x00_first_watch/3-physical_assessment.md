# MedDefense — Physical Security Risk Decomposition (MedDefense Central)

## Observation 1: Server Room Access

Vulnerability: The server room, which houses core infrastructure for the entire hospital, is accessed with the same generic badge issued to every employee — clinical, administrative, and custodial — with no camera on the door and no visitor log.

Threat: Any badge holder, including staff with no legitimate business in the server room, can enter unsupervised and unrecorded. A lost, stolen, or cloned badge — or simple tailgating through the shared cafeteria corridor — grants the same access.

Impact: Confidentiality (physical access to data-bearing servers), Integrity (tampering with servers, e.g. planting the kind of persistence mechanism seen on billing-srv-01), and Availability (physical damage, unplugging, or theft of hardware running the EHR, billing, and PACS).

Severity: Critical — this single unmonitored, unrestricted room houses nearly all of MedDefense's critical infrastructure at once.

## Observation 2: Network Closet

Vulnerability: A second-floor network closet containing switches and patch panels has no lock, the door was found ajar, and a laminated sheet with the switch management username and password is taped to the wall inside.

Threat: Anyone who happens to open the unlocked door — an employee, contractor, or visitor who wanders in — can read the credentials on the wall and log directly into the switch management interface with full administrative access.

Impact: Confidentiality (traffic interception via port mirroring), Integrity (reconfiguring VLANs or switch settings), and Availability (disabling ports or the switch itself, taking down network segments).

Severity: Critical — physical access plus visible admin credentials removes every barrier between a casual passerby and full control of the network switching layer.

## Observation 3: Nurse Station

Vulnerability: A third-floor nurse station workstation is logged into the EHR with a patient record on screen, unattended and idle for at least 15 minutes, under a sign that actively instructs staff not to log out between shifts.

Threat: Any passerby — another patient, a visitor, or a staff member without a treatment relationship to that patient — can read or alter the visible record. Because the "stay logged in" practice is posted as policy, this is not a one-off lapse but a routine condition at every shift change.

Impact: Confidentiality (unauthorized viewing of PHI, a direct HIPAA exposure) and Integrity (an unattended, authenticated session could be used to alter the patient record).

Severity: Critical — this is an active, ongoing PHI exposure sanctioned by official signage, not a rare or theoretical event.

## Observation 4: Medical IoT (Vital Signs Monitor)

Vulnerability: A connected vital signs monitor is running firmware last updated in 2019 and sits on the same IP range/network segment as ordinary staff workstations.

Threat: An attacker who compromises any workstation on that shared segment (e.g. via phishing, the same entry vector suspected on billing-srv-01) could pivot to the monitor and exploit its several-years-unpatched firmware.

Impact: Integrity (falsified vital sign readings leading to incorrect clinical decisions) and Availability (the device could be disabled or made to malfunction) — both with direct, immediate patient safety consequences.

Severity: Critical — unpatched medical devices reachable from the general user network create a direct path from a routine phishing compromise to patient physical harm.

## Observation 5: Emergency Exit

Vulnerability: A fire exit between the public waiting area and the restricted administrative wing is deliberately propped open with a wedge, with a handwritten sign indicating this is routine practice for staff passage.

Threat: Any member of the public in the waiting area — a patient, a visitor, or someone with malicious intent posing as either — can walk unchallenged past this defeated barrier directly toward the IT department and executive offices.

Impact: Confidentiality is the primary concern (unauthorized physical access to IT and administrative areas, and any unattended systems or documents inside them); it could also enable follow-on Integrity or Availability impacts if the person reaches IT infrastructure.

Severity: High — the access path is serious and leads directly to IT, but unlike Observation 3, it requires an outside actor to actively notice and use the opportunity rather than being a continuously realized exposure.
