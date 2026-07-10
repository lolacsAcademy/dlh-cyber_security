# The Human Vector — Social Engineering Analysis

## Scenario 1 — FortiGate Firmware Email
Vector Type: Phishing (with brand impersonation)
Target: Sarah Park, IT Director — directly responsible for the device named
Psychological Lever: Urgency (24h deadline, threat of service termination)
Red Flags: Sender domain fortinet-support.net, not fortinet.com; unsolicited emergency-patch link; vendors don't push firmware patches via email links
Technical Control: Email gateway with domain reputation checks + link sandboxing
Administrative Control: Policy — vendor patches only via official vendor portal, verify via ticket/callback first

## Scenario 2 — CEO Wire Transfer
Vector Type: Business Email Compromise (BEC)
Target: Robert Kim, CFO — has payment authority, targeted via fake authority + secrecy
Psychological Lever: Authority + Urgency
Red Flags: Sender address subtly different from real CEO; urgency + instruction to keep it secret; request bypasses normal approval process
Technical Control: DMARC/anti-spoofing enforcement on email domain
Administrative Control: Dual-approval + out-of-band callback verification for wire transfers over a set amount

## Scenario 3 — Mike from IT Phone Call
Vector Type: Vishing (with pretexting)
Target: Nurse — trusts IT authority, primed by recent real incident (billing-srv-01)
Psychological Lever: Authority + Helpfulness
Red Flags: Legit IT never asks for a spoken password; caller not verified via known extension; fake "emergency audit" framing right after a real breach
Technical Control: MFA — a spoken password alone becomes useless
Administrative Control: Policy — IT never asks for passwords by phone; mandatory callback verification for any credential request
## Scenario 4 — Parking Permit Smishing
Vector Type: Smishing
Target: All employees — routine bureaucratic topic + fear of towing
Psychological Lever: Urgency / Fear
Red Flags: Unsolicited SMS demanding immediate action; link not on official MedDefense domain; page not behind real SSO
Technical Control: SSO + MFA so a harvested password alone doesn't grant access
Administrative Control: Awareness training on smishing; official comms only via known channels, never SMS links

## Scenario 5 — CME Association Watering Hole
Vector Type: Watering hole attack
Target: MedDefense physicians — trust a routine external site outside MedDefense's control
Psychological Lever: Familiarity
Red Flags: Unexpected redirect after visiting a normally trusted site; unusual pop-ups/downloads; site behaves differently than prior visits
Technical Control: Web filtering/EDR with exploit protection on all endpoints
Administrative Control: Keep browsers/plugins patched org-wide; restrict which external sites clinical devices can reach

## Scenario 6 — Typosquatted Patient Portal
Vector Type: Typosquatting (with brand impersonation)
Target: Patients/staff searching for the portal — trust top search-ad result
Psychological Lever: Familiarity
Red Flags: Misspelled domain (defence vs defense); paid ad above the real organic result; URL doesn't match the known bookmarked portal
Technical Control: DNS filtering blocking known typosquat domains
Administrative Control: Brand-monitoring service to flag lookalike domains; patient education to bookmark the official URL
## Scenario 7 — Tailgating in Scrubs
Vector Type: Pretexting (physical tailgating)
Target: Staff member holding the badge door — social norm of helpfulness toward a "colleague"
Psychological Lever: Helpfulness / Familiarity
Red Flags: Visitor badge expired 2 days ago; badge partially hidden; no independent ID check before the door was held
Technical Control: Anti-tailgating mantrap/turnstile requiring individual badge tap per person
Administrative Control: Policy — no tailgating, staff required to challenge/report unbadged individuals
