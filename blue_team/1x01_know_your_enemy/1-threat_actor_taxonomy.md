# Threat Actor Taxonomy

## Report A:
  Actor Type: Nation-state
  Internal/External: External
  Resources: High — zero-day, stolen code-signing cert
  Sophistication: High — custom RAT, encrypted DNS C2
  Primary Motivation: Espionage (IP/data theft)
  Confidence Level: High — 14mo dwell + custom tooling = APT signature

## Report B:
  Actor Type: Organized crime (RaaS)
  Internal/External: External
  Resources: Medium — commercial RAT, known vuln
  Sophistication: Medium — off-the-shelf tools, known exploit
  Primary Motivation: Financial gain
  Confidence Level: High — double extortion + ransom demand pattern

## Report C:
  Actor Type: Hacktivist
  Internal/External: External
  Resources: Low — SQLi, defacement only
  Sophistication: Low — no lateral movement, basic exploit
  Primary Motivation: Political/philosophical belief
  Confidence Level: High — activist logo, protest message, no data theft

## Report D:
  Actor Type: Insider threat (malicious)
  Internal/External: Internal
  Resources: Low — used existing access, no special tools
  Sophistication: Medium — planned ahead (rogue VPN acct, disabled backup)
  Primary Motivation: Revenge
  Confidence Level: High — timing tied directly to termination
## Report E:
  Actor Type: Unskilled attacker
  Internal/External: External
  Resources: Low — public mining tool
  Sophistication: Low — automated exploit of known CVE
  Primary Motivation: Financial gain (mining)
  Confidence Level: High — mass infection across 300+ orgs, not targeted

## Report F:
  Actor Type: Shadow IT
  Internal/External: Internal
  Resources: Low — personal device, no funding
  Sophistication: Low — default creds, no expertise involved
  Primary Motivation: None — negligent, not malicious (personal convenience)
  Confidence Level: High — employee admitted intent, no malice

## Report G: — Ambiguous
  Actor Type: Insider (malicious) OR Organized crime — both fit.

  Insider case: physician's own credentials misused, account compromised or shared. Internal, Low resources, Low-Medium sophistication, Motivation: financial gain (data resale) or insurance fraud prep.

  Organized crime case: external actor using stolen physician credentials. External, Medium resources (credential theft/brokering), Medium sophistication, Motivation: financial gain.

  Confidence Level: Low — evidence supports either.

  To distinguish: check login device/geolocation fingerprint vs physician's real location, look for phishing/credential-theft hitting that physician, monitor dark web for the data surfacing, run network forensics on the source IP (VPN/proxy vs residential).

## Report H:
  Actor Type: Organized crime (extortion)
  Internal/External: External
  Resources: Low-Medium — no custom tools, Tor for anonymity
  Sophistication: Low-Medium — exploited known internal bug, not zero-day
  Primary Motivation: Financial gain / blackmail
  Confidence Level: Medium — extortion pattern clear, actor sophistication unconfirmed
