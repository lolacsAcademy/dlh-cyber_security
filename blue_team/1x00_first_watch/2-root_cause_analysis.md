# MedDefense — Root Cause Analysis (billing-srv-01)

## 1. Identifying the process

The process named "kworker" is not the real Linux kworker. Genuine kworker processes are kernel threads: they run as root, show up wrapped in brackets (e.g. [kworker/0:1]), and have no associated file on disk. This one is a real executable file at /var/www/html/.cache/kworker, running as the low-privilege www-data user — the same account Apache runs as. The name was chosen deliberately to blend into a normal process list.

The connection to stratum+tcp://pool.monero.org:4443 confirms what it actually is: "stratum" is the standard protocol cryptocurrency miners use to submit work to a mining pool, and Monero is the cryptocurrency being mined. The config.json file confirms this further — it lists three mining pools and a wallet address to receive payouts.

**Purpose:** this is a cryptomining malware (cryptojacker). It hijacks the server's CPU to mine Monero for whoever controls that wallet address, at MedDefense's expense.

## 2. The real compromise, before Availability was affected

**Integrity:** The attacker placed and executed an unauthorized file on the server (the fake kworker binary and its config), disguised to look like a legitimate system process. Unauthorized software running on a system is, by definition, an unauthorized modification of that system — this is an Integrity violation, and it happened before any performance symptoms appeared.

**Confidentiality:** The miner runs as www-data, meaning it entered through the Apache web application, not through a legitimate login. That means an unauthorized party gained code execution on a server that stores billing and claims data. Whether or not data was actually exfiltrated, the attacker had the access needed to read that data — the exposure risk exists the moment unauthorized access is achieved, not only if theft is later proven.

CPU saturation (Availability) is the visible symptom, but it is the last thing that happened, not the first. Integrity and Confidentiality were both already compromised before the server ever became slow.

## 3. Why the sysadmin's fix does not solve the problem

Upgrading the hardware (16GB RAM / 8 vCPUs) does not remove the malware, does not close the entry point the attacker used, and does not revoke the attacker's access. It only gives the miner more resources to work with — and possibly makes the compromise harder to notice, since CPU usage per core would look less alarming on a bigger machine.

The sysadmin diagnosed a capacity problem because that is the only symptom visible in day-to-day monitoring (CPU load, app slowness). But the actual root cause is that the server was compromised through a vulnerability, most likely the known RCE vulnerabilities in Apache 2.4.29 flagged in Marcus's notes. Until that vulnerability is identified and patched, upgrading hardware only delays the next visible symptom — it does not remove the attacker.

## 4. Connection to the January ransomware incident

The same server was hit by ransomware in January, rebuilt, and is now running cryptomining malware through what appears to be the same entry point (an unpatched Apache vulnerability). Two different payloads, same door left open.

This suggests the January rebuild restored the server's function but not its security — it was very likely rebuilt from the same vulnerable configuration, without patching the vulnerability that allowed the original ransomware in.

**Key question to escalate:** Was billing-srv-01 rebuilt from a hardened, fully patched image after the January incident, and was the vulnerability that allowed the original breach ever formally identified and fixed — or was the server simply restored to get billing operational again, with no root-cause remediation? The pattern across both incidents points to "restore and move on" rather than "investigate and fix," which is a process gap, not just a technical one.
