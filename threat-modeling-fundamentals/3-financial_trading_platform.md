# Task 3: Financial Trading Platform Threat Model

## System Overview

The platform lets users view real-time stock prices, execute buy/sell orders, transfer funds between accounts, and set up automated trading rules.

System requirements:
- High availability (99.99% uptime)
- Low latency (<100ms for trades)
- Regulatory compliance (SEC, FINRA)

## 1. Most Critical CIA Component

**Most critical component: Integrity**

In a trading platform, the worst outcome is not a data leak or even downtime — it's data being silently modified. If an attacker changes an order, a balance, or a trade record and it isn't caught, the financial damage is direct, can be very large, and is often hard to reverse once trades have executed. A data leak is bad for privacy and reputation, and downtime is bad for availability and revenue, but a corrupted trade or balance can cause irreversible financial loss and is exactly the kind of thing regulators like the SEC and FINRA require strict controls and audit trails around (accurate records, accurate trade reporting, accurate account balances). This makes Integrity the top priority, just ahead of Availability (the system also has a strict 99.99% uptime requirement) and Confidentiality.

**Can security requirements conflict with performance requirements? Yes.**

This system requires both strong security and very low latency (<100ms for trades), and these two goals can pull against each other:
- Strong encryption and additional authentication checks (e.g. MFA on every sensitive action) add processing time, which can push trade execution closer to or over the 100ms limit.
- Detailed audit logging and real-time anomaly detection require extra processing on every transaction, which adds latency.
- Strict rate limiting, useful for stopping abuse, could also slow down or block legitimate high-frequency trading activity if not tuned carefully.

In practice, this means security controls for this system need to be designed with performance in mind from the start (e.g. asynchronous logging, hardware-accelerated encryption, lightweight session validation) rather than added as an afterthought, since a naive implementation could violate the latency requirement.

## 2. Threat Model: Automated Trading Rules Feature

### Risk 1: Logic Flaws in Trading Rules

**Description:** Automated trading rules execute based on conditions set by the user (e.g. "sell if price drops below $X"). If the rule engine has bugs or edge cases that aren't handled correctly, a rule could execute incorrectly, at the wrong time, or with the wrong amount.

**Impact:** Unintended trades could be executed, causing direct financial loss to the user, and potentially affecting market activity if it happens at scale.

**Mitigation:** Thoroughly test the rule engine with edge cases (e.g. extreme price swings, simultaneous triggers), and implement safeguards like maximum trade size limits and sanity checks before any automated trade is executed.

### Risk 2: Race Conditions

**Description:** If multiple automated rules, or a rule combined with a manual order, can be triggered and processed at nearly the same time, the system might process them in an unexpected order or even both at once if proper locking isn't in place.

**Impact:** A user could end up executing duplicate trades, overselling shares they don't actually hold, or transferring more funds than available, since two near-simultaneous operations both read the same "before" state.

**Mitigation:** Use database transactions with proper locking (or equivalent concurrency controls) so that operations affecting the same account or asset are processed safely in sequence, not in parallel against stale data.

### Risk 3: Unauthorized Rule Modifications

**Description:** If an attacker gains access to a user's account, or if there are weaknesses in how rules are authenticated/authorized, the attacker could create or modify automated trading rules without the legitimate user's knowledge.

**Impact:** An attacker could quietly set up rules that drain funds, manipulate the user's trading activity, or transfer money out over time without triggering an obvious single large transaction.

**Mitigation:** Require re-authentication (e.g. MFA) specifically when creating or modifying trading rules, and send the user a notification any time a rule is created or changed, so unauthorized changes are noticed quickly.

## 3. Defense-in-Depth: Compromised User Account

If an attacker compromises a user's account credentials, the system should not rely on login alone to stop damage. The following five layers help limit what the attacker can actually do, even with valid credentials.

### Layer 1: Multi-Factor Authentication (MFA)

Even if a password is stolen, MFA (e.g. a one-time code or authenticator app) adds a second barrier the attacker likely doesn't have, which can stop many account takeovers before they even start.

### Layer 2: Transaction Limits

Setting maximum amounts for trades or fund transfers (especially for new or unusual activity) limits how much damage a single compromised session can cause, even if the attacker is logged in.

### Layer 3: Anomaly Detection

Monitoring for unusual behavior (e.g. login from a new location, trades far outside the user's normal pattern, rapid-fire transactions) can flag or pause suspicious activity automatically, even if the attacker has valid credentials.

### Layer 4: Session Management

Short session lifetimes, automatic logout after inactivity, and the ability to remotely revoke active sessions mean that even a hijacked session has a limited window of usefulness for the attacker.

### Layer 5: Audit Trails

Detailed, tamper-proof logs of every action taken (logins, trades, fund transfers, rule changes) allow the platform to investigate exactly what happened after a compromise, support regulatory reporting requirements, and help reverse or contain damage faster.

## References
- OWASP Cheat Sheet Series - Multi-Factor Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- FINRA - Cybersecurity: https://www.finra.org/rules-guidance/key-topics/cybersecurity
