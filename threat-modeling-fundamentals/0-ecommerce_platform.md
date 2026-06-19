# Task 0: E-commerce Platform Threat Model

## System Overview

Users can browse products and add items to a cart without logging in. Checkout, payment, and viewing order history require authentication.

Architecture:
- React frontend
- Node.js API backend
- PostgreSQL database
- Stripe payment integration

## System Architecture
+------------------+

|  User Browser    |

|  (React Frontend)|

+--------+---------+

|

| HTTPS

|

========= TRUST BOUNDARY #1 =========

|

+--------v---------+

|   Node.js API    |

|     Backend      |

+--------+---------+

|

|

========= TRUST BOUNDARY #2 =========

|

+--------v---------+

| PostgreSQL DB    |

+------------------+
     |
     |
========= TRUST BOUNDARY #3 =========

|

+--------v---------+

| Stripe Payment   |

|    Service       |

+------------------+

## 1. STRIDE Threats for Checkout Process

### Threat 1: Price Manipulation

**STRIDE Category:** Tampering (T)

**Threat Description**
Browsing and cart actions don't need authentication, so a user can use browser developer tools or a proxy such as Burp Suite to change the price of a product before the checkout request reaches the server. If the backend trusts the price sent by the frontend instead of checking it against the real price, the user pays whatever value they typed.

**Attack Scenario**
1. User adds a product worth $100 to the cart.
2. Attacker intercepts the checkout request using browser dev tools or Burp Suite.
3. Attacker changes the price field from $100 to $1.
4. The modified request is sent to the API.
5. If the backend trusts the client-side price, the purchase completes at $1.

**Potential Impact**
- Direct financial loss
- Fraudulent purchases
- Loss of customer trust

**Likelihood:** Medium-High — price manipulation tools (browser dev tools, proxies) are free and widely available, no special skill needed.

**Suggested Mitigation**
Never trust a price coming from the client. The Node.js backend must look up the real price from PostgreSQL using the product ID for every item at checkout, and recalculate the total server-side before sending it to Stripe.

### Threat 2: Payment Data Interception

**STRIDE Category:** Information Disclosure (I)

**Threat Description**
Payment details travel from the browser to the backend and then to Stripe. If HTTPS is misconfigured or the user is on an unsecured network, an attacker performing a man-in-the-middle attack could intercept this traffic and read card or personal data.

**Attack Scenario**
1. A user connects through an insecure network (e.g. public Wi-Fi).
2. Attacker on the same network intercepts traffic.
3. Payment information is captured during transmission.
4. Stolen data is used for fraud.

**Potential Impact**
- Exposure of payment information
- Financial fraud
- Regulatory/compliance issues

**Likelihood:** Medium — most systems use HTTPS by default, but misconfigurations or weak TLS settings still happen.

**Suggested Mitigation**
Enforce HTTPS/TLS 1.2+ everywhere, use HSTS so browsers can't fall back to HTTP, and use Stripe's own SDK/Elements so raw card numbers never pass through the company's own server.

### Threat 3: Session Hijacking at Checkout

**STRIDE Category:** Spoofing (S)

**Threat Description**
Checkout and order history require authentication, which means a session token or cookie proves who the user is. If that token is stolen (e.g. through XSS or an insecure cookie), an attacker can impersonate the user and check out or view their order history.

**Attack Scenario**
1. Attacker steals a session token, for example through an XSS vulnerability or an unprotected cookie.
2. Attacker reuses the token to appear as the logged-in user.
3. Attacker completes a purchase or views private order history under the victim's identity.

**Potential Impact**
- Unauthorized purchases
- Exposure of another user's personal order history
- Customer dissatisfaction and support costs

**Likelihood:** Medium — depends on whether the frontend has XSS protections and whether cookies are configured securely.

**Suggested Mitigation**
Use Secure, HttpOnly, SameSite cookies so tokens can't be read by JavaScript or sent on cross-site requests. Keep session lifetime short, and require re-authentication before sensitive actions like checkout.

## 2. Trust Boundaries

A trust boundary exists wherever data moves from one trust level to another.

### Trust Boundary 1: User Browser → Node.js API
**Description:** The browser is untrusted because users can modify requests, headers, cookies, and even the JavaScript running in their own browser.
**Risks:** Parameter tampering, cross-site scripting (XSS), injection attacks.
**Security Controls:** Input validation, authentication, authorization, rate limiting.

### Trust Boundary 2: Node.js API → PostgreSQL Database
**Description:** The backend sends queries to the database and reads back stored data.
**Risks:** SQL injection, unauthorized data access, data corruption.
**Security Controls:** Parameterized queries, least-privilege database accounts, database auditing.

### Trust Boundary 3: Node.js API → Stripe Payment Service
**Description:** The application communicates with a third-party payment provider outside the company's own infrastructure.
**Risks:** API key theft, service impersonation, payment fraud.
**Security Controls:** Secure API key management, HTTPS/TLS encryption, Stripe webhook signature validation.

## 3. DREAD Analysis: SQL Injection in Product Search

**Threat Description**
The product search function accepts user input. If the backend builds SQL queries using string concatenation instead of parameterized queries, an attacker can inject SQL commands through the search box.

Example:
```sql
SELECT * FROM products WHERE name LIKE '%user_input%';
```
Attacker input: `' OR 1=1 --`

Resulting query:
```sql
SELECT * FROM products WHERE name LIKE '%' OR 1=1 --';
```
This can expose all records or allow further database attacks.

**DREAD Scoring** (scale 1-10, using the official rating scale)

| Factor | Score | Justification |
|---|---|---|
| Damage Potential | 9 | Falls in the "7-9: Significant data breach or major functionality loss" range — a successful SQL injection on search could expose all customer and product records stored in PostgreSQL. |
| Reproducibility | 10 | "Attack works every time, no special conditions needed" — once a working payload is found, it works the same way on every attempt. |
| Exploitability | 8 | Falls in "7-9: Requires basic hacking tools (Burp Suite, SQLmap)" — no login needed, and free tools like sqlmap or even a manually typed payload can test it. |
| Affected Users | 9 | "7-9: Majority of users affected" — search is used by every visitor, and if it's connected to the same database as customer/order data, a large share of users' data could be exposed. |
| Discoverability | 9 | "7-9: Can be found with automated scanning tools" — search boxes are one of the first things both attackers and automated scanners test, since no authentication is needed to reach them. |

**Calculation**

DREAD Score = (D + R + E + A + D) / 5
= (9 + 10 + 8 + 9 + 9) / 5
= 45 / 5
= **9.0 / 10**

**Risk Level:** 9.0 falls in the 8.0-10.0 range → **CRITICAL** (fix immediately).

**Mitigation**
- Use parameterized queries / prepared statements instead of string concatenation.
- Apply input validation on the search field.
- Use least-privilege database accounts so even a successful injection has limited reach.
- Consider an ORM that prevents raw SQL injection by design.

## References
- OWASP Cheat Sheet Series - Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- OWASP Cheat Sheet Series - SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- Security at Stripe: https://stripe.com/security
- Meier, J. D., Mackman, A., Dunner, M., Vasireddy, S., Escamilla, R., & Murukan, A. (2003). Improving Web Application Security: Threats and Countermeasures. Microsoft Corporation.
