# 3-hash_analysis: The Hash Laboratory

MedDefense Health Systems — 1x04 Task 3

## Part 1 — The Avalanche Effect

SHA-256("MedDefense") = 39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098
SHA-256("MedDefense1") = 97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92
Diff: 62 of 64 hex characters differ (96.9%)

MD5("MedDefense") = 75d47fd4b4d183456d0f98fd9ba6ae4d
MD5("MedDefense1") = 0d2aed72043f78c2935e61ba8520306d
Diff: 30 of 32 hex characters differ (93.8%)

A single added character changed nearly the entire output in both algorithms — this is the avalanche effect: well-designed hash functions ensure a tiny input change produces an unpredictable, large output change, so hashes cannot be used to estimate how similar two inputs are.

## Part 2 — Hash Collisions and the Birthday Problem

MD5 (128-bit): 2^128 possible outputs = 340,282,366,920,938,463,463,374,607,431,768,211,456
SHA-256 (256-bit): 2^256 possible outputs = 115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,936

A shorter hash has a smaller output space, so by the birthday paradox, finding two different inputs that produce the same hash (a collision) requires far fewer attempts than the full output space — roughly the square root of it. For MD5 this is around 2^64 attempts, which is computationally feasible today; for SHA-256 it is around 2^128, still infeasible. A birthday attack exploits this: it doesn't need to match a specific target hash, only find any two inputs that collide, which is a much easier problem.

If MedDefense's AD uses RC4 for Kerberos tickets (Finding 018), and RC4-encrypted tickets can be requested via Kerberoasting and cracked offline, the underlying key material is tied to the NT hash, which is MD4-based — a hash even weaker than MD5. This means Kerberoasted RC4 tickets can be cracked significantly faster than tickets using AES, directly exposing user passwords once an attacker has network access to request them.

## Part 3 — Rainbow Table Demonstration

MD5("password123") = 482c811da5d5b4bc6d497ffa98491e38
crackstation.net lookup result: FOUND — plaintext "password123" recovered instantly (unsalted, in precomputed rainbow table).

MD5("s4lt9xQ2:password123") = 6d537fa53f1db2c22b0451ef4ef9fbe8
crackstation.net lookup result: NOT FOUND.

Salting defeats rainbow tables because the precomputed tables are built for known, common (unsalted) input strings — adding a unique random salt before hashing means the attacker's table would need a separate entry for every possible salt+password combination, which is computationally infeasible to precompute. Every user needs a unique salt because if all users shared one salt, an attacker could still precompute a single rainbow table for that salt and crack every account with it, defeating the purpose.

## Part 4 — Key Stretching

bcrypt: built on the Blowfish cipher, deliberately slow, and includes a built-in salt. It resists brute-force by making each guess expensive; the "cost factor" is a power-of-2 work factor — increasing it doubles the time per hash attempt.

PBKDF2: applies an underlying hash (e.g. SHA-256) repeatedly, thousands of times, to a password plus salt. Its "iteration count" directly controls how many rounds are applied, making brute-force proportionally slower, but unlike bcrypt/Argon2 it is not memory-hard, so it's more vulnerable to GPU/ASIC cracking.

Argon2: winner of the 2015 Password Hashing Competition, deliberately memory-hard (not just CPU-slow), which makes GPU/ASIC-based cracking far more expensive since attackers need large amounts of fast memory per guess. Its "cost factor" controls both memory usage and iteration count.

Recommendation for MedDefense's application password storage: Argon2id — modern, memory-hard, resistant to both CPU and GPU-based attacks, and it's the current OWASP-recommended default.

Active Directory by default uses the NT hash (MD4-based), unsalted, with no iteration/cost factor — not a key-stretching algorithm at all. This is not adequate: MD4 is cryptographically broken and the hash is unsalted, so it's vulnerable to fast offline cracking (as directly demonstrated by Finding 018 / RC4 Kerberoasting above).

## Part 5 — Integrity Verification Script

See 3-hash_verify.sh in this directory.
