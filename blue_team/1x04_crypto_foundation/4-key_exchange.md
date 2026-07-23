# 4-key_exchange: The Key Exchange

MedDefense Health Systems — 1x04 Task 4

## Part 1 — The DH Simulation

openssl dhparam -out dhparams.pem 2048
→ Generated 2048-bit DH parameters (dhparams.pem, 428 bytes)

openssl genpkey -paramfile dhparams.pem -out alice_private.pem
openssl pkey -in alice_private.pem -pubout -out alice_public.pem
→ Alice's key pair generated from shared parameters

openssl genpkey -paramfile dhparams.pem -out bob_private.pem
openssl pkey -in bob_private.pem -pubout -out bob_public.pem
→ Bob's key pair generated from the same shared parameters

openssl pkeyutl -derive -inkey alice_private.pem -peerkey bob_public.pem -out alice_secret.bin
openssl pkeyutl -derive -inkey bob_private.pem -peerkey alice_public.pem -out bob_secret.bin
→ Both secrets: 256 bytes (2048 bits)

diff alice_secret.bin bob_secret.bin
→ No output — the two independently derived secrets are identical

## Part 2 — The Explanation

Alice and Bob each generated their own private key, kept secret on their own machine, and only sent their public key to each other over the network. Using math based on modular exponentiation, when Alice combines her own private key with Bob's public key, she arrives at the same number Bob gets when he combines his private key with Alice's public key — even though neither ever sent that number anywhere. Eve, watching the network, only sees the two public keys and the shared DH parameters, none of which are secret by design. To compute the same shared secret, Eve would need either Alice's or Bob's private key, which never left their machines, or she would need to solve the discrete logarithm problem to recover a private key from a public key — a problem that is computationally infeasible at 2048-bit key sizes. So Eve ends up with the same public information as everyone else, but no way to derive the actual shared secret.

## Part 3 — The MITM Attack

Plain Diffie-Hellman authenticates nothing — it only guarantees that whoever holds the matching private key can compute the shared secret, not who that person actually is. If Eve sits on the network path, she can intercept Alice's public key and send Alice her own public key instead, then do the same toward Bob, completing two separate DH exchanges: one shared secret with Alice, a different one with Bob. Alice and Bob believe they're talking to each other, but every message actually passes through Eve, who decrypts, reads or modifies it, then re-encrypts it for the other side. If MedDefense's Central-Westside VPN tunnel used DH without certificate-based authentication, an attacker positioned on that network path could perform exactly this attack and transparently intercept or alter all VPN traffic between the two sites. Certificates prevent this because they cryptographically bind a public key to a verified identity, signed by a trusted certificate authority — so each side can confirm the public key it received truly belongs to the other party, not to an attacker, and can immediately detect a mismatch if someone tries to substitute their own key.
