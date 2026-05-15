# 0x03 Cryptography Basics

## Task 0 - SHA1
Script that hashes a given password using SHA-1 algorithm and stores the result in 0_hash.txt
## Task 1 - SHA256
Script that hashes a given password using SHA-256 algorithm and stores the result in 1_hash.txt
## Task 2 - MD5
Script that hashes a given password using MD5 algorithm and stores the result in 2_hash.txt
## Task 3 - Secure Password Hash
Script that accepts a password as argument, combines it with a random 16-character value using OpenSSL, and generates a SHA-512 hash stored in 3_hash.txt
## Task 4 - Wordlist Mode
Script that cracks passwords using John the Ripper's Wordlist Mode with the RockYou wordlist, accepts hash.txt as argument and stores cracked passwords in 4-password.txt
## Task 5 - Windows Authentication Cracking
Script that cracks NTLM/NT hash format passwords using John the Ripper, accepts hash.txt as argument and stores the cracked password in 5-password.txt
## Task 6 - John Cracking
Script that cracks a SHA-256 hashed password using John the Ripper, accepts crack.txt as argument and stores the cracked password in 6-password.txt
## Task 7 - Hashcat Straight Attack
Script that cracks an MD5 hashed password using Hashcat with the RockYou wordlist, accepts hash.txt as argument and stores the cracked password in 7-password.txt
## Task 8 - Hashcat Combination
Script that combines two wordlists using Hashcat, accepts wordlist1.txt and wordlist2.txt as arguments and outputs all combined passwords
## Task 9 - Hashcat Combination Attack
Script that cracks an MD5 hashed password using Hashcat combination attack with wordlist1.txt and wordlist2.txt, accepts hash.txt as argument and stores the cracked password in 9-password.txt
