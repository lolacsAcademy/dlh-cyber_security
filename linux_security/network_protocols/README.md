## Task 0 - Analyze iptables Rules
Script that displays all current iptables rules in a readable format including line numbers.
## Task 1 - Basic Firewall Rules
Script that configures iptables to block all incoming traffic by default while keeping SSH port 22 open to maintain remote access to the machine.
## Task 2 - Harden World-Writable Directories
Script that finds all world-writable directories, displays their paths and fixes permissions so only the owner can write to them.
## Task 3 - Identify Common Vulnerabilities
Script that runs a Lynis audit to check for unpatched vulnerabilities and security weaknesses on the system.
## Task 4 - Audit SSH Configuration
Script that checks and reports non-standard SSH configuration settings found in /etc/ssh/sshd_config.
## Task 5 - SSH Configuration Hardening
Review and improve SSH server configuration to follow security best practices, ensuring only secure protocols and authentication methods are used.
## Task 6 - Check for NFS Vulnerabilities
Script that scans for NFS shares accessible by anyone on the network using showmount.
## Task 7 - Audit SNMP Configuration
Script that searches SNMP configuration for lines containing the public community string which allows public access.
## Task 8 - Examine SMTP Server Settings
Script that checks SMTP server configuration for STARTTLS security feature and reports if it is not configured.
## Task 9 - TLS Version Testing
Test which TLS versions are supported by Google using OpenSSL and record results in a JSON file.
## Task 10 - Check for Weak SSL/TLS Ciphers
Script that tests an SSL/TLS server for weak ciphers using nmap ssl-enum-ciphers script.
