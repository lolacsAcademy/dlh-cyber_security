# Task 2: IoT Smart Thermostat Threat Model

## System Overview

A smart thermostat connects to home Wi-Fi, controls heating/cooling, collects temperature data, receives commands from a mobile app, and updates its firmware over-the-air (OTA).

Architecture:
- IoT device (thermostat) with embedded firmware
- Home Wi-Fi connection
- Mobile app (control interface)
- Cloud/vendor backend (for OTA updates and remote commands)

## System Architecture

    +------------------+
    |  Mobile App       |
    +--------+----------+
             |
             | Internet / Cloud
             |
    +--------v----------+
    |  Vendor Cloud      |
    |  Backend           |
    +--------+----------+
             |
             | Home Wi-Fi
             |
    +--------v----------+
    |  Smart Thermostat  |
    |  (Device + Firmware)|
    +--------+----------+
             |
             | Controls
             |
    +--------v----------+
    |  Heating/Cooling    |
    |  System             |
    +--------------------+

## 1. IoT-Specific Threats

These threats are specific to physical IoT devices and don't typically apply to standard web applications, since web apps don't have physical hardware, embedded firmware, or constrained processing power in the same way.

### Threat 1: Physical Tampering

**Description:** Unlike a web server sitting in a secured data center, an IoT thermostat is physically present in someone's home and can be picked up, opened, or removed by anyone with access to the house.

**Impact:** Attacker could extract data, modify hardware, or use physical access as a stepping stone to compromise the device's software.

### Threat 2: Weak Default Credentials

**Description:** Many IoT devices ship with default usernames/passwords (e.g. admin/admin) that users never change, unlike most web applications which force account creation with unique credentials.

**Impact:** Attacker can easily gain control of the device using known default credentials, especially if these are published online or guessable.

### Threat 3: Unencrypted Communications

**Description:** Some IoT devices, due to limited processing power, send data (temperature readings, commands) without proper encryption, unlike most modern web apps which default to HTTPS.

**Impact:** Attacker on the same network could intercept and read or modify data, including commands sent to control the heating/cooling system.

### Threat 4: Firmware Vulnerabilities

**Description:** IoT devices run embedded firmware that is harder to patch than typical web application code, and many devices never receive updates after purchase.

**Impact:** Known vulnerabilities in outdated firmware can remain exploitable for the entire lifetime of the device, since there's no equivalent to quickly redeploying a web server.

### Threat 5: Botnet Recruitment

**Description:** IoT devices are frequently targeted by malware to be recruited into large botnets (e.g. the Mirai botnet), since many devices share the same default credentials and weak security, and are always online.

**Impact:** A compromised thermostat could be used, without the owner's knowledge, to participate in large-scale DDoS attacks against other targets, in addition to spying on the home network.

## 2. Physical Access Attack Chain

If an attacker gains physical access to the thermostat device, this opens an attack path that isn't available to someone attacking only over the network.

**Attack Chain**

1. **Initial access:** Attacker physically removes or accesses the thermostat (e.g. visitor, break-in, or device shipped/resold without being wiped).
2. **Locate debug interfaces:** Attacker opens the device casing and looks for exposed debug ports (such as UART or JTAG), which are often left enabled by manufacturers for testing purposes.
3. **Connect and extract data:** Using the debug port, the attacker connects a device (like a USB-to-serial adapter) and gains a console or shell access to the device's internals.
4. **Memory/firmware extraction:** Attacker dumps the device's memory or firmware, which may contain hardcoded credentials, Wi-Fi passwords, encryption keys, or proprietary code.
5. **Hardware manipulation:** Attacker could also physically modify the device, for example reflashing it with malicious firmware before returning it to its original location.

**Potential Impacts**
- Exposure of the home Wi-Fi password stored on the device, giving the attacker access to the broader home network.
- Extraction of any cloud account credentials or API keys stored in the firmware, potentially compromising the vendor account too.
- A reflashed device could act as a persistent backdoor into the home network, even after being placed back in its original location.
- Loss of control over the heating/cooling system itself.

## 3. Security Controls for OTA Update Process

The OTA process is one of the most sensitive parts of an IoT device, since it's the mechanism that changes the device's actual code. The following are essential security requirements.

### Code Signing

**Requirement:** Every firmware update must be digitally signed by the manufacturer using a private key, and the device must verify this signature with the corresponding public key before installing the update.

**Why it matters:** Without this, an attacker could push their own malicious firmware to the device, and the device would have no way to know it's not legitimate.

### Secure Boot

**Requirement:** The device should verify, at every startup, that the firmware currently running has not been tampered with, using a hardware-rooted trust chain.

**Why it matters:** Even if an attacker manages to write unauthorized firmware to the device (e.g. through physical access), secure boot prevents that firmware from actually running.

### Encrypted Update Channel

**Requirement:** Firmware updates must be downloaded over an encrypted channel (e.g. TLS), not sent in plaintext.

**Why it matters:** Without encryption, an attacker on the network could intercept the update in transit, read it, or attempt to replace it with a malicious version.

### Rollback Protection

**Requirement:** The device should not allow firmware to be downgraded to an older, known-vulnerable version without strong justification and authorization.

**Why it matters:** Without this, an attacker could force the device back to an older firmware version that has known security flaws, even if a fixed version was already installed.

## References
- OWASP IoT Security Verification Standard (ISVS): https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS
