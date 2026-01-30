# MITRE ATT&CK Enterprise Framework v18.1

**Document Control:**  
Version: 1.0  
Last Updated: January 2026  
Owner: Paul Leone  

**Framework Version:** ATT&CK v18.1 (October 2025)

---

## TA0001 - Initial Access

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1078 | Valid Accounts | **FULL** | Splunk correlation detects failed auth patterns; Wazuh monitors authentication logs; TheHive creates cases for brute force (>5 failures/5min); Authentik enforces account lockout; SSH tracks all authentication attempts | Deploy UEBA for behavioral baselines; implement impossible travel detection |
| T1133 | External Remote Services | **FULL** | pfSense logs all VPN connections; SSH session logging to SIEM; Traefik access logs track ForwardAuth requests; Uptime Kuma monitors service availability; Tailscale audit logs | Add geolocation-based alerts; implement time-of-day access policies |
| T1190 | Exploit Public-Facing Application | **PARTIAL** | Weekly OpenVAS scans detect vulnerabilities; Nessus authenticated scans verify patch levels; Suricata/Snort IDS signatures; SafeLine WAF blocks OWASP Top 10 attacks (25% block rate) | Deploy virtual patching via WAF rules; implement honeypot services |
| T1566 | Phishing | **FULL** | Shuffle phishing analysis workflow analyzes email headers, URLs, attachments; Cortex multi-engine analysis (VirusTotal, URLhaus, PhishTank); MISP correlates known phishing IOCs; Pi-hole blocks malicious domains | Add email gateway integration; deploy user reporting mechanism; implement DMARC/SPF/DKIM validation |
| T1091 | Replication Through Removable Media | **FULL** | Group Policy blocks autorun.inf execution; Wazuh FIM monitors USB device insertion (Event ID 2003); alerts on unauthorized removable media; registry monitoring detects autorun changes | Deploy USB whitelisting; implement file encryption requirements for removable media |
| T1189 | Drive-by Compromise | **PARTIAL** | Pi-hole blocks 2M+ malicious domains; Suricata/Snort detect exploit kit traffic patterns; SafeLine WAF protects web applications; DNS filtering prevents callback connections | Add browser isolation technology; implement content security policies; deploy endpoint isolation for high-risk browsing |
| T1199 | Trusted Relationship | **PARTIAL** | MISP tracks vendor compromise campaigns; vulnerability scanning includes supply chain components; monitoring of third-party integrations | **GAP:** Implement vendor security assessments; deploy third-party risk management program; add API gateway monitoring |
| T1195 | Supply Chain Compromise | **PARTIAL** | Package signature verification on Linux systems; Docker image verification (SHA-256); Git commit signing enforced | **GAP:** Deploy SBOM tracking (Trivy/Grype); implement dependency scanning; add software composition analysis |
| T1659 | Content Injection | **MINIMAL** | SafeLine WAF blocks common injection patterns; input validation at application layer | **GAP:** Deploy Content Security Policy (CSP) headers globally; implement subresource integrity (SRI) checks |

**Tactic Summary:**

**Strengths:** Strong authentication monitoring, phishing detection, network-based filtering

**Gaps:** Limited supply chain visibility, minimal content injection protection

**Priority:** Implement SBOM tracking (Q1 2026), enhance WAF rulesets (Q2 2026)

---

## TA0002 - Execution (8 of 12 techniques - 67% coverage)

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1059.001 | PowerShell | **FULL** | Sysmon captures PowerShell commands (Event ID 1, 4103, 4104); Wazuh detects obfuscated PowerShell (base64, encoded commands); Splunk searches for suspicious patterns (Invoke-Expression, DownloadString); script block logging enabled | Add PowerShell Constrained Language Mode; implement JEA (Just Enough Administration) |
| T1059.003 | Windows Command Shell | **FULL** | Sysmon logs cmd.exe execution with full command-line; Wazuh detects living-off-the-land binaries (LOLBins); parent-child process analysis identifies anomalies; TheHive escalates suspicious executions | Deploy application whitelisting (AppLocker/WDAC); implement command-line auditing policies |
| T1059.006 | Python | **PARTIAL** | Wazuh monitors Python process execution; auditd logs script execution on Linux; limited visibility into script content analysis | **GAP:** Implement Python script sandboxing; add runtime application self-protection (RASP); deploy code signing requirements |
| T1059.013 | Container CLI/API | **PARTIAL** | Required Action: Enable comprehensive container command auditing: kubectl exec logging, docker exec logging, Container escape detection | Wazuh: Add rules for container command execution; Splunk: Create correlation for kubectl/docker exec; Audit: Enable Kubernetes audit logging (--audit-log-path) |
| T1053 | Scheduled Task/Job | **FULL** | Wazuh monitors scheduled task creation (Event ID 4698, 106); Sysmon tracks Task Scheduler API calls; FIM detects changes to cron/Task Scheduler directories; Splunk correlates privileged task creation | Add baseline of legitimate scheduled tasks; implement approval workflow for new tasks |
| T1106 | Native API | **PARTIAL** | auditd logs system calls on Linux; Sysmon captures CreateRemoteThread, VirtualAllocEx; limited direct API call visibility | **GAP:** Deploy endpoint detection with API hooking; implement process injection detection; add kernel-level monitoring |
| T1129 | Shared Modules | **FULL** | Sysmon ImageLoad events (Event ID 7) track DLL loading; Wazuh alerts on unsigned/untrusted DLLs; code signing validation enforced; detection of DLL search order hijacking | Implement DLL whitelisting; add certificate pinning for critical modules |
| T1203 | Exploitation for Client Execution | **PARTIAL** | Suricata/Snort IDS signatures detect known exploit patterns; vulnerability scanning identifies unpatched client software; Cortex analyzes suspicious files with VirusTotal | **GAP:** Add exploit mitigation features (EMET/Windows Defender Exploit Guard); implement application sandboxing; deploy zero-day protection |
| T1204 | User Execution | **FULL** | Sysmon tracks process creation from user-writable directories; Wazuh monitors execution of files from Temp/Downloads; Cortex analyzes executables with multi-engine scanning; VirusTotal integration for malware detection | Add email attachment sandboxing; implement user training simulation; deploy macro blocking policies |
| T1569 | System Services | **FULL** | Wazuh monitors service creation/modification (Event ID 7045, 7036); Sysmon tracks service installation; FIM alerts on service binary changes; unauthorized service detection | Implement service whitelisting; add approval workflow for service changes |
| T1047 | Windows Management Instrumentation | **MINIMAL** | Limited WMI event monitoring; Sysmon tracks WMI activity (Event ID 19-21) | **GAP:** Enable comprehensive WMI logging; implement WMI subscription monitoring; add WMI persistence detection |
| T1648 | Serverless Execution | **NOT APPLICABLE** | No cloud serverless infrastructure in scope | N/A |
| T1609 | Container Administration Command | **PARTIAL** | Docker audit logging enabled; Kubernetes audit logs to SIEM; monitoring of kubectl/docker exec commands; see also T1059.013 for container CLI/API execution monitoring | **GAP:** Implement admission controllers; add runtime container security (Falco); deploy container network policies |

**Tactic Summary:**

**Strengths:** Comprehensive process monitoring, script execution detection, service tracking

**Gaps:** Limited WMI visibility, minimal API call monitoring, container CLI/API monitoring incomplete (T1059.013)

**Priority:** Enhance WMI logging (immediate), implement container command auditing (T1059.013 - Q1 2026), deploy container security tools (Q2 2026)

---

## TA0003 - Persistence

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1098 | Account Manipulation | **FULL** | Active Directory logs track group membership changes (Event ID 4728, 4732, 4756); Wazuh monitors user attribute modifications; Splunk correlation detects privilege escalation patterns; TheHive escalates unauthorized changes | Implement privileged access management (PAM); add approval workflow for admin group changes |
| T1136 | Create Account | **FULL** | Wazuh monitors account creation (Event ID 4720 Windows, useradd Linux); Splunk alerts on new accounts created outside business hours; unauthorized account detection via baseline comparison | Add account provisioning workflow; implement automated account lifecycle management |
| T1543 | Create or Modify System Process | **FULL** | Sysmon Event ID 7045 tracks service creation; Wazuh monitors systemd unit changes on Linux; FIM alerts on service binary modifications; unauthorized service detection | Deploy service creation approval workflow; implement signed service binary requirement |
| T1547 | Boot or Logon Autostart Execution | **FULL** | Sysmon Event ID 13 monitors registry Run keys; Wazuh FIM tracks startup folders, /etc/init.d, systemd; detection of persistence via: Run keys, startup scripts, scheduled tasks, WMI subscriptions | Add autostart location baseline; implement startup item approval process |
| T1053 | Scheduled Task/Job | **FULL** | Comprehensive monitoring (see TA0002 above); persistence-specific detection includes: task creation by non-admin users, tasks with SYSTEM privileges, tasks pointing to suspicious paths | Implement task scheduler hardening; add scheduled task inventory baseline |
| T1505 | Server Software Component | **PARTIAL** | Wazuh FIM monitors web directories (/var/www, IIS wwwroot); Yara signatures detect common web shells (China Chopper, WSO, b374k); IDS signatures for web shell activity; limited PHP/ASP behavioral analysis | **GAP:** Deploy web shell-specific detection (NeoPI); implement web application firewall with virtual patching; add file integrity baseline for web assets |
| T1078 | Valid Accounts | **FULL** | Behavioral analysis detects: unusual login times, geographic anomalies, impossible travel, privileged account usage patterns; Splunk dashboards track authentication trends; UEBA planned for Q2 2026 | Deploy full UEBA capabilities; implement privileged access analytics; add session recording for admin accounts |
| T1546.018 | Event Triggered Execution: Python Startup Hooks | **MINIMAL** | No monitoring of Python startup files (.pythonrc, sitecustomize.py, usercustomize.py); Limited tracking of PYTHONSTARTUP environment variable; Wazuh FIM does not monitor Python site-packages directories | **GAP:** Implement Wazuh FIM on ~/.pythonrc, /usr/lib/python*/site-packages, /etc/pythonrc.d/; Monitor PYTHONSTARTUP environment variable changes; Add auditd rules for Python startup file access; Deploy baseline for legitimate Python customizations |
| T1556 | Modify Authentication Process | **PARTIAL** | Wazuh FIM monitors: /etc/pam.d, LSASS process memory, credential providers, SSH authorized_keys; limited detection of in-memory credential provider injection | **GAP:** Implement memory scanning for credential provider tampering; add LSASS protection; deploy credential guard on Windows |
| T1197 | BITS Jobs | **MINIMAL** | Limited BITS job monitoring | **GAP:** Enable BitsAdmin logging (Event ID 59, 60, 61); implement BITS job enumeration; add suspicious BITS transfer detection |
| T1037 | Boot or Logon Initialization Scripts | **PARTIAL** | FIM monitors common script locations (bashrc, profile, logon scripts); limited detection of obfuscated scripts | **GAP:** Add script content analysis; implement script whitelisting; deploy behavioral analysis for script execution |
| T1176 | Browser Extensions | **MINIMAL** | No browser extension monitoring | **GAP:** Deploy browser extension inventory; implement extension whitelisting; add browser telemetry collection |
| T1554 | Compromise Client Software Binary | **PARTIAL** | FIM monitors application directories; code signing validation detects unsigned binaries; limited binary integrity verification | **GAP:** Implement application whitelisting; add runtime binary verification; deploy EDR with process hollowing detection |

**Additional Unmonitored Persistence Techniques:**

- **T1137** (Office Application Startup): No Office macro/add-in monitoring
- **T1525** (Implant Internal Image): No VM/container image integrity monitoring
- **T1137** (Office Test): No Office persistence mechanism detection
- **T1546** (Event Triggered Execution): Partial coverage; WMI, Accessibility Features need enhancement; T1546.018 (Python Startup Hooks) not monitored

**Tactic Summary:**

**Strengths:** Strong account monitoring, registry persistence detection, service tracking

**Gaps:** Limited BITS monitoring, minimal browser extension visibility, no Office persistence detection

**Priority:** Enable BITS logging (immediate), deploy application binary monitoring (Q1 2026)

---

## TA0004 - Privilege Escalation

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1068 | Exploitation for Privilege Escalation | **PARTIAL** | Weekly OpenVAS + monthly Nessus scans identify kernel exploits; Sysmon monitors unusual child processes from vulnerable applications; Wazuh detects known exploit patterns; limited zero-day detection | **GAP:** Deploy exploit mitigation features (EMET, Windows Defender Exploit Guard); implement kernel patch verification; add memory exploit detection |
| T1134 | Access Token Manipulation | **PARTIAL** | Sysmon Event ID 4648 (explicit credential logon), 4672 (special privileges assigned); detection of SeDebugPrivilege abuse; limited token impersonation monitoring | **GAP:** Implement comprehensive token manipulation detection; add Windows Defender Credential Guard; deploy API hooking for token APIs |
| T1548 | Abuse Elevation Control Mechanism | **PARTIAL** | Sysmon detects UAC bypass attempts (registry keys, file system redirects); Wazuh monitors eventvwr.exe, fodhelper.exe abuse; limited coverage of all bypass techniques | **GAP:** Enable UAC monitoring (Event ID 4103); implement UAC configuration auditing; add detection for UIPI bypasses |
| T1053 | Scheduled Task/Job | **FULL** | Comprehensive monitoring of privileged task creation; detection of task creation with SYSTEM privileges; alerts on tasks created by non-admin users; tracking of task modification | Deploy task creation approval workflow; implement privileged task baseline |
| T1078 | Valid Accounts | **FULL** | Tracks privileged account usage patterns; monitors admin account logons outside business hours; detects lateral movement via admin accounts; TheHive escalates anomalous privileged access | Add privileged access management (PAM) solution; implement just-in-time (JIT) admin access |
| T1055 | Process Injection | **MINIMAL** | Sysmon captures CreateRemoteThread, QueueUserAPC; limited visibility into process hollowing, reflective DLL injection | **GAP:** Deploy advanced EDR with process injection detection; implement memory scanning; add API hooking for injection techniques |
| T1543 | Create or Modify System Process | **FULL** | Covered under TA0003 Persistence | See Persistence section |
| T1574 | Hijack Execution Flow | **MINIMAL** | FIM monitors DLL directories; limited DLL search order hijacking detection; no PATH hijacking monitoring | **GAP:** Implement DLL preloading detection; add PATH manipulation monitoring; deploy signed binary enforcement |
| T1484 | Domain Policy Modification | **FULL** | Active Directory audit logs track GPO changes (Event ID 5136, 5137, 5141); Wazuh alerts on unauthorized GPO modifications; SIEM correlation detects privilege escalation via GPO | Implement GPO change approval workflow; add GPO baseline comparison |

**Additional Unmonitored Techniques:**

- **T1547** (Boot or Logon Autostart): Covered under Persistence
- **T1037** (Boot/Logon Initialization): Partial coverage
- **T1611** (Escape to Host): No container escape detection
- **T1546** (Event Triggered Execution): Partial WMI coverage; T1546.018 (Python Startup Hooks) not monitored - see Persistence section

**Tactic Summary:**

**Strengths:** Strong privileged account monitoring, GPO change detection, scheduled task tracking

**Gaps:** Minimal process injection visibility, limited UAC bypass coverage, no container escape detection

**Priority:** Deploy advanced EDR for process injection (Q2 2026), enhance UAC monitoring (immediate)

---

## TA0005 - Defense Evasion

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1027 | Obfuscated Files or Information | **PARTIAL** | Cortex Yara signatures detect packing, base64 encoding; limited entropy analysis; detection of certutil decode, PowerShell encoding | **GAP:** Deploy advanced entropy analysis; implement sandbox detonation; add machine learning-based obfuscation detection |
| T1036 | Masquerading | **PARTIAL** | Sysmon tracks process path anomalies; Wazuh validates code signing; detection of processes running from unusual locations; limited filename spoofing detection | **GAP:** Implement process name whitelist; add parent-child process validation; deploy binary reputation scoring |
| T1070 | Indicator Removal | **FULL** | Windows Event ID 1102 alerts on log clearing; Wazuh monitors file deletion in critical directories; immutable SIEM logs prevent tampering; FIM tracks log file modifications | Add log integrity verification; implement write-once-read-many (WORM) storage for critical logs |
| T1112 | Modify Registry | **FULL** | Sysmon Event ID 13 captures all registry modifications; Wazuh FIM monitors critical registry keys; baseline deviation detection; alerts on security-related key changes | Implement registry change approval workflow; add registry rollback capability |
| T1140 | Deobfuscate/Decode Files | **PARTIAL** | Process command-line monitoring detects certutil, base64 commands; limited file content analysis post-decoding | **GAP:** Deploy file detonation sandbox; implement recursive unpacking analysis; add memory-based deobfuscation detection |
| T1202 | Indirect Command Execution | **PARTIAL** | Sysmon tracks LOLBin usage (mshta, regsvr32, rundll32, wmic); Wazuh alerts on unusual parent-child relationships; detection of script execution via non-standard interpreters | **GAP:** Implement comprehensive LOLBin baseline; add behavioral analysis for indirect execution; deploy application control policies |
| T1222 | File and Directory Permissions Modification | **FULL** | Wazuh FIM alerts on permission changes; auditd logs chmod/chown on Linux; icacls/takeown monitoring on Windows; detection of privilege escalation via ACL modification | Add permission change approval workflow; implement least privilege validation |
| T1484 | Group Policy Modification | **FULL** | Covered under TA0004 Privilege Escalation; comprehensive GPO change auditing | See Privilege Escalation section |
| T1562 | Impair Defenses | **FULL** | Wazuh monitors: Windows Defender tampering (registry, services), firewall rule changes, security service stops, log deletion attempts; alerts on antimalware service termination | Implement tamper protection; add service recovery automation; deploy security tool health monitoring |
| T1564 | Hide Artifacts | **MINIMAL** | FIM monitors hidden file creation; limited alternate data stream (ADS) detection; no VBA stomping detection | **GAP:** Enable ADS scanning; implement VBA source code extraction; add hidden process detection |
| T1601 | Modify System Image | **NOT APPLICABLE** | Network device firmware monitoring not implemented (firewall managed via pfSense) | N/A for current scope |
| T1006 | Direct Volume Access | **MINIMAL** | Limited raw disk access monitoring | **GAP:** Deploy volume shadow copy monitoring; add raw disk access alerting; implement VSS change detection |

### New Defense Evasion Techniques in v18.1

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1678 | Delay Execution | **MINIMAL** | Limited sleep/timeout command monitoring; Sysmon captures timeout.exe, sleep commands; no behavioral analysis for time-delay patterns | **GAP:** Implement detection for extended sleep commands (>60 seconds); Add correlation for delays preceding malicious activity; Deploy sandbox evasion detection; Monitor timeout/sleep in scripts |
| T1679 | Selective Exclusion | **PARTIAL** | Wazuh monitors Windows Defender exclusion additions (registry HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions); Limited detection of firewall/EDR exclusions | **GAP:** Monitor all security tool configuration changes; Alert on antivirus exclusion paths (especially C:\Windows, C:\Users); Track pfSense/firewall bypass rule additions; Implement security tool configuration baseline |
| T1036.012 | Masquerading: Browser Fingerprint | **MINIMAL** | No browser fingerprinting detection; limited user-agent analysis in Traefik/Suricata logs | **GAP:** Deploy browser telemetry collection; Implement user-agent anomaly detection; Add browser fingerprinting signature detection (Canvas, WebGL); Monitor for automation frameworks (Puppeteer, Selenium) |
| T1562.013 | Disable or Modify Network Device Firewall | **PARTIAL** | pfSense logs firewall rule changes via syslog; Limited SNMP monitoring for network devices | **GAP:** Implement SNMP trap monitoring for all network devices; Add Checkmk SNMP monitoring for firewall config changes; Deploy configuration backup validation; Alert on unauthorized firewall rule deletions |

**Major Unmonitored Defense Evasion Techniques:**

- **T1550** (Use Alternate Authentication Material): Pass-the-hash, pass-the-ticket detection needed
- **T1218** (System Binary Proxy Execution): Partial LOLBin coverage; need comprehensive monitoring
- **T1207** (Rogue Domain Controller): No DC replication monitoring
- **T1620** (Reflective Code Loading): No in-memory module detection
- **T1553** (Subvert Trust Controls): Code signing bypass detection limited
- **T1497** (Virtualization/Sandbox Evasion): No sandbox evasion detection
- **T1599** (Network Boundary Bridging): No network bridge detection

**Tactic Summary:**

**Strengths:** Strong log protection, registry monitoring, security tool tampering detection

**Gaps:** Minimal obfuscation analysis, limited indirect execution detection, no alternate authentication material monitoring, new v18.1 techniques (T1678 Delay Execution, T1679 Selective Exclusion, T1036.012 Browser Fingerprint, T1562.013 Network Device Firewall) require enhancement

**Priority:** Deploy advanced obfuscation detection (Q2 2026), implement pass-the-hash monitoring (Q1 2026)

---

## TA0006 - Credential Access

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1003 | OS Credential Dumping | **FULL** | Sysmon Event ID 10 detects LSASS process access; Wazuh alerts on Mimikatz signatures; detection of SAM/SYSTEM file access; monitoring of credential dumping tools (pwdump, gsecdump) | Deploy Windows Defender Credential Guard; implement LSASS protection (RunAsPPL); add memory scanning for credential extraction |
| T1110 | Brute Force | **FULL** | Multi-source correlation: failed logins from firewall, SSH, Authentik, RDP; Shuffle workflow creates TheHive cases for brute force (>5 failures/5min); account lockout enforcement; IP-based rate limiting | Add distributed brute force detection; implement CAPTCHA after failed attempts; deploy geolocation-based blocking |
| T1555 | Credentials from Password Stores | **PARTIAL** | Wazuh FIM monitors browser credential directories (Chrome, Firefox); limited coverage of password manager access (KeePass, 1Password); no macOS Keychain monitoring | **GAP:** Implement comprehensive password store monitoring; add credential access behavioral analysis; deploy browser credential protection |
| T1552 | Unsecured Credentials | **PARTIAL** | Wazuh FIM monitors sensitive directories (/root/.ssh, .aws, .kube); Yara signatures detect credential patterns in files; limited coverage of memory credential scanning | **GAP:** Deploy secret scanning tools (TruffleHog, GitLeaks); implement memory credential detection; add configuration file credential scanning |
| T1528 | Steal Application Access Token | **MINIMAL** | Limited OAuth token monitoring | **GAP:** Implement OAuth token theft detection; add API token usage monitoring; deploy token expiration enforcement |
| T1557 | Adversary-in-the-Middle | **MINIMAL** | TLS validation prevents MITM; limited ARP spoofing detection | **GAP:** Deploy ARP spoofing detection (ArpWatch); implement certificate pinning; add network anomaly detection for MITM |
| T1558 | Steal or Forge Kerberos Tickets | **MINIMAL** | No Kerberos ticket monitoring (Event ID 4769, 4768) | **GAP:** Enable Kerberos event logging; implement golden/silver ticket detection; add Kerberos encryption downgrade monitoring |
| T1539 | Steal Web Session Cookie | **MINIMAL** | No browser cookie theft monitoring | **GAP:** Implement session hijacking detection; add browser telemetry; deploy session binding (IP, User-Agent validation) |

**Additional Unmonitored Techniques:**

- **T1556** (Modify Authentication Process): Partial coverage under Persistence
- **T1040** (Network Sniffing): No promiscuous mode detection
- **T1111** (Multi-Factor Authentication Interception): No MFA push notification monitoring
- **T1606** (Forge Web Credentials): No SAML token forgery detection
- **T1649** (Steal or Forge Authentication Certificates): No certificate theft detection

**Tactic Summary:**

**Strengths:** Strong brute force detection, LSASS access monitoring, credential dumping detection

**Gaps:** Minimal Kerberos monitoring, limited password store coverage, no session hijacking detection

**Priority:** Enable Kerberos logging (immediate), implement session monitoring (Q1 2026)

---

## TA0007 - Discovery

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1087 | Account Discovery | **FULL** | Command-line monitoring detects: net user, net group, whoami, id, getent; Wazuh tracks LDAP queries (Event ID 4662); Active Directory enumeration alerts; detection of account enumeration via SMB | Add baseline of legitimate discovery activity; implement honeypot accounts for detection |
| T1010 | Application Window Discovery | **PARTIAL** | Limited GUI enumeration detection; process monitoring tracks tasklist, Get-Process | **GAP:** Implement GUI interaction monitoring; add screenshot detection; deploy user activity analytics |
| T1217 | Browser Bookmark Discovery | **PARTIAL** | Wazuh FIM monitors browser profile access; limited content analysis of bookmarks | **GAP:** Deploy browser telemetry collection; add bookmark enumeration detection; implement user behavior analytics |
| T1482 | Domain Trust Discovery | **FULL** | Active Directory logs LDAP queries (Event ID 4662); Wazuh monitors nltest, dsquery commands; detection of trust enumeration; SMB session monitoring | Implement AD enumeration baseline; add honeypot OUs for detection |
| T1083 | File and Directory Discovery | **FULL** | Sysmon/auditd tracks dir, ls, find commands; detection of recursive directory traversal; monitoring of file enumeration in sensitive directories; alerts on rapid file system scanning | Add file access behavioral baseline; implement honeypot files for detection |
| T1046 | Network Service Discovery | **FULL** | Suricata/Snort detect port scans (SYN scans, full connects, UDP scans); pfSense logs scan activity; Splunk correlates reconnaissance patterns; detection of network sweeps | Deploy deception technology (honeypots); implement port scan response automation |
| T1049 | System Network Connections Discovery | **FULL** | Sysmon Event ID 3 logs network connections; auditd tracks netstat commands; monitoring of connection enumeration; detection of network profiling | Add network connection baseline; implement connection anomaly detection |
| T1018 | Remote System Discovery | **FULL** | Suricata/Snort detect network sweeps; detection of ping sweeps, ARP scans; monitoring of network reconnaissance tools (nmap, masscan); pfSense logs scanning activity | Deploy network segmentation alerting; add internal reconnaissance detection |
| T1082 | System Information Discovery | **FULL** | Command-line monitoring tracks: systeminfo, uname, hostname, Get-ComputerInfo; detection of system profiling commands; monitoring of WMI queries for system info | Implement discovery command baseline; add system information honeypot values |
| T1016 | System Network Configuration Discovery | **FULL** | Monitors ipconfig, ifconfig, ip addr, route, netsh commands; detection of network adapter enumeration; tracking of routing table queries | Add network configuration change alerting; implement network topology obfuscation |
| T1007 | System Service Discovery | **PARTIAL** | Monitors sc query, systemctl, service commands; limited behavioral analysis | **GAP:** Implement service enumeration baseline; add service discovery anomaly detection |
| T1518.002 | Backup Software Discovery | **FULL** | Sysmon/auditd tracks backup software processes; Command-line monitoring detects backup enumeration queries; Registry monitoring (HKLM\SOFTWARE\Backup); Process monitoring for backup service queries (Get-Service, sc query) | Implement backup software inventory baseline; add behavioral detection for rapid backup enumeration; deploy honeypot backup configurations |
| T1680 | Local Storage Discovery | **PARTIAL** | Command-line monitoring detects df, mount, lsblk, fsutil commands; auditd logs storage queries on Linux; limited behavioral baseline for storage enumeration patterns | **GAP:** Implement behavioral baseline for normal storage discovery; Add detection for rapid enumeration (>10 queries/min); Deploy SIEM correlation for unusual storage profiling patterns; Add cloud storage enumeration detection |
| T1124 | System Time Discovery | **PARTIAL** | Limited time discovery monitoring (net time, w32tm) | **GAP:** Add time synchronization monitoring; implement time-based behavioral analysis |

**Additional Unmonitored Discovery Techniques:**

- **T1069** (Permission Groups Discovery): Partial coverage; need comprehensive group enumeration detection
- **T1057** (Process Discovery): Process listing commands monitored; behavioral analysis needed
- **T1012** (Query Registry): Limited registry query monitoring outside of modifications
- **T1518** (Software Discovery): Vulnerability scanners provide inventory; T1518.002 (Backup Software Discovery) fully covered via process/registry monitoring; limited detection for other software enumeration patterns
- **T1135** (Network Share Discovery): No share enumeration monitoring (net view, net share)
- **T1201** (Password Policy Discovery): No password policy query detection (net accounts)
- **T1120** (Peripheral Device Discovery): No device enumeration monitoring
- **T1614** (System Location Discovery): No geolocation discovery monitoring

**Tactic Summary:**

**Strengths:** Strong network reconnaissance detection, comprehensive command-line monitoring, AD enumeration tracking

**Gaps:** Limited share enumeration detection, minimal peripheral discovery monitoring, no password policy query detection, local storage discovery (T1680) needs behavioral baseline

**Priority:** Implement share enumeration monitoring (Q1 2026), add peripheral device tracking (Q2 2026), enhance local storage discovery detection (T1680 - Q1 2026)

---

## TA0008 - Lateral Movement

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1210 | Exploitation of Remote Services | **PARTIAL** | Suricata/Snort signatures detect known exploits (EternalBlue, BlueKeep); vulnerability scanning identifies exploitable services; limited zero-day detection | **GAP:** Deploy exploit detection via behavioral analysis; implement exploit mitigation features; add honeypot services |
| T1021.001 | Remote Desktop Protocol | **FULL** | Suricata monitors RDP traffic; Wazuh tracks RDP sessions (Event ID 4624 type 10, 4625); Splunk correlates unusual RDP patterns; detection of RDP from unusual sources; monitoring of RDP tunneling | Implement RDP gateway with MFA; add session recording; deploy geographic restrictions |
| T1021.002 | SMB/Windows Admin Shares | **FULL** | Suricata monitors SMB traffic; Event logs track admin share access (Event ID 5140, 5145); Wazuh alerts on lateral movement via PsExec, WMIC; detection of administrative tool usage | Deploy SMB signing enforcement; implement network segmentation; add admin share access baseline |
| T1021.004 | SSH | **FULL** | Comprehensive SSH logging to SIEM; Wazuh monitors all SSH sessions; detection of: key-based auth anomalies, unusual SSH sources, privilege escalation via sudo; Splunk tracks SSH lateral movement patterns | Implement SSH certificate authority; add session recording; deploy jump host architecture |
| T1080 | Taint Shared Content | **PARTIAL** | Wazuh FIM monitors shared directories; detection of file modifications on network shares; limited content tampering detection | **GAP:** Implement share access behavioral baseline; add file integrity verification; deploy honeypot files on shares |
| T1563 | Remote Service Session Hijacking | **PARTIAL** | Limited session hijacking detection; monitoring of unusual session activity | **GAP:** Implement session validation (IP, User-Agent binding); add session termination on anomaly; deploy privileged session monitoring |
| T1021.006 | Windows Remote Management | **MINIMAL** | Limited WinRM monitoring (Event ID 4688 for wsmprovhost.exe) | **GAP:** Enable comprehensive WinRM logging (Event ID 6, 91, 168); implement WinRM usage baseline; add remote PowerShell detection |
| T1072 | Software Deployment Tools | **MINIMAL** | No SCCM/deployment tool monitoring | **GAP:** Implement deployment tool activity monitoring; add unauthorized deployment detection; deploy approval workflow |
| T1550 | Use Alternate Authentication Material | **MINIMAL** | No pass-the-hash/pass-the-ticket detection | **GAP:** Enable detection of: pass-the-hash (Event ID 4624/4625 type 9), pass-the-ticket (Kerberos anomalies), token theft; deploy Credential Guard |

**Tactic Summary:**

**Strengths:** Strong RDP/SMB/SSH monitoring, comprehensive authentication logging, lateral movement detection

**Gaps:** Minimal WinRM visibility, no pass-the-hash detection, limited deployment tool monitoring

**Priority:** Implement pass-the-hash detection (immediate), enable WinRM logging (Q1 2026)

---

## TA0009 - Collection

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1560 | Archive Collected Data | **PARTIAL** | Process monitoring detects: 7zip, WinRAR, tar, zip commands; Wazuh tracks archive creation in suspicious locations; limited behavioral analysis of data staging | **GAP:** Implement data staging detection via file access patterns; add archive content analysis; deploy DLP for sensitive data archiving |
| T1123 | Audio Capture | **PARTIAL** | Limited microphone access monitoring; process monitoring detects audio recording tools | **GAP:** Implement audio device access controls; add microphone usage monitoring; deploy privacy controls |
| T1005 | Data from Local System | **PARTIAL** | Wazuh FIM detects mass file access; limited data exfiltration staging detection; monitoring of file access in sensitive directories | **GAP:** Deploy DLP for sensitive file access; implement data classification; add user entity behavior analytics (UEBA) for abnormal file access |
| T1039 | Data from Network Shared Drive | **MINIMAL** | No dedicated network share access monitoring beyond authentication logs | **GAP:** Implement share access behavioral baseline; deploy file access auditing on shares; add DLP for share-based exfiltration |
| T1025 | Data from Removable Media | **PARTIAL** | Wazuh monitors USB device insertion (Event ID 2003); limited file access monitoring from removable media | **GAP:** Implement removable media file access tracking; add DLP for USB data transfers; deploy device control policies |
| T1074 | Data Staged | **MINIMAL** | Limited staging location monitoring; file creation in Temp directories tracked | **GAP:** Implement behavioral detection for data staging; add anomaly detection for large file consolidation; deploy honeypot staging directories |
| T1213.006 | Data from Information Repositories: Databases | **MINIMAL** | No database-specific monitoring implemented; limited visibility into database query patterns or mass data extraction | **GAP:** Implement database access logging (MySQL/PostgreSQL audit logs); Deploy query monitoring for mass SELECT statements; Add SIEM correlation for unusual database access patterns; Implement database exfiltration detection (large result sets, off-hours queries); Consider if databases are in lab scope |
| T1114 | Email Collection | **MINIMAL** | No email access monitoring (Outlook PST, webmail) | **GAP:** Deploy email access auditing; implement mailbox audit logging; add email exfiltration detection |
| T1115 | Clipboard Data | **NOT APPLICABLE** | No clipboard monitoring capabilities | **GAP:** Implement clipboard access detection; add clipboard content analysis for sensitive data |
| T1530 | Data from Cloud Storage | **NOT APPLICABLE** | Minimal cloud storage usage; no cloud access monitoring | N/A or deploy cloud access security broker (CASB) if cloud usage increases |

**Major Unmonitored Collection Techniques:**

- **T1213.006** (Data from Databases): No database query monitoring or exfiltration detection
- **T1056** (Input Capture): No keylogger detection, credential input monitoring
- **T1113** (Screen Capture): No screenshot detection capabilities
- **T1125** (Video Capture): No webcam access monitoring
- **T1119** (Automated Collection): Limited detection of automated data gathering scripts
- **T1185** (Browser Session Hijacking): No browser extension/plugin monitoring for data theft
- **T1213** (Data from Information Repositories): T1213.006 (Databases) not monitored; No SharePoint/wiki/documentation platform monitoring

**Tactic Summary:**

**Strengths:** Basic archive detection, USB device monitoring, file access tracking

**Gaps:** Minimal DLP capabilities, no email collection detection, limited staging detection

**Priority:** Deploy DLP solution (Q2 2026), implement email auditing (Q1 2026), add UEBA for collection detection (Q2 2026)

---

## TA0010 - Exfiltration

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1020 | Automated Exfiltration | **PARTIAL** | pfSense monitors bandwidth usage; Prometheus tracks outbound traffic volume; Suricata detects large data transfers; threshold alerts for unusual upload rates | **GAP:** Implement behavioral baseline for normal data transfers; add time-series anomaly detection; deploy DLP for automated exfiltration prevention |
| T1030 | Data Transfer Size Limits | **PARTIAL** | Network monitoring detects chunked transfers; Splunk analyzes transfer patterns; limited detection of data obfuscation via chunking | **GAP:** Implement transfer pattern analysis; add detection for slow exfiltration; deploy statistical analysis of outbound data sizes |
| T1048 | Exfiltration Over Alternative Protocol | **PARTIAL** | Suricata monitors non-standard protocols; pfSense logs unusual port usage; DNS tunneling detection via query analysis (Pi-hole); ICMP tunneling detection | **GAP:** Enhance DNS tunneling detection (entropy analysis, subdomain length); add steganography detection; implement protocol anomaly detection |
| T1041 | Exfiltration Over C2 Channel | **FULL** | Suricata/Snort detect C2 beacon patterns; pfSense logs all outbound connections; MISP correlates known C2 IOCs; Cortex enriches suspicious IPs with threat intelligence; TheHive tracks C2 communications | Deploy automated C2 blocking; implement beacon detection (jitter analysis); add domain generation algorithm (DGA) detection |
| T1011 | Exfiltration Over Other Network Medium | **MINIMAL** | No Bluetooth/WiFi exfiltration monitoring | **GAP:** Implement wireless network monitoring; add Bluetooth device detection; deploy air-gapped network controls |
| T1052 | Exfiltration Over Physical Medium | **PARTIAL** | USB device insertion monitored; limited file transfer tracking to removable media | **GAP:** Implement USB file transfer auditing; add DLP for removable media; deploy device control policies with allow/block lists |
| T1567 | Exfiltration Over Web Service | **MINIMAL** | TLS inspection limited; no web service-specific exfiltration detection (Dropbox, Google Drive, Pastebin) | **GAP:** Deploy web service usage monitoring; implement cloud DLP; add web traffic categorization; monitor OAuth token usage |
| T1029 | Scheduled Transfer | **MINIMAL** | Limited detection of scheduled exfiltration tasks | **GAP:** Correlate scheduled tasks with network activity; add time-based exfiltration pattern detection; implement job scheduler monitoring |
| T1537 | Transfer Data to Cloud Account | **MINIMAL** | No cloud upload monitoring | **GAP:** Deploy CASB for cloud service monitoring; implement cloud DLP; add sanctioned vs. unsanctioned cloud service detection |

**Tactic Summary:**

**Strengths:** Strong C2 detection, DNS tunneling monitoring, bandwidth alerting

**Gaps:** Limited web service exfiltration detection, no physical medium file tracking, minimal cloud exfiltration monitoring

**Priority:** Deploy DLP capabilities (Q2 2026), implement web service monitoring (Q1 2026), add physical media auditing (Q1 2026)

**Note on ATT&CK v18.1 Updates:**

- T1681 (Search Threat Vendor Data): Reconnaissance technique; not directly detectable in lab environment (external attacker activity)
- T1677 (Poisoned Pipeline Execution): Not applicable unless CI/CD pipelines are in scope; see Execution section if implementing

---

## TA0011 - Command and Control

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1071 | Application Layer Protocol | **FULL** | Suricata/Snort analyze HTTP/HTTPS traffic patterns; pfSense logs all application protocols; Traefik access logs provide HTTP visibility; detection of C2 over HTTP/HTTPS, DNS, SMTP | Deploy TLS inspection for encrypted C2; implement user-agent analysis; add HTTP header anomaly detection |
| T1132 | Data Encoding | **PARTIAL** | Suricata detects base64, hex encoding in traffic; limited entropy analysis; Splunk searches for encoded data patterns | **GAP:** Implement comprehensive entropy analysis; add multi-layer decoding detection; deploy ML-based encoding detection |
| T1001 | Data Obfuscation | **PARTIAL** | Suricata monitors traffic anomalies; limited protocol obfuscation detection; detection of steganography signatures | **GAP:** Deploy steganography detection tools; implement protocol conformance validation; add traffic normalization analysis |
| T1568 | Dynamic Resolution | **FULL** | Pi-hole logs all DNS queries; pfSense DNS logs forwarded to SIEM; Suricata detects DGA patterns; detection of: fast flux, domain generation algorithms, DNS tunneling; MISP correlates suspicious domains | Enhance DGA detection with ML models; implement NXDomain tracking; add DNS reputation scoring |
| T1573 | Encrypted Channel | **PARTIAL** | Suricata analyzes TLS metadata (certificate details, cipher suites, JA3 fingerprints); limited TLS decryption capabilities; detection of unusual TLS patterns | **GAP:** Deploy TLS inspection infrastructure; implement certificate anomaly detection; add JA3/JA3S fingerprint threat intelligence |
| T1571 | Non-Standard Port | **FULL** | Suricata/pfSense detect protocol-port mismatches (HTTP on 8443, SSH on 443); Splunk correlates unusual port usage; detection of port obfuscation; monitoring of all non-standard service ports | Add port usage behavioral baseline; implement service fingerprinting; deploy protocol conformance validation |
| T1095 | Non-Application Layer Protocol | **PARTIAL** | Suricata monitors ICMP tunneling; pfSense logs raw socket connections; limited detection of custom protocols | **GAP:** Implement comprehensive ICMP analysis; add GRE/IPIP tunnel detection; deploy protocol anomaly detection |
| T1572 | Protocol Tunneling | **PARTIAL** | Suricata detects SSH tunneling, DNS tunneling, VPN-over-DNS; limited detection of protocol encapsulation techniques | **GAP:** Deploy comprehensive tunneling detection; implement encapsulation pattern analysis; add behavioral baseline for tunneling |
| T1090 | Proxy | **FULL** | pfSense logs proxy connections; Suricata detects SOCKS, HTTP proxy usage; detection of: internal proxy usage, unusual proxy chains, tor exit nodes | Add proxy authentication enforcement; implement proxy reputation scoring; deploy allowlist for legitimate proxies |
| T1219 | Remote Access Software | **MINIMAL** | Limited remote access tool detection (TeamViewer, AnyDesk, LogMeIn signatures in Suricata) | **GAP:** Deploy comprehensive remote access tool inventory; implement application control for remote access; add remote access behavioral baseline |
| T1105 | Ingress Tool Transfer | **PARTIAL** | Monitors file downloads via HTTP/HTTPS; PowerShell DownloadFile detection; limited executable download analysis | **GAP:** Implement comprehensive download monitoring; add executable reputation checking; deploy sandbox for downloaded files |
| T1104 | Multi-Stage Channels | **MINIMAL** | Limited multi-stage C2 detection | **GAP:** Implement C2 session correlation across channels; add multi-protocol C2 detection; deploy behavioral analysis for staged communication |

**Additional Unmonitored C2 Techniques:**

- **T1102** (Web Service): Limited detection of C2 over legitimate web services (Twitter, GitHub, Pastebin)
- **T1659** (Content Injection): Minimal content injection detection in C2 channels
- **T1205** (Traffic Signaling): No port knocking or traffic manipulation detection
- **T1665** (Hide Infrastructure): Limited CDN/cloud fronting detection

**Tactic Summary:**

**Strengths:** Strong DNS monitoring, proxy detection, non-standard port identification

**Gaps:** Limited TLS inspection, minimal remote access tool detection, no traffic signaling monitoring

**Priority:** Deploy TLS inspection (Q2 2026), implement remote access tool controls (Q1 2026), add web service C2 detection (Q2 2026)

---

## TA0040 - Impact

| Technique ID | Technique Name | Defense Status | Lab Implementation | Recommendations |
|--------------|----------------|----------------|-------------------|-----------------|
| T1485 | Data Destruction | **PARTIAL** | Wazuh FIM detects mass file deletion (>50 files/min); monitoring of del, rm, Remove-Item commands; limited detection of secure wipe tools | **GAP:** Implement file deletion behavioral baseline; add volume shadow copy deletion detection; deploy immutable backups |
| T1486 | Data Encrypted for Impact | **FULL** | Wazuh detects mass file modification (>50 files/min); Shuffle ransomware workflow monitors: file extension changes (.encrypted, .locked), ransomware note creation (README.txt), encryption tool execution; automated containment via Active Response; sub-30-minute MTTR | Deploy ransomware-specific behavioral detection; implement canary files for early detection; add automated network isolation |
| T1490 | Inhibit System Recovery | **PARTIAL** | Wazuh FIM monitors backup file access; Event ID 524 (VSS deletion) alerts; limited vssadmin, wbadmin command detection | **GAP:** Implement comprehensive backup tampering detection; add volume shadow copy protection; deploy immutable backup verification |
| T1498 | Network Denial of Service | **PARTIAL** | Suricata detects SYN floods, UDP floods; pfSense monitors bandwidth spikes; Prometheus alerts on connection exhaustion; limited distributed DDoS detection | **GAP:** Deploy comprehensive DDoS mitigation; implement rate limiting at firewall; add uplink provider DDoS protection |
| T1496 | Resource Hijacking | **FULL** | Prometheus monitors CPU/memory anomalies; Grafana alerts on sustained high resource usage; Wazuh detects cryptomining processes (xmrig, cpuminer); detection of GPU mining activity; Checkmk infrastructure monitoring | Add cryptomining network pattern detection; implement process reputation scoring; deploy GPU usage monitoring |
| T1489 | Service Stop | **FULL** | Wazuh monitors service stop events (Event ID 7036); systemd service failures tracked; critical service protection alerts; detection of security service termination; automated service recovery | Implement service stop approval workflow; add critical service health checks; deploy service dependency mapping |
| T1657 | Financial Theft | **NOT APPLICABLE** | No financial transaction monitoring in scope | N/A |
| T1491 | Defacement | **PARTIAL** | Wazuh FIM monitors web directories; limited web content integrity verification | **GAP:** Implement website content baseline; add automated defacement detection; deploy web application integrity monitoring |
| T1561 | Disk Wipe | **MINIMAL** | Limited detection of disk wipe tools (diskpart, dd, shred) | **GAP:** Implement disk modification monitoring; add MBR/boot sector protection; deploy bootloader integrity verification |
| T1499 | Endpoint Denial of Service | **PARTIAL** | Resource exhaustion monitoring; process CPU/memory limits; limited fork bomb detection | **GAP:** Implement process spawn rate limiting; add resource quota enforcement; deploy fork bomb detection |

**Additional Unmonitored Impact Techniques:**

- **T1495** (Firmware Corruption): No UEFI/BIOS integrity monitoring
- **T1529** (System Shutdown/Reboot): Limited shutdown command monitoring
- **T1531** (Account Access Removal): No bulk account deletion detection

**Tactic Summary:**

**Strengths:** Excellent ransomware detection, strong resource hijacking monitoring, service stop protection

**Gaps:** Limited disk wipe detection, minimal defacement monitoring, no firmware integrity verification

**Priority:** Implement disk modification monitoring (Q1 2026), add defacement detection (Q1 2026), deploy firmware integrity checks (Q3 2026)

---

## Overall Coverage Summary

**Coverage by Tactic**

| Tactic | Coverage | Maturity | Priority Enhancements |
|--------|----------|----------|-----------------------|
| Initial Access | 67% (6/9) | Strong | SBOM tracking, content injection detection (T1659 existing) |
| Execution | 67% (9/13) | Strong | WMI logging, container CLI/API (T1059.013), container security enhancement |
| Persistence | 37% (8/20) | Moderate | BITS monitoring, browser extension tracking, Office persistence, Python startup hooks (T1546.018) |
| Privilege Escalation | 38% (5/13) | Moderate | Process injection detection, UAC bypass enhancement, container escape detection |
| Defense Evasion | 21% (13/46) | Weak | Obfuscation analysis, pass-the-hash detection, alternate auth material monitoring, v18.1 techniques (T1678, T1679, T1036.012, T1562.013) |
| Credential Access | 27% (4/15) | Weak | Kerberos monitoring, session hijacking detection, password store coverage |
| Discovery | 30% (10/32) | Moderate | Share enumeration, peripheral tracking, backup software (T1518.002 covered), local storage (T1680) baseline |
| Lateral Movement | 56% (5/9) | Strong | Pass-the-hash detection, WinRM logging, deployment tool monitoring |
| Collection | 20% (4/18) | Weak | DLP implementation, email auditing, UEBA, database monitoring (T1213.006) |
| Exfiltration | 44% (4/9) | Moderate | DLP deployment, web service monitoring, physical media auditing |
| Command and Control | 38% (6/16) | Moderate | TLS inspection, remote access tool controls, web service C2 detection |
| Impact | 46% (6/13) | Moderate | Disk modification monitoring, defacement detection, firmware integrity |

**Overall lab coverage: 30% (65 techniques of 216)**

---

## Key Changes in v18.1

| Change Type | Count | Details |
|-------------|-------|---------|
| **New Techniques** | 12 | T1059.013, T1213.006, T1678, T1546.018, T1562.013, T1680, T1036.012, T1677, T1681, T1679, T1518.002, T1204.005 |
| **Total Techniques** | 216 | Increased from 191 (13% growth) |
| **Total Sub-techniques** | 475 | Increased from 385 (23% growth) |
| **Lab Coverage Impact** | -4% | Coverage adjusted from 34% to 30% due to denominator increase |

---

## Threat Intelligence Updates

**New Threat Actors (Update MISP):**

- G1053 - Storm-0501 (Ransomware operations)
- G1048 - UNC3886 (VMware/network device exploitation)
- G1052 - Contagious Interview (Supply chain via fake interviews)
- G1051 - Medusa Group (Ransomware)
- G1050 - Water Galura (APT/critical infrastructure)
- G1049 - AppleJeus (Cryptocurrency theft)

**New Malware Families (Update IDS Signatures):**

- S1240 - RedLine Stealer
- S1242 - Qilin Ransomware
- S1244 - Medusa Ransomware
- S1111 - DarkGate Loader
- S1229 - Havoc C2 Framework
- S1247 - Embargo Ransomware
- S1245 - InvisibleFerret Backdoor