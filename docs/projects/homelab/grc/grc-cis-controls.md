# CIS Critical Security Controls v8.1
```text
Document Control:
Version: 2.0
Last Updated: January 2026
Owner: Paul Leone
Classification: External Use
```    
---

## Table of Contents

1. [CIS Control 1: Inventory and Control of Enterprise Assets](#cis-control-1-inventory-and-control-of-enterprise-assets)
2. [CIS Control 2: Inventory and Control of Software Assets](#cis-control-2-inventory-and-control-of-software-assets)
3. [CIS Control 3: Data Protection](#cis-control-3-data-protection)
4. [CIS Control 4: Secure Configuration of Enterprise Assets and Software](#cis-control-4-secure-configuration-of-enterprise-assets-and-software)
5. [CIS Control 5: Account Management](#cis-control-5-account-management)
6. [CIS Control 6: Access Control Management](#cis-control-6-access-control-management)
7. [CIS Control 7: Continuous Vulnerability Management](#cis-control-7-continuous-vulnerability-management)
8. [CIS Control 8: Audit Log Management](#cis-control-8-audit-log-management)
9. [CIS Control 9: Email and Web Browser Protections](#cis-control-9-email-and-web-browser-protections)
10. [CIS Control 10: Malware Defenses](#cis-control-10-malware-defenses)
11. [CIS Control 11: Data Recovery](#cis-control-11-data-recovery)
12. [CIS Control 12: Network Infrastructure Management](#cis-control-12-network-infrastructure-management)
13. [CIS Control 13: Network Monitoring and Defense](#cis-control-13-network-monitoring-and-defense)
14. [CIS Control 14: Security Awareness and Skills Training](#cis-control-14-security-awareness-and-skills-training)
15. [CIS Control 15: Service Provider Management](#cis-control-15-service-provider-management)
16. [CIS Control 16: Application Software Security](#cis-control-16-application-software-security)
17. [CIS Control 17: Incident Response Management](#cis-control-17-incident-response-management)
18. [CIS Control 18: Penetration Testing](#cis-control-18-penetration-testing)
19. [Summary of Compliance Status](#summary-of-compliance-status)

---

## CIS Control 1: Inventory and Control of Enterprise Assets

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 1.1 | Establish and maintain detailed enterprise asset inventory | External Excel Inventory, Checkmk inventory, Wazuh agent inventory (25+ endpoints), Prometheus node exporters, PatchMon tracking (30+ hosts), DNS records, SSH host keys in Ansible | Compliant - Multiple sources provide comprehensive coverage |
| 1.2 | Address unauthorized assets weekly | Partial - NetalertX network discovery identifies unknown devices; no documented weekly review process | Gap: Need documented weekly unauthorized asset review procedure |
| 1.3 | Utilize an active discovery tool (IG2) | NetalertX network discovery, nmap scans, custom Python scanner | Compliant - Active scanning implemented |
| 1.4 | Use DHCP logging to update inventory (IG2) | Asus Router DHCP logs (192.168.1.0/24) + pfSense DHCP logs (192.168.100.0/24) forwarded to Splunk/Elastic | Compliant - DHCP logging centralized |
| 1.5 | Use passive asset discovery tool (IG3) | Passive network monitoring via Suricata/pfSense flow logs | Compliant - Passive discovery via traffic analysis |

**Control 1 Overall Status**: **Compliant** (minor process documentation gap in 1.2)

---

## CIS Control 2: Inventory and Control of Software Assets

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 2.1 | Establish and maintain software inventory | External Excel Inventory, PatchMon Software Inventory (5,000+ packages), Checkmk inventory, Nessus software scanning, Wazuh agent software tracking | Compliant - Multi-source software inventory |
| 2.2 | Ensure authorized software is currently supported | PatchMon tracks EOL software; vulnerability scanners flag unsupported versions; documented exceptions for necessary legacy software | Compliant - Supported software validation process |
| 2.3 | Address unauthorized software monthly | N/A - Single-user lab environment | N/A |
| 2.4 | Utilize automated software inventory tools (IG2) | PatchMon agent-based inventory, Checkmk, Wazuh software tracking, Nessus authenticated scans | Compliant - Automated discovery |
| 2.5 | Allowlist authorized software (IG2) | Not Implemented - No application allowlisting solution deployed | Gap: Implement AppLocker, Windows Defender Application Control, or CrowdSec allowlisting |
| 2.6 | Allowlist authorized libraries (IG2) | Not Implemented - No DLL/library allowlisting | Gap: IG2 requirement not addressed |
| 2.7 | Allowlist authorized scripts (IG3) | Not Implemented - No script execution control (PowerShell Constrained Language Mode, etc.) | Gap: IG3 requirement not addressed |

**Control 2 Overall Status**: **Partially Compliant** (IG1 fully compliant; IG2/IG3 gaps in allowlisting)

---

## CIS Control 3: Data Protection

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 3.1 | Establish and maintain a data management process | Documented in GRC document; data classification, retention, disposal procedures defined | Compliant |
| 3.2 | Establish and maintain data inventory | Sensitive data tracked in inventory; backup data cataloged; scan credentials documented | Compliant |
| 3.3 | Configure data access control lists | File system ACLs; SSH key-based access; database access controls; Authentik RBAC | Compliant |
| 3.4 | Enforce data retention | 90-day log retention; backup retention policies; automated cleanup | Compliant |
| 3.5 | Securely dispose of data | Secure deletion procedures; encrypted backup disposal; NIST SP 800-88 alignment | Compliant |
| 3.6 | Encrypt data on end-user devices | Windows BitLocker, Linux LUKS, encrypted laptop drives | Compliant |
| 3.7 | Establish data classification scheme (IG2) | Sensitive/Confidential/Public labels used in documentation | Compliant |
| 3.8 | Document data flows (IG2) | Partial - Network architecture documented; full data flow diagrams not comprehensive | Gap: Create detailed data flow diagrams |
| 3.9 | Encrypt data on removable media (IG2) | USB drives encrypted; backup tapes encrypted | Compliant |
| 3.10 | Encrypt sensitive data in transit (IG2) | TLS 1.3 (Traefik), SSH encryption, syslog-ng TLS, VPN encryption | Compliant |
| 3.11 | Encrypt sensitive data at rest (IG2) | Encrypted backups, database encryption, scan credential encryption | Compliant |
| 3.12 | Segment data processing based on sensitivity (IG2) | VLAN segmentation; backend isolation (Traefik); network segmentation | Compliant |
| 3.13 | Deploy Data Loss Prevention solution (IG3) | Not Implemented - No DLP solution deployed | Gap: IG3 requirement (acceptable for homelab) |
| 3.14 | Log sensitive data access (IG3) | Partial - File access logged via Wazuh FIM; database query logging not comprehensive | Gap: Enhanced database audit logging |

**Control 3 Overall Status**: **IG1/IG2 Compliant; IG3 Partial** (DLP not applicable to homelab)

---

## CIS Control 4: Secure Configuration of Enterprise Assets and Software

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 4.1 | Establish and maintain secure configuration process | CIS Benchmark audits via Wazuh; configuration drift detection; automated remediation via Ansible; Ansible baselines; IaC version control. Not Implemented - documented secure configuration process (policy document) | Action Required: Create formal secure configuration policy document |
| 4.2 | Establish secure configuration process for network infrastructure | Network device hardening standards documented; SSH hardening policy; firewall rule standards | Compliant |
| 4.3 | Configure automatic session locking | 15-min timeout (general OS); 2-min timeout (mobile devices); enforced via GPO/Ansible | Compliant |
| 4.4 | Implement firewall on servers | UFW (Linux), Windows Firewall, iptables rules managed via Ansible | Compliant |
| 4.5 | Implement firewall on end-user devices | Host-based firewalls enabled on all endpoints; default-deny ruleset | Compliant |
| 4.6 | Securely manage enterprise assets | SSH key-based admin access; IaC version control (Git); HTTPS-only management interfaces | Compliant |
| 4.7 | Manage default accounts | Root login disabled (SSH); default vendor accounts removed; validated via Nessus scans | Compliant |
| 4.8 | Uninstall unnecessary services (IG2) | Minimal service footprint; unnecessary services disabled; verified via authenticated scans | Compliant |
| 4.9 | Configure trusted DNS servers (IG2) | Enterprise-controlled DNS (Pi-hole, Unbound); DNSSEC validation | Compliant |
| 4.10 | Enforce automatic lockout on portable devices (IG2) | Failed auth lockout (laptops: 20 attempts; mobile: 10 attempts) via GPO/MDM | Compliant |
| 4.11 | Enforce remote wipe capability (IG2) | Not Implemented - Mobile device wipe capability via planned MDM; laptops rely on full-disk encryption | Gap: Implement remote wipe for laptops (BitLocker recovery key escrowing) |
| 4.12 | Separate enterprise workspaces on mobile devices (IG3) | Not Implemented - No Android Work Profile/iOS Managed App separation | Gap: IG3 mobile device management |

**Control 4 Overall Status**: **Needs Process Documentation** (4.1 critical)

---

## CIS Control 5: Account Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 5.1 | Establish and maintain account inventory | Authentik user database, Active Directory accounts, SSH key inventory (Ansible), Wazuh user tracking | Compliant |
| 5.2 | Use unique passwords | Vaultwarden password manager; 8-char minimum (MFA accounts); 14-char minimum (non-MFA) | Compliant - Exceeds CIS recommendations |
| 5.3 | Disable dormant accounts after 45 days | Automated via Active Directory account expiration policies; Authentik account lifecycle management | Compliant |
| 5.4 | Restrict admin privileges to dedicated accounts | Separate admin accounts (no dual-use); SSH sudo enforcement; Authentik RBAC | Compliant |
| 5.5 | Establish service account inventory (IG2) | Service accounts documented in inventory; ownership tracked; quarterly reviews | Compliant |
| 5.6 | Centralize account management (IG2) | Authentik SSO + Active Directory; centralized SSH key management (Ansible) | Compliant |

**Control 5 Overall Status**: **Fully Compliant**

---

## CIS Control 6: Access Control Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 6.1 | Establish access granting process | Documented onboarding procedures; Authentik provisioning; SSH key distribution workflow | Compliant |
| 6.2 | Establish access revocation process | Offboarding checklist; Authentik account deactivation; SSH key revocation (Ansible); Wazuh Active Response | Compliant |
| 6.3 | Require MFA for externally-exposed applications | Authentik enforces MFA via TOTP; all external services require MFA | Compliant |
| 6.4 | Require MFA for remote network access | VPN (Tailscale) requires device authentication; SSH keys + optional passphrase | Compliant |
| 6.5 | Require MFA for administrative access | 100% admin accounts require Authentik MFA; SSH key-based auth for privileged access | Compliant |
| 6.6 | Establish authentication/authorization system inventory (IG2) | Authentik, Active Directory, SSH key infrastructure documented; annual review | Compliant |
| 6.7 | Centralize access control (IG2) | Authentik SSO for Traefik-routed services; Active Directory domain authentication | Compliant |
| 6.8 | Define and maintain role-based access control (IG3) | Not Implemented - Requires enterprise-wide RBAC documentation (access rights per role for all systems) | Action Required: Document RBAC policies for all enterprise systems (AD groups, Authentik roles, SSH sudo policies) |

**Control 6 Overall Status**: **Mostly Compliant**; 6.8 needs broader RBAC documentation

---

## CIS Control 7: Continuous Vulnerability Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 7.1 | Establish vulnerability management process | Documented dual-scanner approach (OpenVAS + Nessus); remediation SLAs; CVSS prioritization | Compliant |
| 7.2 | Establish remediation process | Risk-based remediation strategy; documented SLAs; monthly reviews; TheHive tracking | Compliant |
| 7.3 | Perform automated OS patch management | PatchMon (Linux), WSUS (Windows), monthly cadence; automated approvals | Compliant - Exceeds monthly requirement |
| 7.4 | Perform automated application patch management | Watchtower (containers), WUD monitoring, monthly cadence | Compliant |
| 7.5 | Perform automated vulnerability scans - internal (IG2) | Weekly OpenVAS (52/year); monthly Nessus authenticated scans (12/year) | Compliant - Exceeds quarterly requirement |
| 7.6 | Perform automated vulnerability scans - external (IG2) | Monthly Nessus scans of externally-exposed assets; OpenVAS external scans | Compliant |
| 7.7 | Remediate detected vulnerabilities (IG2) | MTTR <72h (Critical); <7 days (High); 95% patched within SLA; verification scans | Compliant |

**Control 7 Overall Status**: **Fully Compliant** - Exceeds industry standards

---

## CIS Control 8: Audit Log Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 8.1 | Establish audit log management process | Documented logging policy; 90-day retention; centralized SIEM; review procedures | Compliant |
| 8.2 | Collect audit logs | 100% security event coverage (DNS, SSH, Traefik, vulnerability scans, patches, Wazuh, Sysmon) | Compliant |
| 8.3 | Ensure adequate log storage | SIEM storage capacity planning; immutable indexes; compressed archival | Compliant |
| 8.4 | Standardize time synchronization (IG2) | NTP sync across all assets; centralized time sources | Compliant |
| 8.5 | Collect detailed audit logs (IG2) | Logs include timestamp, user, source IP, action, result, SSH key fingerprints, DNS query details | Compliant |
| 8.6 | Collect DNS query logs (IG2) | Pi-hole query logs; Unbound logs; Bind9 query logging; forwarded to SIEM | Compliant |
| 8.7 | Collect URL request logs (IG2) | Traefik access logs (JSON format); proxy logs; forwarded to SIEM | Compliant |
| 8.8 | Collect command-line logs (IG2) | Sysmon Event ID 1 (process creation); PowerShell logging; Bash history; Wazuh command monitoring | Compliant |
| 8.9 | Centralize audit logs (IG2) | Dual SIEM (Splunk + Elastic); syslog-ng encrypted forwarding; centralized storage | Compliant |
| 8.10 | Retain audit logs 90 days minimum (IG2) | 90-day retention policy; immutable SIEM indexes | Compliant |
| 8.11 | Conduct audit log reviews weekly (IG2) | Splunk dashboards; Wazuh alerts; weekly correlation searches; automated reviews | Compliant |
| 8.12 | Collect service provider logs (IG3) | Partial - Cloud service logs collected where available; not comprehensive across all SaaS platforms | Gap: Document which SaaS platforms provide logs |

**Control 8 Overall Status**: **Fully Compliant** (IG1/IG2); **IG3 Partial** (limited by SaaS provider capabilities)

---

## CIS Control 9: Email and Web Browser Protections

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 9.1 | Ensure only fully supported browsers/email clients | Latest browser versions enforced; unsupported clients blocked; automated update verification | Compliant |
| 9.2 | Use DNS filtering services | Pi-hole DNS filtering (2M+ blocked domains); malware/phishing domain blocking | Compliant |
| 9.3 | Maintain network-based URL filters (IG2) | Traefik URL filtering; SafeLine WAF; category-based blocking; reputation filtering | Compliant |
| 9.4 | Restrict browser/email extensions (IG2) | Partial - GPO restricts extensions on managed Windows devices; Linux/personal devices rely on user compliance | Gap: Enforce extension restrictions across all platforms |
| 9.5 | Implement DMARC (IG2) | DMARC policy published; SPF + DKIM implemented for outbound mail | Compliant |
| 9.6 | Block unnecessary file types (IG2) | Partial - Email gateway blocks .exe/.scr/.bat attachments; not comprehensive | Gap: Expand blocked file type list |
| 9.7 | Deploy email server anti-malware (IG3) | Not Implemented - No dedicated email gateway anti-malware (homelab uses external email providers) | Gap: IG3 requirement (not applicable - no on-prem email server) |

**Control 9 Overall Status**: **IG1 Compliant; IG2 Partial; IG3 N/A** (no on-prem email)

---

## CIS Control 10: Malware Defenses

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 10.1 | Deploy and maintain anti-malware software | Wazuh FIM + VirusTotal integration; ClamAV; Microsoft Defender; rootkit detection | Compliant |
| 10.2 | Configure automatic anti-malware signature updates | Automated signature updates (daily); ClamAV freshclam; Defender definition updates | Compliant |
| 10.3 | Disable autorun/autoplay for removable media | GPO disables autorun; Linux udev rules block autoplay; verified compliance | Compliant |
| 10.4 | Configure automatic scanning of removable media (IG2) | Wazuh FIM monitors USB insertions; ClamAV on-access scanning | Compliant |
| 10.5 | Enable anti-exploitation features (IG2) | Windows DEP/WDEG enabled; Linux ASLR/PIE; macOS SIP/Gatekeeper | Compliant |
| 10.6 | Centrally manage anti-malware software (IG2) | Wazuh central management; Group Policy for Windows Defender; centralized config | Compliant |
| 10.7 | Use behavior-based anti-malware (IG2) | Wazuh behavioral analysis; Windows Defender behavior monitoring; Suricata IDS behavioral detection | Compliant |

**Control 10 Overall Status**: **Fully Compliant**

---

## CIS Control 11: Data Recovery

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 11.1 | Establish and maintain data recovery process | Documented backup procedures; restore workflows; recovery prioritization; annual reviews | Compliant |
| 11.2 | Perform automated backups | Proxmox automated backups (bi-weekly); Docker volume backups; database backups; weekly cadence | Compliant |
| 11.3 | Protect recovery data | Encrypted backups (AES-256); offsite storage; access controls; encrypted transmission | Compliant |
| 11.4 | Establish isolated instance of recovery data | Offsite backups (cloud + offline USB); air-gapped backup copies; versioned backups | Compliant |
| 11.5 | Test data recovery (IG2) | Quarterly restore testing; documented test results; validation procedures | Compliant |

**Control 11 Overall Status**: **Fully Compliant**

---

## CIS Control 12: Network Infrastructure Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 12.1 | Ensure network infrastructure is up-to-date | Network device patch management; monthly version checks; automated update notifications | Compliant |
| 12.2 | Establish secure network architecture (IG2) | Documented network architecture; segmentation design; least-privilege network design | Compliant |
| 12.3 | Securely manage network infrastructure (IG2) | SSH key-based management; HTTPS-only interfaces; IaC version control (Git) | Compliant |
| 12.4 | Establish architecture diagrams (IG2) | Network topology diagrams; Subnet/VLAN documentation; NetAlertX Networking mapping | Compliant |
| 12.5 | Centralize network AAA (IG2) | Not Implemented -- Lab does not have a dedicated AAA service deployed | Gap: implement AAA service |
| 12.6 | Use secure network protocols (IG2) | 802.1X port security (planned); WPA3 wireless; TLS 1.3; SSH v2 only | Compliant |
| 12.7 | Ensure remote devices use VPN + AAA (IG2) | Tailscale mesh VPN requires device authentication; Cloudflare Tunnels; no direct internet exposure | Compliant |
| 12.8 | Establish dedicated admin workstations (IG3) | Partial - Dedicated admin VM; not fully air-gapped from internet | Gap: Implement fully isolated admin workstation |

**Control 12 Overall Status**: **IG1/IG2 Compliant; IG3 Partial**

---

## CIS Control 13: Network Monitoring and Defense

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 13.1 | Centralize security event alerting (IG2) | Dual SIEM (Splunk + Elastic); TheHive case management; Discord/email alerting | Compliant |
| 13.2 | Deploy host-based IDS (IG2) | Wazuh EDR on 25+ endpoints; FIM monitoring; rootkit detection; process monitoring | Compliant |
| 13.3 | Deploy network IDS (IG2) | Suricata (IPS inline); Snort (IDS passive); CrowdSec (behavioral) | Compliant |
| 13.4 | Perform traffic filtering between segments (IG2) | pfSense/OPNsense inter-VLAN ACLs; firewall rules per segment; default-deny policies | Compliant |
| 13.5 | Manage access control for remote assets (IG2) | NAC principles applied; Tailscale device posture checks; Wazuh agent compliance verification | Compliant |
| 13.6 | Collect network traffic flow logs (IG2) | pfSense/OPNsense flow logs; Suricata EVE JSON; packet captures (tcpdump); SIEM ingestion | Compliant |
| 13.7 | Deploy host-based IPS (IG3) | Wazuh Active Response (firewall-drop, host-deny); EDR blocking capabilities | Compliant |
| 13.8 | Deploy network IPS (IG3) | Suricata inline blocking mode; CrowdSec automated firewall rules; pfSense IPS integration | Compliant |
| 13.9 | Deploy port-level access control (IG3) | Not Implemented -- Network switching replacement required; currently using MAC filtering + admin VLAN segmentation | Gap: Implement 802.1X NAC |
| 13.10 | Perform application layer filtering (IG3) | SafeLine WAF (OWASP CRS rules); Traefik middleware filtering; NGINX Ingress rules | Compliant |
| 13.11 | Tune security event alerting thresholds (IG3) | Monthly tuning of Splunk/Wazuh/Suricata thresholds; false positive reduction tracking | Compliant |

**Control 13 Overall Status**: **IG2 Fully Compliant; IG3 Mostly Compliant** (802.1X gap)

---

## CIS Control 14: Security Awareness and Skills Training

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 14.1 | Establish security awareness program | N/A - Single-user lab environment | N/A |
| 14.2 | Train workforce on social engineering | N/A - Single-user lab environment | N/A |
| 14.3 | Train workforce on authentication best practices | N/A - Single-user lab environment | N/A |
| 14.4 | Train workforce on data handling | N/A - Single-user lab environment | N/A |
| 14.5 | Train workforce on unintentional data exposure | N/A - Single-user lab environment | N/A |
| 14.6 | Train workforce on incident recognition/reporting | N/A - Single-user lab environment | N/A |
| 14.7 | Train workforce on identifying missing security updates | N/A - Single-user lab environment | N/A |
| 14.8 | Train workforce on insecure network dangers | N/A - Single-user lab environment | N/A |
| 14.9 | Conduct role-specific security training (IG2) | N/A - Single-user lab environment hands-on lab work; no formal certification program | N/A |

**Control 14 Overall Status**: **Limited Applicability** (single-user homelab)

---

## CIS Control 15: Service Provider Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 15.1 | Establish service provider inventory | Cloud providers documented (Cloudflare, Tailscale, etc.) | Compliant |
| 15.2 | Establish service provider management policy (IG2) | N/A - Single-user lab environment | N/A |
| 15.3 | Classify service providers (IG2) | N/A - Single-user lab environment | N/A |
| 15.4 | Ensure contracts include security requirements (IG2) | N/A - Single-user lab environment | N/A |
| 15.5 | Assess service providers (IG3) | N/A - Single-user lab environment | N/A |
| 15.6 | Monitor service providers (IG3) | N/A - Single-user lab environment | N/A |
| 15.7 | Securely decommission service providers (IG3) | N/A - Single-user lab environment | N/A |

**Control 15 Overall Status**: **Limited Applicability** (single-user homelab)

---

## CIS Control 16: Application Software Security

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 16.1 | Establish secure application development process (IG2) | Informal - IaC follows security best practices; no formal SDLC documentation | Gap: Document secure development lifecycle |
| 16.2 | Establish vulnerability disclosure process (IG2) | N/A - Single-user lab environment | N/A |
| 16.3 | Perform root cause analysis on vulnerabilities (IG2) | Informal - Post-incident reviews conducted; no formal RCA process | Gap: Document RCA procedures |
| 16.4 | Establish third-party software component inventory (IG2) | Partial - Docker images tracked; no comprehensive SBOM tracking | Gap: Implement SBOM tracking (Trivy/Grype) |
| 16.5 | Use up-to-date third-party components (IG2) | Watchtower auto-updates; WUD monitoring; trusted sources (official Docker images; maintained OSS projects) | Compliant |
| 16.6 | Establish vulnerability severity rating system (IG2) | CVSS scoring; risk-based prioritization; documented remediation SLAs | Compliant |
| 16.7 | Use standard hardening templates (IG2) | CIS Benchmarks for application infrastructure; IaC templates (Ansible/Terraform); documented configurations | Compliant |
| 16.8 | Separate production/non-production systems (IG2) | N/A - Single-user lab environment | N/A |
| 16.9 | Train developers in secure coding (IG2) | N/A - Single-user lab environment | N/A |
| 16.10 | Apply secure design principles (IG2) | Least privilege; input validation; defense-in-depth architecture; secure defaults | Compliant |
| 16.11 | Leverage vetted security modules (IG2) | Authentik (IAM); Step-CA (PKI); Traefik (reverse proxy); trusted open-source security libraries | Compliant |
| 16.12 | Implement code-level security checks (IG3) | Limited - Infrastructure code linting (Ansible-lint/Terraform validate); no comprehensive SAST/DAST | Gap: Implement SAST/DAST scanning |
| 16.13 | Conduct application penetration testing (IG3) | Informal - Vulnerability scanning covers web apps; Kali/Parrot OS Pen testing | Gap: Formal pen testing (IG3) |
| 16.14 | Conduct threat modeling (IG3) | Informal - Security architecture design considers threats; no formal STRIDE/DREAD modeling | Gap: Document threat models (IG3) |

**Control 16 Overall Status**: **IG2 Mostly Compliant** (infrastructure focus, not software development); **IG3 Partial**

---

## CIS Control 17: Incident Response Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 17.1 | Designate incident handling personnel | N/A - Single-user lab environment | N/A |
| 17.2 | Establish contact information for reporting | Discord channels; SMTP relay; Cloudflare email routing | Compliant |
| 17.3 | Establish enterprise incident reporting process | TheHive case creation process; reporting timeframes defined; multi-channel reporting (Discord, email, API) | Compliant |
| 17.4 | Establish incident response process (IG2) | Documented IR plan; TheHive playbooks | Compliant |
| 17.5 | Assign key roles and responsibilities (IG2) | N/A - Single-user lab environment | N/A |
| 17.6 | Define communication mechanisms (IG2) | Primary: Discord; Secondary: SMTP/Cloudflare email routing; multi-path redundancy | Compliant |
| 17.7 | Conduct routine IR exercises (IG2) | N/A - Single-user lab environment | N/A |
| 17.8 | Conduct post-incident reviews (IG2) | N/A - Single-user lab environment | N/A |
| 17.9 | Establish incident thresholds (IG3) | Severity matrix documented; CVSS thresholds; Splunk alert severities; MISP threat levels; Prometheus thresholds | Compliant |

**Control 17 Overall Status**: **Mostly Compliant**; **Minor Gap** in formal exercise scheduling

---

## CIS Control 18: Penetration Testing

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 18.1 | Establish penetration testing program (IG2) | Informal - Vulnerability scanning exceeds pen testing frequency; no formal pen testing engagement | Gap: Document formal pen testing program |
| 18.2 | Perform external penetration tests annually (IG2) | Informal - Weekly OpenVAS/monthly Nessus scans provide partial coverage; no dedicated external pen test | Gap: Conduct formal external pen test |
| 18.3 | Remediate penetration test findings (IG2) | Vulnerability remediation process covers pen test findings; documented remediation workflows | Compliant - Process exists |
| 18.4 | Validate security measures post-test (IG3) | Informal - Re-scanning validates remediation; no formal security control validation | Gap: Post-remediation validation testing |
| 18.5 | Perform internal penetration tests annually (IG3) | Informal -- No formal internal pen testing. Local scanning, enumeration and vulnerability testing. | Gap: IG3 requirement |

**Control 18 Overall Status**: **IG2 Partial** (vulnerability scanning substitutes for pen testing); **IG3 Not Implemented**

---

## Summary of Compliance Status

### Overall CIS Controls v8.1.2 Compliance

| Implementation Group | Controls Fully Compliant | Controls Partially Compliant | Controls Not Implemented | Overall Score |
|---------------------|--------------------------|------------------------------|-------------------------|---------------|
| **IG1** (56 safeguards) | 52 (93%) | 4 (7%) | 0 (0%) | **93% Compliant** |
| **IG2** (74 additional safeguards) | 60 (81%) | 12 (16%) | 2 (3%) | **81% Compliant** |
| **IG3** (29 additional safeguards) | 15 (52%) | 8 (28%) | 6 (20%) | **52% Compliant** |

