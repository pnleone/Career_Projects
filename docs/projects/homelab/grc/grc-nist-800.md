# NIST SP 800-53 Rev 5 Framework

**Document Control:**  
Version: 1.0  
Last Updated: January 2026  
Owner: Paul Leone  
Classification: Internal Use  

**Framework Version:** NIST SP 800-53 Revision 5

---

## Access Control (AC) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| AC-1 | Policy and Procedures | Lab mission statement defines security-first architecture; documented access control requirements | Implemented |
| AC-2 | Account Management | Authentik user lifecycle management; SSH individual user accounts; Wazuh tracks active sessions; no shared credentials | Implemented |
| AC-2(1) | Automated System Account Management | Authentik automated provisioning/deprovisioning | Implemented |
| AC-2(2) | Automated Temporary Account Management | N/A - No temporary accounts in lab environment | N/A |
| AC-2(3) | Disable Accounts | Authentik automated account disabling after 90 days inactivity | Partial |
| AC-2(4) | Automated Audit Actions | SIEM tracks all account creation/modification/deletion | Implemented |
| AC-2(5) | Inactivity Logout | Authentik 30-min idle timeout; SSH ClientAliveInterval=300 | Implemented |
| AC-2(7) | Privileged User Accounts | Separate admin accounts; monitored via SIEM; MFA enforced | Implemented |
| AC-2(9) | Restrictions on Shared Accounts | N/A -- Single user home lab | N/A |
| AC-2(12) | Account Monitoring Atypical Usage | Splunk behavioral analysis; unusual login times/geoIP tracking | Partial |
| AC-2(13) | Disable High-Risk Accounts | Wazuh Active Response disables compromised accounts. Remote access via root is not authorized. | Implemented |
| AC-3 | Access Enforcement | Authentik/AD RBAC groups; SSH sudo enforcement; Traefik middleware access control | Implemented |
| AC-3(7) | Role-Based Access Control | Authentik groups map to application permissions; AD OUs for Windows | Implemented |
| AC-3(8) | Revocation of Access | Centralized SSH key revocation via Ansible; Authentik account deactivation | Implemented |
| AC-5 | Separation of Duties | N/A -- Single user home lab | N/A |
| AC-6 | Least Privilege | SSH sudo policies; Authentik role-based permissions; minimal access granted | Implemented |
| AC-6(1) | Authorize Access to Security Functions | Security tool access restricted to SOC role; documented in Authentik | Implemented |
| AC-6(2) | Non-Privileged Access for Non-Security Functions | Standard user accounts for daily operations | Implemented |
| AC-6(5) | Privileged Accounts | Separate privileged accounts; monitored; MFA enforced | Implemented |
| AC-6(9) | Log Use of Privileged Functions | All sudo commands logged to SIEM; Windows privileged operations audited | Implemented |
| AC-7 | Unsuccessful Logon Attempts | SSH MaxAuthTries=5; Authentik lockout after 5 failures; Wazuh active-response | Implemented |
| AC-8 | System Use Notification | SSH banner configured; Authentik login notice | Implemented |
| AC-11 | Device Lock | N/A -- Single user home lab | N/A |
| AC-12 | Session Termination | Authentik session timeout; SSH automatic disconnect | Implemented |
| AC-17 | Remote Access | SSH hardening; IP restrictions (firewall + Traefik); MFA for admin access; Tailscale VPN | Implemented |
| AC-17(1) | Monitoring and Control | VPN connections logged; SSH sessions monitored; Traefik access logs | Implemented |
| AC-17(2) | Protection via Encryption | SSH AES-256-GCM; TLS 1.3 (Traefik); Tailscale WireGuard | Implemented |
| AC-17(4) | Privileged Commands via Remote Access | Privileged SSH sessions logged separately; sudo usage tracked | Implemented |
| AC-17(9) | Disconnect or Disable Access | Remote access can be disabled via firewall rules; Tailscale ACLs | Partial |
| AC-17(10) | Authenticate Remote Commands | SSH key-based authentication; command verification via logging | Implemented |

---

## Audit and Accountability (AU) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| AU-1 | Policy and Procedures | Comprehensive logging policy documented; 100% security event coverage requirement | Implemented |
| AU-2 | Event Logging | DNS queries, SSH sessions, Traefik requests, patch events, scan activity, Wazuh events logged | Implemented |
| AU-3 | Content of Audit Records | Logs include: timestamp, user, source IP, action, result; Wazuh includes file hashes, process trees | Implemented |
| AU-3(1) | Additional Audit Information | SSH key fingerprints, DNS query details, Traefik request/response, Sysmon process telemetry | Implemented |
| AU-4 | Audit Log Storage Capacity | 90-day retention; auto-archival to cold storage; capacity monitoring via Prometheus | Implemented |
| AU-5 | Response to Audit Logging Process Failures | SIEM alerts on logging failures; redundant log paths (local + remote) | Implemented |
| AU-5(1) | Storage Capacity Warning | Prometheus/Pulse alerts at 80% capacity; automated archival triggers, Proxmox and NAS storage monitoring. | Implemented |
| AU-5(2) | Real-Time Alerts | Splunk/Elastic real-time correlation; Wazuh instant alerts; sub-60s notification latency | Implemented |
| AU-6 | Audit Record Review | Splunk/ Elastic dashboards (DNS/SSH/Traefik); automated correlation; vulnerability trending; Wazuh dashboards | Implemented |
| AU-6(1) | Automated Process Integration | SIEM correlation across Splunk/Elastic/Wazuh; TheHive case aggregation; n8n/Shuffle workflows | Implemented |
| AU-6(3) | Correlate Audit Record Repositories | Multi-source correlation: Splunk + Elastic + Wazuh + network logs; unified timeline analysis | Implemented |
| AU-6(5) | Integrated Analysis | Cortex multi-engine analysis; MISP threat intelligence; Shuffle enrichment pipelines | Implemented |
| AU-7 | Audit Record Reduction | Splunk SPL queries; Elastic KQL; Wazuh filters; automated report generation | Implemented |
| AU-7(1) | Automatic Processing | Scheduled Splunk searches; Elastic detection rules; automated dashboards | Implemented |
| AU-9 | Protection of Audit Information | Logs forwarded to immutable SIEM; Splunk read-only indexes; syslog-ng TLS encryption; Elastic immutable streams | Implemented |
| AU-11 | Audit Record Retention | 90-day hot retention; 1-year cold storage; automated lifecycle management | Implemented |
| AU-12 | Audit Record Generation | Universal Forwarders (30+ hosts); Elastic Agents; Wazuh agents (25+); structured JSON format | Implemented |
| AU-12(1) | System-Wide Audit Trail | Centralized logging across all infrastructure; time-correlated via NTP (SC-45) | Implemented |
| AU-12(2) | Standardized Formats | JSON/CEF formats; normalized in SIEM; CIM-compliant (Splunk) | Implemented |

---

## Assessment, Authorization, and Monitoring (CA) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| CA-1 | Policy and Procedures | Assessment and authorization policy documented; continuous monitoring strategy defined | Implemented |
| CA-2 | Control Assessments | Weekly OpenVAS scans; monthly Nessus authenticated scans; CIS Benchmark audits; Wazuh SCA | Implemented |
| CA-2(1) | Independent Assessors | N/A -- Single user home lab | N/A |
| CA-3 | Information Exchange | Documented interconnections; firewall rules for external connections | Partial |
| CA-5 | Plan of Action and Milestones | Vulnerability tracking in TheHive; remediation SLAs documented | Partial |
| CA-6 | Authorization | N/A -- Single user home lab | N/A |
| CA-7 | Continuous Monitoring | Automated vulnerability scanning; real-time patch status; security posture dashboards; Wazuh real-time FIM | Implemented |
| CA-7(1) | Independent Assessment | N/A -- Single user home lab | N/A |
| CA-7(3) | Trend Analyses | Grafana dashboards track vulnerability trends over time | Implemented |
| CA-8 | Penetration Testing | Informal testing -- scanning, enumeration, vulnerability assessments. | Partial |
| CA-9 | Internal System Connections | Network diagram documents internal connections; firewall rules enforce segmentation; Netalert mapping. | Implemented |

---

## Configuration Management (CM) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| CM-1 | Policy and Procedures | Configuration management policy documented; IaC standards defined | Implemented |
| CM-2 | Baseline Configuration | Ansible playbooks define baselines; PatchMon baseline tracking; CIS Benchmark baselines audited via Nessus | Implemented |
| CM-2(2) | Automation Support | Ansible automation; Terraform IaC; automated baseline verification | Implemented |
| CM-2(3) | Retention of Previous Configurations | Git version control; snapshot-before-patch; configuration history retained | Implemented |
| CM-2(6) | Development and Test Environments | N/A -- Single user home lab | N/A |
| CM-3 | Configuration Change Control | Snapshot-before-patch; WSUS approval workflows; pre-scan snapshots; Git pull requests | Implemented |
| CM-3(2) | Testing and Validation | WSUS test deployments; Ansible dry-run; patch validation before production | Implemented |
| CM-4 | Impact Analyses | N/A -- Single user home lab | N/A |
| CM-5 | Access Restrictions for Change | Ansible playbook execution restricted; WSUS approval required; Git branch protection | Implemented |
| CM-6 | Configuration Settings | CIS Benchmark compliance audits; hardened SSH/Traefik configs; configuration deviations detected | Implemented |
| CM-6(1) | Automated Management | Ansible automation; configuration drift detection; automated remediation | Implemented |
| CM-7 | Least Functionality | Unnecessary services disabled; verified via authenticated Nessus scans | Implemented |
| CM-7(1) | Periodic Review | N/A -- Single user home lab | N/A |
| CM-8 | System Component Inventory | PatchMon (5,000+ packages, 30+ hosts); WUD (50+ containers); OpenVAS/Nessus asset databases; Wazuh agent inventory; Netalert Inventory | Implemented |
| CM-8(1) | Updates During Install/Removal | Inventory updated automatically and manually; Wazuh tracks software changes | Implemented |
| CM-8(2) | Automated Maintenance | PatchMon daily updates; WUD container tracking; automated inventory reconciliation | Implemented |
| CM-8(3) | Automated Unauthorized Component Detection | Nessus compliance scans detect unauthorized software; Wazuh FIM alerts on new executables; Netalert new device notifications. | Implemented |
| CM-9 | Configuration Management Plan | IaC strategy documented; Ansible playbook standards; Git workflow defined | Partial |
| CM-14 | Signed Components | Docker image signature verification (SHA-256); Step-CA signed certificates | Implemented |

---

## Contingency Planning (CP) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| CP-1 | Policy and Procedures | Backup procedures documented; failover strategies defined | Partial |
| CP-2 | Contingency Plan | N/A -- Single user home lab | N/A |
| CP-3 | Contingency Training | N/A -- Single user home lab | N/A |
| CP-4 | Contingency Plan Testing | N/A -- Single user home lab | N/A |
| CP-6 | Alternate Storage Site | N/A -- Single user home lab | N/A |
| CP-7 | Alternate Processing Site | N/A -- Single user home lab | N/A |
| CP-9 | System Backup | Proxmox automated backups bi-weekly; encrypted backups; dual backup solutions | Implemented |
| CP-9(1) | Testing for Reliability | Quarterly restore testing documented | Implemented |
| CP-9(3) | Separate Storage | Off-host encrypted backups; physically separate storage | Implemented |
| CP-9(8) | Cryptographic Protection | Encrypted backups via Proxmox Backup Server | Implemented |
| CP-10 | System Recovery | Documented restore procedures; IaC enables rapid rebuild | Partial |

---

## Identification and Authentication (IA) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| IA-1 | Policy and Procedures | Authentication policy documented; MFA requirements defined | Implemented |
| IA-2 | Identification and Authentication | SSH keys; Authentik SSO; unique user identities required | Implemented |
| IA-2(1) | MFA to Privileged Accounts | Authentik TOTP enforced for all admin accounts; SSH key + passphrase | Implemented |
| IA-2(2) | MFA to Non-Privileged Accounts | Authentik TOTP available; SSH keys only (equivalent to 2FA) | Implemented |
| IA-2(8) | Replay Resistant | SSH session tokens; Authentik session cookies with CSRF protection | Implemented |
| IA-2(10) | Single Sign-On | Authentik SSO integration; Traefik ForwardAuth; OAuth2 provider | Implemented |
| IA-2(12) | Acceptance of PIV Credentials | N/A -- Single user home lab | N/A |
| IA-3 | Device Identification | SSH host keys; device certificates via Step-CA | Implemented |
| IA-4 | Identifier Management | Centralized user management via Authentik/AD; SSH keys tracked in Ansible | Implemented |
| IA-5 | Authenticator Management | SSH keys managed via Ansible; Authentik credential policies; centralized key distribution | Implemented |
| IA-5(1) | Password-Based Authentication | SSH passwords disabled globally; Authentik enforces complexity requirements | Implemented |
| IA-5(2) | PKI-Based Authentication | Step-CA two-tier PKI; SSH Ed25519 keys; automated certificate issuance | Implemented |
| IA-5(7) | No Embedded Unencrypted Authenticators | Vaultwarden secrets management; Ansible Vault encrypted vars; no hardcoded credentials | Implemented |
| IA-5(14) | Managing PKI Trust Stores | Step-CA root/intermediate CA management; automated trust distribution | Implemented |
| IA-5(18) | Password Managers | Vaultwarden deployed; biometric unlock; zero-knowledge encryption | Implemented |
| IA-8 | Non-Organizational User Authentication | N/A -- Single user home lab | N/A |
| IA-11 | Re-authentication | Authentik session timeout requires re-auth; SSH session timeout | Implemented |
| IA-12 | Identity Proofing | N/A -- Single user home lab | N/A |

---

## Incident Response (IR) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| IR-1 | Policy and Procedures | Incident response policy documented; SOC procedures defined | Implemented |
| IR-2 | Incident Response Training | N/A -- Single user home lab | N/A |
| IR-3 | Incident Response Testing | N/A -- Single user home lab | N/A |
| IR-4 | Incident Handling | TheHive case management; Wazuh Active Response; Splunk correlation; n8n/Shuffle SOAR orchestration | Implemented |
| IR-4(1) | Automated Incident Handling | Wazuh Active Response (firewall-drop, host-deny); VirusTotal quarantine; Shuffle workflows; sub-30-min MTTR | Implemented |
| IR-4(4) | Information Correlation | TheHive correlates Splunk/Wazuh/Suricata/scanners; Cortex enrichment; MISP threat context | Implemented |
| IR-5 | Incident Monitoring | Real-time SIEM dashboards; Discord notifications; TheHive case tracking; 100% security event visibility | Implemented |
| IR-5(1) | Automated Tracking | TheHive automated case creation; Shuffle orchestration; Cortex job tracking; Wazuh forensic data collection | Implemented |
| IR-6 | Incident Reporting | TheHive case documentation; Shuffle notifications; Discord/email alerting; Splunk executive reports | Implemented |
| IR-6(1) | Automated Reporting | Shuffle automated notifications (Discord, email, PagerDuty); TheHive status updates; Splunk scheduled reports | Implemented |
| IR-7 | Incident Response Assistance | TheHive knowledge base; documented playbooks (15+); Shuffle workflow library; Cortex analyzer catalog | Implemented |
| IR-8 | Incident Response Plan | Comprehensive IR plan; TheHive playbooks; Shuffle workflows; multi-channel alerting | Implemented |
| IR-8(1) | Breaches | Limited -- Wazuh Automated alerting and active response; TheHive automated case creation | Partial |

---

## Maintenance (MA) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| MA-1 | Policy and Procedures | Maintenance policy informal - personal lab environment | Partial |
| MA-2 | Controlled Maintenance | Change control via Git; snapshot-before-patch | Partial |
| MA-3 | Maintenance Tools | Ansible automation tools version controlled | Partial |
| MA-4 | Nonlocal Maintenance | SSH remote maintenance logged; session monitoring | Implemented |
| MA-4(6) | Cryptographic Protection | SSH encryption for remote maintenance; TLS for web-based tools | Implemented |
| MA-5 | Maintenance Personnel | Not applicable - single administrator | N/A |
| MA-6 | Timely Maintenance | Patch SLAs defined and tracked | Partial |

---

## Media Protection (MP) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| MP-1 | Policy and Procedures | Media protection policy informal | Partial |
| MP-2 | Media Access | Physical media access controlled | Partial |
| MP-3 | Media Marking | N/A -- Single user home lab | N/A |
| MP-4 | Media Storage | Backup media stored securely; encrypted | Implemented |
| MP-5 | Media Transport | Encrypted backups for transport | Partial |
| MP-6 | Media Sanitization | Secure deletion procedures documented | Partial |
| MP-7 | Media Use | Removable media disabled via GPO (Windows) | Partial |

---

## Physical and Environmental Protection (PE) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| PE-1 | Policy and Procedures | N/A -- Single user home lab | N/A |
| PE-2 | Physical Access Authorizations | N/A -- Single user home lab | N/A |
| PE-3 | Physical Access Control | N/A -- Single user home lab | N/A |
| PE-6 | Monitoring Physical Access | N/A -- Single user home lab | N/A |
| PE-8 | Visitor Access Records | N/A -- Single user home lab | N/A |
| PE-9 | Power Equipment and Cabling | UPS battery backup for critical systems | N/A |
| PE-11 | Emergency Power | UPS provides temporary power | N/A |
| PE-12 | Emergency Lighting | N/A -- Single user home lab | N/A |
| PE-13 | Fire Protection | Residential fire protection | N/A |
| PE-14 | Environmental Controls | N/A -- Single user home lab | N/A |
| PE-15 | Water Damage Protection | N/A -- Single user home lab | N/A |
| PE-16 | Delivery and Removal | N/A -- Single user home lab | N/A |

---

## Planning (PL) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| PL-1 | Policy and Procedures | Planning policy documented in lab mission statement | Partial |
| PL-2 | System Security Plans | GRC documentation serves as security plan | Implemented |
| PL-4 | Rules of Behavior | N/A -- Single user home lab | N/A |
| PL-7 | Concept of Operations | Lab architecture and operations documented | Partial |
| PL-8 | Security Architecture | Defense-in-depth architecture documented; network diagrams maintained | Implemented |
| PL-8(1) | Defense in Depth | Multi-layer security controls across network/application/data layers | Implemented |
| PL-9 | Central Management | Centralized management via Ansible, Authentik, SIEM | Partial |

---

## Program Management (PM) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| PM-1 | Information Security Program Plan | Lab security program documented in GRC framework | Partial |
| PM-5 | System Inventory | Comprehensive asset inventory maintained (PatchMon, Wazuh, OpenVPN, Nessus, Netalert) | Implemented |
| PM-9 | Risk Management Strategy | Risk-based vulnerability prioritization; CVSS scoring | Implemented |
| PM-10 | Authorization Process | N/A -- Single user home lab | N/A |
| PM-12 | Insider Threat Program | N/A -- Single user home lab | N/A |
| PM-14 | Testing, Training, Monitoring | N/A -- Single user home lab | N/A |
| PM-16 | Threat Awareness Program | N/A -- Single user home lab | N/A |
| PM-16(1) | Automated Threat Intelligence Sharing | MISP automated feed synchronization; Shuffle vulnerability aggregation | Implemented |

---

## Personnel Security (PS) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| PS-1 | Policy and Procedures | Not applicable - personal lab | N/A |
| PS-2 | Position Risk Designation | Not applicable | N/A |
| PS-3 | Personnel Screening | Not applicable | N/A |
| PS-4 | Personnel Termination | Not applicable | N/A |
| PS-5 | Personnel Transfer | Not applicable | N/A |
| PS-6 | Access Agreements | Not applicable | N/A |
| PS-7 | External Personnel Security | Not applicable | N/A |
| PS-8 | Personnel Sanctions | Not applicable | N/A |

---

## Risk Assessment (RA) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| RA-1 | Policy and Procedures | Risk assessment policy documented; CVSS scoring methodology defined | Implemented |
| RA-3 | Risk Assessment | CVSS scoring of vulnerabilities; exploit likelihood assessment; risk-based remediation prioritization | Implemented |
| RA-3(1) | Supply Chain Risk Assessment | MISP vendor compromise tracking; limited supply chain visibility | Partial |
| RA-5 | Vulnerability Monitoring and Scanning | Weekly OpenVAS network scans; monthly Nessus authenticated scans; daily PatchMon package checks; CVE correlation with NVD | Implemented |
| RA-5(2) | Update Vulnerabilities to Be Scanned | Daily NVT updates (OpenVAS); plugin updates (Nessus); MISP feed sync; Shuffle CVE aggregation | Implemented |
| RA-5(3) | Breadth and Depth of Coverage | Network scans (OpenVAS); authenticated OS scans (Nessus); compliance audits (CIS); 75+ assets covered | Implemented |
| RA-5(5) | Privileged Access | Authenticated scans via SSH keys (Linux); domain service accounts (Windows); SNMP v3 (network devices) | Implemented |
| RA-5(8) | Review Historic Audit Logs | Vulnerability trends tracked in Grafana; historical scan results archived; MTTR calculated over time | Implemented |
| RA-5(10) | Correlate Scanning Information | SIEM correlates vulnerability scans with exploit databases; Wazuh links vulnerabilities to installed software | Implemented |
| RA-5(11) | Public Disclosure Program | N/A -- Single user home lab | N/A |
| RA-7 | Risk Response | N/A -- Single user home lab | N/A |
| RA-10 | Threat Hunting | Wazuh threat hunting queries; Splunk investigation searches; MITRE ATT&CK mapping | Implemented |

---

## System and Communications Protection (SC) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| SC-1 | Policy and Procedures | System protection policy documented; encryption requirements defined | Implemented |
| SC-7 | Boundary Protection | DNS at edge (Pi-hole); SSH firewall rules; Traefik ingress controller; pfSense ACLs; IDS/IPS | Implemented |
| SC-7(3) | Access Points | Managed access points via Traefik/Nginx Ingress; Safeline WAF; Cloudflare/Tailscale RBAC | Implemented |
| SC-7(4) | External Telecommunications | Verizon; VPN services (Tailscale, PIA); Cloudflare Tunnels | Implemented |
| SC-7(5) | Deny by Default / Allow by Exception | pfSense/OPNsense default-deny rules; Traefik explicit route definitions; firewall whitelist approach | Implemented |
| SC-7(8) | Route Traffic to Authenticated Proxy | Traefik reverse proxy with Authentik authentication | Implemented |
| SC-7(21) | Isolation of System Components | Traefik isolates backend services; NGINX Ingress isolates K3s pods; network segmentation | Implemented |
| SC-8 | Transmission Confidentiality and Integrity | TLS 1.3 (Traefik); SSH encryption; DNS-over-TLS (future); encrypted scan credentials | Implemented |
| SC-8(1) | Cryptographic Protection | AES-256-GCM (SSH/Traefik); Ed25519 keys; TLS 1.3 ciphersuites | Implemented |
| SC-8(2) | Pre/Post-Transmission Handling | TLS termination at edge (Traefik); encrypted storage at rest | Implemented |
| SC-12 | Cryptographic Key Establishment and Management | Step-CA automated certificate issuance; SSH key generation (ed25519); centralized key management | Implemented |
| SC-13 | Cryptographic Protection | Modern algorithms only (Ed25519, AES-256-GCM, TLS 1.3); weak cipher detection via vulnerability scans | Implemented |
| SC-17 | Public Key Infrastructure Certificates | Step-CA PKI (Root + Intermediate CA); Traefik cert distribution; automated renewal | Implemented |
| SC-17(1) | Certificate Validation | OCSP validation; CRL distribution; client certificate validation | Implemented |
| SC-20 | Secure Name/Address Resolution (Authoritative) | Bind9 authoritative DNS; DNSSEC signing | Implemented |
| SC-20(2) | Data Origin and Integrity | DNSSEC validation; DNS query authentication | Implemented |
| SC-21 | Secure Name/Address Resolution (Recursive) | Pi-hole/Unbound recursive resolver; DNSSEC validation enabled | Implemented |
| SC-23 | Session Authenticity | Authentik session tokens; SSH session IDs; TLS session tickets | Implemented |
| SC-28 | Protection of Information at Rest | Encrypted backups; TLS in transit; scan credential encryption; SSH private keys encrypted | Implemented |
| SC-28(1) | Cryptographic Protection at Rest | AES-256 encrypted backups | Partial |
| SC-28(3) | Cryptographic Keys | Step-CA offline root CA; SSH keys encrypted; Vaultwarden secrets management | Implemented |
| SC-39 | Process Isolation | Container isolation (Docker); VM isolation (Proxmox); process separation | Implemented |
| SC-45 | System Time Synchronization | NTP time synchronization across infrastructure; centralized time source | Implemented |
| SC-45(1) | Synchronization with Authoritative Time Source | Chrony NTP client; Internet time servers (pool.ntp.org) | Implemented |

---

## System and Information Integrity (SI) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| SI-1 | Policy and Procedures | System integrity policy documented; malware protection requirements defined | Implemented |
| SI-2 | Flaw Remediation | Multi-platform patch management; MTTR <72h for Critical CVEs; remediation verified via re-scans | Implemented |
| SI-2(2) | Automated Flaw Remediation Status | Watchtower auto-updates; WSUS auto-approval rules; n8n orchestration; Wazuh alerts on unpatched systems | Implemented |
| SI-2(3) | Time to Remediate Flaws | N/A -- Single user home lab | N/A |
| SI-2(4) | Automated Patch Management Tools | PatchMon (Linux); WSUS (Windows); Watchtower (containers); OpenVAS/Nessus verification | Implemented |
| SI-2(6) | Removal of Previous Versions | Old container images pruned after Watchtower updates; superseded patches cleaned via WSUS | Implemented |
| SI-3 | Malicious Code Protection | Wazuh FIM with VirusTotal; Suricata/Snort signatures; ClamAV/Microsoft Defender; rootkit detection | Implemented |
| SI-3(4) | Updates Only by Privileged Users | AV signature updates restricted to admin accounts; WSUS authorization | Implemented |
| SI-3(10) | Malicious Code Analysis | Cortex multi-engine analysis (VirusTotal, Yara); Shuffle malware workflow; TheHive case management | Implemented |
| SI-4 | System Monitoring | Prometheus; Uptime Kuma; Splunk/Elastic SIEM; Wazuh EDR; Suricata/Snort IDS; Netalert; multi-layered detection | Implemented |
| SI-4(1) | System-Wide Intrusion Detection | Suricata/Snort on all network segments; centralized SIEM correlation | Implemented |
| SI-4(2) | Automated Tools for Real-Time Analysis | Splunk real-time correlation; Wazuh real-time FIM; Elastic SIEM; Suricata inline blocking; Cortex automation | Implemented |
| SI-4(4) | Inbound and Outbound Communications Traffic | Suricata/Snort IDS on all segments; pfSense flow logs; Traefik access logs; DNS query logging; complete visibility | Implemented |
| SI-4(5) | System-Generated Alerts | Discord webhooks; Splunk scheduled alerts; Wazuh Discord/email; Prometheus alertmanager; CVSS-based routing | Implemented |
| SI-4(12) | Automated Alerts | Prometheus Alertmanager; Grafana automated alerts; Splunk real-time searches; Wazuh Active Response triggers | Implemented |
| SI-4(16) | Correlate Monitoring Information | Multi-source correlation across Splunk/Elastic/Wazuh/network logs; TheHive aggregation | Implemented |
| SI-4(18) | Analyze Traffic/Event Patterns | Cortex pattern recognition; MISP campaign correlation | Partial |
| SI-4(23) | Host-Based Devices | Wazuh EDR on 25+ endpoints; FIM real-time monitoring; rootkit detection; process monitoring; Sysmon integration | Implemented |
| SI-5 | Security Alerts, Advisories, and Directives | PatchMon CVE alerts; WUD update notifications; Discord webhooks; OpenVAS/Nessus scan completion alerts | Implemented |
| SI-5(1) | Automated Alerts and Advisories | Discord webhooks for scan completion; CVSS-based alert routing; TheHive case auto-creation | Implemented |
| SI-7 | Software, Firmware, and Information Integrity | Docker image SHA-256 verification; Step-CA certificate validation; Wazuh FIM integrity monitoring | Implemented |
| SI-7(1) | Integrity Checks | Wazuh FIM real-time integrity monitoring; file hash verification; registry monitoring (Windows) | Implemented |
| SI-7(6) | Cryptographic Protection | SHA-256 image signatures; TLS certificate validation; file integrity checksums | Implemented |
| SI-7(7) | Integration of Detection and Response | Wazuh FIM triggers Active Response; SIEM correlation with integrity violations | Implemented |
| SI-10 | Information Input Validation | WAF input validation (SafeLine); Traefik header validation; DNS query sanitization | Implemented |
| SI-12 | Information Management and Retention | 90-day log retention; 30-day backup retention; automated lifecycle management | Implemented |

---

## Supply Chain Risk Management (SR) Family

| Control | Control Name | Implementation | Status |
|---------|-------------|----------------|--------|
| SR-1 | Policy and Procedures | N/A -- Single user home lab | N/A |
| SR-2 | Supply Chain Risk Management Plan | N/A -- Single user home lab | N/A |
| SR-3 | Supply Chain Controls and Processes | Vetted open-source projects; trusted Docker registries; official package repositories | Partial |
| SR-3(1) | Diverse Supply Base | N/A -- Single user home lab | N/A |
| SR-4 | Provenance | N/A -- Single user home lab | N/A |
| SR-5 | Acquisition Strategies | N/A -- Single user home lab | N/A |
| SR-6 | Supplier Assessments | N/A -- Single user home lab | N/A |
| SR-9 | Tamper Resistance and Detection | N/A -- Single user home lab | N/A |
| SR-10 | Inspection of Systems or Components | Visual inspection of hardware; no formal process | Partial |
| SR-11 | Component Authenticity | Docker image signature verification; package signature validation | Implemented |
| SR-11(3) | Anti-Counterfeit Scanning | N/A -- Single user home lab | N/A |
| SR-12 | Component Disposal | Secure deletion procedures; encrypted storage wiping | Implemented |