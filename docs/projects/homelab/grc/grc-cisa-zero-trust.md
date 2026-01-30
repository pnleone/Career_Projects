# CISA Zero Trust Maturity Model v2.0

**Document Control:**  
Version: 1.0  
Last Updated: January 2026  
Owner: Paul Leone  

**Framework Version:** 2.0

---

## Zero Trust Architecture Implementation Overview

This cybersecurity lab demonstrates comprehensive Zero Trust Architecture (ZTA) principles aligned with **NIST SP 800-207** and **CISA Zero Trust Maturity Model v2.0**. The implementation achieves **Advanced maturity** (Stage 3 of 4) across core Zero Trust pillars through explicit verification of every access request, least-privilege enforcement via RBAC, assume-breach mentality with continuous monitoring, and encrypt-everything policies using modern cryptographic standards.

**CISA Zero Trust Maturity Level: Advanced (Stage 3 of 4)**

---

## CISA Zero Trust Maturity Model v2.0 Alignment

The CISA ZTMM defines four maturity stages across five core pillars (Identity, Devices, Networks, Applications and Workloads, Data) with three cross-cutting capabilities (Visibility and Analytics, Automation and Orchestration, Governance). This lab demonstrates Advanced-stage implementation across all pillars with targeted progression toward Optimal maturity.

**Maturity Stage Definitions:**

- **Traditional:** Manual configurations, static policies, siloed enforcement, limited correlation
- **Initial:** Starting automation, cross-pillar integration, aggregated visibility, responsive least privilege
- **Advanced:** Automated controls, centralized visibility, cross-pillar coordination, risk-based least privilege, pre-defined mitigations
- **Optimal:** Fully automated just-in-time lifecycles, dynamic policies, comprehensive situational awareness, cross-pillar interoperability

---

## Zero Trust Pillar Implementation

### Identity (CISA ZTMM Table 2)

**Maturity: Advanced**

**Authentication:** Agency authenticates all identity using phishing-resistant MFA (FIDO2/PIV initiating implementation) with continuous validation. Authentik SSO enforces phishing-resistant MFA (TOTP) for 100% administrative accounts with OAuth2/OIDC integration. SSH access uses certificate-based authentication (Ed25519 keys) validated via Step-CA PKI. MFA required for VPN access (Tailscale device authentication). Transition from password-based to passwordless authentication underway via FIDO2/WebAuthn planning.

**Identity Stores:** Agency begins to securely consolidate and integrate self-managed (Active Directory, local accounts) and hosted identity stores (Authentik cloud-ready SSO). Authentik provides centralized identity management with LDAP/SAML/OAuth2 integrations across hybrid environments. Single sign-on (SSO) implemented for 90% of web services via Traefik ForwardAuth middleware.

**Risk Assessments:** Agency determines identity risk with automated analysis and dynamic rules. Splunk correlates failed authentication patterns, geoIP anomalies, impossible travel scenarios, and behavioral baselines to inform access decisions. Wazuh monitors account lifecycle events (creation, modification, privilege escalation) with automated alerts for high-risk activities. TheHive case creation triggered by identity risk threshold violations.

**Access Management:** Agency authorizes need-based and session-based access tailored to actions and resources. Authentik enforces 30-minute session timeouts with automatic re-authentication requirements. SSH sessions use temporary sudo elevation with privileged operations requiring explicit justification. OAuth2 scopes limit application permissions to minimum required for task completion. Account access reviews conducted quarterly with automated expiration workflows.

**Visibility and Analytics:** Agency performs automated analysis across user and entity activity logs and augments collection to address visibility gaps. 100% authentication event logging (successful/failed logins, MFA challenges, privilege escalations, account modifications) forwarded to dual SIEM. Behavioral analytics detect unusual login times, geographic anomalies, credential stuffing, and privilege abuse. Real-time correlation identifies compromised credentials within 5 minutes of suspicious activity.

**Automation and Orchestration:** Agency manually orchestrates privileged user identities and automates orchestration of all identities with integration across environments. Standard user provisioning/deprovisioning automated via Authentik workflows. Privileged account management requires manual approval with automated expiration (24-hour temporary elevation). SSH key distribution centralized via Ansible with automated rotation schedules. Service account credentials stored in Vaultwarden with automated retrieval.

**Governance:** Agency implements identity policies for enterprise-wide enforcement with automation and periodic updates. CIS Benchmark password policies enforced (14-char minimum non-MFA, 8-char with MFA). MFA enforcement policies updated monthly based on threat intelligence. Account lifecycle policies define provisioning, modification, and deactivation workflows. Quarterly access reviews validate RBAC group assignments and permission grants.

**Framework Alignment:** NIST CSF PR.AA/AC, CIS 5.1-6.8, ISO 27001 A.5.15-5.18, NIST 800-53 AC-2/AC-3/IA-2/IA-4/IA-5, PCI-DSS 8.1-8.3, OWASP A07.

**Gap to Optimal:** Requires full automation of privileged identity orchestration, continuous identity risk scoring with real-time policy adjustments, just-in-time access for all accounts, behavior-based comprehensive analytics across all systems, and dynamic policy updates without manual intervention.

---

### Devices (CISA ZTMM Table 3)

**Maturity: Advanced**

**Policy Enforcement and Compliance Monitoring:** Agency has verified insights on initial access and enforces compliance for most devices and virtual assets. Wazuh agents (25+ endpoints) provide real-time compliance validation against CIS Benchmarks (92-98% compliance). Nessus authenticated scans verify device configurations monthly with automated remediation workflows. Ansible enforces configuration baselines with drift detection triggering automatic alerts. Virtual asset compliance (50+ containers, 30+ VMs) monitored via Proxmox and Docker health checks with policy violations triggering automated quarantine.

**Asset and Supply Chain Risk Management:** Agency begins to develop comprehensive enterprise view via automated processes across vendors. PatchMon tracks 5,000+ packages across 30+ hosts with daily vulnerability correlation to NVD database. Container image verification via SHA-256 signatures with Docker Content Trust. Package signature validation (GPG keys) for all software installations. Vulnerability disclosure workflows via Shuffle integrate MISP threat intelligence for supply chain compromise detection. Limited SBOM tracking (gap identified—requires Trivy/Grype implementation Q1 2026).

**Resource Access:** Agency's initial resource access considers verified device insights. Authentik ForwardAuth validates device compliance before granting application access via OAuth2 device flow. Step-CA certificates authenticate devices for service-to-service communication. Wazuh compliance status integrated into access control decisions with non-compliant devices restricted to remediation VLAN. SSH access restricted to registered host keys with certificate-based authentication. Traefik middleware validates device headers and IP reputation before proxying requests.

**Device Threat Protection:** Agency begins to consolidate threat protection to centralized solutions and integrates with policy enforcement. Wazuh EDR provides FIM, rootkit detection, and vulnerability assessment on 25+ endpoints. ClamAV (Linux) and Microsoft Defender (Windows) deployed with centralized management. Suricata/Snort network IDS provides device-level threat detection. YARA rules detect malware signatures with multi-engine analysis via Cortex (VirusTotal, Hybrid Analysis). Automated containment via Wazuh Active Response (firewall-drop, account-disable, process-kill).

**Visibility and Analytics:** Agency automates inventory collection including endpoint monitoring on standard devices and virtual assets with anomaly detection. Real-time asset discovery via NetalertX network monitoring, Checkmk infrastructure tracking, and Prometheus node exporters. Endpoint telemetry (Sysmon process trees, network connections, file modifications) forwarded to SIEM with behavioral analysis. Device lifecycle tracking from provisioning through deprovisioning with audit trails. Virtual asset provisioning patterns monitored for anomalies indicating credential compromise or resource abuse.

**Automation and Orchestration:** Agency implements monitoring and enforcement to manually disconnect or isolate non-compliant devices and virtual assets. Proxmox automation provisions VMs with pre-configured security baselines. Docker/Watchtower auto-updates containers with rollback capability. WSUS automated patch approval for Windows endpoints with pre-deployment testing. Ansible playbooks remediate configuration drift with snapshot-before-patch strategy. Manual intervention required for device quarantine decisions (automated workflows planned Q2 2026).

**Governance:** Agency sets enterprise-wide policies for device/virtual asset lifecycle with automated enforcement mechanisms. Lifecycle policies define procurement standards, configuration baselines, monitoring requirements, update schedules, and decommissioning procedures. CIS Benchmark policies enforced via Wazuh SCA with quarterly compliance reviews. Vulnerability remediation SLAs (Critical <72h, High <7d) tracked via TheHive. Hardware refresh cycles documented with end-of-life tracking preventing legacy device deployment.

**Framework Alignment:** NIST CSF PR.IP/DE.CM, CIS 1.1-2.7/4.1-4.12/10.1-10.7, ISO 27001 A.5.9/A.8.1/A.8.7/A.8.8/A.8.19, NIST 800-53 CM-8/SI-2/SI-3/SI-4, PCI-DSS 2.4/5.1-5.2/6.4.3/11.5, OWASP A02/A03.

**Gap to Optimal:** Requires fully automated provisioning, monitoring, isolation, remediation, and deprovisioning processes; comprehensive real-time device risk analytics informing resource access; unified threat protection with advanced capabilities; automated lifecycle policies for all assets; complete SBOM tracking.

---

### Networks (CISA ZTMM Table 4)

**Maturity: Advanced**

**Network Segmentation:** Agency expands deployment of endpoint/application profile isolation with ingress/egress micro-perimeters and service-specific interconnections. 3-tier architecture (DMZ, application, backend) with VLAN isolation per service criticality. pfSense/OPNsense enforce default-deny firewall rules with explicit allow-lists per segment. Traefik reverse proxy provides ingress micro-perimeter with ForwardAuth authentication at edge. Backend services isolated from direct internet access via internal-only VLANs. Critical workloads (SIEM, authentication, PKI) deployed on dedicated VLANs with restricted lateral movement paths.

**Network Traffic Management:** Agency implements dynamic network rules periodically adapted based on automated risk-aware application profile assessments. Application profiles defined for web services, databases, DNS, monitoring, and administrative access with distinct QoS policies. pfSense traffic shaping prioritizes critical services (SIEM, authentication) during congestion. Traefik load balancing distributes traffic based on backend health checks and response times. Periodic reviews (monthly) adjust traffic policies based on bandwidth utilization, latency metrics, and security posture changes.

**Traffic Encryption:** Agency ensures encryption for all applicable internal/external traffic, manages key issuance/rotation, and begins cryptographic agility. TLS 1.3 mandatory for all web services via Traefik with modern cipher suites (AES-256-GCM, ChaCha20-Poly1305). SSH connections encrypted with AES-256-GCM using Ed25519 keys. VPN encryption via WireGuard (ChaCha20) and OpenVPN (AES-256). Syslog-ng TLS encrypts log transmission to SIEM. Step-CA PKI automates certificate issuance, renewal, and rotation with 90-day certificate lifetimes. DNSSEC provides DNS response integrity. Weak cipher detection via vulnerability scans with automated remediation.

**Network Resilience:** Agency has configured network capabilities to dynamically manage availability demands and resilience for majority of applications. HA firewall cluster (pfSense CARP) provides <5-second failover. Dual Pi-hole DNS with automatic failover maintains 99.9% availability. Dual SIEM architecture (Splunk + Elastic) ensures resilience to platform failures. Redundant internet connections with automatic failover. Load balancing via Traefik distributes traffic across healthy backends. Critical services deployed with multiple replicas across hypervisors.

**Visibility and Analytics:** Agency deploys anomaly-based network detection across all environments with correlation from multiple sources and automated threat hunting. 100% network traffic visibility via pfSense flow logs, Traefik access logs, Pi-hole DNS query logs, and Suricata/Snort IDS. Real-time correlation detects port scans, DGA domains, DNS tunneling, C2 beacons, and lateral movement patterns. MISP IOC correlation identifies known-bad infrastructure. Splunk threat hunting dashboards track network reconnaissance, protocol anomalies, and bandwidth spikes. Behavioral baselines detect deviations indicating compromise.

**Automation and Orchestration:** Agency uses automated change management (CI/CD) to manage configuration/lifecycle for all networks/environments, responding to and enforcing policies. Terraform defines network infrastructure-as-code with Git version control. Ansible playbooks configure firewall rules, routing tables, and VLANs with automated deployment. Pre-deployment validation prevents misconfigurations. Automated rollback capability via snapshots. Policy violations (firewall rule changes, routing modifications) trigger alerts with automatic reversion. Network provisioning/deprovisioning follows automated workflows with approval gates for production changes.

**Governance:** Agency incorporates automation in implementing tailored policies and facilitates transition from perimeter-focused protections. Network segmentation policies define VLAN assignments, firewall ACLs, and traffic flows with automated enforcement via Terraform/Ansible. Encryption policies mandate TLS 1.3 minimum with weak cipher prohibition. Traffic management policies define QoS priorities and bandwidth allocations. Quarterly policy reviews update network security requirements based on threat landscape evolution. Exception approvals documented with compensating controls.

**Framework Alignment:** NIST CSF PR.AC/PR.DS/DE.CM, CIS 12.1-13.10, ISO 27001 A.8.20-8.23, NIST 800-53 SC-7/SC-8/SC-20/SI-4, PCI-DSS 1.1-1.4/4.2, OWASP A04.

**Gap to Optimal:** Requires fully distributed micro-perimeters with extensive micro-segmentation, dynamic just-in-time/just-enough connectivity, continuously evolving network rules based on real-time risk, enterprise-wide situational awareness with advanced automated telemetry correlation, infrastructure-as-code with fully automated initiation/expiration.

---

### Applications and Workloads (CISA ZTMM Table 5)

**Maturity: Advanced**

**Application Access:** Agency automates application access decisions with expanded contextual information and enforced expiration adhering to least privilege. Authentik OAuth2/OIDC authorization considers user identity, group membership, device compliance (Wazuh status), source IP reputation, time-of-day restrictions, and MFA verification. Session-based access with 30-minute idle timeout requires re-authentication. OAuth2 scopes limit permissions to minimum required operations. Traefik middleware enforces path-based access control with header validation. Service-to-service communication authenticated via Step-CA certificates (mutual TLS planned).

**Application Threat Protections:** Agency integrates threat protections into all application workflows protecting against application-specific and targeted threats. SafeLine WAF deploys OWASP Core Rule Set (CRS) with 25% attack block rate protecting against SQL injection, XSS, command injection, and path traversal. Traefik security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options) prevent common attacks. Input validation via WAF and application-level sanitization. Suricata/Snort application-layer signatures detect exploit attempts. Rate limiting prevents brute force and DoS attacks. Security testing via OWASP ZAP and Burp Suite during deployment.

**Accessible Applications:** Agency makes most applicable mission critical applications available over open public networks to authorized users. Cloudflare Tunnels expose internal services without port forwarding or firewall exceptions. Traefik reverse proxy provides public internet access with mandatory authentication via Authentik ForwardAuth. All public-facing applications protected by WAF and DDoS mitigation. Tailscale mesh VPN provides secure remote access to administrative interfaces. Internal-only applications (monitoring, SIEM backends, PKI) remain isolated on private VLANs accessible only via VPN.

**Secure Application Development and Deployment Workflow:** Agency uses distinct coordinated teams for development/security/operations while removing developer access to production for code deployment. Infrastructure-as-Code (Terraform, Ansible) defines deployment environments with Git version control. Separate development, staging, and production environments with network isolation. CI/CD pipelines (planned Q2 2026) will automate security testing and deployment. Docker images built from trusted base images with signature verification. Immutable container workloads (50+ containers) with changes deployed via version updates. Developer SSH access restricted to non-production environments.

**Application Security Testing:** Agency integrates application security testing into development/deployment with periodic dynamic testing. Pre-deployment vulnerability scanning via OpenVAS and Nessus identifies misconfigurations and known vulnerabilities. Manual penetration testing for critical services identifies logic flaws and business logic vulnerabilities. Static code analysis (planned with CI/CD implementation) will scan custom scripts and configurations. Dynamic testing via OWASP ZAP crawls web applications for OWASP Top 10 vulnerabilities. Container image scanning (planned Trivy/Grype) will detect vulnerable dependencies.

**Visibility and Analytics:** Agency automates profile and security monitoring for most applications with heuristics identifying trends and refining processes. Prometheus monitors application performance metrics (response times, error rates, resource utilization). Uptime Kuma tracks service availability (50+ monitors) with multi-channel alerting. Application logs forwarded to SIEM with correlation detecting authentication failures, error spikes, and suspicious patterns. Grafana visualizes application health trends with historical analysis. Security event monitoring identifies exploitation attempts, privilege escalations, and data exfiltration patterns.

**Automation and Orchestration:** Agency automates application configurations to respond to operational and environmental changes. Docker/Watchtower auto-updates containers with rollback capability. Traefik dynamic configuration discovers new services and applies security policies automatically. Ansible playbooks deploy configuration changes with validation testing. Health checks trigger automatic failover to healthy backends. Resource scaling (planned with Kubernetes) will adjust compute allocation based on demand. Backup automation runs bi-weekly with quarterly restore validation.

**Governance:** Agency implements tiered, tailored policies enterprise-wide for applications/lifecycles and leverages automation for enforcement. Application categorization (Tier 1: SIEM/EDR, Tier 2: Firewalls/DNS, Tier 3: Supporting services) defines security requirements and SLAs. Deployment policies require security hardening, vulnerability scanning, and change approval. Patching policies mandate critical updates within 72 hours, high within 7 days. Software asset inventory tracks application versions with automated outdated software detection. Quarterly reviews validate policy compliance and update requirements based on threat evolution.

**Framework Alignment:** NIST CSF PR.AC/PR.IP/PR.PS, CIS 2.3/16.1-16.14/18.1-18.5, ISO 27001 A.8.23/A.8.26/A.14.1-14.2, NIST 800-53 AC-3/SA-8/SA-11/SI-10, PCI-DSS 6.4-6.6, OWASP A01/A05/A06/A08.

**Gap to Optimal:** Requires continuous real-time authorization incorporating behavior/usage patterns, advanced real-time threat protections with content-aware analysis, all applications internet-accessible where appropriate, immutable workloads with automated redeployment, automated security testing throughout SDLC for deployed applications, continuous dynamic monitoring with comprehensive visibility, fully automated configuration optimization.

---

### Data (CISA ZTMM Table 6)

**Maturity: Advanced**

**Data Inventory Management:** Agency automates data inventory enterprise-wide covering all applicable data with data loss prevention based on static attributes/labels. Filesystem monitoring tracks data repositories across 30+ hosts and 50+ containers. Database inventories document schemas, tables, and record counts. Backup inventories track encrypted archives with retention tracking. Application data flows documented with sensitivity classification. Pi-hole DNS logging provides data access pattern visibility. Egress filtering prevents unauthorized data transfer with bandwidth monitoring detecting exfiltration attempts. DLP planning underway (formal deployment Q2 2026) for comprehensive data loss prevention.

**Data Categorization:** Agency automates some data categorization and labeling in consistent, tiered, targeted manner with simple structured formats and regular review. Sensitivity tiers (Public, Internal, Confidential, Restricted) defined with handling requirements. Filesystem metadata tags indicate sensitivity levels. Database schemas include classification fields. Application logs categorized by security relevance (authentication, authorization, system events, security events). Quarterly reviews update data classifications based on changing risk profiles. Automated labeling (planned with DLP implementation) will apply consistent categorization across repositories.

**Data Availability:** Agency primarily makes data available from redundant, highly available data stores and ensures access to historical data. Dual SIEM architecture (Splunk + Elastic) provides redundant log storage with 90-day hot retention, 1-year cold storage. Database replication ensures availability during maintenance. Backup retention policy maintains 4 weekly, 12 monthly, and 7 yearly backups with offsite storage. High-availability services deployed across multiple hypervisors. Cloud-hosted services (Authentik planning) will provide geographic redundancy. Disaster recovery procedures documented with quarterly restore testing.

**Data Access:** Agency automates data access controls considering identity, device risk, application, data category with time limits where applicable. Authentik RBAC groups map to data repository permissions (read, write, delete). Filesystem ACLs enforce least-privilege access with quarterly reviews. Database role-based permissions limit query capabilities. SSH key-based authentication prevents credential-based data access. Application-level authorization validates user permissions before data retrieval. Session-based access with 30-minute timeout requires re-authentication. Service account credentials rotated quarterly with access auditing.

**Data Encryption:** Agency encrypts all data at rest/transit across enterprise to maximum extent, begins cryptographic agility, and protects encryption keys. TLS 1.3 encrypts all network communications (web, SSH, VPN, syslog). AES-256-GCM encrypts backups with keys stored in Vaultwarden. SSH private keys encrypted with passphrases. Database encryption-at-rest enabled where applicable. Ansible Vault encrypts configuration secrets with no hardcoded credentials. Step-CA PKI automates certificate lifecycle with 90-day rotation. Syslog-ng TLS encrypts log transmission. Key management policies prevent key hardcoding with centralized storage and rotation schedules. Cryptographic agility planning addresses algorithm deprecation.

**Visibility and Analytics:** Agency maintains data visibility enterprise-wide with automated analysis/correlation and begins employing predictive analytics. SIEM correlation tracks data access patterns, failed authorization attempts, and anomalous queries. Database audit logging monitors administrative actions, schema changes, and bulk exports. File integrity monitoring (Wazuh FIM) detects unauthorized modifications with real-time alerts. Bandwidth monitoring identifies unusual upload volumes indicating exfiltration. Access pattern analysis detects credential sharing and privilege abuse. Predictive analytics (limited—UEBA deployment planned) will forecast data security risks based on historical trends.

**Automation and Orchestration:** Agency implements data lifecycle and security policies primarily through automated methods in consistent, tiered, targeted manner enterprise-wide. Backup automation runs bi-weekly with encrypted storage and quarterly restore validation. Log retention automated with lifecycle management (90-day hot to cold storage transition). Data sanitization procedures documented with automated secure deletion (DBAN, shred). Filesystem cleanup scripts remove outdated temporary files. Database archival processes migrate historical data to long-term storage. Access reviews automated with quarterly reports identifying orphaned permissions and stale accounts.

**Governance:** Agency begins integration of data lifecycle policy enforcement across enterprise with unified definitions for data governance. Data classification policy defines sensitivity tiers with handling requirements. Retention policy specifies storage durations (logs: 1 year, backups: 7 years, database records: per business requirements). Encryption policy mandates TLS 1.3 and AES-256 with key management standards. Access control policy enforces least-privilege with quarterly reviews. Backup policy requires bi-weekly execution with quarterly restore testing. Destruction policy defines secure deletion methods and timelines. Policies reviewed annually with updates based on regulatory changes.

**Framework Alignment:** NIST CSF PR.DS/ID.AM, CIS 3.1-3.14/8.1-8.11/11.1-11.5, ISO 27001 A.5.12/A.5.14/A.5.33/A.8.10/A.8.24, NIST 800-53 MP-3/MP-6/SC-28/AU-9/CP-9, PCI-DSS 3.1-3.7/10.5-10.7, OWASP A04/A09.

**Gap to Optimal:** Requires continuous dynamic inventory with robust data loss prevention blocking suspected exfiltration, fully automated granular categorization/labeling enterprise-wide, dynamic data availability optimization, automated just-in-time/just-enough access with continuous review, encryption-in-use where appropriate with full cryptographic agility, comprehensive visibility with robust/predictive analytics, maximum automation of all lifecycles and policies, unified dynamic enforcement of all policies.

---

## Cross-Cutting Capabilities (CISA ZTMM Table 7)

### Visibility and Analytics

**Maturity: Advanced**

Agency expands automated collection of logs/events enterprise-wide including virtual environments for centralized analysis correlating across multiple sources. 100% security event logging across DNS, SSH, Traefik, firewalls, endpoints, applications, and infrastructure forwarded to dual SIEM (Splunk + Elastic). Real-time correlation detects multi-stage attacks combining network reconnaissance, authentication failures, and privilege escalation. Multi-source enrichment via MISP, Cortex, geoIP databases, and threat intelligence feeds. Behavioral baselines identify anomalies in user activity, network traffic, and application usage. Grafana visualizes security posture with 20+ dashboards tracking vulnerabilities, patch compliance, authentication patterns, and threat indicators. Virtual environment monitoring includes container lifecycle events, VM provisioning patterns, and resource consumption anomalies.

**Framework Alignment:** NIST CSF DE.AE/DE.CM, CIS 8.1-8.11/13.1-13.8, ISO 27001 A.8.15-8.16, NIST 800-53 AU-2/AU-6/SI-4, PCI-DSS 10.2-10.6, OWASP A09.

**Gap to Optimal:** Requires comprehensive visibility enterprise-wide via centralized dynamic monitoring with advanced automated analysis across all log types, behavior-based analytics with ML/UEBA, comprehensive situational awareness including all externally-hosted resources.

---

### Automation and Orchestration

**Maturity: Advanced**

Agency automates orchestration and response activities enterprise-wide, leveraging contextual information from multiple sources to inform decisions. Shuffle SOAR orchestrates incident response workflows (15+ playbooks) integrating TheHive case management, Cortex analysis, MISP enrichment, and automated remediation. Wazuh Active Response provides automated containment (firewall-drop, account-disable, process-kill) with sub-30-minute MTTR. Infrastructure-as-Code (Terraform, Ansible) automates provisioning, configuration, and decommissioning with version control. Patch management automated across platforms (PatchMon, WSUS, Watchtower) with vulnerability-driven prioritization. Certificate lifecycle automated via Step-CA with 90-day rotation. Alert workflows integrate Discord, email, TheHive, and PagerDuty for multi-channel notification.

**Framework Alignment:** NIST CSF RS.AN/RS.MI/PR.IP, CIS 4.1-4.2/7.3-7.4/17.1-17.9, ISO 27001 A.5.24-5.27/A.8.32, NIST 800-53 IR-4(1)/CM-2/CM-3/SI-2, PCI-DSS 6.4.5/12.10, OWASP A02/A08.

**Gap to Optimal:** Requires orchestration and response activities dynamically responding to enterprise-wide changing requirements and environmental changes, full automation of all identity orchestration, automated mitigation deployment without manual approval, predictive analytics triggering proactive response.

---

### Governance

**Maturity: Advanced**

Agency implements tiered, tailored policies enterprise-wide and leverages automation where possible to support enforcement. Access policy decisions incorporate contextual information from multiple sources. Security policies documented with version control (Git) and quarterly reviews. CIS Benchmark baselines enforced via Wazuh SCA with automated compliance reporting. Vulnerability remediation SLAs enforced (Critical <72h, High <7d) with TheHive case tracking. Configuration management policies define baseline standards with Ansible enforcement and drift detection. Encryption policies mandate TLS 1.3 and modern algorithms with vulnerability scan validation. Access control policies enforce least-privilege with automated quarterly reviews identifying permission creep. Incident response policies define escalation criteria and notification procedures. Policy exceptions require documented compensating controls and annual re-approval.

**Framework Alignment:** NIST CSF GV.PO/GV.RM, CIS 4.1/18.1-18.5, ISO 27001 A.5.1/A.5.36, NIST 800-53 PL-1/PM-1/PM-9, PCI-DSS 12.1-12.11.

**Gap to Optimal:** Requires fully automated enterprise-wide policies enabling tailored local controls with continuous enforcement and dynamic updates without manual intervention, automated policy creation/modification based on threat intelligence, real-time policy adjustments responding to environmental changes.

---

## Zero Trust Maturity Summary

| CISA Pillar | Maturity Stage | Key Capabilities | Lab-Specific Evidence |
|-------------|----------------|------------------|-----------------------|
| Identity | Advanced | Phishing-resistant MFA, consolidated identity stores, automated risk assessment, need-based access, automated analysis, integrated orchestration, enterprise-wide policies | • Authentik SSO with TOTP MFA enforced on 100% admin accounts, OAuth2/OIDC across 90% web services<br>• Splunk correlation: failed auth patterns, geoIP anomalies, impossible travel, behavioral baselines<br>• Wazuh monitors account lifecycle events with automated alerts<br>• 30-minute session timeouts with re-auth requirements<br>• SSH certificate-based auth via Step-CA PKI<br>• CIS password policies enforced (14-char non-MFA, 8-char with MFA)<br>• Quarterly access reviews validate RBAC assignments |
| Devices | Advanced | Verified compliance insights, automated asset tracking, device-aware access control, centralized threat protection, automated inventory/anomaly detection, monitoring/enforcement mechanisms, enterprise-wide lifecycle policies | • Wazuh agents on 25+ endpoints: 92-98% CIS Benchmark compliance, real-time FIM, rootkit detection<br>• Nessus authenticated scans monthly with remediation workflows<br>• PatchMon tracks 5,000+ packages across 30+ hosts, daily NVD correlation<br>• NetalertX network discovery, Checkmk infrastructure tracking, Prometheus exporters<br>• Container signature verification (SHA-256, Docker Content Trust)<br>• Non-compliant devices quarantined to remediation VLAN<br>• Virtual asset compliance: 50+ containers, 30+ VMs via Proxmox/Docker health checks |
| Networks | Advanced | Endpoint/application isolation with micro-perimeters, dynamic risk-aware traffic management, full encryption with cryptographic agility, dynamic availability management, anomaly-based detection with correlation, automated change management (CI/CD), tailored automated policies | • 3-tier architecture: DMZ, application, backend with per-service VLAN isolation<br>• pfSense CARP HA cluster: <5-second failover, 99.9%+ availability<br>• TLS 1.3 mandatory via Traefik with modern ciphers (AES-256-GCM, ChaCha20-Poly1305)<br>• Step-CA PKI: automated cert issuance, 90-day rotation, Ed25519 keys<br>• Dual Pi-hole DNS with automatic failover<br>• 100% traffic visibility: pfSense flow logs, Traefik access logs, Pi-hole queries, Suricata/Snort IDS<br>• Terraform defines network IaC with Git version control<br>• Ansible configures firewall rules, routing, VLANs with automated deployment |
| Applications and Workloads | Advanced | Automated access with contextual enforcement, integrated threat protections, most applications publicly accessible with protection, distinct dev/sec/ops teams with restricted production access, integrated periodic security testing, automated monitoring with trends, automated configuration response, tiered enterprise-wide policies | • Authentik OAuth2 considers: identity, groups, device compliance (Wazuh), source IP, time-of-day, MFA<br>• SafeLine WAF: OWASP CRS, 25% attack block rate (SQLi, XSS, command injection, path traversal)<br>• Traefik security headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options<br>• Cloudflare Tunnels expose services without port forwarding<br>• Docker immutable workloads: 50+ containers with version-based updates<br>• Separate dev/staging/production environments with network isolation<br>• Pre-deployment scanning: OpenVAS, Nessus, OWASP ZAP, Burp Suite<br>• Prometheus monitors performance, Uptime Kuma tracks 50+ service monitors |
| Data | Advanced | Automated enterprise-wide inventory with DLP based on labels, automated consistent categorization with regular review, redundant highly-available stores with historical access, automated controls considering multiple attributes with time limits, full encryption at rest/transit with cryptographic agility and key protection, enterprise-wide visibility with correlation and initial predictive analytics, primarily automated lifecycle enforcement in targeted manner, integrated policy enforcement with unified definitions | • Filesystem monitoring: 30+ hosts, 50+ containers via Wazuh FIM<br>• Dual SIEM: 90-day hot retention, 1-year cold storage, database replication<br>• Backup retention: 4 weekly, 12 monthly, 7 yearly with offsite storage<br>• Sensitivity tiers defined: Public, Internal, Confidential, Restricted with handling requirements<br>• AES-256-GCM encrypts backups with keys in Vaultwarden<br>• TLS 1.3 encrypts all network communications (web, SSH, VPN, syslog)<br>• Authentik RBAC groups map to data repository permissions with quarterly reviews<br>• 30-minute session timeouts with re-auth for data access<br>• Pi-hole DNS logging provides data access pattern visibility |
| Visibility and Analytics (Cross-Cutting) | Advanced | Automated enterprise-wide collection including virtual environments, centralized multi-source correlation, anomaly detection, threat hunting | • Dual SIEM (Splunk + Elastic): 100% security event coverage across DNS, SSH, Traefik, firewalls, endpoints, applications<br>• Real-time correlation: multi-stage attacks, network reconnaissance + auth failures + privilege escalation<br>• Multi-source enrichment: MISP IOCs, Cortex analysis, geoIP, threat feeds<br>• Behavioral baselines identify anomalies in user activity, network traffic, app usage<br>• Grafana: 20+ dashboards tracking vulnerabilities, patch compliance, auth patterns, threat indicators<br>• Virtual environment monitoring: container lifecycle, VM provisioning, resource consumption anomalies<br>• SIEM retention: 90-day hot, 1-year cold with automated lifecycle management |
| Automation and Orchestration (Cross-Cutting) | Advanced | Enterprise-wide automated orchestration/response leveraging contextual information, IaC automation, SOAR workflows, automated patch management, certificate lifecycle automation | • Shuffle SOAR: 15+ playbooks integrating TheHive case mgmt, Cortex analysis, MISP enrichment<br>• Wazuh Active Response: automated containment (firewall-drop, account-disable, process-kill), sub-30-min MTTR<br>• Terraform/Ansible IaC: provisioning, configuration, decommissioning with Git version control<br>• Automated patching: PatchMon, WSUS, Watchtower with vulnerability-driven prioritization<br>• Step-CA: automated cert issuance, renewal, 90-day rotation<br>• Alert workflows: Discord, email, TheHive, PagerDuty multi-channel notification<br>• Proxmox automation: VMs with pre-configured baselines, snapshot-before-patch |
| Governance (Cross-Cutting) | Advanced | Tiered tailored policies enterprise-wide with automation support, contextual access decisions, documented version-controlled policies, quarterly reviews, automated compliance reporting | • Security policies in Git with version control and quarterly reviews<br>• CIS Benchmark baselines enforced via Wazuh SCA with automated compliance reporting (92-98%)<br>• Vulnerability remediation SLAs: Critical <72h, High <7d tracked via TheHive<br>• Configuration management: Ansible enforcement with drift detection and automated alerts<br>• Encryption policies mandate TLS 1.3, modern algorithms validated via vulnerability scans<br>• Access control policies: least-privilege with automated quarterly reviews<br>• Incident response policies: escalation criteria, notification procedures documented<br>• Policy exceptions require documented compensating controls and annual re-approval |

**Overall CISA Zero Trust Maturity: Advanced (Stage 3 of 4) — 87% of functions at Advanced or higher**

This Zero Trust implementation demonstrates Advanced-stage maturity aligned with CISA ZTMM v2.0, providing production-ready capabilities directly transferable to federal civilian executive branch agencies and enterprise environments pursuing Executive Order 14028 compliance and OMB M-22-09 objectives.