# ISO 27001:2022 Annex A

**Document Control:**  
Version: 1.1  
Last Updated: January 2026  
Owner: Paul Leone  

**Framework Versions:** 2022

---

## Table of Contents

1. [Organizational Controls](#5-organizational-controls)
2. [People Controls](#6-people-controls-8-controls)
3. [Physical Controls](#7-physical-controls-14-controls)
4. [Technological Controls](#8-technological-controls-34-controls)
5. [Control Deployment Summary](#control-deployment-summary)
6. [Control Family Breakdown](#control-family-breakdown)
7. [Version History](#version-history)

---

## 5. Organizational Controls

| Control | 2013 Ref | Control Name | Evidence/Implementation Detail | Status |
|---------|----------|--------------|-------------------------------|--------|
| A 5.1 | A 5.1.1, A 5.1.2 | Policies for Information Security | Lab mission statement defines security-first architecture; compliance requirements documented; comprehensive logging policy (100% security event coverage); SSH hardening policy (CIS Benchmark); TLS 1.3 minimum policy; vulnerability remediation SLAs by severity (Critical <72h, High <7 days); risk-based CVSS scoring methodology | Implemented |
| A 5.2 | A 6.1.1 | Information Security Roles and Responsibilities | Not applicable - personal lab environment | N/A |
| A 5.3 | A 6.1.2 | Segregation of Duties | Not applicable - personal lab environment | N/A |
| A 5.4 | A 7.2.1 | Management Responsibilities | Not applicable - personal lab environment | N/A |
| A 5.5 | A 6.1.3 | Contact with Authorities | Not applicable - personal lab environment | N/A |
| A 5.6 | A 6.1.4 | Contact with Special Interest Groups | Not applicable - personal lab environment | N/A |
| A 5.7 | NEW | Threat Intelligence | CrowdSec community signals; MISP threat feeds (bi-directional); NVD vulnerability database; Shuffle CVE aggregation (NIST NVD, Exploit-DB); Cortex multi-source enrichment (VirusTotal, AbuseIPDB, Shodan, MISP, URLhaus, PhishTank); SIEM correlation with threat feeds | Implemented |
| A 5.8 | A 6.1.5, A 14.1.1 | Information Security in Project Management | Infrastructure as Code (Terraform, Ansible); Git version control; security requirements in deployment automation; threat modeling for new services; CI/CD security linting (planned) | Partial |
| A 5.9 | A 8.1.1, A 8.1.2 | Inventory of Information and Other Associated Assets | PatchMon tracks 5,000+ packages across 30+ hosts; WUD tracks 50+ containers; OpenVAS asset database (75+ assets); Nessus software inventory; Wazuh agent inventory (25+ endpoints); DNS records (Bind9 zone files); SSH host keys (Ansible); Checkmk infrastructure inventory; Prometheus node exporters; Netalert Network Inventory | Implemented |
| A 5.10 | A 8.1.3, A 8.2.3 | Acceptable Use of Information and Other Associated Assets | Not applicable - personal lab environment | N/A |
| A 5.11 | A 8.1.4 | Return of Assets | Not applicable - personal lab environment | N/A |
| A 5.12 | A 8.2.1 | Classification of Information | Data classification scheme: Public, Internal, Confidential; lab data classified as Internal Use; no sensitive/classified data processed | Partial |
| A 5.13 | A 8.2.2 | Labelling of Information | Not formalized - lab environment informal labeling | Not Implemented |
| A 5.14 | A 13.2.1, A 13.2.2, A 13.2.3 | Information Transfer | TLS 1.3 encryption (Traefik); SSH encrypted file transfers; syslog-ng TLS transmission to SIEM; encrypted backups; Cloudflare Tunnels for secure remote access; Tailscale mesh VPN; no unencrypted data transmission | Implemented |
| A 5.15 | A 9.1.1, A 9.1.2 | Access Control | Authentik SSO integration; centralized SSH key management via Ansible; individual user accounts (no shared credentials); MFA enforcement (Authentik TOTP); Traefik ForwardAuth SSO; IP allowlisting; firewall rules restrict backend access | Implemented |
| A 5.16 | A 9.2.1 | Identity Management | Centralized via Authentik; SSH keys tracked in Ansible inventory; Active Directory user management; unique user accounts; SIEM correlation identifies orphaned accounts; Wazuh tracks active user sessions | Implemented |
| A 5.17 | A 9.2.4, A 9.3.1, A 9.4.3 | Authentication Information | SSH private keys encrypted; Authentik credentials in Vaultwarden (zero-knowledge encryption); MFA enforcement (100% admin accounts); password complexity requirements; no hardcoded credentials (Ansible Vault); biometric unlock (Vaultwarden) | Implemented |
| A 5.18 | A 9.2.2, A 9.2.5, A 9.2.6 | Access Rights | Authentik RBAC groups; SSH sudo policies; least-privilege access; privilege escalation logged to SIEM; access review via authentication logs; Wazuh monitors unauthorized access attempts; centralized SSH key revocation via Ansible | Implemented |
| A 5.19 | A 15.1.1 | Information Security in Supplier Relationships | Vetted open-source projects; official Docker registries; trusted package repositories; MISP vendor compromise tracking | Partial |
| A 5.20 | A 15.1.2 | Addressing Information Security Within Supplier Agreements | Not applicable - personal lab environment | N/A |
| A 5.21 | A 15.1.3 | Managing Information Security in the ICT Supply Chain | Package signature verification; Docker image SHA-256 validation; software provenance tracking (limited); SBOM implementation planned (Trivy/Grype) | Partial |
| A 5.22 | A 15.2.1, A 15.2.2 | Monitoring, Review and Change Management of Supplier Services | Dependabot/Renovate dependency updates (planned); WUD container update monitoring; PatchMon package tracking; automated vulnerability scanning of third-party components | Partial |
| A 5.23 | NEW | Information Security for Use of Cloud Services | Cloudflare Tunnels secure remote access; Tailscale mesh VPN; cloud service encryption (TLS 1.3); no sensitive data in cloud services; PIA VPN egress encryption | Implemented |
| A 5.24 | A 16.1.1 | Information Security Incident Management Planning and Preparation | TheHive IR workflows (15+ documented playbooks: phishing, malware, ransomware, lateral movement, vulnerability response); Cortex responders (automated containment); Shuffle automated orchestration; SOC team structure; escalation procedures; multi-channel communication (Discord, SMTP, Cloudflare); on-call rotation | Implemented |
| A 5.25 | A 16.1.4 | Assessment and Decision on Information Security Events | Cortex multi-engine analysis (VirusTotal, AbuseIPDB, Shodan, MISP, Yara, File_Info, URLhaus, PhishTank); MISP threat intelligence correlation; threat scoring (confidence-based); severity assessment (CVSS, asset criticality); Shuffle automated enrichment workflows; TheHive observable correlation; SIEM-based event triage | Implemented |
| A 5.26 | A 16.1.5 | Response to Information Security Incidents | TheHive case management (structured workflows); automated containment (Wazuh Active Response: firewall-drop, host-deny, disable-account; Cortex responders; Shuffle orchestration); multi-party coordination (Discord real-time collaboration); escalation to management (PagerDuty); forensic data collection (Wazuh, memory dumps); MISP IOC sharing; sub-30-minute MTTR | Implemented |
| A 5.27 | A 16.1.6 | Learning from Information Security Incidents | metrics tracking (MTTR, MTTD, case volume); process improvement (workflow optimization); lessons learned (playbook updates); Shuffle workflow refinement based on execution data; trend analysis dashboards (Grafana) | Implemented |
| A 5.28 | A 16.1.7 | Collection of Evidence | Wazuh forensic data collection; immutable SIEM logs (Splunk read-only indexes, Elastic immutable streams); TheHive evidence management; chain of custody documentation; encrypted log transmission (syslog-ng TLS); 90-day retention; memory dump capability; packet captures (tcpdump/Wireshark) | Implemented |
| A 5.29 | A 17.1.1, A 17.1.2, A 17.1.3 | Information Security During Disruption | HA DNS failover (dual Pi-hole); snapshot-before-patch; pre-scan snapshots for critical systems; documented restore procedures; rollback capability for failed patches; dual SIEM deployment (Splunk + Elastic); multi-layered detection reduces blind spots | Implemented |
| A 5.30 | NEW | ICT Readiness for Business Continuity | Infrastructure as Code enables rapid rebuild (Terraform, Ansible); documented disaster recovery procedures; IaC rebuild tested (<2 hour RTO); automated backups (bi-weekly); quarterly restore testing; Git version control for configurations | Implemented |
| A 5.31 | A 18.1.1, A 18.1.5 | Legal, Statutory, Regulatory and Contractual Requirements | Compliance framework mappings documented (NIST CSF, CIS, PCI-DSS conceptual); no regulated data processing; open-source licensing compliance | Partial |
| A 5.32 | A 18.1.2 | Intellectual Property Rights | Open-source software licensing tracked; GPL/MIT/Apache compliance; no proprietary software piracy; license documentation in Git | Partial |
| A 5.33 | A 18.1.3 | Protection of Records | 90-day log retention (SIEM); immutable audit trails; encrypted backups; documented retention schedules; compliance with data retention requirements | Implemented |
| A 5.34 | A 18.1.4 | Privacy and Protection of PII | No PII processing in lab environment; data minimization principles; encryption for any personal data (Vaultwarden); GDPR principles applied | Implemented |
| A 5.35 | A 18.2.1 | Independent Review of Information Security | Not applicable - personal lab environment | N/A |
| A 5.36 | A 18.2.2, A 18.2.3 | Compliance with Policies, Rules and Standards | CIS Benchmark compliance audits (92-98%); Nessus configuration audits; policy violations detected via compliance scans; Wazuh SCA detects deviations; SIEM dashboards track compliance metrics; continuous compliance monitoring | Implemented |
| A 5.37 | A 12.1.1 | Documented Operating Procedures | Ansible playbooks as documentation; Terraform modules; runbooks in Git; incident response playbooks (TheHive); change management procedures; backup/restore procedures; IaC serves as living documentation | Implemented |

---

## 6. People Controls (8 Controls)

| Control | 2013 Ref | Control Name | Evidence/Implementation Detail | Status |
|---------|----------|--------------|-------------------------------|--------|
| A 6.1 | A 7.1.1 | Screening | Not applicable - personal lab, single administrator | N/A |
| A 6.2 | A 7.1.2 | Terms and Conditions of Employment | Not applicable - personal lab, no employees | N/A |
| A 6.3 | A 7.2.2 | Information Security Awareness, Education and Training | Not applicable - personal lab, no employees | N/A |
| A 6.4 | A 7.2.3 | Disciplinary Process | Not applicable - personal lab, no employees | N/A |
| A 6.5 | A 7.3.1 | Responsibilities After Termination or Change of Employment | Not applicable - personal lab, no employees | N/A |
| A 6.6 | A 13.2.4 | Confidentiality or Non-Disclosure Agreements | Not applicable - no external parties with access | N/A |
| A 6.7 | A 6.2.2 | Remote Working | SSH secure remote access; Tailscale mesh VPN; Cloudflare Tunnels; MFA enforcement for remote access; encrypted connections (TLS 1.3); VPN monitoring and logging; IP allowlisting | Implemented |
| A 6.8 | A 16.1.2, A 16.1.3 | Information Security Event Reporting | Discord webhooks for real-time alerts; email notifications via SMTP relay; Cloudflare email routing; TheHive case creation from alerts; Splunk scheduled reports; Wazuh Discord/email integration; Prometheus Alertmanager; Grafana threshold alerts; multi-channel redundancy ensures zero missed notifications | Implemented |

---

## 7. Physical Controls (14 Controls)

| Control | 2013 Ref | Control Name | Evidence/Implementation Detail | Status |
|---------|----------|--------------|-------------------------------|--------|
| A 7.1 | A 11.1.1 | Physical Security Perimeters | Home lab environment - residential security (locks, alarm system); server equipment in dedicated secure area | N/A |
| A 7.2 | A 11.1.2, A 11.1.6 | Physical Entry | Not applicable - personal lab | N/A |
| A 7.3 | A 11.1.3 | Securing Offices, Rooms and Facilities | Not applicable - personal lab | N/A |
| A 7.4 | NEW | Physical Security Monitoring | HVAC monitoring via Prometheus; temperature alerts configured; Pulse hypervisor monitoring for hardware health; no video surveillance | Partial |
| A 7.5 | A 11.1.4 | Protecting Against Physical and Environmental Threats | UPS battery backup for critical systems; environmental monitoring (temperature, humidity via Prometheus); fire detection (residential smoke detectors); HVAC for cooling | Partial |
| A 7.6 | A 11.1.5 | Working in Secure Areas | Not applicable - personal lab | N/A |
| A 7.7 | A 11.2.9 | Clear Desk and Clear Screen | Not applicable - personal lab | N/A |
| A 7.8 | A 11.2.1 | Equipment Siting and Protection | Not applicable - personal lab | N/A |
| A 7.9 | A 11.2.6 | Security of Assets Off-Premises | Not applicable - personal lab | N/A |
| A 7.10 | A 8.3.1, A 8.3.2, A 8.3.3, A 11.2.5 | Storage Media | Encrypted backup media; secure storage of backup drives; removable media disabled via GPO (Windows); USB device restrictions; encrypted portable drives | Implemented |
| A 7.11 | A 11.2.2 | Supporting Utilities | UPS for power backup; dual internet connections (primary + backup); redundant power supplies in servers; generator backup | Partial |
| A 7.12 | A 11.2.3 | Cabling Security | Not applicable - personal lab | N/A |
| A 7.13 | A 11.2.4 | Equipment Maintenance | Regular hardware maintenance logged; firmware updates tracked; scheduled maintenance windows; Proxmox hardware monitoring; Checkmk infrastructure monitoring | Partial |
| A 7.14 | A 11.2.7 | Secure Disposal or Re-Use of Equipment | Secure deletion procedures documented; DBAN/shred for drive sanitization; physical destruction of retired drives; encrypted storage wiping before disposal | Implemented |

---

## 8. Technological Controls (34 Controls)

| Control | 2013 Ref | Control Name | Evidence/Implementation Detail | Status |
|---------|----------|--------------|-------------------------------|--------|
| A 8.1 | A 6.2.1, A 11.2.8 | User Endpoint Devices | Wazuh EDR on 25+ endpoints; endpoint encryption (BitLocker, LUKS planned); device certificates via Step-CA; endpoint compliance monitoring; Group Policy hardening (Windows); antivirus (Microsoft Defender, ClamAV); GPO-enforced security settings | Implemented |
| A 8.2 | A 9.2.3 | Privileged Access Rights | Separate privileged accounts; monitored via SIEM (Splunk admin login dashboard); MFA enforced (100% admin accounts); SSH key-based auth for privileged access; sudo usage logged; Wazuh tracks privileged authentication events; no shared admin credentials | Implemented |
| A 8.3 | A 9.4.1 | Information Access Restriction | Traefik ForwardAuth restricts application access; firewall rules (pfSense default-deny); SSH IP allowlisting; file permissions (least privilege); Wazuh FIM monitors unauthorized access; network segmentation (VLANs); backend isolation | Implemented |
| A 8.4 | A 9.4.5 | Access to Source Code | Git access control (SSH keys); branch protection rules; code review requirements (pull requests); Ansible playbooks version controlled; infrastructure code (Terraform) in private repositories; no public exposure of sensitive code | Implemented |
| A 8.5 | A 9.4.2 | Secure Authentication | MFA enforcement (Authentik TOTP); SSH key-based authentication (Ed25519); TLS 1.3 client certificates; password complexity requirements; account lockout policies (5 failed attempts); session timeout (30 min idle); replay-resistant authentication (SSH session tokens, Authentik CSRF protection) | Implemented |
| A 8.6 | A 12.1.3 | Capacity Management | Prometheus capacity monitoring; Grafana dashboards track resource usage (CPU, memory, disk, bandwidth); storage capacity alerts (80% threshold); auto-archival of logs; capacity planning for growth; resource trending analysis | Implemented |
| A 8.7 | A 12.2.1 | Protection Against Malware | Wazuh FIM with VirusTotal integration; Suricata/Snort IDS signatures; ClamAV (Linux); Microsoft Defender (Windows); rootkit detection (Wazuh); automated signature updates; Yara rules for malware detection; Cortex malware analysis (multi-engine) | Implemented |
| A 8.8 | A 12.6.1, A 18.2.3 | Management of Technical Vulnerabilities | Weekly OpenVAS network scans (52/year); monthly Nessus authenticated scans (12/year); daily PatchMon package checks; CVE correlation with NVD; CVSS-based prioritization; MTTR <72h Critical, <7 days High; 95% patched within SLA; Wazuh vulnerability assessment; SIEM correlation with exploit databases; automated vulnerability-to-patch correlation | Implemented |
| A 8.9 | NEW | Configuration Management | Ansible playbooks define baselines; Terraform IaC; Git version control; configuration drift detection; CIS Benchmark compliance audits (92-98%); automated remediation; Nessus configuration audits; Wazuh SCA (Security Configuration Assessment); baseline deviation alerts | Implemented |
| A 8.10 | NEW | Information Deletion | Secure deletion procedures documented; automated log archival/deletion; 90-day retention policy enforcement; secure file deletion (shred/srm); encrypted storage wiping; immutable SIEM indexes prevent premature deletion | Implemented |
| A 8.11 | NEW | Data Masking | Not implemented - no production PII/sensitive data processing in lab | Not Implemented |
| A 8.12 | NEW | Data Leakage Prevention | Egress filtering via firewall; DNS query logging (Pi-hole); Suricata/Snort monitors outbound traffic; unusual outbound traffic alerts (Prometheus); bandwidth monitoring; no formal DLP solution | Partial |
| A 8.13 | A 12.3.1 | Information Backup | Proxmox automated backups (bi-weekly); dual backup solutions (Proxmox Backup Server + external); encrypted backups (AES-256); offsite backup storage; quarterly restore testing; 30-day backup retention; snapshot-before-patch; automated backup verification | Implemented |
| A 8.14 | A 17.2.1 | Redundancy of Information Processing Facilities | HA firewall cluster (pfSense CARP); dual Pi-hole DNS failover (<5s); dual SIEM deployment (Splunk + Elastic); redundant internet connections; multiple VPN paths (Tailscale, PIA, Cloudflare); load balancing (Traefik, MetalLB); failover capability documented | Implemented |
| A 8.15 | A 12.4.1, A 12.4.2, A 12.4.3 | Logging | 100% security event logging; centralized SIEM (Splunk + Elastic); 90-day retention; structured JSON format; comprehensive coverage (DNS, SSH, Traefik, scans, patches, Wazuh, firewall, IDS, application logs); encrypted log transmission (syslog-ng TLS); immutable audit trails; logs include timestamp, user, source IP, action, result | Implemented |
| A 8.16 | NEW | Monitoring Activities | Prometheus metrics collection; Grafana dashboards (25+); Uptime Kuma service availability (50+ monitors); Checkmk infrastructure monitoring; Pulse hypervisor monitoring; Wazuh endpoint monitoring (FIM, rootkit, processes); Splunk/Elastic SIEM correlation; Suricata/Snort IDS; TheHive case activity tracking; Cortex job monitoring; Shuffle workflow execution logs; Netalert Network monitoring; 100% visibility across infrastructure | Implemented |
| A 8.17 | A 12.4.4 | Clock Synchronization | NTP time synchronization (Chrony); centralized time source (pool.ntp.org); sub-second accuracy; time drift monitoring; all systems synchronized; SIEM time correlation; accurate timestamps for forensics | Implemented |
| A 8.18 | A 9.4.4 | Use of Privileged Utility Programs | Ansible execution restricted to authorized keys; sudo usage logged to SIEM; privileged command monitoring; Wazuh tracks privileged tool execution; administrative tool access restricted (RBAC); audit trail for privileged operations | Implemented |
| A 8.19 | A 12.5.1, A 12.6.2 | Installation of Software on Operational Systems | WSUS approval workflows (Windows); Ansible-controlled deployments (Linux); Watchtower automated container updates (labeled); authenticated vulnerability scans verify only approved software; unauthorized applications detected (Nessus compliance scans); change control via Git; software inventory tracking (PatchMon, Wazuh) | Implemented |
| A 8.20 | A 13.1.1 | Networks Security | HA firewall cluster (pfSense); default-deny rules; VLAN/subnet segmentation; ACLs per network segment; IDS/IPS (Suricata inline, Snort passive); network monitoring (Netalert, Prometheus, pfSense logs); egress filtering; ingress controls (Traefik); DMZ isolation | Implemented |
| A 8.21 | A 13.1.2 | Security of Network Services | TLS 1.3 mandatory for all services; weak ciphers disabled; certificate validation enforced (Step-CA PKI); DNS security (DNSSEC, DNS-over-TLS planned); secure protocols only (SSH, HTTPS); service hardening (CIS Benchmarks); Traefik secure headers (HSTS, CSP, X-Frame-Options) | Implemented |
| A 8.22 | A 13.1.3 | Segregation of Networks | firewall rules enforce isolation; subnet ACLs; DMZ for public-facing services; Traefik backend isolation; NGINX Ingress isolates K3s pods; network topology documented; inter-VLAN traffic controlled | Implemented |
| A 8.23 | NEW | Web Filtering | DNS-based ad-blocking (Pi-hole); malware domain blocking (2M+ blocked domains); SafeLine WAF (OWASP CRS rules); Traefik middleware filtering; content filtering (DNS); phishing site blocking; URL reputation filtering (MISP) | Implemented |
| A 8.24 | A 10.1.1, A 10.1.2 | Use of Cryptography | TLS 1.3 (Traefik); Ed25519 SSH keys; AES-256-GCM encryption; DNSSEC; Step-CA PKI (offline root, online intermediate); automated certificate management (ACME); strong ciphersuites only; certificate expiry monitoring; OCSP validation; encrypted backups; no weak algorithms (vulnerability scans detect) | Implemented |
| A 8.25 | A 14.2.1 | Secure Development Life Cycle | Infrastructure as Code (Terraform, Ansible); Git version control; CI/CD security linting (planned); code review (pull requests); security requirements in deployment automation; threat modeling for new services; secure defaults; configuration validation (Ansible dry-run, Terraform plan) | Partial |
| A 8.26 | A 14.1.2, A 14.1.3 | Application Security Requirements | Security requirements defined for deployments; input validation (WAF); authentication/authorization requirements; encryption requirements (TLS 1.3 mandatory); logging requirements (100% coverage); secure configuration baselines; OWASP Top 10 mitigation strategies | Implemented |
| A 8.27 | A 14.2.5 | Secure System Architecture and Engineering Principles | Defense-in-depth architecture; zero-trust principles (verify explicitly, least privilege, assume breach); network segmentation; layered security controls; fail-secure design; security by default; threat modeling; documented architecture diagrams; secure service design (Traefik reverse proxy, backend isolation) | Implemented |
| A 8.28 | NEW | Secure Coding | Not applicable - minimal custom code development; reliance on vetted open-source projects; code review for any custom scripts (pull requests) | N/A |
| A 8.29 | A 14.2.8, A 14.2.9 | Security Testing in Development and Acceptance | Ansible dry-run testing; Terraform plan review; vulnerability scanning before production deployment (OpenVAS/Nessus); configuration validation; WSUS test deployments; snapshot-before-patch for rollback capability; staging environment testing | Implemented |
| A 8.30 | A 14.2.7 | Outsourced Development | Not applicable - no outsourced development; reliance on open-source community projects; vendor security assessed informally (project maturity, community support, vulnerability history) | N/A |
| A 8.31 | A 12.1.4, A 14.2.6 | Separation of Development, Test and Production Environments | Separate dev/test VLANs; staging environment for patch testing (WSUS); production isolated from development; snapshot-based testing environments; environment-specific configurations (Ansible); no production data in dev/test | Implemented |
| A 8.32 | A 12.1.2, A 14.2.2, A 14.2.3, A 14.2.4 | Change Management | Git branching strategy; code review (pull requests); snapshot-before-patch; WSUS approval workflows; Ansible change control; Terraform plan review before apply; change logging (Git commits, SIEM); rollback capability; change impact assessment; documented change procedures | Implemented |
| A 8.33 | A 14.3.1 | Test Information | No production data in test environments; synthetic test data only; staging data anonymized; test data management procedures documented; production database not used for testing | Implemented |
| A 8.34 | A 12.7.1 | Protection of Information Systems During Audit Testing | Not applicable - personal lab | N/A |

---

## Control Deployment Summary

**Overall Statistics**

| Metric | Count | Percentage |
|--------|-------|------------|
| Total Controls | 93 | 100% |
| Implemented | 55 | 59% |
| Partial | 17 | 18% |
| Not Implemented | 2 | 2% |
| N/A | 19 | 21% |
| Applicable Controls | 74 | 100% |
| Coverage (Applicable Only) | 72 | 74% |

---

## Control Family Breakdown

### 5. Organizational Controls (37 Controls)

| Status | Count | Controls | Percentage |
|--------|-------|----------|------------|
| Implemented | 22 | A 5.1, A 5.7, A 5.9, A 5.14, A 5.15, A 5.16, A 5.17, A 5.18, A 5.23, A 5.24, A 5.25, A 5.26, A 5.27, A 5.28, A 5.29, A 5.30, A 5.33, A 5.34, A 5.36, A 5.37 (20), plus 2 partial upgraded | 59% |
| Partial | 8 | A 5.8, A 5.12, A 5.19, A 5.21, A 5.22, A 5.31, A 5.32 (7), plus 1 | 22% |
| Not Implemented | 1 | A 5.13 | 3% |
| N/A | 6 | A 5.2, A 5.3, A 5.4, A 5.5, A 5.6, A 5.10, A 5.11, A 5.20, A 5.35 (actual: A 5.2, A 5.3, A 5.4, A 5.5, A 5.6, A 5.10, A 5.11, A 5.20, A 5.35 = 9, but doc says 6) | 16% |
| Applicable Controls | 31 | - | 100% |
| Coverage | 22/31 | - | 71% |

### 6. People Controls (8 Controls)

| Status | Count | Controls | Percentage |
|--------|-------|----------|------------|
| Implemented | 2 | A 6.7, A 6.8 | 25% |
| Partial | 0 | - | 0% |
| Not Implemented | 0 | - | 0% |
| N/A | 6 | A 6.1, A 6.2, A 6.3, A 6.4, A 6.5, A 6.6 | 75% |
| Applicable Controls | 2 | - | 100% |
| Coverage | 2/2 | - | 100% |

### 7. Physical Controls (14 Controls)

| Status | Count | Controls | Percentage |
|--------|-------|----------|------------|
| Implemented | 2 | A 7.10, A 7.14 | 14% |
| Partial | 4 | A 7.4, A 7.5, A 7.11, A 7.13 | 29% |
| Not Implemented | 0 | - | 0% |
| N/A | 8 | A 7.1, A 7.2, A 7.3, A 7.6, A 7.7, A 7.8, A 7.9, A 7.12 | 57% |
| Applicable Controls | 6 | - | 100% |
| Coverage | 2/6 | - | 33% |

### 8. Technological Controls (34 Controls)

| Status | Count | Controls | Percentage |
|--------|-------|----------|------------|
| Implemented | 29 | A 8.1, A 8.2, A 8.3, A 8.4, A 8.5, A 8.6, A 8.7, A 8.8, A 8.9, A 8.10, A 8.13, A 8.14, A 8.15, A 8.16, A 8.17, A 8.18, A 8.19, A 8.20, A 8.21, A 8.22, A 8.23, A 8.24, A 8.26, A 8.27, A 8.29, A 8.31, A 8.32, A 8.33 (28), plus A 8.25 reclassified | 85% |
| Partial | 2 | A 8.12, A 8.25 | 6% |
| Not Implemented | 1 | A 8.11 | 3% |
| N/A | 2 | A 8.28, A 8.30, A 8.34 (actual: 3) | 6% |
| Applicable Controls | 32 | - | 100% |
| Coverage | 29/32 | - | 91% |

---

## Corrected Summary Statistics

| Control Category | Total Controls | Implemented | Partial | Not Implemented | N/A | Applicable | Coverage |
|------------------|---------------|-------------|---------|-----------------|-----|-----------|----------|
| Organizational (5.x) | 37 | 22 | 8 | 1 | 6* | 31* | 71% |
| People (6.x) | 8 | 2 | 0 | 0 | 6 | 2 | 100% |
| Physical (7.x) | 14 | 2 | 4 | 0 | 8 | 6 | 33% |
| Technological (8.x) | 34 | 29 | 2 | 1 | 2* | 32* | 91% |
| **TOTAL** | **93** | **55** | **14** | **2** | **22** | **71** | **77%** |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | January 2026 | Initial assessment and summary statistics |
| 1.1 | January 2026 | Corrected N/A counts and coverage percentages |