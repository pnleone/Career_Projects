# Security Lab - Governance, Risk and Compliance Summary

**Document Control:**   
Version: 1.0  
Last Updated: January 2026  
Owner: Paul Leone

**Framework Versions:** NIST CSF 2.0, CIS Controls v8.1, NIST SP 800-53 Rev 5, ISO 27001:2022, PCI-DSS v4.0, OWASP Top 10 2025, MITRE ATT&CK Enterprise v18.1, CISA ZTMM v2.0, NIST SP 800-207 Zero Trust

---

## Executive Overview

### Framework Alignment with Lab Mission

This cybersecurity lab demonstrates production-ready security capabilities aligned with nine industry-standard frameworks, each validating specific aspects of the lab's mission to simulate enterprise-grade SecOps, Systems Engineering, and Network Defense operations.

### Mission Alignment by Framework

**NIST Cybersecurity Framework 2.0** validates threat detection & response capabilities through comprehensive implementation across all six functions (Govern, Identify, Protect, Detect, Respond, Recover). The framework's risk-based approach directly supports the lab mission of demonstrating production-ready SOC operations, achieving Tier 3-4 maturity with automated incident response workflows reducing MTTR to <30 minutes.

**CIS Controls v8.1** validates defense-in-depth architecture through 93% IG1 compliance and 81% IG2 compliance, demonstrating foundational security hygiene (asset inventory, patch management, centralized logging) and advanced security capabilities (network segmentation, MFA enforcement, vulnerability management). The controls map directly to enterprise infrastructure operations with automated patch management across 5,000+ packages and comprehensive security monitoring.

**ISO 27001:2022** validates security engineering & automation through 77% overall control coverage, with exceptional performance in technological controls (91%). The framework demonstrates policy-driven security architecture with CIS Benchmark compliance, Infrastructure as Code automation, and comprehensive audit capabilities supporting compliance-ready operations.

**NIST SP 800-53 Rev 5** validates technical security engineering depth through strong implementation in Access Control (90%), Audit & Accountability (100%), and System Integrity (90%). The framework demonstrates enterprise-grade controls spanning identity management, cryptographic protection, and continuous monitoring—directly transferable to Security Engineer roles.

**MITRE ATT&CK Enterprise v18.1** validates operational threat detection capabilities through 30% technique coverage (65 of 216 techniques) across 12 adversary tactics. Strong coverage in Initial Access (67%), Execution (67%), and Lateral Movement (56%) demonstrates real-world threat hunting and detection engineering capabilities aligned with SOC Analyst responsibilities.

**OWASP Top 10 (2025)** validates application security engineering through strong coverage across 9 of 10 categories. Advanced maturity in cryptographic failures, injection prevention, and authentication demonstrates secure application architecture principles applicable to DevSecOps and application security roles.

**PCI-DSS v4.0** validates compliance-ready technical controls through 85% conceptual implementation of requirements. While the lab processes no cardholder data, the architecture demonstrates production-ready capabilities in network segmentation, encryption, logging, and vulnerability management that directly transfer to regulated environments.

**CISA Zero Trust Maturity Model v2.0** validates zero trust architecture implementation through Advanced maturity (Stage 3 of 4) across all five core pillars (Identity, Devices, Networks, Applications & Workloads, Data) plus three cross-cutting capabilities (Visibility & Analytics, Automation & Orchestration, Governance). The framework demonstrates explicit verification of every access request, least-privilege enforcement via RBAC, assume-breach mentality with continuous monitoring, and encrypt-everything policies using modern cryptographic standards.

**NIST SP 800-207 Zero Trust Architecture** validates comprehensive implementation of all seven ZT tenets through hybrid deployment model combining device agent/gateway (Authentik + Traefik), enclave gateway (pfSense/OPNsense), and resource portal approaches. The framework demonstrates mature logical component deployment with policy decision points, policy enforcement points, and continuous monitoring achieving 6 of 8 pillars at Advanced level.

### Architectural Principles Demonstrated

**Defense in Depth** is validated across all frameworks through multi-layered security controls:

- Network perimeter defense (CIS 12.1-12.4, NIST SC-7, ISO A.8.20, PCI-DSS 1.x, CISA ZTMM Networks, NIST 800-207 SC-7)
- Application layer protection (OWASP A01-A10, NIST SI-10, ISO A.8.26, CISA ZTMM Applications, NIST 800-207 SA-8)
- Endpoint security (CIS 10.1-10.7, NIST SI-3/SI-4, ATT&CK detection coverage, CISA ZTMM Devices, NIST 800-207 IA-3)
- Identity controls (CIS 5-6, NIST AC/IA families, ISO A.5.15-5.18, OWASP A07, CISA ZTMM Identity, NIST 800-207 IA-2)

**Secure by Design** is validated through embedded security controls:

- Mandatory encryption (NIST SC-8/SC-13/SC-28, ISO A.8.24, OWASP A04, PCI-DSS 4.2, CISA ZTMM Data, NIST 800-207 SC-8)
- Authenticated access (NIST IA-2, CIS 6.3-6.5, ISO A.5.17, OWASP A07, CISA ZTMM Identity Advanced, NIST 800-207 IA-2(1))
- Least privilege (NIST AC-6, CIS 5.4/6.1, ISO A.5.18, OWASP A01, CISA ZTMM per-session access, NIST 800-207 AC-6)
- IaC automation (NIST CM-2/CM-3, CIS 4.1, ISO A.8.9/A.8.32, CISA ZTMM Automation Advanced, NIST 800-207 CM-2(2))

**Zero Trust Architecture** is validated through continuous verification principles:

- Identity verification (NIST IA-2(1)/AC-3, ISO A.5.15, OWASP A07, CISA ZTMM Identity Advanced with phishing-resistant MFA, NIST 800-207 Tenet 6)
- Network micro-segmentation (NIST SC-7(21), CIS 12.2, ISO A.8.20, CISA ZTMM Networks Advanced 3-tier architecture, NIST 800-207 Tenet 2)
- Encrypted communications (NIST SC-8(1), PCI-DSS 4.2, OWASP A04, CISA ZTMM full encryption TLS 1.3, NIST 800-207 SC-8(1))
- Assume breach monitoring (ATT&CK coverage, NIST SI-4, CIS 13.1-13.6, CISA ZTMM Visibility Advanced 100% logging, NIST 800-207 Tenet 7)

### Framework Purpose & Organizational Value

**NIST Cybersecurity Framework 2.0**

**Purpose:** Provides risk-based framework for managing cybersecurity across enterprise operations through six core functions (Govern, Identify, Protect, Detect, Respond, Recover).

**Organizational Value:** Enables executive-level communication of cybersecurity posture, facilitates risk-informed decision making, and provides maturity benchmarking. Organizations use CSF 2.0 for board-level reporting, vendor risk assessments, and strategic security planning. The framework's flexibility makes it applicable across industries and organization sizes.

**CIS Controls v8.1**

**Purpose:** Delivers prescriptive, prioritized safeguards organized into three Implementation Groups (IG1: basic hygiene, IG2: enhanced security, IG3: advanced capabilities) based on organizational maturity and resources.

**Organizational Value:** Provides actionable security roadmap with clear prioritization—IG1 controls address 80% of common attacks. Organizations use CIS Controls for security program development, gap analysis, and resource allocation. The framework's specificity enables measurable progress tracking and budget justification.

**ISO 27001:2022**

**Purpose:** Establishes requirements for Information Security Management Systems (ISMS) with 93 controls across organizational, people, physical, and technological domains, supporting formal certification.

**Organizational Value:** Enables third-party certification demonstrating security commitment to customers, partners, and regulators. Organizations use ISO 27001 for contract requirements, regulatory compliance (GDPR, HIPAA alignment), and competitive differentiation in security-conscious markets.

**NIST SP 800-53 Rev 5**

**Purpose:** Provides comprehensive catalog of security/privacy controls for federal systems, organized into 20 control families covering technical, operational, and management safeguards.

**Organizational Value:** Serves as authoritative technical control baseline for government contractors and regulated industries. Organizations use 800-53 for FedRAMP compliance, FISMA requirements, and as technical reference for implementing CSF/ISO controls with specific implementation guidance.

**MITRE ATT&CK Enterprise v18.1**

**Purpose:** Documents adversary tactics, techniques, and procedures (TTPs) based on real-world observations, providing common taxonomy for threat-informed defense.

**Organizational Value:** Enables threat-based security testing, detection engineering, and purple team exercises. Organizations use ATT&CK for security tool evaluation, SOC playbook development, and measuring defensive coverage against known adversary behaviors. The framework transforms reactive security into proactive threat hunting.

**OWASP Top 10 (2025)**

**Purpose:** Identifies most critical web application security risks based on industry data, providing developer-focused guidance for secure application development.

**Organizational Value:** Drives secure coding practices, developer training, and application security testing priorities. Organizations use OWASP Top 10 for DevSecOps integration, penetration testing scopes, and measuring application security maturity. The framework bridges security and development teams with shared risk language.

**PCI-DSS v4.0**

**Purpose:** Mandates technical and operational requirements for organizations handling payment card data, enforced through annual assessments and potential financial penalties for non-compliance.

**Organizational Value:** Ensures payment security protecting customer data and brand reputation. Organizations must achieve PCI compliance to process credit cards—non-compliance risks data breaches, fines up to $100k/month, and loss of payment processing privileges. The framework provides detailed security requirements reducing breach risk.

**CISA Zero Trust Maturity Model v2.0**

**Purpose:** Defines four maturity stages (Traditional, Initial, Advanced, Optimal) across five core pillars (Identity, Devices, Networks, Applications & Workloads, Data) and three cross-cutting capabilities (Visibility & Analytics, Automation & Orchestration, Governance) providing actionable roadmap for zero trust adoption.

**Organizational Value:** Enables organizations to assess current zero trust posture and prioritize investments across identity-centric security, device trust, network micro-segmentation, application protection, and data security. Federal agencies use ZTMM for EO 14028 compliance; private sector organizations leverage the model for modernization roadmaps. The framework's staged approach supports incremental transformation aligned with organizational maturity and resources.

**NIST SP 800-207 Zero Trust Architecture**

**Purpose:** Establishes foundational principles and logical architecture for zero trust implementation through seven core tenets: explicit resource definition, location-independent security, per-session access, dynamic policy, asset integrity monitoring, dynamic authentication, and comprehensive telemetry collection.

**Organizational Value:** Provides vendor-neutral technical guidance for zero trust deployment spanning policy decision/enforcement points, trust algorithms, and hybrid deployment models. Organizations use 800-207 for architecture design, RFP requirements, and validating vendor solutions against federal standards. The framework's logical component model enables technology-agnostic implementation suitable for cloud, on-premises, and hybrid environments.

### Overall Lab Assessment

**Core Strengths**

**Operational Security Excellence**

- 100% security event logging with dual SIEM architecture (Splunk + Elastic) providing <5min MTTD
- Automated incident response via SOAR (Shuffle) achieving <30min MTTR with 15+ documented playbooks
- Multi-layered threat detection through network IDS/IPS (Suricata/Snort), host EDR (Wazuh 25+ endpoints), and behavioral analytics (CrowdSec)
- Comprehensive vulnerability management with weekly OpenVAS + monthly Nessus scans exceeding industry standards, <72hr critical MTTR

**Technical Architecture Maturity**

- Defense-in-depth implementation across network (segmentation, firewalls, IDS/IPS), application (WAF, reverse proxy), endpoint (EDR, FIM), and identity (SSO, MFA, PKI) layers
- Infrastructure as Code automation (Terraform, Ansible) enabling repeatable deployments with version control and audit trails
- Advanced cryptographic implementation: TLS 1.3 mandatory, Step-CA PKI, Ed25519 SSH keys, AES-256 encryption, zero weak algorithms
- High availability architecture: HA firewall cluster, dual SIEM, dual DNS with <5s failover, redundant internet
- Zero trust principles: explicit verification (Authentik SSO 100% coverage), micro-segmentation (3-tier VLAN architecture), encrypted communications (TLS 1.3 mandatory), continuous monitoring (dual SIEM 100% event coverage)

**Framework Compliance & Documentation**

- NIST CSF 2.0: Tier 3-4 maturity with 100% function coverage
- CIS Controls v8.1: 93% IG1, 81% IG2 compliance
- ISO 27001:2022: 77% overall, 91% technological controls
- NIST 800-53: 100% Audit & Accountability, 90%+ in AC/IA/SC/SI families
- PCI-DSS v4.0: 85% technical control implementation
- CISA ZTMM v2.0: Advanced maturity (Stage 3/4) across all 5 pillars + 3 cross-cutting capabilities
- NIST SP 800-207: Comprehensive implementation of all 7 ZT tenets, 6 of 8 pillars at Advanced level

This executive overview demonstrates that the lab achieves production-grade security capabilities across technical controls (91% ISO technological, 100% NIST AU, 90%+ AC/IA/SC/SI), operational processes (NIST Tier 3-4, 93% CIS IG1), threat detection (67% ATT&CK Initial Access/Execution), and zero trust architecture (CISA ZTMM Advanced across all pillars, NIST 800-207 comprehensive tenet implementation). Strategic gaps in supply chain security, advanced detection, DLP, and formal testing represent realistic areas for continued maturity advancement, mirroring the continuous improvement cycles found in enterprise security programs.

## NIST Cybersecurity Framework 2.0 Implementation Summary

<div class="two-col-right">
  <div class="text-col">
    <p>
      This personal cybersecurity lab demonstrates comprehensive implementation of NIST CSF 2.0 across all six core functions. The environment serves as a learning platform for enterprise-grade security controls while maintaining conceptual compliance with NIST, CIS, ISO 27001, and PCI-DSS frameworks.
    </p>
    <p>
      <strong>Overall Maturity: Tier 3 (Repeatable) - Approaching Tier 4 (Adaptive)</strong>
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/misc/nist-csf.png" alt="NIST CSF 2.0 Logo">
      <figcaption>NIST Cybersecurity Framework 2.0</figcaption>
    </figure>
  </div>
</div>

### Function Implementation Analysis

**GOVERN (GV) - Tier 3**

**Implementation:** Risk management strategy established with documented CVSS-based prioritization, defined risk tolerances (Critical CVEs <72h MTTR, High <7d), and comprehensive security policies including SSH hardening (CIS Benchmark), TLS 1.3 minimum, and 100% security event logging. Limited by personal lab context (no stakeholder management, oversight, or enterprise integration).

**Key Controls:** Mission-aligned security objectives, criticality tiering (Tier 1: SIEM/EDR, Tier 2: Firewalls/DNS, Tier 3: Supporting services), vulnerability remediation SLAs, supply chain risk awareness through vetted open-source selection.

**IDENTIFY (ID) - Tier 4**

**Implementation:** Comprehensive automated asset discovery and continuous risk assessment across 30+ hosts and 5,000+ packages. Real-time vulnerability correlation with NVD, MITRE ATT&CK mapping, and threat intelligence integration via MISP.

**Key Controls:** Multi-platform inventory (Checkmk, Prometheus, PatchMon, Wazuh), network topology documentation, CVSS base/temporal/environmental scoring, threat intelligence feeds (CrowdSec, AlienVault OTX, abuse.ch), automated vulnerability disclosure workflows via Shuffle.

**PROTECT (PR) - Tier 4**

**Implementation:** Defense-in-depth architecture with automated patch management (PatchMon, WSUS, WUD, Watchtower), centralized identity management (Authentik SSO with MFA), and comprehensive data protection (TLS 1.3, AES-256 encryption, immutable SIEM indexes).

**Key Controls:** Certificate-based authentication (Step-CA), RBAC enforcement, least-privilege access, configuration management via IaC (Terraform, Ansible), secure software development practices, CIS Benchmark compliance audits.

**DETECT (DE) - Tier 3**

**Implementation:** Continuous monitoring with 100% network visibility, multi-source correlation (Splunk, Elastic, Wazuh, Suricata), and automated threat analysis via Cortex/MISP. Real-time alerting through Discord/email with severity-based escalation to TheHive.

**Key Controls:** Weekly OpenVAS + monthly Nessus scans, daily PatchMon checks, DNS query logging, FIM, Yara rules, MITRE ATT&CK-based threat hunting. **Gap:** Lacks ML-based anomaly detection for Tier 4 advancement.

**RESPOND (RS) - Tier 3**

**Implementation:** Documented IR procedures with 15+ TheHive playbooks, automated orchestration via Shuffle (phishing, malware, ransomware workflows), and multi-engine analysis through Cortex. Active Response capabilities via Wazuh and pfSense API for automated containment.

**Key Controls:** Incident categorization with MITRE ATT&CK mapping, forensic data collection, automated enrichment workflows, virtual patching (Safeline WAF), emergency remediation via Ansible. **Gap:** Lacks tabletop exercises and formal BC/DR drills for Tier 4 maturity.

**RECOVER (RC) - Tier 3**

**Implementation:** Backup/restore procedures with encrypted backups (AES-256), snapshot-based rollback strategies, HA DNS failover (dual Pi-hole), and documented RTO/RPO targets. Service prioritization aligns with criticality tiers.

**Key Controls:** System rebuild playbooks, service validation checklists, verification testing procedures, UPS-backed power protection. **Gap:** Requires formal BC/DR exercises and recovery plan testing for Tier 4.

### Key Achievements

- **100% Function Coverage:** All six CSF 2.0 functions implemented with documented processes and automated controls
- **Advanced Detection:** Multi-SIEM architecture (Splunk + Elastic + Wazuh) provides <5min MTTD for critical events
- **Automated Response:** Shuffle orchestration reduces MTTR by 70% compared to manual workflows
- **Risk-Based Approach:** CVSS environmental scoring integrates asset criticality and exploit maturity
- **Continuous Assessment:** Real-time security posture visibility through 20+ Grafana dashboards
- **Threat Intelligence:** MISP platform aggregates 5+ community feeds with automated IOC correlation
- **Zero Trust Principles:** SSO enforcement, MFA, certificate-based auth, network segmentation

---

## CIS Critical Security Controls v8.1 Implementation Summary

<div class="two-col-right">
  <div class="text-col">
    <p>
      This cybersecurity lab demonstrates comprehensive implementation of CIS Controls v8.1 across 18 control families. The environment achieves 93% compliance at Implementation Group 1 (IG1), 81% at IG2, and 52% at IG3, with strategic gaps primarily in areas requiring multi-user organizational structures or commercial-grade infrastructure.
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/misc/cis-controls.png" alt="CIS Controls v8.1 Logo">
      <figcaption>CIS Critical Security Controls v8.1</figcaption>
    </figure>
  </div>
</div>

### Implementation Group Compliance

**IG1 (Basic Cyber Hygiene) - 93% Compliant**

**Status:** 52 of 56 safeguards fully implemented

**Strengths:** Complete coverage of foundational controls including asset inventory (Controls 1-2), data protection (Control 3), patch management (Control 7), centralized logging (Control 8), malware defenses (Control 10), and backup/recovery (Control 11).

**Gaps:** Application allowlisting (2.5), weekly unauthorized asset reviews (1.2), comprehensive data flow diagrams (3.8), formal secure configuration policy documentation (4.1).

**IG2 (Enhanced Security) - 81% Compliant**

**Status:** 60 of 74 additional safeguards implemented

**Strengths:** Advanced monitoring capabilities exceed requirements—weekly OpenVAS scans vs quarterly requirement, 90-day log retention, dual SIEM architecture, comprehensive vulnerability management with <72h MTTR for critical CVEs. Network segmentation, encrypted communications (TLS 1.3), MFA enforcement, and automated patch management demonstrate mature security posture.

**Critical Gaps:**
- Network AAA service (12.5)
- Application/script allowlisting (2.5-2.7)
- Remote wipe capability for laptops (4.11)
- Formal penetration testing program (18.1-18.2)
- Comprehensive RBAC documentation (6.8)

**IG3 (Advanced Security) - 52% Compliant**

**Status:** 15 of 29 additional safeguards implemented

**Strengths:** Host-based IPS (Wazuh Active Response), network IPS (Suricata inline blocking), application layer filtering (SafeLine WAF), behavior-based malware detection, detailed audit logging with command-line capture.

**Gaps:** 802.1X port-level NAC (13.9), isolated admin workstation (12.8), DLP solution (3.13), mobile device containerization (4.12), formal SAST/DAST scanning (16.12), threat modeling documentation (16.14), annual penetration testing (18.5).

### Control-by-Control Analysis

**Fully Compliant Controls (100%):**
- Control 5: Account Management
- Control 7: Continuous Vulnerability Management (exceeds standards)
- Control 10: Malware Defenses
- Control 11: Data Recovery

**Mostly Compliant Controls (80-99%):**
- Control 1: Asset Inventory (99% - minor process gap)
- Control 3: Data Protection (95% - IG1/IG2 complete)
- Control 6: Access Control (90% - needs RBAC documentation)
- Control 8: Audit Log Management (98% - IG1/IG2 complete)
- Control 12: Network Infrastructure (85% - lacks AAA)
- Control 13: Network Monitoring (90% - lacks 802.1X)

**Partial Compliance (50-79%):**
- Control 2: Software Inventory (70% - allowlisting gaps)
- Control 4: Secure Configuration (75% - needs policy docs)
- Control 9: Email/Web Protection (65% - limited by homelab)
- Control 16: Application Security (60% - infrastructure focus)
- Control 18: Penetration Testing (40% - vulnerability scanning substitute)

**Limited Applicability:**
- Control 14: Security Awareness (N/A - single-user)
- Control 15: Service Provider Management (N/A - single-user)
- Control 17: Incident Response (85% - lacks multi-user elements)

### Key Achievements

- **Exceeds Scanning Requirements:** Weekly OpenVAS + monthly Nessus vs quarterly CIS baseline
- **Advanced SIEM:** Dual platform (Splunk + Elastic) with 100% security event coverage
- **Automated Patching:** Multi-platform management (PatchMon, WSUS, Watchtower, WUD)
- **Comprehensive Inventory:** 30+ hosts, 5,000+ packages, automated discovery
- **Defense-in-Depth:** Network segmentation, host/network IPS, WAF, EDR on 25+ endpoints
- **Rapid Remediation:** <72h MTTR for critical CVEs, 95% patch compliance
- **Encrypted Everything:** TLS 1.3, AES-256 backups, VPN tunnels, syslog-ng TLS

---

## ISO 27001:2022 Annex A Implementation Summary

<div class="two-col-right">
  <div class="text-col">
    <p>
      This cybersecurity lab demonstrates comprehensive implementation of ISO 27001:2022 Annex A controls across 93 requirements spanning organizational, people, physical, and technological domains. The environment achieves 77% overall coverage of applicable controls, with particularly strong implementation in technological controls (91%) and organizational security practices (71%).
    </p>
    <p>
      <strong>Overall Compliance: 77% of Applicable Controls (55 Implemented, 14 Partial)</strong>
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/misc/iso27001.png" alt="ISO 27001:2022 Logo">
      <figcaption>ISO 27001:2022 Certification</figcaption>
    </figure>
  </div>
</div>

### Control Family Analysis

**5. Organizational Controls - 71% Coverage (22/31 Applicable)**

**Implementation:** Strong foundation in security policies (A.5.1), threat intelligence (A.5.7 via MISP/CrowdSec), comprehensive asset inventory (A.5.9 tracking 5,000+ packages across 30+ hosts), encrypted data transfer (A.5.14 with TLS 1.3), centralized access control (A.5.15 via Authentik SSO), and robust incident response (A.5.24-A.5.28 with TheHive/Shuffle orchestration).

**Key Achievements:**
- **Incident Management Excellence:** 15+ documented IR playbooks, automated containment via Wazuh Active Response, sub-30-minute MTTR, forensic data collection with immutable SIEM logs
- **Business Continuity:** HA DNS failover, IaC-enabled <2hr RTO, automated bi-weekly backups, quarterly restore testing
- **Compliance Monitoring:** CIS Benchmark audits (92-98%), continuous compliance tracking via SIEM dashboards

**Gaps:**
- Formal information labeling (A.5.13) - informal only
- Complete SBOM tracking (A.5.21) - planned Trivy/Grype implementation
- Comprehensive supply chain monitoring (A.5.22) - partial dependency tracking
- Independent security reviews (A.5.35) - N/A for personal lab

**6. People Controls - 100% Coverage (2/2 Applicable)**

**Implementation:** Complete coverage of applicable controls with secure remote working (A.6.7 via Tailscale mesh VPN, MFA enforcement, TLS 1.3 encryption) and comprehensive security event reporting (A.6.8 through Discord webhooks, email notifications, TheHive case creation, multi-channel redundancy).

**Note:** Six controls (A.6.1-A.6.6) marked N/A due to single-user lab environment (no employee screening, training, or termination processes required).

**7. Physical Controls - 33% Coverage (2/6 Applicable)**

**Implementation:** Limited by residential homelab context. Implemented controls include secure storage media management (A.7.10 with encrypted backup media, USB restrictions, GPO enforcement) and secure equipment disposal (A.7.14 with documented DBAN/shred procedures, physical drive destruction).

**Partial Implementation:**
- Environmental monitoring (A.7.4) - Prometheus temperature/HVAC monitoring, no video surveillance
- Physical threat protection (A.7.5) - UPS backup, residential fire detection, environmental monitoring
- Utility redundancy (A.7.11) - Dual internet, UPS, no generator
- Equipment maintenance (A.7.13) - Hardware monitoring via Proxmox/Checkmk

**Note:** Eight controls (A.7.1-A.7.3, A.7.6-A.7.9, A.7.12) marked N/A as residential physical security controls not applicable to homelab environment.

**8. Technological Controls - 91% Coverage (29/32 Applicable)**

**Implementation:** Exceptional coverage demonstrating enterprise-grade security architecture. Comprehensive endpoint protection (A.8.1 with Wazuh EDR on 25+ endpoints), privileged access management (A.8.2 with separate admin accounts, 100% MFA), robust malware defenses (A.8.7 via Wazuh FIM, Suricata/Snort, multi-engine Cortex analysis), and advanced vulnerability management (A.8.8 with weekly OpenVAS, monthly Nessus, <72h critical MTTR).

**Key Achievements:**
- **Defense-in-Depth:** Multi-layered security with network segmentation, WAF (SafeLine), IDS/IPS (Suricata inline), host-based protection
- **Cryptographic Excellence:** TLS 1.3 mandatory, Ed25519 SSH keys, Step-CA PKI, AES-256-GCM encryption, DNSSEC, no weak algorithms
- **Comprehensive Logging:** 100% security event coverage, dual SIEM (Splunk + Elastic), 90-day retention, immutable audit trails, encrypted syslog-ng transmission
- **Configuration Management:** Ansible/Terraform IaC, Git version control, CIS Benchmark compliance (92-98%), automated drift detection
- **High Availability:** HA firewall cluster, dual Pi-hole DNS (<5s failover), dual SIEM, redundant internet, load balancing

**Partial Implementation:**
- Data leakage prevention (A.8.12) - egress filtering and monitoring without formal DLP
- Secure SDLC (A.8.25) - IaC practices with planned CI/CD security linting

**Gaps:**
- Data masking (A.8.11) - not required (no production PII processing)
- Secure coding (A.8.28) - N/A (minimal custom development)
- Outsourced development (A.8.30) - N/A (open-source reliance)

### Critical Control Highlights

**Access Control & Identity Management:**
- Centralized SSO (Authentik) with MFA enforcement (100% admin accounts)
- SSH key-based authentication with centralized management (Ansible)
- RBAC implementation, least-privilege access, privileged action logging
- Session timeout, account lockout policies, certificate-based auth (Step-CA)

**Threat Detection & Response:**
- Multi-source threat intelligence (MISP, CrowdSec, AlienVault OTX, abuse.ch)
- Automated incident orchestration (Shuffle workflows, Cortex responders)
- Real-time alerting with <5min MTTD for critical events
- Forensic data collection with chain of custody documentation

**Data Protection:**
- Encryption at rest (AES-256 backups, encrypted endpoints)
- Encryption in transit (TLS 1.3, SSH, VPN tunnels, syslog-ng TLS)
- Secure deletion procedures, 90-day log retention, immutable SIEM indexes
- Offsite backup storage with quarterly restore testing

**Network Security:**
- VLAN/subnet segmentation with firewall ACLs per segment
- Default-deny firewall policies, DMZ isolation, backend protection
- IDS/IPS (Suricata inline blocking, Snort passive, CrowdSec behavioral)
- DNS security (Pi-hole filtering 2M+ domains, DNSSEC, planned DNS-over-TLS)

### Compliance Strengths

1. **Technological Excellence:** 91% coverage with enterprise-grade implementations exceeding homelab expectations
2. **Incident Response Maturity:** Comprehensive IR capabilities with documented playbooks, automated orchestration, and forensic readiness
3. **Continuous Monitoring:** 100% visibility across infrastructure with multi-platform SIEM, real-time alerting, and automated correlation
4. **Vulnerability Management:** Weekly/monthly scanning cadence, <72h critical MTTR, 95% patch compliance, risk-based prioritization
5. **Encryption Everywhere:** Mandatory TLS 1.3, strong ciphersuites, PKI implementation, encrypted backups and transmission

---

## NIST SP 800-53 Rev 5 Implementation Summary

<div class="two-col-right">
  <div class="text-col">
    <p>
      This cybersecurity lab demonstrates comprehensive implementation of NIST SP 800-53 Rev 5 security controls across 18 control families and 324+ individual requirements. The environment achieves strong compliance in technical control families (AC, AU, IA, SC, SI) with 85%+ implementation rates, while organizational controls (PE, PS, PM) are appropriately marked N/A due to single-user homelab context.
    </p>
    <p>
      <strong>Overall Maturity: High (Technical Controls) / Moderate (Administrative Controls)</strong>
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/misc/nist-800-53.png" alt="NIST SP 800-53 Rev 5 Logo">
      <figcaption>NIST SP 800-53 Rev 5</figcaption>
    </figure>
  </div>
</div>

### Control Family Compliance Analysis

**Access Control (AC) - 90% Implementation**

**27 controls implemented/partial of 30 applicable**

Strong enforcement through Authentik SSO with MFA (100% admin accounts), SSH key-based authentication, centralized RBAC via Authentik groups and Active Directory OUs, and comprehensive session management. Privileged access monitored via SIEM with dedicated dashboards tracking all admin logins, sudo usage, and account lifecycle events. Remote access hardened with IP restrictions, Traefik middleware filtering, and Tailscale VPN integration.

**Key Achievements:** Automated account management (AC-2 series), behavioral anomaly detection via Splunk geoIP tracking, Wazuh Active Response for high-risk account disabling, role-based access enforcement across all services.

**Gaps:** Account monitoring for atypical usage (AC-2(12)) partially implemented - behavioral analysis exists but not comprehensive.

**Audit and Accountability (AU) - 100% Implementation**

**18 controls fully implemented**

Exceptional logging posture with 100% security event coverage across DNS, SSH, Traefik, patches, scans, and endpoint telemetry. Dual SIEM architecture (Splunk + Elastic) provides redundancy and specialized capabilities - Splunk for correlation/analytics, Elastic for scalability. Logs include comprehensive context (timestamp, user, source IP, action, result, SSH key fingerprints, DNS query details, Sysmon process trees). Immutable audit trails via Splunk read-only indexes and Elastic immutable streams prevent tampering. 90-day hot retention with 1-year cold storage and automated lifecycle management.

**Key Achievements:** Sub-60s alert latency (AU-5(2)), multi-source correlation across 4+ log repositories (AU-6(3)), standardized JSON/CEF formats (AU-12(2)), encrypted syslog-ng TLS transmission (AU-9).

**Assessment, Authorization, and Monitoring (CA) - 80% Implementation**

**8 controls implemented/partial of 10 applicable**

Continuous monitoring excellence with weekly OpenVAS network scans (52/year) and monthly Nessus authenticated scans (12/year) far exceeding baseline requirements. Real-time security posture dashboards via Grafana track vulnerability trends, patch compliance, and security metrics. CIS Benchmark compliance audits (92-98%) and Wazuh Security Configuration Assessment provide ongoing validation.

**Gaps:** Independent assessors (CA-2(1), CA-7(1)) N/A for homelab; formal penetration testing (CA-8) remains informal with scanning/enumeration substituting for full engagements.

**Configuration Management (CM) - 95% Implementation**

**15 controls implemented of 16 applicable**

Infrastructure-as-Code excellence via Ansible playbooks defining baselines and Terraform managing infrastructure. Git version control provides configuration history with snapshot-before-patch strategy enabling rapid rollback. CIS Benchmark baselines audited continuously with automated drift detection and remediation. Comprehensive inventory tracking 5,000+ packages across 30+ hosts via PatchMon, 50+ containers via WUD, and 25+ endpoints via Wazuh agents.

**Key Achievements:** Automated baseline verification (CM-2(2)), signed component verification (CM-14), unauthorized software detection via Nessus compliance scans and Wazuh FIM (CM-8(3)).

**Contingency Planning (CP) - 75% Implementation**

**6 controls implemented of 8 applicable**

Robust backup strategy with Proxmox automated bi-weekly backups, encrypted storage (AES-256), dual backup solutions (Proxmox Backup Server + external), and quarterly restore testing. Off-host storage provides physical separation. Infrastructure-as-Code enables rapid system rebuild with documented <2hr RTO. HA DNS failover via dual Pi-hole (<5s switchover) ensures service continuity.

**Gaps:** Formal contingency plan documentation (CP-1, CP-10) partial - procedures documented but not comprehensive enterprise plan.

**Identification and Authentication (IA) - 95% Implementation**

**17 controls implemented of 18 applicable**

Advanced authentication architecture with Step-CA two-tier PKI (offline root, online intermediate CA), Ed25519 SSH keys, Authentik SSO providing OAuth2/OIDC integration, and Vaultwarden password manager with zero-knowledge encryption and biometric unlock. MFA enforced for all administrative access via Authentik TOTP. SSH passwords disabled globally, replaced with key-based authentication. No embedded unencrypted credentials - Ansible Vault encrypts all secrets.

**Key Achievements:** Replay-resistant authentication via SSH session tokens and Authentik CSRF protection (IA-2(8)), automated PKI trust distribution (IA-5(14)), centralized authenticator management (IA-5).

**Incident Response (IR) - 90% Implementation**

**11 controls implemented of 13 applicable**

Comprehensive IR capabilities via TheHive case management with 15+ documented playbooks (phishing, malware, ransomware, lateral movement, vulnerability response), Shuffle SOAR orchestration for automated workflows, and Cortex multi-engine analysis. Wazuh Active Response provides automated containment (firewall-drop, host-deny, account disabling) with sub-30-minute MTTR. Real-time monitoring via dual SIEM with Discord/email/PagerDuty multi-channel alerting ensures zero missed notifications.

**Key Achievements:** Automated incident handling (IR-4(1)), multi-source correlation across Splunk/Wazuh/Suricata/scanners (IR-4(4)), automated tracking and forensic data collection (IR-5(1)).

**Gap:** Breach notification (IR-8(1)) partially implemented - automated alerting exists but formal notification procedures limited.

**Maintenance (MA) - 60% Implementation**

**4 controls implemented/partial of 6 applicable**

Remote maintenance via SSH fully logged and monitored with cryptographic protection (TLS 1.3, SSH AES-256-GCM). Change control enforced through Git version control, snapshot-before-patch strategy, and WSUS approval workflows. Patch SLAs defined (Critical <72h, High <7d) and tracked via TheHive.

**Gaps:** Formal maintenance policy documentation (MA-1, MA-2, MA-3) informal for homelab environment.

**Risk Assessment (RA) - 85% Implementation**

**10 controls implemented of 12 applicable**

Sophisticated vulnerability management with CVSS base + temporal + environmental scoring incorporating exploit maturity and asset criticality. Daily PatchMon checks, weekly OpenVAS scans, and monthly Nessus authenticated scans provide comprehensive coverage of 75+ assets. SIEM correlation links vulnerabilities to exploit databases. Vulnerability trends tracked in Grafana with historical MTTR calculations demonstrating continuous improvement.

**Key Achievements:** Privileged access scanning via SSH keys and domain service accounts (RA-5(5)), historical audit log review (RA-5(8)), vulnerability-to-installed software correlation (RA-5(10)), MITRE ATT&CK-based threat hunting (RA-10).

**Gaps:** Supply chain risk assessment (RA-3(1)) partial - MISP vendor tracking exists but limited visibility.

**System and Communications Protection (SC) - 95% Implementation**

**24 controls implemented of 25 applicable**

Encryption excellence with mandatory TLS 1.3, Ed25519 SSH keys, AES-256-GCM ciphersuites, and Step-CA PKI infrastructure. Defense-in-depth boundary protection via pfSense default-deny firewall rules, Traefik reverse proxy with Authentik authentication, SafeLine WAF, and Suricata/Snort IDS/IPS. DNSSEC implementation for both authoritative (Bind9) and recursive (Pi-hole/Unbound) resolution. Complete network segmentation with VLAN isolation and Traefik backend protection.

**Key Achievements:** Zero weak algorithms (verified via vulnerability scans), OCSP/CRL certificate validation (SC-17(1)), NTP synchronization across all infrastructure with sub-second accuracy (SC-45), process isolation via containers and VMs (SC-39).

**System and Information Integrity (SI) - 90% Implementation**

**25 controls implemented of 28 applicable**

Multi-layered malware defense via Wazuh FIM with VirusTotal integration, Suricata/Snort IDS signatures, ClamAV (Linux), Microsoft Defender (Windows), and Cortex multi-engine analysis. Real-time system monitoring across Prometheus, Uptime Kuma, dual SIEM, Wazuh EDR (25+ endpoints), and network IDS providing complete visibility. Automated patch management via PatchMon/WSUS/Watchtower with <72h MTTR for critical vulnerabilities. WAF input validation (SafeLine OWASP CRS rules) and Traefik header validation protect against injection attacks.

**Key Achievements:** Automated flaw remediation status tracking (SI-2(2)), real-time integrity monitoring with automated response integration (SI-7(7)), system-wide intrusion detection (SI-4(1)), host-based EDR on 25+ endpoints (SI-4(23)).

**Supply Chain Risk Management (SR) - 40% Implementation**

**4 controls implemented/partial of 12 applicable**

Limited by homelab scope with no formal supplier management program. Relies on vetted open-source projects, trusted Docker Hub publishers, and official OS repositories. Docker image signature verification (SHA-256) and package signature validation provide component authenticity (SR-11). Secure deletion procedures for component disposal (SR-12).

**Gaps:** Most SR controls (SR-1, SR-2, SR-4, SR-5, SR-6) N/A for single-user environment without procurement processes.

**Organizational Control Families (PE, PS, PM, PL, MP, MA)**

- **Personnel Security (PS):** 0% - All 8 controls N/A (no employees requiring screening, training, sanctions)
- **Physical and Environmental Protection (PE):** 0% - All 14 controls N/A (residential homelab with basic UPS/fire protection)
- **Program Management (PM):** 40% - 3 implemented (comprehensive asset inventory via PM-5, risk management strategy via PM-9, automated threat intelligence sharing via PM-16(1))
- **Planning (PL):** 60% - 4 implemented/partial (defense-in-depth architecture via PL-8, GRC documentation as security plan via PL-2)
- **Media Protection (MP):** 40% - Partial implementation (encrypted backups, secure deletion documented, removable media restrictions via GPO)

**Critical Control Highlights by Security Objective**

**Confidentiality:**
- TLS 1.3 mandatory for all services with weak ciphers disabled
- Ed25519 SSH keys with passwords disabled globally
- AES-256-GCM encryption for backups and at-rest data
- Step-CA PKI with automated certificate management
- Vaultwarden zero-knowledge password vault with biometric unlock

**Integrity:**
- Immutable SIEM audit logs (Splunk read-only indexes, Elastic immutable streams)
- Wazuh FIM real-time integrity monitoring with automated response
- Docker image SHA-256 signature verification
- Git version control for all infrastructure code
- Signed certificates via Step-CA PKI

**Availability:**
- HA firewall cluster (pfSense CARP)
- Dual Pi-hole DNS with <5s failover
- Dual SIEM deployment (Splunk + Elastic)
- Redundant internet connections
- UPS battery backup for critical systems
- Automated backups with quarterly restore testing

**Authentication:**
- Centralized SSO via Authentik with OAuth2/OIDC
- MFA enforcement (100% admin accounts via TOTP)
- SSH key-based authentication with centralized management
- Step-CA certificate-based authentication
- No hardcoded credentials (Ansible Vault encryption)

### Maturity Assessment by Control Family

**Tier 4 (Adaptive):**
- AU (Audit and Accountability) - Automated correlation, real-time alerts, immutable logs
- IA (Identification and Authentication) - PKI automation, centralized management, MFA
- SI (System and Information Integrity) - Multi-layered detection, automated response, continuous monitoring
- CM (Configuration Management) - IaC automation, drift detection, automated remediation

**Tier 3 (Defined):**
- AC (Access Control) - Documented policies, centralized enforcement, behavioral monitoring
- IR (Incident Response) - Comprehensive playbooks, SOAR orchestration, documented procedures
- RA (Risk Assessment) - Standardized scoring, historical trending, threat hunting
- SC (System and Communications Protection) - Defense-in-depth, encryption everywhere, validated controls

**Tier 2 (Managed):**
- CP (Contingency Planning) - Regular backups, restore testing, documented procedures
- CA (Continuous Assessment) - Scheduled scanning, compliance audits, gap tracking
- MA (Maintenance) - Change control, patch tracking, remote access monitoring

**Limited Applicability:**
- PE, PS, PM, PL, MP - Constrained by single-user homelab context

**Framework Strengths:**

1. **Audit Excellence:** 100% AU family implementation with immutable logs, sub-60s alerting, multi-source correlation
2. **Encryption Everywhere:** 95% SC family compliance with modern algorithms, mandatory TLS 1.3, comprehensive PKI
3. **Automated Response:** 90% IR family implementation with SOAR orchestration, <30min MTTR, multi-channel alerting
4. **Continuous Monitoring:** 90% SI family coverage with multi-layered detection, real-time FIM, EDR on 25+ endpoints
5. **Configuration Automation:** 95% CM family implementation via IaC, Git version control, automated drift detection

---

## MITRE ATT&CK Enterprise v18.1 Implementation Summary

<div class="two-col-right">
  <div class="text-col">
    <p>
      This cybersecurity lab demonstrates threat-informed defense aligned with MITRE ATT&CK Enterprise Matrix v18.1, achieving 30% overall coverage (65 of 216 techniques) across 12 adversary tactics. The implementation prioritizes high-impact techniques with strong detection capabilities in Initial Access (67%), Execution (67%), and Lateral Movement (56%), while identifying strategic gaps in Defense Evasion (21%), Credential Access (27%), and Collection (20%) that inform the security roadmap.
    </p>
    <p>
      <strong>Framework Version:</strong> ATT&CK v18.1 (October 2025) | <strong>Total Techniques:</strong> 216 | <strong>Sub-techniques:</strong> 475
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/misc/mitre-attack.png" alt="MITRE ATT&CK Framework Logo">
      <figcaption>MITRE ATT&CK Enterprise v18.1</figcaption>
    </figure>
  </div>
</div>

### Tactic-by-Tactic Analysis

**Initial Access (TA0001) - 67% Coverage (6/9 techniques)**

**Maturity: Strong**

Comprehensive monitoring via multi-layered detection: phishing analysis through Shuffle workflows with Cortex multi-engine scanning (VirusTotal, URLhaus, PhishTank), MISP IOC correlation, and Pi-hole domain blocking (2M+ malicious domains). Valid account monitoring via Splunk correlation detecting failed authentication patterns, Wazuh authentication tracking, and TheHive automated case creation (>5 failures/5min triggers). External remote service logging through pfSense VPN monitoring, SSH session tracking, and Traefik ForwardAuth auditing.

**Critical Gaps:** Supply chain compromise (T1195) requires SBOM tracking; content injection (T1659) needs CSP headers and SRI checks; trusted relationship (T1199) lacks vendor security assessments.

**Priority Actions:** Q1 2026 - Deploy SBOM tracking (Trivy/Grype); Q2 2026 - Enhance WAF rulesets for injection protection.

**Execution (TA0002) - 67% Coverage (9/13 techniques)**

**Maturity: Strong**

Exceptional process visibility via Sysmon capturing PowerShell commands (Event ID 4103/4104), Windows command shell execution with full command-line arguments, and scheduled task creation. Wazuh detects obfuscated PowerShell, LOLBins, and parent-child process anomalies. Shared module tracking via ImageLoad events identifies unsigned/untrusted DLLs with code signing validation.

**Critical Gaps:** WMI execution (T1047) has minimal event monitoring; container CLI/API (T1059.013) lacks comprehensive kubectl/docker exec logging; native API (T1106) requires endpoint detection with API hooking for process injection visibility.

**Priority Actions:** Immediate - Enable comprehensive WMI logging; Q1 2026 - Implement container command auditing (T1059.013); Q2 2026 - Deploy container runtime security (Falco).

**Persistence (TA0003) - 37% Coverage (8/20 techniques)**

**Maturity: Moderate**

Strong account lifecycle monitoring via Active Directory group membership tracking (Event ID 4728/4732/4756), account creation alerts (Event ID 4720), and behavioral analysis detecting unusual login times/geographic anomalies. Boot/logon autostart detection through Sysmon registry monitoring (Run keys), Wazuh FIM tracking startup folders and systemd units, with comprehensive persistence mechanism coverage.

**Critical Gaps:** BITS jobs (T1197) lack monitoring; browser extensions (T1176) unmonitored; Office persistence (T1137) has no macro/add-in detection; Python startup hooks (T1546.018) require FIM on .pythonrc and site-packages directories.

**Priority Actions:** Immediate - Enable BITS logging (Event ID 59/60/61); Q1 2026 - Deploy application binary monitoring; Q2 2026 - Implement browser extension inventory.

**Privilege Escalation (TA0004) - 38% Coverage (5/13 techniques)**

**Maturity: Moderate**

Comprehensive privileged account tracking via SIEM correlation detecting admin logons outside business hours, lateral movement via admin accounts, and GPO modification auditing (Event ID 5136/5137/5141). Scheduled task monitoring identifies privilege escalation through task creation with SYSTEM privileges by non-admin users.

**Critical Gaps:** Process injection (T1055) has minimal visibility into CreateRemoteThread/process hollowing/reflective DLL injection; UAC bypass (T1548) lacks comprehensive Event ID 4103 monitoring; container escape (T1611) undetected.

**Priority Actions:** Q2 2026 - Deploy advanced EDR for process injection detection; Immediate - Enhance UAC bypass monitoring.

**Defense Evasion (TA0005) - 21% Coverage (13/46 techniques)**

**Maturity: Weak - Priority Focus Area**

Strong log protection via immutable SIEM (Splunk read-only indexes, Elastic immutable streams), registry modification tracking (Sysmon Event ID 13), and security tool tampering detection (Windows Defender, firewall, antimalware services). Indicator removal monitoring alerts on Event ID 1102 (log clearing) with FIM tracking critical directory file deletions.

**Critical Gaps:** Obfuscation analysis limited (T1027); no pass-the-hash/pass-the-ticket detection (T1550); minimal alternate data stream scanning (T1564); virtualization/sandbox evasion unmonitored (T1497). **v18.1 NEW:** Delay execution (T1678), selective exclusion (T1679), browser fingerprinting (T1036.012), network device firewall tampering (T1562.013) require implementation.

**Priority Actions:** Q1 2026 - Implement pass-the-hash detection (Event ID 4624/4625 type 9); Q2 2026 - Deploy advanced obfuscation analysis with entropy/sandbox detonation.

**Credential Access (TA0006) - 27% Coverage (4/15 techniques)**

**Maturity: Weak - Critical Gap**

Excellent brute force detection via multi-source correlation (firewall, SSH, Authentik, RDP), Shuffle automated case creation (>5 failures/5min), and IP-based rate limiting. LSASS access monitoring through Sysmon Event ID 10 detects credential dumping with Mimikatz signature alerts and SAM/SYSTEM file access tracking.

**Critical Gaps:** Kerberos monitoring (T1558) absent - no golden/silver ticket detection (Event ID 4768/4769); session hijacking (T1539) undetected; password store coverage (T1555) incomplete; MFA interception (T1111) unmonitored.

**Priority Actions:** Immediate - Enable Kerberos event logging; Q1 2026 - Implement session monitoring with IP/User-Agent binding; Q2 2026 - Deploy comprehensive password store monitoring.

**Discovery (TA0007) - 30% Coverage (10/32 techniques)**

**Maturity: Moderate**

Comprehensive network reconnaissance detection via Suricata/Snort identifying port scans (SYN/UDP/full connect), ping sweeps, ARP scans with pfSense logging and Splunk pattern correlation. Command-line monitoring tracks account enumeration (net user/group, whoami, getent), file discovery (dir, ls, find), and system profiling (systeminfo, uname, hostname) with Active Directory LDAP query auditing (Event ID 4662).

**Critical Gaps:** Share enumeration (T1135) unmonitored (net view/share); password policy queries (T1201) undetected; peripheral device discovery (T1120) absent; backup software discovery (T1518.002) fully covered via process/registry monitoring; local storage discovery (T1680) needs behavioral baseline for rapid enumeration patterns.

**Priority Actions:** Q1 2026 - Implement share enumeration monitoring, enhance local storage discovery (T1680) with behavioral baseline; Q2 2026 - Add peripheral device tracking.

**Lateral Movement (TA0008) - 56% Coverage (5/9 techniques)**

**Maturity: Strong**

Excellent protocol monitoring across RDP (Suricata traffic + Event ID 4624 type 10), SMB (Event ID 5140/5145 + PsExec/WMIC detection), and SSH (comprehensive session logging + key-based auth anomaly detection). Admin share access tracking via Splunk correlation identifies lateral movement patterns with alerts on unusual RDP/SMB sources.

**Critical Gaps:** Pass-the-hash/pass-the-ticket (T1550) undetected - critical for lateral movement prevention; WinRM (T1021.006) has minimal monitoring (Event ID 6/91/168 needed); software deployment tools (T1072) unmonitored.

**Priority Actions:** Immediate - Implement pass-the-hash detection; Q1 2026 - Enable comprehensive WinRM logging.

**Collection (TA0009) - 20% Coverage (4/18 techniques)**

**Maturity: Weak - Strategic Gap**

Basic capabilities include archive detection (7zip, WinRAR, tar, zip), USB device insertion monitoring (Event ID 2003), and file access tracking in sensitive directories via Wazuh FIM. Limited data staging detection through file creation monitoring in Temp directories.

**Critical Gaps:** No DLP capabilities; email collection (T1114) unmonitored; screen/video capture undetected (T1113/T1125); input capture/keylogger detection absent (T1056); database exfiltration (T1213.006) lacks query monitoring for mass SELECT statements and large result sets.

**Priority Actions:** Q1 2026 - Implement email auditing; Q2 2026 - Deploy DLP solution and UEBA for collection pattern detection.

**Exfiltration (TA0010) - 44% Coverage (4/9 techniques)**

**Maturity: Moderate**

Strong C2 channel monitoring via Suricata/Snort detecting beacon patterns, MISP IOC correlation, and Cortex threat intelligence enrichment. DNS tunneling detection through Pi-hole query analysis, bandwidth monitoring via pfSense/Prometheus with threshold alerts for unusual upload rates.

**Critical Gaps:** Web service exfiltration (T1567) minimal - no Dropbox/Google Drive/Pastebin detection; cloud exfiltration (T1537) unmonitored; physical medium file tracking (T1052) limited beyond device insertion.

**Priority Actions:** Q1 2026 - Implement web service monitoring and physical media auditing; Q2 2026 - Deploy comprehensive DLP.

**Command & Control (TA0011) - 38% Coverage (6/16 techniques)**

**Maturity: Moderate**

Comprehensive application layer protocol analysis via Suricata/Snort for HTTP/HTTPS/DNS/SMTP patterns, pfSense logging all protocols, Traefik HTTP visibility. Dynamic resolution detection through Pi-hole DNS logging, Suricata DGA pattern recognition, fast flux identification, and MISP domain correlation. Non-standard port detection via protocol-port mismatch analysis (HTTP on 8443, SSH on 443).

**Critical Gaps:** TLS inspection limited - JA3/JA3S fingerprinting exists but no decryption; remote access tools (T1219) minimally detected (TeamViewer/AnyDesk signatures only); web service C2 (T1102) over legitimate platforms (Twitter/GitHub/Pastebin) unmonitored.

**Priority Actions:** Q1 2026 - Implement remote access tool controls; Q2 2026 - Deploy TLS inspection infrastructure and web service C2 detection.

**Impact (TA0040) - 46% Coverage (6/13 techniques)**

**Maturity: Moderate**

Exceptional ransomware detection via Wazuh mass file modification monitoring (>50 files/min), Shuffle workflows detecting file extension changes (.encrypted/.locked), ransomware note creation, with automated containment achieving sub-30-minute MTTR. Resource hijacking monitoring through Prometheus CPU/memory anomaly detection, cryptomining process identification (xmrig, cpuminer), and Checkmk infrastructure tracking.

**Critical Gaps:** Disk wipe (T1561) has minimal tool detection (diskpart, dd, shred); defacement (T1491) lacks web content integrity verification; firmware corruption (T1495) has no UEFI/BIOS monitoring.

**Priority Actions:** Q1 2026 - Implement disk modification monitoring and defacement detection; Q3 2026 - Deploy firmware integrity checks.

### ATT&CK v18.1 Framework Updates

**Impact on Lab:** v18.1 introduced 12 new techniques increasing total from 191 to 216 (13% growth) and sub-techniques from 385 to 475 (23% growth). Lab coverage decreased from 34% to 30% due to denominator expansion, highlighting new detection opportunities.

**Critical New Techniques Requiring Implementation:**

- **T1059.013** (Container CLI/API): kubectl/docker exec logging
- **T1678** (Delay Execution): Sleep/timeout command behavioral analysis
- **T1679** (Selective Exclusion): Security tool configuration monitoring
- **T1036.012** (Browser Fingerprint Masquerading): User-agent anomaly detection
- **T1562.013** (Network Device Firewall Tampering): SNMP trap monitoring
- **T1546.018** (Python Startup Hooks): FIM on .pythonrc/site-packages
- **T1213.006** (Database Exfiltration): Query monitoring, large result set detection
- **T1518.002** (Backup Software Discovery): Fully implemented via process/registry
- **T1680** (Local Storage Discovery): Behavioral baseline needed for rapid enumeration

**Threat Intelligence Updates:** MISP integration required for 7 new threat actors (Storm-0501, UNC3886, Contagious Interview, Medusa, Water Galura, AppleJeus, G1049) and 7 new malware families (RedLine Stealer, Qilin/Medusa Ransomware, DarkGate, Havoc C2, Embargo, InvisibleFerret).

### Coverage Strengths

1. **Multi-Layered Detection:** Dual SIEM (Splunk + Elastic), network IDS (Suricata/Snort), host EDR (Wazuh 25+ endpoints), 100% security event logging
2. **Automated Response:** Shuffle SOAR orchestration, TheHive case management, Wazuh Active Response, sub-30-minute MTTR for critical threats
3. **Threat Intelligence:** MISP correlation, Cortex multi-engine analysis, CrowdSec community feeds, AlienVault OTX
4. **Process Visibility:** Sysmon comprehensive telemetry, command-line auditing, parent-child analysis, LOLBin detection
5. **Network Monitoring:** Complete visibility via pfSense flow logs, Traefik access logs, DNS query logging, 100% traffic coverage

---

## OWASP Top 10 (2025) Implementation Summary

<div class="two-col-right">
  <div class="text-col">
    <p>
      This cybersecurity lab demonstrates comprehensive mitigation of OWASP Top 10 (2025) web application security risks, achieving strong coverage across 9 of 10 categories with advanced maturity levels. The implementation leverages defense-in-depth architecture combining WAF protection (SafeLine with OWASP CRS rules), secure authentication (Authentik SSO with MFA), cryptographic excellence (TLS 1.3, Step-CA PKI), and comprehensive logging (100% security event coverage with 90-day retention).
    </p>
    <p>
      <strong>Overall OWASP 2025 Compliance: 9/10 Strong | 1/10 Moderate (Supply Chain)</strong>
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/misc/owasp.png" alt="OWASP Top 10 Logo">
      <figcaption>OWASP Top 10 (2025)</figcaption>
    </figure>
  </div>
</div>

### 2025 Framework Changes

OWASP Top 10 (2025) introduces significant updates from the 2021 version: **A10 (Mishandling of Exceptional Conditions)** replaces Server-Side Request Forgery as a new category addressing 24 CWEs related to improper error handling and failing open. **A01 (Broken Access Control)** now encompasses SSRF within access control failures. Categories A04, A05, and A06 have shifted rankings reflecting improved industry practices in cryptographic implementation and secure design.

### Category-by-Category Analysis

**A01:2025 - Broken Access Control (Strong - Advanced Maturity)**

**Coverage:** Comprehensive access control enforcement across all service layers

**Implementation:** Authentik ForwardAuth mandates authentication for all Traefik-routed services with OAuth2/OIDC integration and RBAC group-based authorization. SSH access exclusively key-based (passwords disabled globally) with sudo policy enforcement. Network-level protection via Traefik IP allowlisting, pfSense default-deny firewall ACLs per VLAN, and comprehensive egress filtering. **SSRF Prevention** achieved through DNS rebinding protection, Traefik backend validation, SSH tunnel restrictions, and network segmentation isolating internal services.

**Monitoring:** Wazuh tracks unauthorized access attempts with SIEM correlation, Splunk authentication dashboard provides real-time visibility, and TheHive automatically creates cases for access violations.

**Framework Alignment:** NIST AC-3 (Access Enforcement), AC-2(7) (Role-Based Schemes), SC-7 (Boundary Protection); ISO 27001 A.5.15 (Access Control), A.9.2 (User Access Management); CIS Control 6.1-6.6 (Access Control Management); PCI-DSS 8.2 (User Authentication).

**A02:2025 - Security Misconfiguration (Strong - Advanced Maturity)**

**Coverage:** Hardened baseline configurations with automated compliance verification

**Implementation:** CIS Benchmark compliance (92-98%) across SSH, Traefik, DNS, and firewall configurations enforced via Ansible playbooks and Terraform IaC. Configuration drift detection through Wazuh SCA and automated remediation workflows. Traefik security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) protect against common attacks. Default credentials eliminated and validated via authenticated Nessus scans. Unnecessary services disabled with minimal attack surface verified weekly (OpenVAS) and monthly (Nessus authenticated scans).

**Continuous Auditing:** Weekly vulnerability scanning, monthly authenticated configuration audits, real-time drift detection with automated alerts.

**Framework Alignment:** NIST CM-6 (Configuration Settings), CM-2 (Baseline Configuration), CM-7 (Least Functionality); ISO 27001 A.8.9 (Configuration Management); CIS Control 4.1 (Secure Configuration); PCI-DSS 2.2 (Configuration Standards).

**A03:2025 - Software Supply Chain Failures (Moderate - Developing Maturity)**

**Coverage:** Partial implementation with strategic gaps identified

**Implementation:** Vetted software sources exclusively (official Docker images, maintained open-source projects from trusted repositories). Package signature verification via GPG keys, container image verification (SHA-256), and coordinated patch management across platforms (PatchMon for Linux, WSUS for Windows, Watchtower for containers). MISP threat intelligence tracks vendor compromise campaigns. Vulnerability-driven update prioritization with rollback capability via snapshots.

**Critical Gaps:** SBOM tracking not implemented (planned Trivy/Grype deployment Q1 2026); CI/CD security linting absent; dependency vulnerability scanning incomplete; automated CVE monitoring for dependencies limited.

**Priority Actions:** Q1 2026 - Deploy Trivy/Grype for SBOM generation; Q2 2026 - Implement CI/CD pipeline security scanning; Q3 2026 - Establish comprehensive dependency monitoring.

**Framework Alignment:** NIST RA-5 (Vulnerability Monitoring), SI-2 (Flaw Remediation), SR-3 (Supply Chain Controls); ISO 27001 A.5.21 (Supply Chain Security); CIS Control 16.5 (Up-to-Date Software), 7.3-7.4 (Patch Management); OWASP SCVS.

**A04:2025 - Cryptographic Failures (Strong - Advanced Maturity)**

**Coverage:** Modern cryptographic implementations with automated management

**Implementation:** 

**Encryption in Transit:** TLS 1.3 mandatory across all services (Traefik), SSH AES-256-GCM, VPN encryption (WireGuard/OpenVPN), DNS-over-TLS planned. 

**Encryption at Rest:** AES-256 encrypted backups, SSH private key encryption, database encryption where applicable. 

**Key Management:** Step-CA two-tier PKI (offline root, online intermediate CA) with automated certificate issuance and renewal, Ed25519 SSH key generation, centralized key management via Ansible, Vaultwarden zero-knowledge secrets management. Modern cipher suites only with weak algorithm detection via vulnerability scans achieving zero certificate expiry incidents.

**Monitoring:** Certificate expiry monitoring (Uptime Kuma, Prometheus alerts), TLS configuration validation (Nessus), weak cipher detection with automated remediation.

**Framework Alignment:** NIST SC-8 (Transmission Confidentiality), SC-12 (Key Establishment), SC-13 (Cryptographic Protection), SC-28 (Protection at Rest); ISO 27001 A.8.24 (Cryptography); CIS Control 13.10 (Encryption); PCI-DSS 4.2.1 (Strong Cryptography).

**A05:2025 - Injection (Strong - Advanced Maturity)**

**Coverage:** Multi-layered injection prevention with WAF and input validation

**Implementation:** SafeLine WAF deploys OWASP Core Rule Set (CRS) with 25% attack block rate, Traefik middleware stack provides header injection prevention, NGINX Ingress annotations enforce request filtering. DNS query validation prevents DNS-based attacks, SSH input sanitization blocks command injection, parameterized queries and ORM usage in applications prevent SQL injection. Content Security Policy (CSP) headers, X-XSS-Protection headers, input sanitization, and output encoding mitigate XSS attacks.

**Monitoring:** Suricata IDS signatures detect injection attempts, WAF logs forwarded to SIEM, Splunk correlation identifies attack patterns, TheHive case creation for confirmed attacks with automated response workflows.

**Framework Alignment:** NIST SI-10 (Information Input Validation), SI-4(23) (Host-Based Detection); ISO 27001 A.8.26 (Application Security Requirements); CIS Control 13.10 (Web Application Filtering); PCI-DSS 6.6 (Web Application Protection); OWASP Injection Prevention.

**A06:2025 - Insecure Design (Strong - Advanced Maturity)**

**Coverage:** Threat-informed architecture with defense-in-depth principles

**Implementation:** Defense-in-depth architecture with multiple security layers (network, application, endpoint), DNS 3-tier design, reverse proxy isolation (Traefik backend protection), network segmentation via VLANs. Zero-trust network access principles enforce explicit verification, least-privilege access, and assume breach mentality. Infrastructure as Code enables immutable infrastructure with declarative configuration. Fail-secure defaults include SSH passwords disabled, Traefik secure configurations, default encryption, and least-privilege by default.

**Documentation:** Architecture diagrams maintained in Git, security controls documented in GRC framework, design decisions recorded, threat model updates for new services.

**Framework Alignment:** NIST RA-3 (Risk Assessment), SA-8 (Security Engineering Principles), SA-17 (Developer Security Architecture); ISO 27001 A.14.1 (Security in Development), A.14.2 (Security in Support Processes); OWASP Secure Design Principles.

**A07:2025 - Authentication Failures (Strong - Advanced Maturity)**

**Coverage:** Robust authentication with MFA enforcement and credential protection

**Implementation:** 

**Multi-Factor Authentication:** Authentik TOTP enforced for 100% administrative accounts, SSH key-based authentication only (passwords disabled globally), Step-CA certificate-based authentication for services. 

**Credential Management:** Vaultwarden zero-knowledge password vault with biometric unlock, Ansible Vault encrypts all variables, no hardcoded credentials, centralized SSH key management. 

**Account Protection:** SSH MaxAuthTries=3, Authentik lockout after 5 failures, Wazuh Active Response for brute force attacks, CrowdSec automated IP blocking. Session management via Authentik tokens, SSH session IDs, TLS session tickets with 30-minute idle timeout.

**Monitoring:** Failed login tracking across all systems, multi-source brute force correlation (firewall, SSH, Authentik, RDP), MFA bypass attempt detection, Splunk admin login dashboard.

**Framework Alignment:** NIST IA-2(1) (MFA), IA-5(1) (Password-Based Authentication), IA-5(7) (No Embedded Credentials), AC-7 (Unsuccessful Logon Attempts); ISO 27001 A.5.17 (Authentication Information), A.9.4.2 (Secure Log-on); CIS Control 6.3-6.5 (MFA); PCI-DSS 8.3 (Multi-Factor Authentication).

**A08:2025 - Software/Data Integrity Failures (Strong - Advanced Maturity)**

**Coverage:** Comprehensive integrity verification with immutable audit trails

**Implementation:** 

**Code Integrity:** Git version control for all infrastructure code, commit signing planned, Terraform plan review before apply, Infrastructure as Code validation via Ansible dry-run. 

**Software Verification:** Package signature verification (GPG), container image verification (SHA-256), Step-CA certificate validation, DNSSEC for DNS integrity. 

**Data Integrity:** Wazuh FIM monitors 100% of critical paths, checksum verification, immutable SIEM indexes (Splunk read-only, Elastic immutable streams), database integrity checks.

**Change Control:** Snapshot-before-patch strategy, WSUS approval workflows, pre-scan snapshots for critical systems, Git version control with rollback capability.

**Framework Alignment:** NIST SI-7 (Software/Firmware/Information Integrity), SI-7(1) (Integrity Checks), CM-3 (Configuration Change Control); ISO 27001 A.12.1.2 (Change Control), A.12.3.1 (Information Backup); CIS Control 2.3 (Authorized Software), 8.6 (Collect Detailed Audit Logs).

**A09:2025 - Security Logging & Alerting Failures (Strong - Advanced Maturity)**

**Coverage:** Comprehensive logging with real-time multi-channel alerting

**Implementation:** 

**100% Security Event Coverage:** DNS queries (Pi-hole), SSH sessions (auth.log), Traefik access logs (JSON format), Wazuh security events, vulnerability scans, patch deployments, authentication attempts, privileged operations. 90-day hot retention with 1-year cold storage. 

**Log Protection:** Immutable SIEM indexes, encrypted transmission (syslog-ng TLS), write-once Elasticsearch indexes, tamper detection, centralized storage.

**Real-Time Alerting:** Discord webhooks, Splunk scheduled alerts, Wazuh Discord/email integration, Prometheus Alertmanager, TheHive case notifications, Cortex analysis alerts, MISP event notifications, Shuffle orchestration actions. Multi-channel redundancy ensures zero missed critical alerts with <3% false positive rate.

**Correlation:** Multi-source correlation (Splunk + Elastic + Wazuh + network logs), TheHive aggregates alerts from all platforms, Shuffle orchestrates cross-platform queries, MITRE ATT&CK mapping for threat context.

**Framework Alignment:** NIST AU-2 (Event Logging), AU-6(3) (Correlate Audit Repositories), AU-9 (Protection of Audit Information), SI-4(5) (System-Generated Alerts); ISO 27001 A.8.15 (Logging), A.8.16 (Monitoring); CIS Control 8.2 (Collect Audit Logs), 8.11 (Conduct Reviews); PCI-DSS 10.2 (Audit Logging), 10.5 (Protect Audit Trails).

**A10:2025 - Mishandling of Exceptional Conditions (Strong - Advanced Maturity)**

**NEW CATEGORY FOR 2025**

**Coverage:** Fail-secure design with comprehensive error handling

**Implementation:** 

**Error Handling:** Traefik circuit breakers prevent cascading failures, graceful degradation maintains core functionality, fail-secure defaults (firewall default-deny), proper exception handling in automation scripts. 

**Input Validation:** Boundary checking, type validation, range checking, malformed request handling across all service entry points. 

**Fail-Secure Design:** pfSense default-deny firewall rules, Traefik rejects invalid requests, SSH connection limits, services fail-closed on errors rather than open.

**Resource Management:** Connection limits (SSH MaxStartups, Traefik connection pools), timeout configurations, rate limiting (API gateways), Kubernetes resource quotas, memory/CPU limits enforced. 

**Monitoring:** Service health checks (Uptime Kuma), Prometheus alerting for service failures, Grafana anomaly dashboards, Pulse hypervisor monitoring, application error rate tracking, Wazuh service failure monitoring.

**Recovery:** Automatic service restarts (systemd, Kubernetes health check-based recovery), documented recovery procedures, backup integrity monitoring.

**Framework Alignment:** NIST SC-5 (Denial of Service Protection), SC-24 (Fail in Known State), CP-10 (System Recovery), SI-4 (System Monitoring); ISO 27001 A.17.1 (Availability); CIS Control 13.3 (Deploy Network-Based IDS); OWASP Error Handling Best Practices.

### Compliance Summary

| OWASP 2025 Category | Maturity | Key Strengths | Strategic Gaps |
|---------------------|----------|---------------|----------------|
| A01: Broken Access Control | Advanced | Authentik SSO, MFA 100%, RBAC, SSRF prevention | Session recording for privileged access |
| A02: Security Misconfiguration | Advanced | 92-98% CIS compliance, IaC automation, drift detection | Container configuration scanning |
| A03: Supply Chain Failures | Developing | Trusted sources, signature verification, coordinated patching | SBOM tracking, dependency scanning, CI/CD security |
| A04: Cryptographic Failures | Advanced | TLS 1.3, Ed25519, Step-CA PKI, automated cert renewal | Full disk encryption rollout |
| A05: Injection | Advanced | WAF 25% block rate, CSP headers, parameterized queries | Advanced ML-based injection detection |
| A06: Insecure Design | Advanced | Zero-trust architecture, threat modeling, defense-in-depth | Formal threat modeling for all services |
| A07: Authentication Failures | Advanced | MFA enforcement, key-based auth, no hardcoded credentials | WebAuthn/FIDO2 implementation |
| A08: Integrity Failures | Advanced | FIM 100% critical paths, immutable logs, Git version control | Automated code signing |
| A09: Logging & Alerting | Advanced | 100% event coverage, <60s alert latency, immutable logs | SIEM correlation ML enhancement |
| A10: Exceptional Conditions | Advanced | Fail-secure defaults, health monitoring, auto-recovery | Chaos engineering validation |

---

## Zero Trust Architecture Implementation Summary

<div class="two-col-right">
  <div class="text-col">
    <p>
      This cybersecurity lab demonstrates comprehensive Zero Trust Architecture (ZTA) principles aligned with <strong>CISA Zero Trust Maturity Model v2.0</strong> and <strong>NIST Special Publication 800-207</strong>. The implementation achieves <strong>Advanced maturity</strong> across all core pillars through explicit verification of every access request, least-privilege enforcement via role-based access control, assume-breach mentality with continuous monitoring, and encrypt-everything policies using modern cryptographic standards.
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/misc/zero-trust.png" alt="Zero Trust Architecture Logo">
      <figcaption>Zero Trust Architecture</figcaption>
    </figure>
  </div>
</div>

### Architecture Highlights

**Core Capabilities**

- **Identity-Centric Security**: Authentik SSO with phishing-resistant MFA (TOTP current, FIDO2/WebAuthn planned), OAuth2/OIDC integration, 30-minute session timeouts
- **Device Trust**: Wazuh agents on 25+ endpoints with CIS Benchmark compliance (92-98%), automated vulnerability assessment, configuration drift detection
- **Network Segmentation:** Multiple subnets (DMZ, Prod, Lab, Isolated LANs) with micro-perimeters, TLS 1.3 mandatory encryption, service-specific isolation
- **Application Protection**: SafeLine WAF with 25% attack block rate, Traefik ForwardAuth validation, OAuth2 scope-based least privilege
- **Data Security:** AES-256 encryption at rest/transit, automated lifecycle management, sensitivity-based classification (Public/Internal/Confidential/Restricted)
- **Continuous Monitoring:** Dual SIEM (Splunk + Elastic) ingesting 100% security events, real-time correlation, behavioral analytics, 90-day hot retention

### CISA Zero Trust Maturity Model v2.0 Alignment

The CISA ZTMM defines four maturity stages across five core pillars (Identity, Devices, Networks, Applications & Workloads, Data) with three cross-cutting capabilities (Visibility & Analytics, Automation & Orchestration, Governance). This lab demonstrates Advanced-stage implementation across all pillars with targeted progression toward Optimal maturity.

**Maturity Stage Definitions:**

- **Traditional:** Manual configurations, static policies, siloed enforcement, limited correlation
- **Initial:** Starting automation, cross-pillar integration, aggregated visibility, responsive least privilege
- **Advanced:** Automated controls, centralized visibility, cross-pillar coordination, risk-based least privilege, pre-defined mitigations
- **Optimal:** Fully automated just-in-time lifecycles, dynamic policies, comprehensive situational awareness, cross-pillar interoperability

#### Five Core Pillars - Advanced Maturity Achieved

**Identity (Advanced):** Phishing-resistant MFA with FIDO2/PIV implementation underway; consolidated identity stores (Authentik SSO + Active Directory); automated risk assessment via Splunk behavioral analytics; need-based session access with 30-minute expiration; automated user orchestration with manual privileged account management; enterprise-wide identity policies with quarterly reviews.

**Devices (Advanced):** Verified compliance insights via Wazuh agents (25+ endpoints) and Nessus authenticated scans; automated asset tracking (5,000+ packages, 50+ containers); device-aware access control integrated with Authentik ForwardAuth; centralized threat protection (Wazuh EDR, ClamAV, Microsoft Defender); automated inventory with anomaly detection; enterprise-wide lifecycle policies with automated enforcement mechanisms.

**Networks (Advanced):** 3-tier architecture with VLAN micro-segmentation and ingress/egress micro-perimeters; dynamic traffic management with periodic risk-aware application profile adjustments; full encryption (TLS 1.3, SSH AES-256-GCM, VPN) with cryptographic agility planning; HA firewall cluster with dual SIEM/DNS providing resilience; anomaly-based detection with multi-source correlation and automated threat hunting; automated change management via Terraform/Ansible IaC.

**Applications & Workloads (Advanced):** Automated access decisions with contextual enforcement (identity, device, IP, time); integrated threat protections (SafeLine WAF 25% block rate, Suricata/Snort signatures, rate limiting); most mission-critical applications publicly accessible via Cloudflare Tunnels with mandatory authentication; distinct dev/sec/ops teams with restricted production access; integrated security testing (OpenVAS, Nessus, OWASP ZAP); automated monitoring with trend analysis via Prometheus/Grafana; tiered enterprise-wide policies with automated enforcement.

**Data (Advanced):** Automated enterprise-wide inventory with egress filtering and bandwidth monitoring (DLP deployment Q2 2026); automated categorization with sensitivity tiers and quarterly reviews; redundant highly-available storage with 90-day hot/1-year cold retention; automated access controls considering identity, device risk, application context with time limits; full encryption at rest/transit (AES-256, TLS 1.3) with protected key management; enterprise-wide visibility with correlation and initial predictive analytics; primarily automated lifecycle enforcement; integrated policy enforcement with unified definitions.

#### Three Cross-Cutting Capabilities

**Visibility and Analytics (Advanced):** Automated enterprise-wide collection including virtual environments; centralized multi-source correlation via dual SIEM (Splunk + Elastic); 100% security event logging with real-time correlation detecting multi-stage attacks; behavioral baselines with anomaly detection; 20+ Grafana dashboards tracking vulnerabilities, patch compliance, authentication patterns, and threat indicators.

**Automation and Orchestration (Advanced):** Enterprise-wide automated orchestration/response leveraging contextual information; Shuffle SOAR with 15+ playbooks integrating TheHive, Cortex, MISP; Wazuh Active Response with sub-30-minute MTTR; Infrastructure-as-Code (Terraform, Ansible) with version control; automated patch management across platforms (PatchMon, WSUS, Watchtower); Step-CA automated certificate lifecycle with 90-day rotation.

**Governance (Advanced):** Tiered tailored policies enterprise-wide with automation support; contextual access decisions incorporating multiple sources; documented version-controlled policies (Git) with quarterly reviews; automated compliance reporting via Wazuh SCA; vulnerability remediation SLAs enforced (Critical <72h, High <7d); configuration management with automated drift detection; policy exceptions requiring documented compensating controls.

#### Zero Trust Maturity Assessment

| Pillar | Maturity Level | Evidence | Next Steps |
|--------|----------------|----------|-----------|
| Identity | Advanced | Authentik SSO 100% coverage, MFA enforcement, certificate-based auth | WebAuthn/FIDO2, biometric authentication |
| Device | Advanced | Wazuh compliance monitoring, Step-CA certificates, endpoint inventory | MDM/Device posture assessment, EDR expansion |
| Network/Environment | Advanced | Microsegmentation, 3-tier architecture, IDS/IPS | Software-defined perimeter (SDP) |
| Application/Workload | Advanced | Container security, API gateway, WAF protection | Service mesh (Istio), runtime protection |
| Data | Advanced | Encryption everywhere, DLP planning, data classification | Full DLP deployment, data tagging |
| Visibility & Analytics (Cross-Cutting) | Advanced | 100% logging, dual SIEM, 90-day retention | ML-based analytics, UEBA deployment |
| Automation & Orchestration (Cross-Cutting) | Developing | SOAR workflows, automated response, enrichment | Advanced ML, predictive analytics |
| Governance (Cross-Cutting) | Limited | Documented version-controlled policies (Git); automated compliance reporting via Wazuh SCA | Fully automated policies, dynamic updates, threat intel-driven policy creation |

**Overall ZTA Maturity: Advanced (6 of 8 pillars at Advanced level)**

### NIST SP 800-207 Zero Trust Architecture Alignment

#### Deployment Model

**Hybrid Approach:**

- **Device Agent/Gateway:** Authentik + Traefik for web services, SSH certificates for terminal access, Wazuh agents for compliance
- **Enclave Gateway:** pfSense/OPNsense protecting network perimeters, dedicated VLANs for service tiers
- **Resource Portal:** Traefik reverse proxy for BYOD/contractor access without client agents

**Trust Algorithm:** Hybrid score-based and criteria-based with contextual evaluation considering subject history, device posture, environmental factors, and real-time threat intelligence.

#### Maturity Assessment by Pillar

**Identity (Advanced)**

**Strengths:** Phishing-resistant MFA, centralized SSO (90% coverage), automated risk assessment with behavioral analytics, session-based least privilege, comprehensive event logging

**Evidence:** Authentik OAuth2/OIDC integration across 50+ services, MFA enforcement logs, Splunk credential compromise detection, quarterly access reviews

**Enhancements Needed:** Full FIDO2/WebAuthn deployment, automated privileged identity orchestration, continuous risk scoring with real-time policy updates, just-in-time access for all accounts

**Devices (Advanced)**

**Strengths:** Real-time compliance validation (92-98%), automated asset tracking (NetalertX, Checkmk), device-aware access control, centralized threat protection (Wazuh EDR), anomaly detection

**Evidence:** Wazuh agent deployment 25+ endpoints, Nessus authenticated scans, PatchMon vulnerability tracking 5,000+ packages, automated quarantine workflows

**Enhancements Needed:** Complete SBOM tracking (Trivy/Grype Q1 2026), fully automated provisioning/remediation/deprovisioning, real-time risk analytics informing access, unified advanced threat protection

**Networks (Advanced)**

**Strengths:** Micro-perimeter isolation with 3-tier architecture, TLS 1.3 + modern ciphers mandatory, HA failover (<5 sec), 100% traffic visibility, automated change management via IaC

**Evidence:** VLAN segmentation per service, pfSense CARP cluster, Step-CA 90-day cert rotation, Traefik ForwardAuth on all paths, Terraform/Ansible IaC version control

**Enhancements Needed:** Fully distributed micro-perimeters, dynamic just-in-time connectivity, continuously evolving rules without manual updates, comprehensive situational awareness

**Applications & Workloads (Advanced)**

**Strengths:** Automated contextual access decisions, integrated WAF protection (OWASP CRS), most services publicly accessible with strong controls, distinct dev/sec/ops, periodic security testing

**Evidence:** OAuth2 device compliance checks, SafeLine WAF 25% block rate, Traefik security headers, OWASP ZAP/Burp Suite testing, immutable container workloads

**Enhancements Needed:** Continuous real-time authorization with behavioral patterns, advanced content-aware protections, immutable workloads with automated redeployment, CI/CD security testing (Q2 2026)

**Data (Advanced)**

**Strengths:** Automated enterprise-wide inventory, consistent tiered classification, redundant highly-available storage (dual SIEM, backup replication), multi-attribute access controls, full encryption at rest/transit

**Evidence:** Filesystem monitoring 30+ hosts, dual SIEM 90-day hot/1-year cold retention, sensitivity tiers with handling requirements, AES-256 encryption, quarterly classification reviews

**Enhancements Needed:** Dynamic DLP with exfiltration blocking (formal deployment Q2 2026), fully automated categorization, just-in-time data access, encryption-in-use where appropriate, robust predictive analytics

**Cross-Cutting Capabilities**

**Visibility & Analytics (Advanced)**

**Implementation:** Dual SIEM architecture (Splunk + Elastic), 100% security event coverage, multi-source correlation detecting multi-stage attacks, behavioral baselines, 20+ Grafana dashboards

**Gap to Optimal:** Machine learning/UEBA for predictive analytics, comprehensive cloud log integration, advanced automated threat hunting, situational awareness for all externally-hosted resources

**Automation & Orchestration (Advanced)**

**Implementation:** Shuffle SOAR with 15+ playbooks, Wazuh Active Response (sub-30-min MTTR), IaC via Terraform/Ansible, automated patch management (PatchMon, WSUS, Watchtower), Step-CA certificate automation

**Gap to Optimal:** Predictive analytics triggering proactive response, full privileged identity automation, automated mitigation deployment without manual approval, dynamic adaptation to environmental changes

**Governance (Advanced)**

**Implementation:** Tiered policies enterprise-wide with automation support, version-controlled policies (Git), CIS Benchmark enforcement via Wazuh SCA, vulnerability SLAs (Critical <72h, High <7d), quarterly reviews

**Gap to Optimal:** Fully automated policies with continuous enforcement, dynamic updates without manual intervention, automated policy creation from threat intelligence, real-time adjustments to environmental changes

#### Key Technologies Deployed

| Category | Technologies | Maturity |
|----------|-------------|----------|
| Identity & Access | Authentik SSO, OAuth2/OIDC/SAML, Step-CA PKI, MFA (TOTP, FIDO2 planning) | Advanced |
| Endpoint Security | Wazuh EDR (25+ agents), ClamAV, Microsoft Defender, CIS Benchmark SCA | Advanced |
| Network Security | pfSense/OPNsense HA cluster, Suricata/Snort IDS, Traefik reverse proxy, SafeLine WAF | Advanced |
| Vulnerability Mgmt | Nessus, PatchMon (5,000+ packages), OpenVAS, OWASP ZAP, Burp Suite | Advanced |
| SIEM & Analytics | Splunk, Elastic Stack, Grafana, Prometheus, Wazuh correlation | Advanced |
| Orchestration | Shuffle SOAR (15+ playbooks), TheHive case mgmt, Cortex analysis, MISP threat intel | Advanced |
| Infrastructure | Proxmox virtualization, Docker containers, Terraform, Ansible, Git version control | Advanced |
| Encryption | TLS 1.3, AES-256-GCM, Ed25519, WireGuard, syslog-ng TLS, Vaultwarden secrets | Advanced |
| Monitoring | Uptime Kuma (50+ monitors), Checkmk, NetalertX, Pi-hole DNS, Prometheus exporters | Advanced |

#### Compliance & Standards Alignment

**Framework Coverage:**

- **CISA ZTMM v2.0:** Advanced (Stage 3/4) across all 5 pillars + 3 cross-cutting capabilities
- **NIST SP 800-207:** Comprehensive implementation of all 7 ZT tenets, mature logical component deployment
- **NIST SP 800-53:** AC-2/AC-3, IA-2/IA-4/IA-5, SC-7/SC-8, SI-2/SI-3/SI-4, CM-8, AU-2/AU-6, IR-4
- **CIS Controls:** 5.1-6.8 (Identity), 1.1-2.7/4.1-4.12/10.1-10.7 (Devices), 12.1-13.10 (Networks), 16.1-18.5 (Applications), 3.1-11.5 (Data)
- **ISO 27001:** A.5.15-5.18 (Identity), A.5.9/A.8.1/A.8.7-8.8/A.8.19 (Assets), A.8.20-8.23 (Networks), A.8.26/A.14.1-14.2 (Applications), A.5.12/A.5.14/A.5.33/A.8.10/A.8.24 (Data)
- **PCI-DSS:** 8.1-8.3 (Identity), 2.4/5.1-5.2/6.4.3/11.5 (Devices), 1.1-1.4/4.2 (Networks), 6.4-6.6 (Applications), 3.1-3.7/10.5-10.7 (Data)
- **OWASP Top 10:** A07 (Authentication), A02/A03 (Devices), A04 (Networks), A01/A05/A06/A08 (Applications), A04/A09 (Data)

#### Zero Trust Tenets Achievement

| NIST SP 800-207 Tenet | Status | Implementation Evidence |
|----------------------|--------|------------------------|
| 1. All resources explicitly defined | ✓ Advanced | 25+ hosts, 50+ containers, 30+ VMs tracked; NetalertX discovery, Proxmox inventory |
| 2. Communication secured regardless of location | ✓ Advanced | TLS 1.3 mandatory, no implicit network trust, Authentik validates all requests |
| 3. Per-session least privilege access | ✓ Advanced | 30-min timeouts, OAuth2 scopes, temporary sudo, session-based authorization |
| 4. Dynamic policy from observable state | ✓ Advanced | Device compliance + identity + behavior + threat intel inform access decisions |
| 5. Asset integrity monitoring | ✓ Advanced | Wazuh CIS compliance, Nessus scans, PatchMon 5,000+ packages, drift detection |
| 6. Dynamic authentication/authorization | ✓ Advanced | MFA enforcement, continuous session evaluation, threat-triggered re-auth |
| 7. Comprehensive telemetry collection | ✓ Advanced | Dual SIEM, 100% event logging, multi-source correlation, policy optimization |

---

## PCI-DSS v4.0 Conceptual Alignment Summary

<div class="two-col-right">
  <div class="text-col">
    <p>
      This cybersecurity lab demonstrates conceptual alignment with PCI-DSS v4.0 requirements through defense-in-depth security controls, comprehensive logging, strong cryptography, and continuous vulnerability management. While the lab processes no actual cardholder data (CHD) or sensitive authentication data (SAD), the security architecture implements PCI-DSS technical and operational controls as a learning framework demonstrating compliance-ready capabilities.
    </p>
    <p>
      <strong>PCI-DSS v4.0 Conceptual Compliance: 85% (Technical Controls Implemented)</strong>
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/misc/pci-dss.png" alt="PCI-DSS v4.0 Logo">
      <figcaption>PCI-DSS v4.0</figcaption>
    </figure>
  </div>
</div>

### PCI-DSS v4.0 (Conceptual Alignment)

**Build and Maintain a Secure Network and Systems**

**Requirement 1: Install and Maintain Network Security Controls**

**Implementation: Strong**

**1.1.1 - Network Segmentation Documented:** Network topology diagrams maintained in Git repository documenting 3-tier architecture (DMZ, application tier, backend), VLAN segmentation strategy, firewall rulesets per segment, data flow diagrams showing cardholder data environment (CDE) boundaries (conceptual).

**1.2.1 - Restrict Inbound/Outbound Traffic:** pfSense/OPNsense default-deny firewall policies with explicit allow rules, egress filtering prevents unauthorized outbound connections, Traefik ingress controller restricts inbound access to authorized services only, CrowdSec behavioral blocking for anomalous traffic patterns.

**1.3.1 - DMZ Implementation:** DMZ isolates public-facing services (Traefik reverse proxy, public DNS) from internal networks, firewall ACLs enforce traffic restrictions between DMZ and internal zones, backend services unreachable from DMZ without explicit routing through application tier.

**1.4.2 - Restrict Public Internet Access:** Internal services isolated from direct internet access, Cloudflare Tunnels and Tailscale VPN provide secure remote access without exposing internal IPs, firewall rules block all inbound traffic except explicitly allowed services, NAT gateway controls outbound internet access.

**Framework Alignment:** NIST SC-7 (Boundary Protection), ISO 27001 A.8.20-8.22 (Network Security), CIS Control 12.1-12.4 (Network Infrastructure Management).

**Requirement 2: Apply Secure Configurations to All System Components**

**Implementation: Strong**

**2.2.2 - Configuration Standards:** CIS Benchmark compliance (92-98%) for SSH, firewalls, DNS, web servers validated via Nessus authenticated scans and Wazuh SCA. Ansible playbooks enforce configuration baselines with version control in Git. Unnecessary services disabled, default accounts removed, security parameters hardened.

**2.2.4 - System Security Parameters:** SSH hardening (CIS Benchmark): root login disabled, password authentication disabled, key-only access, MaxAuthTries=3. Traefik secure defaults: HSTS enabled, secure headers (CSP, X-Frame-Options), TLS 1.3 minimum. pfSense hardening: default-deny policies, anti-spoofing, state tracking.

**Framework Alignment:** NIST CM-6 (Configuration Settings), ISO 27001 A.8.9 (Configuration Management), CIS Control 4.1-4.12 (Secure Configuration).

**Protect Account Data**

**Requirement 4: Protect Cardholder Data with Strong Cryptography**

**Implementation: Strong**

**4.2.1 - Strong Cryptography for Transmission:** TLS 1.3 mandatory across all services via Traefik reverse proxy with modern cipher suites (AES-256-GCM, ChaCha20-Poly1305), SSH connections encrypted with AES-256-GCM, VPN encryption (WireGuard with ChaCha20, OpenVPN with AES-256), syslog-ng TLS for encrypted log transmission, DNSSEC for DNS query integrity.

**4.2.1 - Strong Cryptography at Rest:** Encrypted backups (AES-256) via Proxmox Backup Server, SSH private keys encrypted with passphrases, database encryption where applicable, Vaultwarden zero-knowledge vault encryption, Ansible Vault encrypts sensitive configuration variables.

**Framework Alignment:** NIST SC-8/SC-13/SC-28 (Cryptographic Protection), ISO 27001 A.8.24 (Cryptography), CIS Control 13.10 (Encryption), OWASP A04 (Cryptographic Failures).

**Maintain a Vulnerability Management Program**

**Requirement 6: Develop and Maintain Secure Systems and Software**

**Implementation: Strong**

**6.3.3 - Security Patches Within One Month:** Multi-platform patch management achieves <7-day MTTR for high-severity vulnerabilities, <72-hour MTTR for critical CVEs exceeding PCI-DSS one-month requirement. PatchMon tracks 5,000+ packages across 30+ hosts with daily compliance checks. WSUS manages Windows patching with automated approvals. Watchtower auto-updates containers. Vulnerability-driven prioritization via CVSS scoring.

**6.4.3 - Inventory of System Components:** Comprehensive asset inventory via PatchMon (5,000+ packages), WUD (50+ containers), OpenVAS asset database (75+ assets), Nessus software inventory, Wazuh agent tracking (25+ endpoints), DNS records, SSH host keys, Checkmk infrastructure inventory, Prometheus node exporters, NetalertX network discovery.

**Framework Alignment:** NIST SI-2 (Flaw Remediation), RA-5 (Vulnerability Monitoring), ISO 27001 A.8.8 (Vulnerability Management), CIS Control 7.3-7.7 (Continuous Vulnerability Management).

**Implement Strong Access Control Measures**

**Requirement 8: Identify Users and Authenticate Access**

**Implementation: Strong**

**8.2.1 - Unique User IDs:** Individual user accounts across all systems via Authentik SSO, Active Directory, and SSH key infrastructure. No shared credentials - each administrator maintains separate privileged account. User account inventory tracked in Authentik database and AD with SIEM correlation identifying orphaned accounts.

**8.2.2 - Strong User Authentication:** SSH key-based authentication exclusively (passwords disabled globally) using Ed25519 cryptographic keys, Authentik enforces password complexity requirements (14-char minimum for non-MFA, 8-char for MFA accounts), password managers (Vaultwarden) enforce unique passwords across services.

**8.2.3 - Multi-Factor Authentication for Remote Access:** MFA enforced for 100% of administrative accounts via Authentik TOTP, SSH remote access secured with key-based authentication (inherently multi-factor: possession of private key + knowledge of passphrase), VPN access (Tailscale) requires device authentication, MFA bypass attempts monitored via Wazuh.

**8.2.5 - No Shared/Group Accounts:** Strict prohibition on shared credentials enforced via Authentik policies and AD group policies. Separate admin accounts for privileged operations. Service accounts documented in inventory with ownership tracking and quarterly reviews.

**8.3.2 - Strong Cryptography for Authentication Data:** SSH private keys encrypted, Authentik credentials stored in Vaultwarden with zero-knowledge encryption, Ansible Vault encrypts all secrets (passwords, API keys, certificates), no hardcoded credentials in code or configuration files.

**Framework Alignment:** NIST AC-2/IA-2/IA-5 (Account and Authentication Management), ISO 27001 A.5.16-5.18 (Identity and Authentication), CIS Control 5.1-6.6 (Account and Access Management), OWASP A07 (Authentication Failures).

**Regularly Monitor and Test Networks**

**Requirement 10: Log and Monitor All Access to System Components and Cardholder Data**

**Implementation: Strong**

**10.2 - Audit Logs for Security Events:** 100% security event coverage including: DNS queries (Pi-hole), SSH sessions (auth.log), Traefik access logs (JSON format), vulnerability scans, patch deployments, authentication attempts, privileged operations, service modifications, account changes, firewall events, IDS alerts, file integrity changes.

**10.3 - Audit Record Details:** Logs include comprehensive context: timestamp (NTP synchronized), user identity, source IP address, action performed, result (success/failure), SSH key fingerprints, DNS query details, HTTP request/response data, Sysmon process telemetry with parent-child relationships.

**10.5 - Protect Audit Logs:** Immutable SIEM indexes (Splunk read-only, Elastic immutable streams) prevent tampering, encrypted log transmission via syslog-ng TLS, centralized storage in dual SIEM architecture, 90-day hot retention with 1-year cold storage, access controls restrict log modification, file integrity monitoring on log directories.

**10.6 - Review Logs and Security Events:** Weekly Splunk dashboard reviews, automated correlation searches detect anomalies, real-time alerting via Discord/email for critical events, Wazuh monitors security events continuously, TheHive aggregates alerts for case management, multi-source correlation identifies attack patterns.

**Framework Alignment:** NIST AU-2/AU-3/AU-6/AU-9/AU-12 (Audit and Accountability), ISO 27001 A.8.15-8.16 (Logging and Monitoring), CIS Control 8.1-8.11 (Audit Log Management), OWASP A09 (Logging & Alerting Failures).

**Requirement 11: Test Security of Systems and Networks Regularly**

**Implementation: Strong**

**11.3.1 - External/Internal Vulnerability Scans Quarterly:** Weekly OpenVAS network scans (52/year) plus monthly Nessus authenticated scans (12/year) exceed quarterly PCI-DSS requirement. Daily PatchMon package vulnerability checks provide continuous assessment. Wazuh Security Configuration Assessment (SCA) performs real-time compliance validation. Scans cover 75+ assets across all network segments.

**11.3.2 - Vulnerability Scans by Qualified Personnel:** Scanning infrastructure operated by qualified security professional (lab owner) with documented vulnerability management process, CVSS-based prioritization methodology, risk-based remediation strategy, quarterly reviews of scan results, documented exceptions and compensating controls.

**11.4.1 - Implement IDS/IPS:** Suricata inline IDS/IPS on all network segments with real-time blocking capability, Snort passive IDS for additional detection, CrowdSec behavioral IPS with community threat intelligence, Wazuh host-based IDS on 25+ endpoints with FIM and rootkit detection.

**11.4.2 - Keep IDS/IPS Updated:** Daily signature updates for Suricata/Snort (Emerging Threats, abuse.ch), CrowdSec community feed synchronization, Wazuh ruleset updates, MISP threat intelligence integration provides IOC updates, Yara signature updates for malware detection.

**Framework Alignment:** NIST RA-5 (Vulnerability Monitoring), CA-2/CA-7/CA-8 (Security Assessment), SI-4 (System Monitoring), ISO 27001 A.8.8 (Vulnerability Management), CIS Control 7.1-7.7 (Vulnerability Management), 13.1-13.8 (Network Monitoring).

### PCI-DSS Compliance Summary

| Requirement Domain | Compliance Level | Key Controls | Gaps/Limitations |
|-------------------|------------------|--------------|------------------|
| 1. Network Security | Strong (95%) | Segmentation, DMZ, default-deny, ACLs | Formal network diagrams need PCI annotation |
| 2. Secure Configuration | Strong (92-98%) | CIS Benchmarks, IaC, drift detection | Container configuration scanning |
| 4. Cryptography | Strong (100%) | TLS 1.3, AES-256, Ed25519, Step-CA PKI | Full disk encryption deployment |
| 6. Vulnerability Management | Strong (95%) | <72h Critical MTTR, weekly/monthly scans | Formal pen testing program |
| 8. Access Control | Strong (100%) | Unique IDs, MFA 100% admin, no shared accounts | WebAuthn/FIDO2 implementation |
| 10. Logging & Monitoring | Strong (100%) | 100% coverage, 90-day retention, immutable logs | SIEM ML enhancement |
| 11. Testing | Strong (100%) | Weekly/monthly scans, IDS/IPS, daily updates | Annual external pen test |

**Overall PCI-DSS v4.0 Conceptual Compliance: 85% (Technical Controls Implemented)**

**Note:** As a personal homelab processing no cardholder data, formal PCI-DSS certification is not required. Implementation demonstrates compliance-ready technical controls suitable for production CDE deployment with appropriate governance additions (policies, procedures, formal assessments, QSA validation).

---

## Comprehensive Framework Alignment Matrix

| Security Domain | NIST CSF 2.0 | CIS v8.1 | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | OWASP 2025 | MITRE ATT&CK v18.1 | CISA ZTMM v2.0 | NIST SP 800-207 |
|-----------------|--------------|----------|----------------|-------------------|--------------|------------|-------------------|----------------|-----------------|
| Asset Management | ID.AM-01 to ID.AM-08 | 1.1-1.5, 2.1-2.4 | A.5.9, A.8.1 | CM-8, CM-8(1)-(3), PM-5 | 2.4, 6.4.3 | N/A | T1018, T1046, T1135 | Devices: Advanced | Tenet 1: Resource Inventory |
| Network Segmentation | PR.AC, DE.CM | 12.1-12.4, 13.4 | A.8.20, A.8.22 | SC-7, SC-7(21) | 1.1.1, 1.3.1 | A01 (SSRF), A06 | N/A | Networks: Advanced | Tenet 2: Micro-segmentation |
| Firewall Management | PR.AC, SC-7 | 12.1-12.2 | A.8.20 | SC-7, SC-7(5) | 1.2.1, 1.4.2 | A02 | N/A | Networks: Advanced | Tenet 2: Boundary Protection |
| Firewall HA | PR.IR-01, RC.RP | 12.1, 12.2 | A.8.14, A.8.20 | CP-9, SC-7(20), SI-4(1) | 1.1.1, 1.3.7 | N/A | N/A | Networks: Advanced | Tenet 7: Resilience |
| DMZ Architecture | PR.IR, SC-7 | 12.2 | A.8.20, A.8.22 | SC-7(21) | 1.3.1 | A06 | N/A | Networks: Advanced | Tenet 2: Isolation |
| Network Monitoring | DE.CM | 13.1-13.6 | A.8.16, A.8.20 | SI-4, SI-4(1)(4) | 11.4.1, 11.4.2 | A09 | T1046, T1049, T1590 | Visibility: Advanced | Tenet 7: Comprehensive Telemetry |
| IDS/IPS | DE.CM-01, DE.AE-02 | 13.1-13.3, 13.6-13.8 | A.8.7, A.8.16, A.8.20 | SI-4, SI-4(1)(2)(5) | 11.4.1, 11.4.2 | N/A | T1046, T1595 | Visibility: Advanced | Tenet 7: Monitoring |
| WAF Protection | DE.CM, RS.MI | 13.10 | A.8.23, A.8.26 | SI-4(23), SI-10, SC-7(11) | 6.6 | A01, A05 (Injection) | T1190, T1659 | Apps: Advanced | Tenet 4: Policy Enforcement |
| VPN/Remote Access | PR.AC, PR.DS-02 | 12.3, 12.7, 13.10 | A.5.14, A.6.7, A.8.21 | AC-17, AC-17(1)(2)(4), SC-8, SC-13 | 4.1, 8.2.3, 12.3 | N/A | T1133 | Identity: Advanced | Tenet 2: Location Independence |
| Access Control & Authorization | PR.AA, PR.AC | 6.1-6.6 | A.5.15, A.5.18, A.8.3 | AC-2, AC-3, AC-6 | 7.1, 7.2, 8.1 | A01 (Broken Access Control) | T1078, T1098, T1087 | Identity: Advanced | Tenet 3: Least Privilege |
| RBAC Implementation | AC-3(7), PR.AA | 6.8 | A.5.18, A.8.3 | AC-2(7), AC-3(7) | 7.1.2 | A01 | T1078 | Identity: Advanced | Tenet 3: Role-Based Access |
| Least Privilege | AC-6, PR.AA | 5.4, 6.1-6.6 | A.5.18 | AC-6, AC-6(1)(2)(5) | 7.1.1 | A01, A06 | T1548 | Identity: Advanced | Tenet 3: Least Privilege |
| SSRF Prevention | PR.AC, DE.CM | 12.3, 13.10 | A.8.20, A.8.21 | SC-7, SI-10 | 6.6 | A01 | N/A | Networks: Advanced | Tenet 4: Policy Enforcement |
| SSO Implementation | IA-2(10), PR.AA | 6.6-6.7 | A.5.15, A.8.5 | IA-2(10) | 8.2.1 | A07 (Authentication) | T1078 | Identity: Advanced | Tenet 3: Centralized Identity |
| MFA Enforcement | IA-2(1), PR.AA-01 | 6.3-6.5 | A.5.17, A.8.5 | IA-2(1)(2) | 8.2.3, 8.3.1 | A07 | T1078, T1111 | Identity: Advanced | Tenet 6: Phishing-Resistant MFA |
| SSH Key Management | IA-5(2), PR.AA | 5.6, 6.7 | A.5.17, A.8.24 | IA-5(2), IA-5(14) | 8.3.2 | A07 | T1552, T1078 | Identity: Advanced | Tenet 6: Certificate-Based Auth |
| Account Lockout | AC-7, PR.AA | 6.3 | A.9.4.2 | AC-7 | 8.2.4, 8.2.5 | A07 | T1110 | Identity: Advanced | Tenet 6: Automated Protection |
| Session Management | AC-12, SC-23 | 6.3 | A.8.5 | AC-2(5), AC-11, AC-12, SC-23 | 8.1.8 | A07 | T1539, T1563 | Identity: Advanced | Tenet 3: Session-Based Access |
| Password Management | IA-5(1), PR.DS | 5.2, 6.2 | A.5.17 | IA-5(1), IA-5(18) | 8.2.2, 8.3.2 | A07 | T1555, T1552 | Identity: Advanced | Tenet 6: Strong Authentication |
| Credential Protection | IA-5(7), PR.DS | 3.11, 6.7 | A.5.17, A.8.24 | IA-5(7), IA-5(18), SC-28(3) | 3.5, 3.6, 8.3.2 | A07, A08 | T1003, T1555, T1552 | Data: Advanced | Tenet 6: Credential Encryption |
| Active Directory | PR.AA-01, AC-2 | 5.3, 5.6, 6.1, 6.8 | A.5.16, A.8.2 | AC-2, AC-3(7), IA-2, IA-4, IA-5 | 8.2, 8.3 | A07 | T1087, T1482 | Identity: Advanced | Tenet 3: Centralized Directory |
| Secrets Management | PR.DS-01, IA-5(7) | 3.11, 5.2, 6.7 | A.5.17, A.8.24 | IA-5(7), IA-5(18), SC-12, SC-28(3) | 3.5, 3.6, 8.2.1 | A07, A08 | T1552, T1555 | Data: Advanced | Tenet 6: Zero-Knowledge Vault |
| PKI/Certificate Management | PR.DS-10, SC-17 | 3.12, 16.14 | A.8.24 | SC-12, SC-13, SC-17, SC-17(1), IA-5(14) | 4.2.1 | A04 (Cryptography) | N/A | Identity: Advanced | Tenet 6: Automated PKI |
| TLS/Encryption (Transit) | PR.DS-02, SC-8 | 3.10, 12.6, 13.10 | A.8.24 | SC-8, SC-8(1), SC-13 | 4.2.1 | A04 | N/A | Data: Advanced | Tenet 2: Encrypt All Communications |
| Encryption at Rest | PR.DS-01, SC-28 | 3.11 | A.8.24 | SC-28, SC-28(1)(3) | 3.4, 4.2.1 | A04 | N/A | Data: Advanced | Tenet 2: Protect Data at Rest |
| Key Management | SC-12, PR.DS | 3.12, 6.7 | A.8.24 | SC-12, SC-13 | 4.2.1 | A04 | N/A | Data: Advanced | Tenet 6: Protected Key Storage |
| DNSSEC | SC-20, PR.DS | 9.2, 12.6 | A.8.21, A.8.23 | SC-20, SC-20(2), SC-21 | 2.2.5 | A04 | N/A | Networks: Advanced | Tenet 2: DNS Integrity |
| DNS Security | PR.DS, DE.CM | 9.2, 12.6 | A.8.21, A.8.23 | SC-20, SC-20(2), SC-21 | 2.2.5 | N/A | T1071.004, T1568 | Networks: Advanced | Tenet 7: DNS Monitoring |
| Configuration Management | PR.PS-01, CM-2 | 4.1-4.12, 16.7 | A.8.9, A.8.32 | CM-2, CM-3, CM-6, CM-6(1), CM-7 | 2.2.2, 2.2.4 | A02 (Misconfiguration) | T1547, T1112 | Devices: Advanced | Tenet 5: Asset Integrity |
| Baseline Hardening | CM-6, PR.IP | 4.1-4.7 | A.8.9 | CM-6, CM-6(1) | 2.2.2, 2.2.4 | A02 | N/A | Devices: Advanced | Tenet 5: Security Baselines |
| Configuration Drift Detection | CM-6(1), PR.PS | 4.1 | A.8.9 | CM-3, CM-6(1) | 2.2.4 | A02 | T1562.001 | Devices: Advanced | Tenet 5: Automated Monitoring |
| IaC/Automation | PR.PS-01, CM-2(2) | 4.1-4.2, 16.1, 16.7, 18.1 | A.5.8, A.5.37, A.8.9, A.8.32 | CM-2(2)(3), CM-3, CM-9 | 6.4.5, 11.6.1 | A02, A08 | N/A | Automation: Advanced | Tenet 5: Immutable Infrastructure |
| Default Credentials | IA-5(1), CM-6 | 4.7, 5.2 | A.5.17 | IA-5(1) | 2.2.3, 8.2.2 | A02, A07 | T1078 | Identity: Advanced | Tenet 6: No Default Credentials |
| Security Headers | SC-8, PR.DS | 9.2, 13.10 | A.8.21, A.8.26 | SC-8, SI-10 | 6.6 | A02, A05 | N/A | Apps: Advanced | Tenet 4: Defense in Depth |
| Vulnerability Management | ID.RA-01 to ID.RA-08, PR.IP, DE.CM-09 | 7.1-7.7 | A.8.8 | RA-3, RA-5, RA-5(2)(3)(5)(8)(10) | 6.3.1, 11.3.1 | N/A | T1190, T1210 | Devices: Advanced | Tenet 5: Continuous Assessment |
| Vulnerability Scanning | RA-5, DE.CM-09 | 7.5-7.6 | A.8.8, A.12.6.1 | RA-5, RA-5(2)(3)(5) | 11.3.1, 11.3.2 | N/A | N/A | Devices: Advanced | Tenet 5: Automated Scanning |
| Patch Management | SI-2, PR.PS-03 | 7.3-7.4, 12.1 | A.8.8, A.8.19 | SI-2, SI-2(2)(4)(6), CM-8 | 6.3.3 | N/A | T1068, T1210 | Devices: Advanced | Tenet 5: Rapid Remediation |
| SBOM/Supply Chain | GV.SC, ID.RA | 15.1-15.7, 16.4-16.5 | A.5.19-5.22 | SR-3, SR-11, SA-10 | 12.8.1-12.8.5 | A03 (Supply Chain) | T1195, T1199 | Governance: Developing | Tenet 5: Component Verification |
| Software Verification | CM-14, SI-7 | 2.3, 16.11 | A.8.32 | SI-7(6), CM-14, SR-11 | 6.3.2 | A03, A08 | T1195, T1553 | Devices: Advanced | Tenet 5: Signature Validation |
| Dependency Tracking | GV.SC-02, ID.RA | 16.4 | A.5.21 | SR-3, SA-10 | 12.8.5 | A03 | T1195 | Governance: Developing | Tenet 5: SBOM Management |
| Logging/Monitoring | DE.CM, DE.AE, AU-2 | 8.1-8.11, 13.1, 13.6 | A.8.15, A.8.16 | AU-2, AU-3, AU-6, AU-6(1)(3)(5), AU-12 | 10.2, 10.3, 10.6 | A09 (Logging & Alerting) | T1070, T1562.002 | Visibility: Advanced | Tenet 7: Comprehensive Telemetry |
| Log Protection | AU-9, DE.CM | 8.9, 8.10 | A.8.15 | AU-9, AU-11, SI-12 | 10.5.1 | A09 | T1070, T1562.002 | Visibility: Advanced | Tenet 7: Immutable Logs |
| Real-Time Alerting | DE.AE-06, RS.CO, SI-4(5) | 8.11, 13.1, 17.2, 17.6 | A.6.8, A.8.16 | AU-5(2), SI-4(5)(12), IR-6(1) | 10.6, 12.10 | A09 | N/A | Visibility: Advanced | Tenet 7: Automated Alerts |
| Alert Correlation | DE.AE, AU-6(3) | 8.11, 13.6 | A.8.16 | AU-6(1)(3)(5), SI-4(16) | 10.6 | A09 | N/A | Visibility: Advanced | Tenet 7: Cross-Pillar Correlation |
| Time Synchronization | DE.CM, AU-8 | 8.4 | A.8.17 | AU-8, SC-45, SC-45(1) | 10.4 | N/A | N/A | Visibility: Advanced | Tenet 7: Synchronized Timestamps |
| Malware Defenses | DE.CM-04, SI-3 | 10.1-10.7 | A.8.7 | SI-3, SI-3(4)(10), SI-7 | 5.1, 5.2 | N/A | T1204, T1566 | Devices: Advanced | Tenet 5: Threat Protection |
| Antivirus/EDR | SI-3, DE.CM | 10.1-10.2, 13.2 | A.8.7 | SI-3, SI-3(4), SI-4(23) | 5.1, 5.2 | N/A | T1562.001 | Devices: Advanced | Tenet 5: Endpoint Detection |
| File Integrity Monitoring | SI-7, SI-7(1) | 10.1, 13.2 | A.8.7, A.8.16 | SI-7(1)(6)(7), AU-9 | 11.5 | A08 (Data Integrity) | T1070, T1565 | Devices: Advanced | Tenet 5: Change Detection |
| Data Protection | PR.DS, ID.AM-07 | 3.1-3.14 | A.5.12, A.5.14, A.5.33, A.5.34, A.8.10 | SC-28, MP-6, MP-4 | 3.1-3.7, 4.1-4.2 | A04 | T1005, T1025 | Data: Advanced | Tenet 2: Encrypt Everything |
| Data Classification | PR.DS, GV.PO | 3.7, 3.12 | A.5.12 | MP-3, RA-2 | 3.1 | N/A | N/A | Data: Advanced | Tenet 4: Sensitivity-Based Controls |
| DLP | PR.DS, DE.CM | 3.13 | A.8.12 | SC-7, SI-4 | 3.4 | N/A | T1020, T1030, T1048 | Data: Developing | Tenet 4: Egress Monitoring |
| Backup/Recovery | RC.RP, RC.HL, CP-9 | 11.1-11.5 | A.5.29, A.5.30, A.8.13, A.8.14 | CP-9, CP-9(1)(3)(8), CP-10 | 12.10.1 | N/A | T1490, T1486 | Data: Advanced | Tenet 7: Resilience |
| Business Continuity | RC.RP, CP-2 | 11.1-11.5 | A.5.29, A.5.30, A.17.1 | CP-2, CP-6, CP-7 | 12.10 | N/A | N/A | Governance: Advanced | Tenet 7: Service Continuity |
| Incident Response | RS.AN, RS.CO, RS.MA, RS.MI | 17.1-17.9 | A.5.24-5.28, A.6.8 | IR-4, IR-4(1)(4), IR-5, IR-5(1), IR-6, IR-7, IR-8 | 12.10 | N/A | All Tactics | Automation: Advanced | Tenet 6: Automated Response |
| SOAR Platform | RS.AN, RS.MI, IR-4(1) | 17.1-17.9 | A.5.24, A.5.25, A.5.26 | IR-4(1), IR-5(1), IR-6(1), AU-6(1)(5) | 12.10 | N/A | All Tactics | Automation: Advanced | Tenet 6: Orchestrated Workflows |
| Threat Intelligence | ID.RA-02, DE.AE-07 | 7.1, 16.4 | A.5.7 | PM-16(1), RA-3(1), SI-4(18) | 11.3.1 | N/A | T1592-T1597 | Visibility: Advanced | Tenet 7: Contextual Enrichment |
| Threat Hunting | DE.CM, RA-10 | 13.6 | A.8.16 | RA-10, SI-4(16) | 11.4 | N/A | All Tactics | Visibility: Advanced | Tenet 7: Proactive Detection |
| Phishing Detection | ID.RA-02, DE.AE-02 | 9.2, 17.1 | A.5.7, A.5.24 | SI-3, SI-4, IR-4 | 11.4, 12.10 | N/A | T1566 | Apps: Advanced | Tenet 4: Email Security |
| Brute Force Detection | DE.CM, AC-7 | 6.3-6.5, 8.11 | A.5.17, A.8.5 | AC-7, SI-4(5) | 8.2.4, 8.2.5 | A07 | T1110 | Identity: Advanced | Tenet 6: Automated Lockout |
| Credential Dumping Detection | DE.CM, SI-4(23) | 10.1, 13.2 | A.8.7 | SI-4(23), AU-6 | 10.6, 11.4 | N/A | T1003 | Devices: Advanced | Tenet 5: LSASS Protection |
| Process Monitoring | DE.CM, AU-12 | 10.1, 13.2 | A.8.16 | SI-4(23), AU-12 | 10.2, 10.6 | N/A | T1059, T1106 | Devices: Advanced | Tenet 5: Execution Telemetry |
| PowerShell Logging | DE.CM, AU-12 | 8.8, 10.1 | A.8.15 | AU-3(1), SI-4 | 10.2.7 | N/A | T1059.001 | Devices: Advanced | Tenet 5: Script Auditing |
| Registry Monitoring | DE.CM, CM-6(1) | 4.1, 8.11 | A.8.9, A.8.16 | CM-6(1), SI-7(1) | 2.2.4, 10.6 | A02, A08 | T1112, T1547 | Devices: Advanced | Tenet 5: Persistence Detection |
| Service Creation Detection | DE.CM, CM-8(3) | 4.8, 10.1 | A.8.1, A.8.16 | SI-4, AU-12 | 10.2, 11.5 | N/A | T1543, T1569 | Devices: Advanced | Tenet 5: Service Monitoring |
| Scheduled Task Monitoring | DE.CM, AU-12 | 7.1, 8.11 | A.8.16 | SI-4, AU-12 | 10.2, 10.6 | N/A | T1053 | Devices: Advanced | Tenet 5: Task Auditing |
| Account Monitoring | AC-2(4), DE.CM | 5.1, 6.1, 8.11 | A.5.16, A.8.16 | AC-2(4)(12), AU-12 | 8.1.2, 10.2.5 | A01, A07 | T1136, T1098 | Identity: Advanced | Tenet 3: Lifecycle Tracking |
| Privilege Escalation Detection | AC-6(9), DE.CM | 5.4, 6.5, 8.11 | A.8.2, A.8.18 | AC-6(9), SI-4 | 7.1, 10.2 | A01 | T1548, T1134 | Identity: Advanced | Tenet 3: Anomaly Detection |
| LSASS Protection | IA-5, SI-3(10) | 5.2, 10.1 | A.5.17, A.8.7 | IA-5(7), SI-3(10) | 8.2.1 | A07 | T1003 | Identity: Advanced | Tenet 6: Memory Protection |
| Lateral Movement Detection | DE.CM, SI-4(16) | 12.3, 13.1-13.3 | A.8.16, A.8.20 | SI-4(1)(16), AU-6(3) | 10.6, 11.4 | N/A | T1021, T1080 | Visibility: Advanced | Tenet 7: Cross-Host Correlation |
| RDP/SMB/SSH Monitoring | AC-17(1), DE.CM | 12.3, 12.7, 13.6 | A.6.7, A.8.16 | AC-17(1), SI-4(4) | 8.3, 10.2 | N/A | T1021.001-.004 | Identity: Advanced | Tenet 2: Remote Session Tracking |
| Network Scanning Detection | DE.CM, SI-4(1) | 13.1-13.3, 18.1 | A.8.16, A.8.20 | SI-4(1)(4), CA-8 | 11.3, 11.4 | N/A | T1046, T1018 | Networks: Advanced | Tenet 7: Reconnaissance Detection |
| Port Scan Detection | DE.CM, SI-4(1) | 13.1, 13.3 | A.8.16, A.8.20 | SI-4(1)(4) | 11.4 | N/A | T1046 | Networks: Advanced | Tenet 7: Anomaly Detection |
| C2 Beacon Detection | DE.CM, SI-4(18) | 13.1, 13.6 | A.5.7, A.8.16 | SI-4(18), IR-4(4) | 10.6, 11.4 | N/A | T1071, T1095 | Visibility: Advanced | Tenet 7: Traffic Analysis |
| DNS Tunneling Detection | DE.CM, SI-4 | 8.6, 9.2, 13.6 | A.8.16, A.8.21 | SC-20, SC-21, SI-4 | 10.6 | N/A | T1071.004, T1048.003 | Networks: Advanced | Tenet 7: DNS Analysis |
| DGA Detection | DE.CM, SI-4 | 9.2, 13.6 | A.8.16, A.8.23 | SC-20(2), SI-4 | 10.6 | N/A | T1568 | Networks: Advanced | Tenet 7: Behavioral Analysis |
| Proxy Detection | DE.CM, SC-7 | 12.3, 13.10 | A.8.20, A.8.21 | SC-7(8), SI-4 | 1.3, 10.6 | N/A | T1090 | Networks: Advanced | Tenet 7: Proxy Monitoring |
| Ransomware Detection | DE.CM, IR-4(1) | 10.1, 11.1-11.5 | A.5.24, A.8.7 | IR-4(1), SI-3(10) | 12.10 | N/A | T1486 | Automation: Advanced | Tenet 6: Automated Containment |
| Cryptomining Detection | DE.CM, SI-4 | 10.1, 13.2 | A.8.7, A.8.16 | SI-4, AU-6 | 10.6, 11.4 | N/A | T1496 | Devices: Advanced | Tenet 5: Resource Monitoring |
| Data Exfiltration Detection | DE.CM, SI-4(4) | 13.6 | A.8.12, A.8.16 | SI-4(4), SC-7 | 10.6 | N/A | T1020, T1041 | Data: Developing | Tenet 4: Egress Detection |
| USB Device Monitoring | MP-7, DE.CM | 11.2.5 | A.7.10, A.8.16 | MP-2, MP-7, SI-4 | 9.6 | N/A | T1091, T1052 | Devices: Advanced | Tenet 5: Removable Media Control |
| Web Shell Detection | DE.CM, SI-3 | 13.10, 16.7 | A.8.7, A.8.26 | SI-3, SI-10 | 6.6, 11.4 | A05 | T1505 | Apps: Advanced | Tenet 4: Web Application Security |
| WMI Monitoring | DE.CM, AU-12 | 8.8, 10.1 | A.8.16 | SI-4, AU-12 | 10.2 | N/A | T1047, T1546.003 | Devices: Developing | Tenet 5: WMI Auditing |
| Container Security | SC-39, DE.CM | 16.1-16.14 | A.8.27 | SC-39, CM-7 | 6.4.3 | N/A | T1059.013, T1610, T1611 | Apps: Developing | Tenet 4: Workload Isolation |
| Log Tampering Detection | AU-9, SI-7 | 8.9, 8.10 | A.8.15 | AU-9, SI-7 | 10.5 | A09 | T1070, T1562.002 | Visibility: Advanced | Tenet 7: Immutable Audit |
| Obfuscation Detection | DE.CM, SI-3(10) | 10.1, 13.2 | A.8.7 | SI-3(10), SI-4(18) | 5.2, 11.4 | A05 | T1027, T1140 | Devices: Developing | Tenet 5: Entropy Analysis |
| Pass-the-Hash Detection | IA-2, DE.CM | 6.3, 8.11 | A.5.17, A.8.16 | IA-2(1), SI-4 | 8.3, 10.2 | A07 | T1550.002 | Identity: Developing | Tenet 6: Credential Replay Detection |
| Kerberos Monitoring | IA-2, DE.CM | 6.1, 8.11 | A.5.17, A.8.16 | IA-2, SI-4 | 8.2, 10.2 | A07 | T1558 | Identity: Developing | Tenet 6: Ticket Analysis |
| DLL Injection Detection | SI-3, DE.CM | 10.1, 13.2 | A.8.7 | SI-3, SI-7 | 5.2, 11.5 | N/A | T1055 | Devices: Developing | Tenet 5: Injection Detection |
| Browser Extension Monitoring | DE.CM, CM-8 | 9.4, 16.1 | A.8.1 | CM-8, SI-4 | 6.5.4 | N/A | T1176 | Apps: Developing | Tenet 4: Extension Inventory |
| Input Validation | SI-10, PR.DS | 13.10, 16.7 | A.8.26 | SI-10 | 6.5 | A05 (Injection Prevention) | T1659 | Apps: Advanced | Tenet 4: Boundary Checking |
| SQL Injection Prevention | SI-10, PR.PS | 16.7 | A.8.26, A.14.2 | SI-10, SA-11 | 6.5.1 | A05 | N/A | Apps: Advanced | Tenet 4: Parameterized Queries |
| XSS Prevention | SI-10, PR.DS | 9.2, 13.10 | A.8.23, A.8.26 | SI-10 | 6.5.7 | A05 | N/A | Apps: Advanced | Tenet 4: Output Encoding |
| Command Injection Prevention | SI-10, PR.PS | 16.7 | A.8.26 | SI-10 | 6.5 | A05 | T1059 | Apps: Advanced | Tenet 4: Input Sanitization |
| Secure Architecture | PL-8, RA-3 | 12.2, 16.1 | A.8.27, A.14.1 | SA-8, SA-17, PL-8 | 6.4 | A06 (Insecure Design) | N/A | Governance: Advanced | Tenet 4: Security by Design |
| Threat Modeling | RA-3, PL-8 | 16.14, 18.1 | A.14.1, A.14.2 | SA-8, RA-3 | 6.3.1 | A06 | N/A | Governance: Developing | Tenet 4: Risk-Based Design |
| Defense in Depth | PR.IR, PL-8(1) | 12.2, 13.4 | A.8.27, A.13.1 | SC-7, PL-8(1) | 1.2 | A06 | N/A | All Pillars: Advanced | Tenet 1-7: Layered Security |
| Change Control | CM-3, PR.IP | 4.1, 16.7, 18.1 | A.8.32 | CM-3, CM-3(2), CM-4, CM-5 | 6.4.5 | A08 | T1554 | Automation: Advanced | Tenet 5: Controlled Changes |
| Code Signing | SI-7, CM-14 | 2.3, 16.11 | A.8.32 | SI-7(6), CM-14 | 6.3.2 | A08 | T1553 | Devices: Developing | Tenet 5: Software Integrity |
| Boundary Protection | SC-7, PR.AC | 12.1-12.4, 13.3 | A.8.20, A.8.22 | SC-7, SC-7(3)(4)(5)(8)(21) | 1.2, 1.3 | A01 | N/A | Networks: Advanced | Tenet 2: Explicit Boundaries |
| Process Isolation | SC-39, PR.PS | 4.8, 16.7 | A.8.27 | SC-39 | 6.4.3 | N/A | T1055 | Apps: Advanced | Tenet 4: Workload Isolation |
| Capacity Management | PR.IR-04, AU-4 | 12.4 (via 4.1) | A.8.6 | AU-4, AU-5(1), CP-2 | 12.1.3 | N/A | N/A | Visibility: Advanced | Tenet 7: Resource Monitoring |
| Physical Security | PR.AA-06, PE-2 | 11.1.1-11.2.9 | A.7.1-A.7.14 | PE-2, PE-3, PE-6, PE-9 | 9.1-9.6 | N/A | N/A | N/A | N/A |
| Removable Media | MP-7, PR.DS | 11.2.5 | A.7.10 | MP-2, MP-4, MP-5, MP-7 | 9.6 | N/A | T1091, T1052 | Devices: Advanced | Tenet 5: Media Controls |
| Remote Maintenance | MA-4, AC-17 | 12.3 | A.6.7 | MA-4, MA-4(6), AC-17 | 8.3 | N/A | T1021 | Identity: Advanced | Tenet 2: Authenticated Maintenance |
| Cloud Security | PR.DS, DE.CM | 15.1 | A.5.23 | SC-7, SC-8, SC-13, AC-17 | 12.8.1-12.8.5 | N/A | T1537 | All Pillars: Advanced | Tenet 2: Cloud-Agnostic Security |
| Evidence Collection | RS.AN-03, AU-9 | 17.1 | A.5.28 | AU-9, IR-4(4), AU-11 | 10.5, 12.10.4 | N/A | N/A | Visibility: Advanced | Tenet 7: Forensic Readiness |
| Environment Separation | PR.IP, CM-2(6) | 16.8 | A.8.31 | CM-2(6), SC-7, CM-7 | 6.4.1 | N/A | N/A | Networks: Advanced | Tenet 2: Logical Isolation |
| Error Handling | SI-11, SC-24 | 16.7 | A.8.26 | SI-11, SC-24 | 6.5 | A10 (Exception Handling) | N/A | Apps: Advanced | Tenet 4: Fail Secure |
| Fail-Secure Design | SC-24, CP-10 | 12.1, 13.3 | A.8.27 | SC-24, CP-2 | 6.4 | A10 (Fail Closed) | N/A | All Pillars: Advanced | Tenet 4: Default Deny |
| Resource Limits | SC-5, SC-6 | 13.3 | A.8.6 | SC-5, SC-6 | 12.1.3 | A10 (DoS Prevention) | T1498, T1499 | Apps: Advanced | Tenet 4: Rate Limiting |
| Service Health Monitoring | SI-4, CP-10 | 8.6, 12.4 | A.8.6, A.8.16 | SI-4, AU-6, CP-10 | 10.6 | A10 (Availability) | T1489 | Visibility: Advanced | Tenet 7: Health Checks |
| Penetration Testing | CA-8, ID.RA-09 | 18.1-18.5 | A.8.29 | CA-8, RA-5(6) | 11.3, 11.4 | N/A | All Tactics | Governance: Developing | Tenet 7: Validation Testing |
| Secure Development | PR.PS-02, SA-8 | 16.1-16.14 | A.5.8, A.8.25-8.29 | SA-3, SA-8, SA-11, CM-3(2) | 6.5 | A06, A08 | N/A | Governance: Advanced | Tenet 4: SDLC Security |
| Source Code Security | CM-3, SA-10 | 16.11 | A.8.4 | CM-3, CM-5, SA-10 | 6.3.2 | A08 | N/A | Governance: Developing | Tenet 5: Code Integrity |
| Supplier Management | GV.SC-02 to GV.SC-05 | 15.1-15.7 | A.5.19-5.22 | SR-3, SR-6, SR-10, SR-11, SA-9 | 12.8 | A03 | T1195, T1199 | Governance: Developing | Tenet 5: Third-Party Risk |
| Zero Trust - Identity | PR.AA, IA-2 | 6.1-6.6 | A.5.15-5.18 | AC-2, AC-3, IA-2, IA-4 | 8.1, 8.2 | A01, A07 | T1078 | Identity: Advanced | Tenet 3: Identity as Perimeter |
| Zero Trust - Device | PR.AA, IA-3 | 1.1-1.5 | A.8.1 | IA-3, CM-8 | 2.4 | N/A | N/A | Devices: Advanced | Tenet 5: Device Trust |
| Zero Trust - Network | SC-7, PR.AC | 12.1-12.4, 13.4 | A.8.20, A.8.22 | SC-7, SC-7(4)(5)(21) | 1.1-1.4 | A01, A06 | N/A | Networks: Advanced | Tenet 2: Never Trust Location |
| Zero Trust - Application | PR.PS, SA-8 | 16.1-16.14 | A.8.25-8.27 | SA-8, SA-17, SC-39 | 6.4, 6.5 | A06 | N/A | Apps: Advanced | Tenet 4: Context-Aware Access |
| Zero Trust - Data | PR.DS, SC-28 | 3.1-3.14 | A.5.12, A.5.14, A.8.24 | SC-28, MP-3, MP-4 | 3.1-3.7 | A04 | N/A | Data: Advanced | Tenet 2: Data-Centric Security |
| Zero Trust - Visibility | DE.CM, AU-6 | 8.1-8.11, 13.6 | A.8.15, A.8.16 | AU-2, AU-6, SI-4 | 10.2-10.6 | A09 | All Tactics | Visibility: Advanced | Tenet 7: Full Observability |
| Zero Trust - Automation | RS.MA, IR-4(1) | 17.1-17.9 | A.5.24-5.27 | IR-4(1), IR-5(1) | 12.10 | N/A | All Tactics | Automation: Advanced | Tenet 6: Dynamic Policies |
| Privileged Access Management | AC-6, PR.AA | 5.4, 6.5 | A.8.2, A.8.18 | AC-2(7), AC-6, AC-6(1)(5)(9) | 7.1, 7.2 | A01 | T1078, T1134 | Identity: Advanced | Tenet 3: JIT/PIM |
| API Security | IA-5, SC-8 | 16.7 | A.8.26, A.14.1 | SC-8, SI-10, IA-5 | 6.5, 6.6 | A01, A05 | N/A | Apps: Advanced | Tenet 4: API Gateway |
| Database Security | SC-28, AC-3 | 3.11, 6.1 | A.8.24, A.9.2 | SC-28, AC-3 | 3.4, 8.2 | A05 | T1213.006 | Data: Advanced | Tenet 4: Query Monitoring |
| Wireless Security | SC-40, AC-18 | 12.6 | A.8.21 | AC-18, SC-40 | 4.1.1 | N/A | N/A | Networks: Advanced | Tenet 2: Wireless Segmentation |
| Email Security | SC-7, SI-8 | 9.1-9.7 | A.8.23 | SC-7, SI-8 | 12.3 | N/A | T1566 | Apps: Advanced | Tenet 4: Email Gateway |
| Mobile Device Security | AC-19, SC-7 | 4.10-4.12 | A.6.7, A.8.1 | AC-19, SC-43 | 8.2.3, 9.6 | N/A | N/A | Devices: Developing | Tenet 5: MDM/MAM |
| Endpoint Protection | SI-3, DE.CM | 10.1-10.7, 13.2 | A.8.7 | SI-3, SI-4(23) | 5.1, 5.2 | N/A | T1204, T1566 | Devices: Advanced | Tenet 5: EDR Coverage |
| Account Lifecycle | AC-2, PR.AA | 5.1-5.6 | A.5.16, A.9.2 | AC-2, AC-2(1)(3)(4) | 8.1.2-8.1.4 | A07 | T1136, T1098 | Identity: Advanced | Tenet 3: Automated Provisioning |
| Privileged Session Recording | AU-12, AC-6(9) | 8.11, 6.5 | A.8.18 | AU-12, AC-6(9) | 10.2.2 | N/A | T1078 | Identity: Advanced | Tenet 3: Session Audit |
| Security Awareness Training | AT-2, PR.AT | 14.1-14.9 | A.6.3 | AT-2, AT-3 | 12.6 | N/A | T1204, T1566 | N/A | N/A |
| Incident Classification | IR-4, RS.AN | 17.4 | A.5.25 | IR-4, IR-5 | 12.10.1 | N/A | All Tactics | Automation: Advanced | Tenet 6: Automated Triage |
| Forensic Analysis | IR-4(4), RS.AN | 17.1 | A.5.28 | IR-4(4), AU-9 | 12.10.4 | N/A | All Tactics | Visibility: Advanced | Tenet 7: Evidence Preservation |
| Communication Security | SC-8, PR.DS | 3.10, 13.10 | A.8.24 | SC-8, SC-13 | 4.2 | A04 | N/A | Data: Advanced | Tenet 2: Encrypted Channels |
| Third-Party Risk | GV.SC, SR-3 | 15.1-15.7 | A.5.19-5.22 | SR-3, SR-5, SR-6 | 12.8 | A03 | T1195, T1199 | Governance: Developing | Tenet 5: Vendor Assessment |
| Compliance Monitoring | CA-7, GV.PO | 18.1-18.5 | A.5.36 | CA-7, PM-9 | 12.11 | N/A | N/A | Governance: Advanced | Tenet 7: Continuous Compliance |
| Risk Assessment | RA-3, ID.RA | 7.1, 18.1 | A.5.7, A.8.8 | RA-3, RA-5 | 12.2 | N/A | N/A | Governance: Advanced | Tenet 4: Risk-Based Decisions |
| Security Metrics | GV.OV, PM-9 | 17.9, 18.1 | A.5.27 | PM-9, CA-7(3) | 12.11 | N/A | N/A | Governance: Advanced | Tenet 7: Performance Tracking |
| Policy Management | GV.PO, PL-1 | 4.1, 18.1 | A.5.1, A.5.36 | PL-1, PM-1 | 12.1 | N/A | N/A | Governance: Advanced | Tenet 4: Policy Automation |
| Disaster Recovery | RC.RP, CP-10 | 11.1-11.5 | A.5.29, A.5.30, A.17.1 | CP-10, CP-2 | 12.10.1 | N/A | N/A | Data: Advanced | Tenet 7: DR Testing |
| Service Continuity | RC.HL, CP-2 | 11.1-11.5 | A.5.29, A.17.1 | CP-2, CP-6, CP-7 | 12.10 | N/A | T1498, T1499 | Apps: Advanced | Tenet 7: HA Architecture |
| Data Retention | PR.DS, MP-6 | 3.4, 8.10 | A.5.33 | MP-6, SI-12 | 3.1, 10.7 | N/A | N/A | Data: Advanced | Tenet 4: Lifecycle Management |
| Secure Disposal | MP-6, PR.IR | 3.5, 11.2.7 | A.5.14, A.7.14 | MP-6, SR-12 | 9.8 | N/A | N/A | Data: Advanced | Tenet 4: Data Sanitization |
| Audit Trail Integrity | AU-9, SI-7 | 8.9, 10.1 | A.8.15 | AU-9, SI-7 | 10.5 | A09 | T1070 | Visibility: Advanced | Tenet 7: Tamper-Proof Logs |
| Non-Repudiation | AU-10, SI-7 | 8.5 | A.8.15 | AU-10, SC-17 | 10.3.4 | A08 | N/A | Visibility: Advanced | Tenet 7: Digital Signatures |
| Trusted Computing | SI-7, SC-34 | N/A | A.8.24 | SI-7, SC-34 | N/A | N/A | N/A | Devices: Developing | Tenet 5: Hardware Root of Trust |
| Virtualization Security | SC-44, CM-7 | N/A | A.8.27 | SC-44, SC-39 | 6.4.3 | N/A | T1611 | Apps: Advanced | Tenet 4: Hypervisor Isolation |
| Container Orchestration | CM-7, SC-39 | 16.1-16.14 | A.8.27 | SC-39, CM-7 | 6.4.3 | N/A | T1610, T1611 | Apps: Developing | Tenet 4: K8s Security |
| Microservices Security | SC-7, SA-8 | 16.1 | A.8.27 | SC-7(21), SA-8 | 6.4 | A06 | N/A | Apps: Advanced | Tenet 4: Service Mesh |
| DevSecOps | SA-10, PR.PS | 16.1-16.14, 18.1 | A.5.8, A.8.25 | SA-10, SA-11 | 6.5 | A08 | N/A | Governance: Developing | Tenet 4: Pipeline Security |
| Secrets Rotation | IA-5, SC-12 | 6.7 | A.8.24 | IA-5, SC-12 | 8.3.2 | A07 | T1552 | Identity: Advanced | Tenet 6: Automated Rotation |
| Certificate Lifecycle | SC-17, IA-5(14) | 3.12 | A.8.24 | SC-17, IA-5(14) | 4.2.1 | A04 | N/A | Identity: Advanced | Tenet 6: ACME Automation |
| Vulnerability Disclosure | RA-5, PM-16 | 7.1, 16.2 | A.5.7 | RA-5, PM-16 | 11.3.1 | A03 | N/A | Governance: Advanced | Tenet 7: Coordinated Disclosure |
| Security Orchestration | IR-4(1), RS.MA | 17.1-17.9 | A.5.24-5.27 | IR-4(1), IR-8 | 12.10 | N/A | All Tactics | Automation: Advanced | Tenet 6: SOAR Platform |
| Behavioral Analytics | AU-6, SI-4(18) | 8.11, 13.6 | A.8.16 | AU-6(5), SI-4(18) | 10.6 | A09 | All Tactics | Visibility: Developing | Tenet 7: UEBA/ML |
| Anomaly Detection | SI-4, DE.AE | 13.6 | A.8.16 | SI-4(2), SI-4(18) | 10.6, 11.4 | A09 | All Tactics | Visibility: Advanced | Tenet 7: Baseline Deviation |
| Deception Technology | SI-4, DE.CM | 13.1 | A.8.16 | SI-4 | 11.4 | N/A | All Tactics | Visibility: Developing | Tenet 7: Honeypots/Honeynets |
| Security Data Lake | AU-6, DE.CM | 8.9, 13.6 | A.8.15 | AU-6, AU-12 | 10.2 | A09 | N/A | Visibility: Advanced | Tenet 7: Centralized Repository |
| SIEM/SOAR Integration | AU-6(1), IR-4(1) | 8.11, 17.1 | A.8.16, A.5.24 | AU-6(1)(3), IR-4(1) | 10.6, 12.10 | A09 | All Tactics | Automation: Advanced | Tenet 6+7: Orchestrated Response |
| Threat Modeling Automation | RA-3, SA-8 | 16.14 | A.14.1 | RA-3, SA-8 | 6.3.1 | A06 | N/A | Governance: Developing | Tenet 4: Continuous Modeling |
| Security Posture Management | CA-7, GV.OV | 4.1, 18.1 | A.5.36, A.8.9 | CA-7, PM-9 | 12.11 | A02 | N/A | Governance: Advanced | Tenet 7: CSPM/CWPP |
| Attack Surface Management | RA-3, ID.AM | 1.1-1.5, 18.1 | A.5.9, A.8.8 | RA-3, RA-5 | 11.3.1 | N/A | T1595, T1596 | Devices: Advanced | Tenet 1: External Exposure |

**Legend:**

- **N/A** = Not Applicable or No Direct Mapping
- **All Tactics** = Relevant to Multiple MITRE ATT&CK Tactics (TA0001-TA0040)
- **Developing** = Maturity stage below Advanced with identified implementation gaps
- **Advanced** = Full implementation with automation and integration

### Framework Coverage Summary

- **NIST CSF 2.0:** 100% of security domains mapped to Functions (Govern, Identify, Protect, Detect, Respond, Recover)
- **CIS Controls v8.1:** 98% of applicable controls mapped (159 safeguards across 18 controls)
- **ISO 27001:2022:** 97% of applicable Annex A controls mapped (93 controls across 4 families)
- **NIST 800-53 Rev 5:** 95% of implemented controls mapped (18 control families)
- **PCI-DSS v4.0:** 85% conceptual alignment (technical controls fully implemented)
- **OWASP Top 10 (2025):** 90% of categories directly addressed (9 of 10 strong coverage)
- **MITRE ATT&CK v18.1:** 30% technique coverage (65 of 216 techniques across 12 tactics)
- **CISA ZTMM v2.0:** Advanced maturity across 6 of 8 pillars (Identity, Devices, Networks, Applications, Data, Visibility/Analytics)
- **NIST SP 800-207:** Comprehensive implementation of all 7 Zero Trust tenets at Advanced level

This comprehensive alignment matrix demonstrates defense-in-depth implementation across nine major cybersecurity frameworks, providing a unified view of security control coverage across traditional security controls and modern Zero Trust Architecture principles. The matrix facilitates gap analysis, compliance reporting, strategic security planning, and demonstrates progression toward Optimal Zero Trust maturity.
