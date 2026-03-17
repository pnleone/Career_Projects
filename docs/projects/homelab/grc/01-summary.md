# Security Lab - Governance, Risk and Compliance Summary

**Document Control:**  
Version: 1.1  
Last Updated: March 2026  
Owner: Paul Leone  

**Framework Versions:** NIST CSF 2.0, CIS Controls v8.1, NIST SP 800-53 Rev 5, ISO 27001:2022, PCI-DSS v4.0, OWASP Top 10 2025, MITRE ATT&CK Enterprise v18.1, CISA ZTMM v2.0, NIST SP 800-207 Zero Trust

---

## Executive Overview

### Framework Alignment with Lab Mission

This cybersecurity lab demonstrates production-ready security capabilities aligned with nine industry-standard frameworks, each validating specific aspects of the lab's mission to simulate enterprise-grade SecOps, Systems Engineering, and Network Defense operations.

### Mission Alignment by Framework

**NIST Cybersecurity Framework 2.0** validates the lab's threat detection & response capabilities through comprehensive implementation across all six functions (Govern, Identify, Protect, Detect, Respond, Recover). Tier 3–4 maturity with automated incident response reducing MTTR to <30 minutes.

**CIS Controls v8.1** validates defense-in-depth architecture through 93% IG1 and 81% IG2 compliance. Controls map directly to enterprise infrastructure operations with automated patch management across 5,000+ packages and comprehensive security monitoring.

**ISO 27001:2022** validates security engineering & automation through 77% overall control coverage, with exceptional performance in technological controls (91%). Policy-driven security architecture with CIS Benchmark compliance, IaC automation, and comprehensive audit capabilities.

**NIST SP 800-53 Rev 5** validates technical security engineering depth through strong implementation in Access Control (90%), Audit & Accountability (100%), and System Integrity (90%). Enterprise-grade controls spanning identity management, cryptographic protection, and continuous monitoring.

**MITRE ATT&CK Enterprise v18.1** validates operational threat detection through 30% technique coverage (65/216 techniques) across 12 adversary tactics. Strong coverage in Initial Access (67%), Execution (67%), and Lateral Movement (56%).

**OWASP Top 10 (2025)** demonstrates comprehensive web application security with 9/10 categories at Strong maturity, leveraging SafeLine WAF, Authentik SSO, TLS 1.3, and comprehensive logging.

**PCI-DSS v4.0** achieves 85% technical control implementation. Demonstrates payment-security-aligned controls applicable to enterprise environments handling sensitive data.

**CISA Zero Trust Maturity Model v2.0** achieves Advanced maturity (Stage 3/4) across all 5 pillars and 3 cross-cutting capabilities. Hybrid deployment model combining device agent/gateway (Authentik + Traefik), enclave gateway (pfSense/OPNsense/Palo Alto), and resource portal approaches.

**NIST SP 800-207** demonstrates comprehensive implementation of all 7 Zero Trust tenets through mature logical component deployment with policy decision points, policy enforcement points, and continuous monitoring at Advanced level.

### Architectural Principles Demonstrated

**Defense in Depth** validated across all frameworks:

- Network perimeter: pfSense/OPNsense HA cluster, Palo Alto PA-VM NGFW (App-ID, Threat Prevention, User-ID), FortiGate 30D, Suricata/Snort IPS, SafeLine WAF
- Network visibility: Zeek NSM (protocol metadata, 3-segment coverage), ntopng/nProbe (NetFlow v9 from Cisco R1/R2/R3, 3560X, and firewalls), dual nProbe collectors
- Application layer: OWASP A01–A10, NIST SI-10, ISO A.8.26, CISA ZTMM Applications, NIST 800-207 SA-8
- Endpoint: CIS 10.1–10.7, NIST SI-3/SI-4, ATT&CK detection coverage, Wazuh EDR 25+ endpoints
- Identity: CIS 5–6, NIST AC/IA families, Authentik SSO, Active Directory, Palo Alto User-ID AD integration

**Secure by Design** validated through:

- Mandatory encryption (TLS 1.3, AES-256, IPSec IKEv2 AES-256-GCM/SHA-384, GlobalProtect TLS 1.3)
- Authenticated access (MFA, SSH key-based, certificate-based via Step-CA, Palo Alto AD-integrated admin auth)
- Least privilege (Authentik RBAC, Palo Alto User-ID group-based policy, AD security groups)
- IaC automation (Terraform, Ansible, Git version control)

**Zero Trust Architecture** validated through:

- Identity verification (MFA enforcement, Palo Alto User-ID AD mapping to security policy, Authentik SSO 100% coverage)
- Network micro-segmentation (VLAN isolation, pfSense/OPNsense zone enforcement, Palo Alto security zones with default inter-zone deny)
- Encrypted communications (TLS 1.3, IPSec IKEv2 site-to-site, GlobalProtect endpoint VPN, WireGuard)
- Assume breach monitoring (Zeek protocol metadata, ntopng flow analysis, dual SIEM, 100% event logging)

### Framework Purpose & Organizational Value

| Framework | Purpose | Organizational Value |
|---|---|---|
| NIST CSF 2.0 | Risk-based framework for managing cybersecurity across six core functions (Govern, Identify, Protect, Detect, Respond, Recover). | Board-level reporting, vendor risk assessments, strategic planning, maturity benchmarking. |
| CIS Controls v8.1 | Prescriptive, prioritized safeguards organized into three Implementation Groups (IG1/IG2/IG3). | Security program development, gap analysis, resource allocation. IG1 addresses 80% of common attacks. |
| ISO 27001:2022 | Requirements for ISMS with 93 controls across organizational, people, physical, and technological domains. | Third-party certification, GDPR/HIPAA alignment, competitive differentiation. |
| NIST SP 800-53 Rev 5 | Comprehensive catalog of security/privacy controls across 20 families for federal and regulated systems. | FedRAMP, FISMA, authoritative technical baseline for government contractors. |
| MITRE ATT&CK v18.1 | Documents adversary TTPs based on real-world observations. 216 techniques / 475 sub-techniques. | Threat-based testing, detection engineering, SOC playbook development, purple team exercises. |
| OWASP Top 10 (2025) | Identifies most critical web application security risks with developer-focused guidance. | DevSecOps integration, pen test scoping, application security maturity measurement. |
| PCI-DSS v4.0 | Technical/operational requirements for handling payment card data. | Payment security, brand protection, breach risk reduction. |
| CISA ZTMM v2.0 | Four maturity stages across 5 pillars + 3 cross-cutting capabilities for zero trust adoption. | EO 14028 compliance, modernization roadmaps, zero trust investment prioritization. |
| NIST SP 800-207 | Foundational principles and logical architecture for zero trust through seven core tenets. | Architecture design, RFP requirements, vendor solution validation against federal standards. |

### Overall Lab Assessment

**Core Strengths**

**Operational Security Excellence**

- 100% security event logging with dual SIEM (Splunk + Elastic) providing <5min MTTD
- Automated incident response via SOAR (Shuffle) achieving <30min MTTR with 15+ documented playbooks
- Multi-layered threat detection: network IDS/IPS (Suricata/Snort, Palo Alto Threat Prevention), host EDR (Wazuh 25+ endpoints), behavioral analytics (CrowdSec), Zeek protocol metadata, ntopng flow analysis
- Comprehensive vulnerability management with weekly OpenVAS + monthly Nessus scans, <72hr critical MTTR

**Technical Architecture Maturity**

- Defense-in-depth across network (VLAN segmentation, pfSense/OPNsense/Palo Alto firewalls, IDS/IPS), application (WAF, reverse proxy), endpoint (EDR, FIM), and identity (SSO, MFA, PKI) layers
- Palo Alto PA-VM NGFW adds App-ID application-layer control, User-ID AD-integrated identity-based policy, Threat Prevention inline IPS, and IPSec/GlobalProtect VPN
- NSM sensor (Zeek + ntopng/nProbe): SOC-grade network visibility across Prod_LAN, Lab_LAN1, Lab_LAN2 — full protocol metadata + NetFlow v9 from all Cisco devices and firewalls
- Infrastructure as Code (Terraform, Ansible) with version control and audit trails
- Advanced cryptography: TLS 1.3, AES-256, IPSec IKEv2 AES-256-GCM, ECDSA P-256, Ed25519 SSH keys, Step-CA PKI
- High availability: HA firewall cluster, dual SIEM, dual DNS with <5s failover, redundant internet
- Zero trust: Authentik SSO 100% coverage, Palo Alto User-ID AD group policy, micro-segmentation (3-tier VLAN + zone architecture), TLS 1.3 mandatory, continuous monitoring

#### Framework Compliance Summary

| Framework | Score / Maturity | Key Metric |
|---|---|---|
| NIST CSF 2.0 | Tier 3–4 (Repeatable → Adaptive) | 100% function coverage |
| CIS Controls v8.1 | 93% IG1 / 81% IG2 / 52% IG3 | 159 safeguards mapped |
| ISO 27001:2022 | 77% overall / 91% technological | 55 implemented, 14 partial |
| NIST SP 800-53 Rev 5 | 100% AU / 95% IA / 95% SC / 90% SI / 90% AC | 18 control families |
| PCI-DSS v4.0 | 85% technical controls | 12 requirements mapped |
| CISA ZTMM v2.0 | Advanced (Stage 3/4) | 6 of 8 pillars at Advanced |
| NIST SP 800-207 | Advanced — all 7 ZT tenets | 6 of 8 pillars at Advanced |
| MITRE ATT&CK v18.1 | 30% technique coverage | 65 of 216 techniques |
| OWASP Top 10 (2025) | 9/10 Strong \| 1/10 Moderate | Supply chain gap identified |

#### Infrastructure Updates (v1.1)

The following additions are reflected throughout this document and the seven GRC detail documents:

| Update | Components | GRC Impact |
|---|---|---|
| Palo Alto PA-VM NGFW | PAN-OS; App-ID; Threat Prevention; User-ID/AD integration; IPSec IKEv2; GlobalProtect VPN; security zone architecture | Advances PR (protect), AC-17, SC-7, SC-8, IA-2, CISA Networks/Identity, MITRE T1133/T1190 |
| NSM Sensor — Zeek | 3-worker AF_PACKET cluster; DNS/HTTP/SSL/SSH/SMB/RDP/DCE-RPC analyzers; Notice/Intel/Weird frameworks; JSON to Elastic + Brim/ZUI | Closes CISA Visibility gap; advances DE.CM-01, SI-4, CIS 13.1/13.2; improves T1046 coverage |
| NSM Sensor — ntopng/nProbe | Dual nProbe (Cisco flows UDP/2055; FW flows UDP/2056); ntopng web UI port 3000; local networks 192.168.3/100/200.0/24 | Completes CIS 13.6 NetFlow coverage; advances SI-4, AU-12, DE.CM-01 |
| Cisco NetFlow (R2 added) | R1, R2 (new), R3, 3560X (Vlan10/30) now all export FNF v9 to 192.168.1.48:2055 | Closes prior R2 NetFlow gap; full flow telemetry across Cisco infrastructure |
| Cisco/VLAN Enhancements | OSPF MD5 auth; 3560X DHCP snooping VLANs 10/20/30/100/120/200; uRPF on R3; updated SVI table | Strengthens SC-7, CIS 12.1/12.2, PR.IR-01, network segmentation evidence |

---

## NIST Cybersecurity Framework 2.0 Implementation Summary

This personal cybersecurity lab demonstrates comprehensive implementation of NIST CSF 2.0 across all six core functions. The environment serves as a learning platform for enterprise-grade security controls while maintaining conceptual compliance with NIST, CIS, ISO 27001, and PCI-DSS frameworks.

**Overall Maturity: Tier 3 (Repeatable) - Approaching Tier 4 (Adaptive)**

### Function Implementation Analysis

| Function | Tier | Implementation Summary | Key Controls / Updates |
|---|---|---|---|
| GOVERN (GV) | Tier 3 | Risk management strategy with CVSS-based prioritization, risk tolerances (Critical CVEs <72h, High <7d), security policies (SSH hardening, TLS 1.3, 100% event logging). PAN-OS update lifecycle added to supply chain controls. | Mission-aligned objectives; criticality tiers; vulnerability SLAs; Palo Alto content update management |
| IDENTIFY (ID) | Tier 4 | Automated asset discovery across 30+ hosts and 5,000+ packages. Asset inventory expanded to include PA-VM, NSM host, Zeek cluster, nProbe instances. Real-time vulnerability correlation, MITRE ATT&CK mapping, MISP threat intelligence. | Checkmk, Prometheus, PatchMon, Wazuh; CVSS scoring; CrowdSec/OTX/abuse.ch feeds; Shuffle disclosure workflows |
| PROTECT (PR) | Tier 4 | Defense-in-depth with automated patching, Authentik SSO/MFA, TLS 1.3/AES-256. Added: Palo Alto zone segmentation (PR.IR-01), User-ID AD group policy (PR.AA-05), IPSec IKEv2 + GlobalProtect VPN (PR.DS-02), App-ID application control. | Step-CA PKI; RBAC; IaC (Terraform/Ansible); CIS Benchmark audits; PA-VM App-ID; User-ID; IPSec AES-256-GCM/SHA-384 |
| DETECT (DE) | Tier 3 | Continuous monitoring with 100% network visibility. Added: Zeek NSM (protocol metadata, 3 segments, DNS/HTTP/SSL/SSH/SMB/RDP/DCE-RPC), ntopng/nProbe (NetFlow v9 from all Cisco devices + firewalls), PA-VM Threat Prevention. Gap: ML-based anomaly detection. | Splunk/Elastic/Wazuh/Suricata; Zeek JSON to Elastic/ZUI; ntopng flow dashboards; dual nProbe; Discord/email/TheHive alerting |
| RESPOND (RS) | Tier 3 | 15+ TheHive playbooks, Shuffle SOAR, Cortex analysis, Wazuh Active Response. Added: Zeek forensic metadata (conn/dns/http/ssl/files logs) as incident data source; PA-VM dynamic block list for rapid IOC containment. Gap: tabletop exercises. | MITRE ATT&CK-mapped playbooks; automated enrichment; Ansible remediation; Brim/ZUI for Zeek forensics; PA-VM EDL blocking |
| RECOVER (RC) | Tier 3 | Encrypted AES-256 backups, snapshot rollback, HA DNS failover, documented RTO/RPO. Gap: formal BC/DR exercises. | PBS automated bi-weekly backups; Proxmox snapshots; dual Unbound/Technitium DNS; UPS; service criticality tiers |

### Key Achievements

- **100% Function Coverage:** All six CSF 2.0 functions with documented processes and automated controls
- **Advanced Detection:** Multi-SIEM (Splunk + Elastic + Wazuh) providing <5min MTTD; Zeek + ntopng close network-layer visibility gap
- **Automated Response:** Shuffle orchestration reduces MTTR by 70% vs manual workflows; PA-VM EDL enables rapid IOC blocking
- **Identity-Aware Network Policy:** Palo Alto User-ID integrates AD groups directly into firewall security policy (PR.AA-05 / AC-3)
- **Encrypted VPN Expansion:** IPSec IKEv2 (AES-256-GCM, SHA-384, DH Group 20) + GlobalProtect supplement Tailscale WireGuard
- **Threat Intelligence:** MISP aggregates 5+ feeds with automated IOC correlation; Zeek Intel framework enables network-layer IOC matching

---

## CIS Critical Security Controls v8.1 Implementation Summary

Comprehensive implementation across 18 control families. 93% IG1 / 81% IG2 / 52% IG3 compliance.

### Implementation Group Compliance

**IG1 (Basic Cyber Hygiene) — 93% Compliant**

**Status:** 52 of 56 safeguards fully implemented.

**Strengths:** Complete coverage of foundational controls: asset inventory (1–2), data protection (3), patch management (7), centralized logging (8), malware defenses (10), backup/recovery (11).

**Gaps:** Application allowlisting (2.5), weekly unauthorized asset reviews (1.2), comprehensive data flow diagrams (3.8), formal secure configuration policy documentation (4.1).

**IG2 (Enhanced Security) — 81% Compliant**

**Status:** 60 of 74 additional safeguards implemented.

**Strengths:** Advanced monitoring exceeds requirements: weekly OpenVAS vs quarterly baseline, 90-day retention, dual SIEM. Network segmentation, TLS 1.3, MFA, automated patch management. Palo Alto App-ID and Threat Prevention advance Controls 12 and 13 maturity.

**Gaps:** Network AAA (12.5), application/script allowlisting (2.5–2.7), remote wipe (4.11), penetration testing (18.1–18.2), RBAC documentation (6.8).

**IG3 (Advanced Security) — 52% Compliant**

**Status:** 15 of 29 additional safeguards implemented.

**Strengths:** Host-based IPS (Wazuh Active Response), network IPS (Suricata inline + Palo Alto Threat Prevention), WAF (SafeLine), behavior-based malware detection, detailed audit logging.

**Gaps:** 802.1X port NAC (13.9), isolated admin workstation (12.8), DLP (3.13), mobile containerization (4.12), SAST/DAST (16.12), threat modeling docs (16.14), annual pen testing (18.5).

### Control-by-Control Analysis

| Control | Score | Status / Notes |
|---|---|---|
| 1: Asset Inventory | 99% | Minor process gap. NSM host, PA-VM, Zeek cluster, nProbe instances added to inventory. |
| 2: Software Inventory | 70% | Allowlisting gaps remain. |
| 3: Data Protection | 95% | IG1/IG2 complete. |
| 4: Secure Configuration | 75% | Needs formal policy docs. PA-VM baseline (PAN-OS hardening, management ACL, MFA) added. |
| 5: Account Management | 100% | Fully compliant. |
| 6: Access Control | 90% | Needs RBAC documentation. Palo Alto User-ID AD group policy strengthens implementation. |
| 7: Vulnerability Management | 100% | Exceeds all baselines. |
| 8: Audit Log Management | 98% | IG1/IG2 complete. Zeek JSON logs (Elastic) and ntopng flow data added as log sources. |
| 9: Email/Web Protection | 65% | Limited by homelab scope. |
| 10: Malware Defenses | 100% | Fully compliant. |
| 11: Data Recovery | 100% | Fully compliant. |
| 12: Network Infrastructure | 88% | Lacks AAA (12.5). PA-VM zone architecture, IPSec/GlobalProtect VPN improve 12.2/12.3/12.7. |
| 13: Network Monitoring | 93% | Lacks 802.1X (13.9). Zeek (13.1/13.2) + ntopng/nProbe (13.6) + PA-VM Threat Prevention (13.8) significantly advance maturity. R2 NetFlow gap closed. |
| 14: Security Awareness | N/A | Single-user environment. |
| 15: Service Provider Mgmt | N/A | Single-user environment. |
| 16: Application Security | 60% | Infrastructure focus; custom dev minimal. |
| 17: Incident Response | 85% | Lacks multi-user elements. |
| 18: Penetration Testing | 40% | Vulnerability scanning substitute; formal testing not conducted. |

### Key Achievements

- Exceeds scanning requirements: weekly OpenVAS + monthly Nessus vs quarterly CIS baseline
- Advanced SIEM: dual platform (Splunk + Elastic) with 100% security event coverage
- NSM deployment: Zeek + ntopng/nProbe close CIS 13 network monitoring gaps (13.1, 13.2, 13.6, 13.8)
- Palo Alto App-ID and Threat Prevention advance Controls 12 and 13 to near-complete IG2 compliance
- Automated patching: PatchMon, WSUS, Watchtower, WUD across all platforms
- Defense-in-Depth: network segmentation, multi-layer IPS, WAF, EDR on 25+ endpoints, Palo Alto NGFW
- Rapid Remediation: <72h critical MTTR, 95% patch compliance

---

## ISO 27001:2022 Annex A Implementation Summary

77% overall coverage (55 implemented, 14 partial). Exceptional technological controls (91%).

### Control Family Analysis

| Domain | Coverage | Highlights |
|---|---|---|
| 5. Organizational Controls | 71% (22/31) | Threat intel (MISP/CrowdSec), asset inventory (5,000+ packages / 30+ hosts), TLS 1.3 transfer (A.5.14), Authentik SSO (A.5.15), TheHive/Shuffle IR (A.5.24–28). Palo Alto User-ID and IPSec VPN strengthen A.5.14/A.5.15. |
| 6. People Controls | 100% (2/2) | Remote working (A.6.7: Tailscale, GlobalProtect, MFA, TLS 1.3); security event reporting (A.6.8: Discord/email/TheHive). |
| 7. Physical Controls | 33% (2/6) | Residential homelab limitations. Encrypted storage, DBAN disposal, UPS, environmental monitoring. |
| 8. Technological Controls | 91% (29/32) | Wazuh EDR 25+ endpoints; MFA 100% admin; multi-engine malware defense; weekly OpenVAS + monthly Nessus. PA-VM Threat Prevention (A.8.7/A.8.20), Zeek/ntopng NSM (A.8.16/A.8.20) strengthen detection and boundary protection. |

### Key Achievements

- Defense-in-Depth: network segmentation, SafeLine WAF, Suricata/Palo Alto IPS, host-based EDR
- Cryptographic Excellence: TLS 1.3, Ed25519 SSH keys, Step-CA PKI, AES-256-GCM, IPSec IKEv2, DNSSEC
- Comprehensive Logging: 100% security event coverage, dual SIEM, 90-day hot/1-year cold retention, Zeek network metadata, ntopng flow data
- Configuration Management: Ansible/Terraform IaC, Git version control, CIS Benchmark compliance (92–98%), automated drift detection
- High Availability: HA firewall cluster, dual DNS (<5s failover), dual SIEM, redundant internet
- NSM Layer (New): Dedicated passive sensor; Zeek + ntopng fulfill A.8.16 (monitoring), A.8.20 (network security) requirements with SOC-grade depth

### Critical Control Highlights

**Access Control & Identity Management:**

- Centralized SSO (Authentik) with MFA enforcement (100% admin accounts)
- Palo Alto User-ID: AD group-based firewall policy enforcement. HR, IT, Lab user groups mapped to differentiated access profiles without per-IP rules
- SSH key-based authentication; RBAC; privileged action logging; session timeout; certificate-based auth (Step-CA)

**Network Security:**

- VLAN/subnet segmentation with firewall ACLs per segment; pfSense/OPNsense; Palo Alto zone-based policy (default inter-zone deny)
- Palo Alto App-ID: 3,000+ application signatures enforce allowlisting at L7 independent of port
- Zeek NSM: passive protocol metadata across Prod_LAN, Lab_LAN1, Lab_LAN2; JSON logs to Elastic
- ntopng/nProbe: NetFlow v9 from R1, R2, R3, 3560X (Cisco) and pfSense/OPNsense (dual nProbe collectors)
- IDS/IPS: Suricata inline blocking, Snort passive, Palo Alto Threat Prevention inline, CrowdSec behavioral

**Data Protection:**

- Encryption at rest (AES-256 backups, encrypted endpoints); encryption in transit (TLS 1.3, SSH, IPSec IKEv2, WireGuard, syslog-ng TLS)
- Secure deletion, 90-day log retention, immutable SIEM indexes, offsite backup with quarterly restore testing

### Compliance Strengths

- Technological Excellence: 91% coverage with enterprise-grade implementation including PA-VM NGFW and NSM sensor
- Incident Response Maturity: 15+ playbooks, automated SOAR orchestration, forensic readiness including Zeek metadata and Brim/ZUI analysis
- Continuous Monitoring: 100% visibility with SIEM + Zeek NSM + ntopng flow data providing multi-layer telemetry
- Vulnerability Management: weekly/monthly scanning cadence, <72h critical MTTR, 95% patch compliance
- Encryption Everywhere: TLS 1.3, IPSec IKEv2, strong ciphersuites, comprehensive PKI, encrypted backups and transmission

---

## NIST SP 800-53 Rev 5 Implementation Summary

324+ individual requirements across 18 control families. Strong compliance in technical families (AC, AU, IA, SC, SI) at 85%+ implementation.

**Overall Maturity: High (Technical Controls) / Moderate (Administrative Controls)**

### Control Family Compliance Analysis

| Family | Score | Summary / Updates |
|---|---|---|
| Access Control (AC) | 90% | 27/30 implemented. Authentik SSO/MFA, SSH key auth, AD RBAC, session management, SIEM dashboards. Added: Palo Alto User-ID AD group enforcement (AC-3); GlobalProtect + IPSec VPN (AC-17). Gap: AC-2(12) behavioral analysis partial. |
| Audit & Accountability (AU) | 100% | 18/18 implemented. Dual SIEM, 100% event coverage, 90-day hot/1-year cold retention, immutable logs. Added: Zeek JSON logs (DNS/HTTP/SSL/SSH/SMB/RDP/files with SHA-256) as AU-12 log source; ntopng flow records as AU-12 network audit trail. |
| Assessment & Authorization (CA) | 80% | 8/10 implemented. Weekly OpenVAS (52/yr) + monthly Nessus exceeds baseline. Grafana dashboards, CIS Benchmark audits. Gaps: CA-2(1) independent assessors N/A; CA-8 formal pen testing informal. |
| Configuration Management (CM) | 95% | 15/16 implemented. Ansible/Terraform IaC, Git version control, CIS baselines, 5,000+ package inventory. Added: PA-VM config management via Ansible (pan-os-python), Git-committed snapshots, candidate vs running config diff (CM-3/CM-7). |
| Contingency Planning (CP) | 75% | 6/8 implemented. PBS bi-weekly encrypted backups (AES-256), quarterly restore testing, HA DNS, <2hr IaC RTO. Gaps: CP-1/CP-10 formal plan documentation partial. |
| Identification & Auth (IA) | 95% | 17/18 implemented. Step-CA two-tier PKI, Ed25519 SSH, Authentik OIDC, Vaultwarden, MFA (TOTP). Added: PA-VM admin auth via AD (IA-2); GlobalProtect machine cert pre-logon (IA-3 device auth); IPSec IKEv2 Phase 1 AES-256-GCM/SHA-384. |
| Incident Response (IR) | 90% | 11/13 implemented. TheHive 15+ playbooks, Shuffle SOAR, Cortex, Wazuh Active Response. Added: Zeek conn/dns/http/ssl/files logs as forensic data sources; Brim/ZUI for local analysis; PA-VM EDL for rapid IOC blocking. |
| Maintenance (MA) | 60% | 4/6 implemented. SSH remote maintenance logged, Git change control, WSUS approvals, patch SLAs. Gaps: MA-1/MA-2/MA-3 formal docs informal. |
| Risk Assessment (RA) | 85% | 10/12 implemented. CVSS base+temporal+environmental scoring, daily PatchMon, weekly OpenVAS, monthly Nessus, 75+ assets. Gaps: RA-3(1) supply chain assessment partial. |
| System & Comm Protection (SC) | 95% | 24/25 implemented. TLS 1.3, Ed25519, AES-256-GCM, Step-CA PKI, pfSense/OPNsense/PA-VM boundary protection, DNSSEC. Added: SC-7 updated to include PA-VM App-ID L7 enforcement and Threat Prevention IPS; SC-8/SC-13 extended with IPSec IKEv2 (AES-256-GCM, SHA-384, DH Group 20, PFS). |
| System & Info Integrity (SI) | 90% | 25/28 implemented. Wazuh FIM/EDR, Suricata/Snort/Palo Alto IPS, ClamAV/Defender, Cortex analysis, automated patching. Added: SI-4 updated — NSM host (192.168.1.48) passively captures 3 segments via Zeek + ntopng; file hashing in Zeek files.log; Notice/Intel/Weird framework detections. |
| Supply Chain (SR) | 40% | 4/12 implemented. Vetted open-source, Docker SHA-256 verification, secure deletion. Most SR controls N/A (no procurement program). |
| Org Controls (PE/PS/PM/PL/MP) | Limited | PE: N/A (residential homelab). PS: N/A (no employees). PM: 40% (asset inventory, risk strategy, threat sharing). PL: 60% (defense-in-depth architecture, GRC as security plan). MP: 40% (encrypted backups, secure deletion, media restrictions). |

### Maturity Assessment by Control Family

| Tier | Families | Rationale |
|---|---|---|
| Tier 4 (Adaptive) | AU, IA, SI, CM | Automated correlation, PKI automation, multi-layered detection including NSM, IaC drift detection |
| Tier 3 (Defined) | AC, IR, RA, SC | Documented policies, centralized enforcement, behavioral monitoring, IPSec/PA-VM additions |
| Tier 2 (Managed) | CP, CA, MA | Scheduled scanning, restore testing, change control |
| Limited Applicability | PE, PS, PM, PL, MP | Constrained by single-user homelab context |

### Critical Control Highlights by Security Objective

**Confidentiality:**

- TLS 1.3 mandatory; IPSec IKEv2 AES-256-GCM site-to-site; GlobalProtect TLS 1.3 endpoint VPN
- Ed25519 SSH keys with passwords disabled globally; Vaultwarden zero-knowledge vault
- AES-256-GCM backups; Step-CA PKI with automated certificate management

**Integrity:**

- Immutable SIEM audit logs (Splunk read-only, Elastic immutable streams)
- Wazuh FIM real-time monitoring; Zeek files.log SHA-256 hashing of extracted files
- Docker image SHA-256 verification; Git version control for all IaC and PA-VM configs

**Availability:**

- HA firewall cluster (pfSense CARP); Palo Alto DoS Protection + Zone Protection profiles
- Dual Unbound/Technitium DNS (<5s failover); dual SIEM; redundant internet; UPS

**Authentication:**

- Authentik SSO (OAuth2/OIDC), MFA (100% admin via TOTP); SSH key-based; Step-CA certs
- Palo Alto admin auth via AD; GlobalProtect pre-logon machine certificate authentication

---

## MITRE ATT&CK Enterprise v18.1 Implementation Summary

30% overall coverage (65 of 216 techniques across 12 adversary tactics).

**Framework Version:** ATT&CK v18.1 (October 2025) | **Total Techniques:** 216 | **Sub-techniques:** 475

### Tactic-by-Tactic Analysis

| Tactic | Coverage | Maturity | Key Updates |
|---|---|---|---|
| Initial Access (TA0001) | 67% (6/9) | Strong | Added: PA-VM GlobalProtect cert-based pre-logon closes T1133 (Partial → Implemented). PA-VM Threat Prevention + App-ID strengthen T1190 exploit prevention. Gaps: T1195 SBOM tracking; T1199 vendor assessments. |
| Execution (TA0002) | 67% (9/13) | Strong | Sysmon PowerShell (4103/4104), LOLBin detection, scheduled task monitoring. Gaps: T1047 WMI minimal; T1059.013 container CLI needs kubectl/docker exec logging; T1106 API hooking. |
| Persistence (TA0003) | 37% (8/20) | Moderate | AD group tracking (4728/4732/4756), Wazuh FIM startup folders/systemd. Gaps: T1197 BITS jobs; T1176 browser extensions; T1137 Office persistence. |
| Privilege Escalation (TA0004) | 38% (5/13) | Moderate | Admin logon SIEM correlation, GPO modification auditing (5136/5137/5141). Gaps: T1055 process injection; T1548 UAC bypass; T1611 container escape. |
| Defense Evasion (TA0005) | 21% (13/46) | Weak | Immutable SIEM logs, registry modification tracking, security tool tampering. Gaps: T1027 obfuscation; T1550 PtH/PtT; T1497 sandbox evasion. NEW v18.1: T1678/T1679/T1036.012/T1562.013 require implementation. |
| Credential Access (TA0006) | 28% (4/15) | Weak | Brute force multi-source detection, LSASS monitoring (Sysmon EID 10). Added: Palo Alto User-ID AD event log visibility partially covers Kerberos (T1558) via EID 4768/4769. Gaps: PtH/PtT undetected; T1539 session hijacking; T1111 MFA interception. |
| Discovery (TA0007) | 32% (10/32) | Moderate | Suricata/Snort port scan/sweep/ARP detection, Splunk pattern correlation, AD LDAP auditing (4662). Added: Zeek conn.log + ntopng flow data improve T1046 coverage (Partial → Implemented). T1018: ntopng host discovery alerts + Zeek weird.log. Gaps: T1135 share enumeration; T1201 password policy queries. |
| Lateral Movement (TA0008) | 56% (5/9) | Strong | RDP (Suricata + 4624 type 10), SMB (5140/5145 + PsExec/WMIC), SSH session logging. Added: Zeek rdp.log, smb_files.log, ssh.log provide per-session protocol metadata for SIEM correlation. Gaps: T1550 PtH/PtT; T1021.006 WinRM; T1072 software deployment tools. |
| Collection (TA0009) | 20% (4/18) | Weak | Archive detection, USB insertion (EID 2003), Wazuh FIM sensitive dirs. Gaps: no DLP; T1114 email collection; T1113/T1125 screen capture; T1056 keyloggers; T1213.006 DB exfiltration. |
| Exfiltration (TA0010) | 46% (4/9) | Moderate | C2 channel monitoring, MISP IOC, Cortex enrichment. Added: Zeek DNS analyzer (high entropy, large TXT records) + ntopng anomalous outbound volume improve T1048 coverage. Gaps: T1567 web service exfil; T1537 cloud exfil. |
| Command & Control (TA0011) | 42% (6/16) | Moderate | Suricata/Snort HTTP/HTTPS/DNS/SMTP, Unbound DGA detection, MISP correlation. Added: Zeek HTTP/DNS/SSL analyzers detect tunneling, beaconing, cert anomalies (T1071, T1572). PA-VM App-ID blocks application-layer tunneling regardless of port. Gaps: full TLS inspection; T1219 remote access tools; T1102 web service C2. |
| Impact (TA0040) | 46% (6/13) | Moderate | Ransomware: Wazuh mass file modification (>50 files/min), Shuffle extension change detection, <30min MTTR. Resource hijacking: Prometheus CPU/memory anomaly, cryptomining process detection. Gaps: T1561 disk wipe; T1491 defacement; T1495 firmware corruption. |

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

- Multi-Layered Detection: Dual SIEM, Suricata/Snort/PA-VM network IPS, Wazuh EDR 25+ endpoints, 100% security event logging
- Network Telemetry (New): Zeek protocol metadata (DNS/HTTP/SSL/SSH/SMB/RDP) + ntopng flow data provide behavioral baseline for T1046, T1071, T1572, T1048 detection
- Automated Response: Shuffle SOAR, TheHive case management, Wazuh Active Response, <30min MTTR
- Threat Intelligence: MISP correlation, Cortex multi-engine, CrowdSec, AlienVault OTX
- Process Visibility: Sysmon telemetry, command-line auditing, parent-child analysis, LOLBin detection

---

## OWASP Top 10 (2025) Implementation Summary

Comprehensive mitigation of OWASP Top 10 (2025) web application security risks. 9/10 categories at Strong/Advanced maturity. Defense-in-depth combining SafeLine WAF (OWASP CRS), Authentik SSO/MFA, TLS 1.3/Step-CA PKI, and dual SIEM with 100% event coverage.

**Overall OWASP 2025 Compliance: 9/10 Strong | 1/10 Moderate (A03: Supply Chain — Developing)**

### 2025 Framework Changes

OWASP Top 10 (2025) introduces significant updates from the 2021 version: **A10 (Mishandling of Exceptional Conditions)** replaces Server-Side Request Forgery as a new category addressing 24 CWEs related to improper error handling and failing open. **A01 (Broken Access Control)** now encompasses SSRF within access control failures. Categories A04, A05, and A06 have shifted rankings reflecting improved industry practices in cryptographic implementation and secure design.

### Category-by-Category Analysis

| Category | Maturity | Key Implementation | Gaps / Actions | Framework Alignment |
|---|---|---|---|---|
| A01:2025 Broken Access Control | Advanced | Authentik ForwardAuth for all Traefik-routed services; OAuth2/OIDC RBAC; SSH key-only (passwords disabled globally); pfSense/PA-VM default-deny ACLs per VLAN/zone. SSRF prevention: DNS rebinding protection, Traefik backend validation, network segmentation. Wazuh + Splunk auth dashboards; TheHive auto case creation. | Session recording for privileged access. | NIST AC-3, AC-2(7), SC-7; ISO A.5.15; CIS 6.1–6.6; PCI-DSS 8.2 |
| A02:2025 Security Misconfiguration | Advanced | CIS Benchmark compliance 92–98% (SSH, Traefik, DNS, firewalls, PA-VM) via Ansible/Terraform IaC. Wazuh SCA drift detection with automated remediation. Traefik security headers (HSTS, CSP, X-Frame-Options). Default credentials eliminated; unnecessary services disabled. Weekly OpenVAS + monthly Nessus validation. | Container configuration scanning. | NIST CM-6, CM-2, CM-7; ISO A.8.9; CIS 4.1; PCI-DSS 2.2 |
| A03:2025 Software Supply Chain Failures | Moderate (Developing) | Vetted open-source sources exclusively; Docker image SHA-256 verification; GPG package signature validation; coordinated patch management (PatchMon/WSUS/Watchtower). MISP tracks vendor compromise campaigns. Snapshot-based rollback capability. | SBOM tracking absent (Trivy/Grype Q2 2026); CI/CD security linting absent; automated dependency CVE monitoring limited. | NIST RA-5, SI-2, SR-3; ISO A.5.21; CIS 7.3–7.4, 16.5; OWASP SCVS |
| A04:2025 Cryptographic Failures | Advanced | Transit: TLS 1.3 mandatory (Traefik), SSH AES-256-GCM, WireGuard, IPSec IKEv2 AES-256-GCM/SHA-384. At Rest: AES-256 encrypted backups, SSH key encryption. Key Mgmt: Step-CA two-tier PKI, Ed25519 keys, Vaultwarden zero-knowledge vault. Zero weak algorithms; zero cert expiry incidents. | Full disk encryption rollout. | NIST SC-8, SC-12, SC-13, SC-28; ISO A.8.24; CIS 13.10; PCI-DSS 4.2.1 |
| A05:2025 Injection | Advanced | SafeLine WAF with OWASP CRS (25% attack block rate). Traefik middleware header injection prevention. DNS query validation; SSH input sanitization; parameterized queries/ORM prevent SQL injection. CSP and X-XSS-Protection headers. PA-VM App-ID blocks injection-prone applications. Suricata IDS signatures forwarded to SIEM. | Advanced ML-based injection detection. | NIST SI-10, SI-4(23); ISO A.8.26; CIS 13.10; PCI-DSS 6.6 |
| A06:2025 Insecure Design | Advanced | Defense-in-depth: layered network/application/endpoint controls. DNS 3-tier design; Traefik reverse proxy isolation; VLAN + PA-VM zone segmentation. Zero trust: explicit verification, least privilege, assume breach. IaC immutable infrastructure (Terraform/Ansible). Fail-secure defaults: SSH passwords disabled, default encryption. Architecture documented in Git. | Formal threat modeling for all services. | NIST RA-3, SA-8, SA-17; ISO A.14.1, A.14.2; OWASP Secure Design |
| A07:2025 Authentication Failures | Advanced | Authentik TOTP MFA enforced 100% admin accounts. SSH key-only (passwords disabled globally). Step-CA certificate-based auth. Palo Alto admin auth via AD. Vaultwarden zero-knowledge vault; Ansible Vault encrypts all secrets; no hardcoded credentials. SSH MaxAuthTries=3; lockout after 5 failures; Wazuh Active Response; CrowdSec IP blocking. 30-min session timeout. | WebAuthn/FIDO2 full deployment. | NIST IA-2(1), IA-5(1), IA-5(7), AC-7; ISO A.5.17; CIS 6.3–6.5; PCI-DSS 8.3 |
| A08:2025 Software/Data Integrity Failures | Advanced | Code: Git version control; Terraform plan review; Ansible dry-run validation. Software: GPG package signature; Docker SHA-256; Step-CA cert validation; DNSSEC. Data: Wazuh FIM 100% critical paths; Zeek files.log SHA-256 file hashing; immutable SIEM indexes (Splunk read-only, Elastic immutable). Snapshot-before-patch; WSUS approvals; Git rollback. | Automated commit signing. | NIST SI-7, SI-7(1), CM-3; ISO A.12.1.2; CIS 2.3, 8.6 |
| A09:2025 Security Logging & Alerting Failures | Advanced | 100% event coverage: DNS, SSH, Traefik (JSON), Wazuh, scans, patch deployments, auth attempts, privileged operations. 90-day hot / 1-year cold retention. Immutable SIEM; syslog-ng TLS. Zeek JSON logs (conn/dns/http/ssl/files) added as network-layer source. Real-time alerting: Discord, Splunk, Prometheus, TheHive, Cortex, MISP, Shuffle. <60s latency; <3% false positive rate. | SIEM ML correlation enhancement. | NIST AU-2, AU-6(3), AU-9, SI-4(5); ISO A.8.15, A.8.16; CIS 8.2, 8.11; PCI-DSS 10.2, 10.5 |
| A10:2025 Mishandling of Exceptional Conditions (NEW 2025) | Advanced | Error Handling: Traefik circuit breakers; graceful degradation; pfSense/PA-VM default-deny (fail-secure); exception handling in automation scripts. Input Validation: boundary/type/range checking at all entry points. Resource Mgmt: SSH MaxStartups; Traefik connection pools; rate limiting; Kubernetes resource quotas. Health Monitoring: Uptime Kuma, Prometheus, Grafana, Wazuh service failure detection. Auto-recovery: systemd/Kubernetes health checks. | Chaos engineering validation. | NIST SC-5, SC-24, CP-10, SI-4; ISO A.17.1; CIS 13.3; OWASP Error Handling |

### Compliance Summary

| Metric | Result |
|---|---|
| Overall Score | 9/10 Strong (Advanced Maturity) · 1/10 Moderate |
| Only Gap Category | A03 — Software Supply Chain Failures (Developing; SBOM tracking planned Q2 2026) |
| Key Strength: Authentication | 100% MFA enforcement, no hardcoded credentials, SSH key-only, Step-CA PKI, PA-VM AD auth |
| Key Strength: Encryption | TLS 1.3 mandatory, AES-256-GCM, IPSec IKEv2, Ed25519, zero weak algorithms |
| Key Strength: Logging | 100% event coverage, dual SIEM, Zeek network metadata, ntopng flow data, <60s alert latency, immutable logs |
| Key Strength: Access Control | Authentik ForwardAuth 100%, RBAC, default-deny firewall/zones, PA-VM App-ID, SSRF prevention |
| Priority Action | Q2 2026 — Trivy/Grype SBOM tracking (closes A03 primary gap) |

---

## Zero Trust Architecture Implementation Summary

This cybersecurity lab demonstrates comprehensive Zero Trust Architecture (ZTA) principles aligned with **CISA Zero Trust Maturity Model v2.0** and **NIST Special Publication 800-207**. The implementation achieves **Advanced maturity** across all core pillars through explicit verification of every access request, least-privilege enforcement via role-based access control, assume-breach mentality with continuous monitoring, and encrypt-everything policies using modern cryptographic standards.

### Architecture Highlights

**Core Capabilities**

- Authentik SSO provides centralized identity verification for 50+ services via OAuth2/OIDC/SAML
- Palo Alto PA-VM NGFW: security zones enforce explicit segmentation; User-ID maps AD group membership to security policy; App-ID enforces application allowlisting at L7
- pfSense/OPNsense HA cluster: enclave gateway model with default-deny ACLs per VLAN
- Step-CA PKI: automated certificate lifecycle, ECDSA P-256, 90-day rotation, ACME/SCEP support
- Wazuh: continuous device compliance validation (92–98% CIS Benchmark), EDR across 25+ endpoints
- Zeek + ntopng: continuous network telemetry (protocol metadata + flow data) across 3 segments — provides behavioral baseline for continuous verification
- Shuffle SOAR + TheHive: automated incident response with 15+ playbooks, <30min MTTR

### CISA Zero Trust Maturity Model v2.0 Alignment

The CISA ZTMM defines four maturity stages across five core pillars (Identity, Devices, Networks, Applications & Workloads, Data) with three cross-cutting capabilities (Visibility & Analytics, Automation & Orchestration, Governance). This lab demonstrates Advanced-stage implementation across all pillars with targeted progression toward Optimal maturity.

| Pillar | Maturity | Evidence | Next Steps |
|---|---|---|---|
| Identity | Advanced | Authentik SSO 100%, MFA enforcement, cert-based auth, Palo Alto User-ID AD group policy | WebAuthn/FIDO2, biometric auth, Authentik-to-PA-VM SAML integration |
| Devices | Advanced | Wazuh compliance monitoring, Step-CA certs, endpoint inventory, GlobalProtect pre-logon cert | MDM/device posture assessment, full SBOM tracking (Trivy/Grype Q2 2026), HIP enforcement |
| Network/Environment | Advanced | Microsegmentation (VLAN + PA-VM zones), 3-tier architecture, IDS/IPS, Zeek/ntopng NSM, IPSec IKEv2 | Software-defined perimeter, PA-VM NetFlow export to ntopng, dynamic just-in-time connectivity |
| Application/Workload | Advanced | Container security, Traefik API gateway, SafeLine WAF, PA-VM App-ID application control | Service mesh (Istio), runtime protection, CI/CD security scanning Q2 2026 |
| Data | Advanced | Encryption everywhere (AES-256/TLS 1.3/IPSec), DLP planning, data classification | Full DLP deployment Q2 2026, data tagging, encryption-in-use |
| Visibility & Analytics (Cross-Cutting) | Advanced | 100% logging, dual SIEM, 90-day retention, Zeek NSM, ntopng flow dashboards, Grafana 20+ dashboards | ML-based analytics, UEBA deployment, PA-VM NetFlow/IPFIX integration |
| Automation & Orchestration (Cross-Cutting) | Advanced | Shuffle SOAR 15+ playbooks, Wazuh Active Response (<30min MTTR), IaC (Terraform/Ansible), automated patch mgmt, Step-CA cert automation | Predictive analytics, full privileged identity automation, dynamic adaptation |
| Governance (Cross-Cutting) | Advanced | Version-controlled policies (Git), Wazuh SCA, vulnerability SLAs (Critical <72h), quarterly reviews, documented compensating controls | Fully automated policies, threat-intel-driven policy creation, real-time adjustments |

**Overall ZTA Maturity: Advanced (6 of 8 pillars at Advanced level)**

### NIST SP 800-207 Zero Trust Architecture Alignment

#### Deployment Model

**Hybrid Approach:**

- **Device Agent/Gateway:** Authentik + Traefik for web services, SSH certificates for terminal access, Wazuh agents for compliance
- **Enclave Gateway:** pfSense/OPNsense/Palo Alto/Fortinet protecting network perimeters, dedicated VLANs for service tiers
- **Resource Portal:** Traefik reverse proxy for BYOD/contractor access without client agents
- **Trust Algorithm:** Hybrid score-based and criteria-based with contextual evaluation considering subject history, device posture, environmental factors, and real-time threat intelligence.

#### Zero Trust Tenets Achievement

| Tenet | Status | Implementation Evidence |
|---|---|---|
| 1. All resources explicitly defined | ✓ Advanced | 25+ hosts, 50+ containers tracked; NetalertX discovery; Proxmox inventory; PA-VM, NSM host, Zeek cluster, nProbe instances added |
| 2. Communication secured regardless of location | ✓ Advanced | TLS 1.3 mandatory; IPSec IKEv2 (AES-256-GCM) site-to-site; GlobalProtect endpoint VPN; WireGuard (Tailscale); no implicit trust by network location |
| 3. Per-session least privilege access | ✓ Advanced | 30-min session timeouts; OAuth2 scopes; temporary sudo; session-based authorization; Palo Alto User-ID per-session group policy |
| 4. Dynamic policy from observable state | ✓ Advanced | Device compliance + AD identity (User-ID) + behavior + threat intel inform access decisions |
| 5. Asset integrity monitoring | ✓ Advanced | Wazuh CIS compliance (92–98%), Nessus scans, PatchMon 5,000+ packages, drift detection, Zeek file hashing |
| 6. Dynamic authentication/authorization | ✓ Advanced | MFA enforcement, continuous session evaluation, threat-triggered re-auth, Palo Alto User-ID real-time AD mapping |
| 7. Comprehensive telemetry collection | ✓ Advanced | Dual SIEM, 100% event logging, Zeek protocol metadata (3 segments), ntopng/nProbe flow data (5 infrastructure sources), multi-source correlation |

#### Key Technologies Deployed

| Category | Technologies | Maturity |
|---|---|---|
| Identity & Access | Authentik SSO, OAuth2/OIDC/SAML, Step-CA PKI, MFA (TOTP/FIDO2 planning), Palo Alto User-ID/AD integration | Advanced |
| Endpoint Security | Wazuh EDR (25+ agents), ClamAV, Microsoft Defender, CIS Benchmark SCA | Advanced |
| Network Security | pfSense/OPNsense HA, Palo Alto PA-VM (App-ID/Threat Prevention/User-ID/IPSec/GlobalProtect), Suricata/Snort IDS, Traefik, SafeLine WAF | Advanced |
| Network Monitoring (New) | Zeek cluster (manager+proxy+3 workers, AF_PACKET), ntopng + dual nProbe (Cisco flows/FW flows), Brim/ZUI forensics | Advanced |
| Vulnerability Mgmt | Nessus, PatchMon (5,000+ packages), OpenVAS, OWASP ZAP, Burp Suite | Advanced |
| SIEM & Analytics | Splunk, Elastic Stack, Grafana, Prometheus, Wazuh correlation | Advanced |
| Orchestration | Shuffle SOAR (15+ playbooks), TheHive case mgmt, Cortex analysis, MISP threat intel | Advanced |
| Infrastructure | Proxmox VE, Docker, Kubernetes, Terraform, Ansible, Git version control | Advanced |
| Encryption | TLS 1.3, AES-256-GCM, Ed25519, IPSec IKEv2 (AES-256-GCM/SHA-384/DH20), WireGuard, syslog-ng TLS, Vaultwarden | Advanced |
| Monitoring | Uptime Kuma (50+ monitors), Checkmk, NetalertX, Technitium DNS, Prometheus exporters | Advanced |

---

## PCI-DSS v4.0 Conceptual Alignment Summary

Conceptual alignment with PCI-DSS v4.0 requirements through defense-in-depth security controls, comprehensive logging, strong cryptography, and continuous vulnerability management. The lab processes no actual cardholder data (CHD) or sensitive authentication data (SAD). Security architecture implements PCI-DSS technical and operational controls as a learning framework demonstrating compliance-ready capabilities.

**Overall: 85% Conceptual Compliance (Technical Controls Implemented)**

**Note:** As a personal homelab processing no cardholder data, formal PCI-DSS certification is not required. Implementation demonstrates compliance-ready technical controls suitable for production CDE deployment with appropriate governance additions (policies, procedures, formal assessments, QSA validation).

### Requirement-by-Requirement Analysis

| Requirement | Domain | Level | Key Implementation | Gaps / Limitations |
|---|---|---|---|---|
| 1.1.1, 1.2.1, 1.3.1, 1.4.2 | Req 1: Network Security Controls | Strong 95% | Network topology documented in Git (3-tier: DMZ, application, backend). Default-deny firewall policies on pfSense/OPNsense/PA-VM. Palo Alto security zones enforce inter-zone deny by default. DMZ isolates Traefik/public DNS from internal networks. Egress filtering; CrowdSec behavioral blocking. Cloudflare Tunnels + Tailscale VPN for remote access without exposed IPs. | Formal PCI-annotated network diagrams; PA-VM NetFlow export to ntopng pending. |
| 2.2.2, 2.2.4 | Req 2: Secure Configuration | Strong 92–98% | CIS Benchmark compliance 92–98% (SSH, firewalls, DNS, web servers, PA-VM) via Ansible/Terraform IaC. Wazuh SCA enforces baseline with automated drift detection. SSH: root login disabled, password auth disabled, MaxAuthTries=3. Traefik: HSTS, CSP, X-Frame-Options, TLS 1.3 minimum. Firewall: default-deny, anti-spoofing, state tracking. Unnecessary services disabled; default accounts removed. | Container configuration scanning. |
| 4.2.1 | Req 4: Cryptography | Strong 100% | Transit: TLS 1.3 mandatory (Traefik), SSH AES-256-GCM, WireGuard (ChaCha20), IPSec IKEv2 AES-256-GCM/SHA-384, syslog-ng TLS, DNSSEC. At Rest: AES-256 encrypted backups (PBS), SSH private key encryption, Vaultwarden zero-knowledge vault, Ansible Vault for secrets. Modern cipher suites only; zero weak algorithms verified via Nessus scans. | Full disk encryption rollout. |
| 6.3.3, 6.4.3 | Req 6: Vulnerability Management | Strong 95% | Patch management: <72h MTTR critical CVEs, <7-day high (exceeds 1-month PCI requirement). PatchMon tracks 5,000+ packages across 30+ hosts daily. WSUS for Windows; Watchtower for containers; CVSS-based prioritization. Asset inventory: PatchMon, WUD (50+ containers), OpenVAS (75+ assets), Nessus, Wazuh (25+ endpoints), Checkmk, NetalertX, DNS records. | Formal penetration testing program. |
| 8.2.1, 8.2.2, 8.2.3, 8.2.5, 8.3.2 | Req 8: Access Control | Strong 100% | Unique IDs: individual accounts via Authentik SSO, Active Directory, SSH key infrastructure; no shared credentials. Auth: Ed25519 SSH key-only (passwords disabled globally); 14-char minimum passwords; Vaultwarden enforces uniqueness. MFA: 100% admin accounts via Authentik TOTP; SSH key + passphrase (inherent 2FA); Tailscale device auth. No shared/group accounts enforced via Authentik/AD policy. Secrets: Ansible Vault, no hardcoded credentials. | WebAuthn/FIDO2 full deployment. |
| 10.2, 10.3, 10.5, 10.6 | Req 10: Logging & Monitoring | Strong 100% | 100% security event coverage: DNS (Unbound), SSH (auth.log), Traefik (JSON), Wazuh, scans, patch deployments, auth attempts, privileged operations, firewall events, IDS alerts, FIM changes. Zeek JSON logs (conn/dns/http/ssl/files) and ntopng flow records added as network-layer audit sources. Log detail: NTP-synced timestamps, user identity, source IP, action, result. Immutable SIEM (Splunk read-only, Elastic immutable); syslog-ng TLS. 90-day hot / 1-year cold retention. Weekly Splunk reviews; real-time Discord/email/TheHive alerting. | SIEM ML correlation enhancement. |
| 11.3.1, 11.3.2, 11.4.1, 11.4.2 | Req 11: Testing & Monitoring | Strong 100% | Scans: Weekly OpenVAS (52/yr) + monthly Nessus authenticated (12/yr) exceed quarterly requirement. Daily PatchMon package checks; Wazuh SCA real-time compliance. 75+ assets covered. Operated by qualified security professional with documented CVSS prioritization methodology. IDS/IPS: Suricata inline (all segments), Snort passive, Palo Alto Threat Prevention inline IPS, CrowdSec behavioral, Wazuh host-based IDS 25+ endpoints. Daily signature updates: Suricata/Snort (Emerging Threats, abuse.ch), CrowdSec community feeds, MISP IOC updates, Yara signatures. | Annual external penetration test. |

### Compliance Summary

| Requirement Domain | Level | Key Controls | Gaps / Limitations |
|---|---|---|---|
| Req 1: Network Security | Strong (95%) | Segmentation, DMZ, default-deny ACLs, PA-VM zone architecture | Formal PCI-annotated network diagrams |
| Req 2: Secure Configuration | Strong (92–98%) | CIS Benchmarks, Ansible/Terraform IaC, Wazuh SCA drift detection, PA-VM hardening | Container configuration scanning |
| Req 4: Cryptography | Strong (100%) | TLS 1.3, AES-256-GCM, IPSec IKEv2, Ed25519, Step-CA PKI, zero weak algorithms | Full disk encryption rollout |
| Req 6: Vulnerability Management | Strong (95%) | <72h critical MTTR, weekly/monthly scans, 5,000+ packages tracked | Formal penetration testing program |
| Req 8: Access Control | Strong (100%) | Unique IDs, MFA 100% admin, SSH key-only, no shared accounts, Ansible Vault secrets | WebAuthn/FIDO2 implementation |
| Req 10: Logging & Monitoring | Strong (100%) | 100% event coverage, Zeek/ntopng network logs, 90-day retention, immutable SIEM, real-time alerting | SIEM ML correlation enhancement |
| Req 11: Testing | Strong (100%) | Weekly/monthly scans, Suricata/Palo Alto IPS, daily signature updates, MISP IOC feeds | Annual external penetration test |
| Overall | 85% Conceptual | Technical controls fully implemented; governance additions required for formal certification | QSA validation, formal policies, no CHD processing |

---

## Framework Coverage Summary

| Framework | Coverage | Key Metric | Status |
|---|---|---|---|
| NIST CSF 2.0 | 100% function coverage | Tier 3–4 across all 6 functions | Updated: PROTECT/DETECT expanded |
| CIS Controls v8.1 | 93% IG1 / 81% IG2 / 52% IG3 | 159 safeguards across 18 controls mapped | Updated: Controls 12/13 significantly advanced |
| ISO 27001:2022 | 77% overall / 91% tech controls | 97% of applicable controls mapped | Updated: A.8.16/A.8.20 NSM coverage added |
| NIST SP 800-53 Rev 5 | 100% AU, 95% IA/SC/CM, 90% AC/SI | 18 control families; 324+ requirements | Updated: AC-3, AC-17, SI-4, SC-7/8/13 expanded |
| PCI-DSS v4.0 | 85% technical controls | 12 requirements conceptually aligned | No change |
| OWASP Top 10 (2025) | 9/10 Strong \| 1/10 Moderate | A03 supply chain gap remains | No change |
| MITRE ATT&CK v18.1 | 30% (65/216 techniques) | 12 tactics covered; T1046/T1133 upgraded | Updated: T1046 Implemented; T1133 Implemented |
| CISA ZTMM v2.0 | Advanced (Stage 3/4) | 6 of 8 pillars at Advanced; Visibility gap closed | Updated: Visibility & Analytics gap resolved |
| NIST SP 800-207 | Advanced — all 7 ZT tenets | Tenet 7 telemetry strengthened | Updated: NSM + PA-VM User-ID expand PEP/telemetry |

This summary demonstrates defense-in-depth implementation across nine major cybersecurity frameworks. Infrastructure updates (Palo Alto PA-VM NGFW, Zeek/ntopng NSM sensor, Cisco/VLAN enhancements) advance maturity across PROTECT, DETECT, and Zero Trust pillars — resolving noted gaps in network visibility, identity-aware policy enforcement, and encrypted VPN coverage.

---

## Strategic Roadmap

| Priority | Action | Framework Impact |
|---|---|---|
| Critical | Enable Kerberos event logging (EID 4768/4769) | MITRE T1558; NIST AU-2; CIS 8.5 |
| Critical | Implement pass-the-hash/ticket detection (EID 4624/4625 type 9) | MITRE T1550; NIST SI-4; CIS 13.6 |
| Critical | Enable comprehensive WMI logging | MITRE T1047; CIS 8.5 |
| High | Deploy Trivy/Grype SBOM tracking | NIST SR-3; CIS 2.5; OWASP A03; MITRE T1195 |
| High | Implement PA-VM NetFlow/IPFIX export to ntopng | CIS 13.6; SI-4; DE.CM-01; ntopng coverage completion |
| High | Configure User-ID for Linux hosts (syslog-based mapping) | NIST AC-3; CIS 6.8; CISA Identity pillar |
| High | Authenticate Authentik SAML integration with Palo Alto | NIST 800-207 PEP; CISA Identity; ZTA dynamic policy |
| High | GlobalProtect HIP enforcement (OS patch level, AV status) | NIST IA-3; CISA Devices pillar; AC-17 |
| High | Deploy formal DLP solution | NIST MP-2; CIS 3.13; ISO A.8.12; MITRE T1048/T1537 |
| Medium | Implement share enumeration monitoring (T1135) | MITRE T1135; CIS 8.5; NIST SI-4 |
| Medium | Deploy CI/CD pipeline security scanning | OWASP A03; CIS 16.12; NIST SA-11 |
| Medium | Implement TLS inspection/JA3S fingerprinting infrastructure | MITRE T1573; CIS 13.10; NIST SC-7 |
| Low | Deploy firmware integrity checks (UEFI/BIOS monitoring) | MITRE T1495; NIST SI-7; CIS 10.5 |
| Low | Implement 802.1X port-level NAC | CIS 13.9 (IG3); NIST AC-3; CISA Networks Optimal |
