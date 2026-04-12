# Security Lab - Governance, Risk and Compliance Summary

**Document Control:**  
Version: 2.0  
Last Updated: April 2026  
Owner: Paul Leone  

**Framework Versions:** NIST CSF 2.0, CIS Controls v8.1, NIST SP 800-53 Rev 5, ISO 27001:2022, MITRE ATT&CK Enterprise v18.1, CISA ZTMM v2.0, NIST SP 800-207 Zero Trust, AICPA SOC 2 (TSC)

---

## Executive Overview

### Framework Alignment with Lab Mission

This cybersecurity lab demonstrates production-ready security capabilities aligned with nine industry-standard frameworks, each validating specific aspects of the lab's mission: enterprise-grade SecOps, Systems Engineering, Network Defense, and multi-cloud hybrid operations.

### Mission Alignment by Framework

**NIST Cybersecurity Framework 2.0** validates threat detection & response capabilities across all six functions (Govern, Identify, Protect, Detect, Respond, Recover). Tier 3–4 maturity with automated incident response reducing MTTR to <30 minutes. Cloud integration strengthens IDENTIFY, PROTECT, and DETECT functions.

**CIS Controls v8.1** validates defense-in-depth architecture through 93% IG1 and 81% IG2 compliance. Controls map to enterprise infrastructure operations with automated patch management across 5,000+ packages, comprehensive security monitoring, and cloud asset inventory integration.

**ISO 27001:2022** validates security engineering & automation through 77% overall control coverage, with 91% technological controls. Policy-driven architecture with CIS Benchmark compliance, IaC automation, comprehensive audit capabilities, and A.5.23 (Cloud Services) fully implemented.

**NIST SP 800-53 Rev 5** validates technical security engineering depth with strong implementation across Access Control (90%), Audit & Accountability (100%), and System Integrity (90%). Cloud controls integrated per family via Notes column additions in v2.0.

**MITRE ATT&CK Enterprise v18.1** validates operational threat detection through 30% technique coverage (65/216 techniques) across 12 adversary tactics. Cloud containment actions integrated where applicable (T1562 Impair Defenses, T1537 Transfer Data to Cloud Account).

**CISA Zero Trust Maturity Model v2.0** achieves Advanced maturity (Stage 3/4) across all 5 pillars and 3 cross-cutting capabilities. Cloud integration across all pillars; no change to overall maturity rating.

**NIST SP 800-207** demonstrates implementation of all 7 Zero Trust tenets at Advanced maturity. Multi-cloud Use Case 2 (Cloud-to-Cloud) advanced from Medium to High applicability.

**AICPA SOC 2 Trust Services Criteria (CC1-CC9)** demonstrates Strong coverage (30/33 criteria implemented) with hybrid cloud scope (AWS, Azure, GCP) included from initial release.

### Architectural Principles Demonstrated

**Defense in Depth** validated across all frameworks:

- Network perimeter: pfSense/OPNsense HA cluster, Palo Alto PA-VM NGFW (App-ID, Threat Prevention, User-ID), FortiGate 30D, Suricata/Snort IPS, SafeLine WAF
- Network visibility: Zeek NSM (protocol metadata, 3-segment coverage), ntopng/nProbe (NetFlow v9 from Cisco R1/R2/R3, 3560X, firewalls)
- Endpoint: Wazuh EDR 25+ on-premises endpoints + 6 cloud nodes (31+ total); CIS Benchmark SCA 92-98%
- Identity: Authentik SSO, Active Directory, Palo Alto User-ID AD integration, Step-CA PKI
- Cloud: AWS Security Groups, GCP VPC firewall policy (Google Threat Intelligence blocking), Azure NSG, Cloud Armor WAF/DDoS, GuardDuty/SCC/Defender for Cloud

**Secure by Design** validated through:

- Mandatory encryption: TLS 1.3, AES-256, IPSec IKEv2 AES-256-GCM/SHA-384, GlobalProtect TLS 1.3, Tailscale WireGuard (ChaCha20-Poly1305)
- Authenticated access: MFA (100% admin accounts), SSH key-based, certificate-based (Step-CA), Palo Alto AD-integrated admin auth
- Least privilege: Authentik RBAC, Palo Alto User-ID group-based policy, AD security groups, AWS IAM instance profiles, GCP minimal service accounts, Azure RBAC per resource group
- IaC automation: Terraform, Ansible, Git version control; cloud IaC via ARM templates and cloud Terraform modules

**Zero Trust Architecture** validated through:

- Identity verification: MFA enforcement, Palo Alto User-ID AD mapping, Authentik SSO 100% coverage; cloud console access enforces provider MFA; no passwords on cloud SSH nodes
- Network micro-segmentation: VLAN isolation, pfSense/OPNsense zone enforcement, Palo Alto security zones; cloud: AWS VPC, GCP VPC, Azure VNet each isolated; Tailscale ACL default-deny
- Encrypted communications: TLS 1.3, IPSec IKEv2, GlobalProtect, WireGuard; all cloud management traffic via Tailscale; no public management ports on any cloud node
- Assume-breach monitoring: Zeek protocol metadata, ntopng flow analysis, dual SIEM, 100% event logging; cloud: CloudTrail, GCP Audit Logs, Azure Activity Log, VPC flow logs

### Multi-Cloud Hybrid Scope (v2.0)

| Provider | Nodes | OS | Native Security Services |
|----------|-------|-----|--------------------------|
| AWS (us-east-2) | 2 | Amazon Linux 2, Windows Server 2025 | GuardDuty, Security Hub, CloudTrail, VPC Flow Logs, Inspector |
| Azure (North Central US) | 2 | Ubuntu 24.04 LTS, Windows Server 2025 | Defender for Cloud, Sentinel, Entra ID, DDoS Protection, Log Analytics |
| GCP (us-central1) | 2 | Debian 13.4, Ubuntu | Security Command Center, Cloud Armor, VPC Firewall Policy, Cloud Logging, Network IDS |

All 6 cloud nodes enrolled in on-premises management stack: Wazuh EDR (CIS SCA), PatchMon (Linux), WSUS (Windows), Checkmk, Ansible, Uptime Kuma. DNS resolves via on-premises Unbound (192.168.1.153/154) over Tailscale. No public management ports on any cloud instance.

### Framework Purpose & Organizational Value

| Framework | Purpose | Organizational Value |
|-----------|---------|----------------------|
| NIST CSF 2.0 | Risk-based framework across six core functions (Govern, Identify, Protect, Detect, Respond, Recover). | Board-level reporting, vendor risk assessments, strategic planning, maturity benchmarking. |
| CIS Controls v8.1 | Prescriptive, prioritized safeguards in three Implementation Groups (IG1/IG2/IG3). | Security program development, gap analysis, resource allocation. IG1 addresses 80% of common attacks. |
| ISO 27001:2022 | ISMS requirements with 93 controls across organizational, people, physical, and technological domains. | Third-party certification, GDPR/HIPAA alignment, competitive differentiation. |
| NIST SP 800-53 Rev 5 | Comprehensive security/privacy controls across 20 families for federal and regulated systems. | FedRAMP, FISMA, authoritative technical baseline for government contractors. |
| MITRE ATT&CK v18.1 | Adversary TTPs based on real-world observations. 216 techniques / 475 sub-techniques. | Threat-based testing, detection engineering, SOC playbook development, purple team exercises. |
| CISA ZTMM v2.0 | Four maturity stages across 5 pillars + 3 cross-cutting capabilities for zero trust adoption. | EO 14028 compliance, modernization roadmaps, zero trust investment prioritization. |
| NIST SP 800-207 | Foundational principles and logical architecture for zero trust via seven core tenets. | Architecture design, RFP requirements, vendor solution validation against federal standards. |
| AICPA SOC 2 (TSC) | Security Common Criteria (CC1-CC9) evaluation for service organization controls. | Audit-readiness demonstration, service organization trust, customer assurance. |

### Overall Lab Assessment

**Operational Security Excellence**

- 100% security event logging with dual SIEM (Splunk + Elastic) providing <5min MTTD
- Automated incident response via Shuffle SOAR achieving <30min MTTR with 15+ documented playbooks
- Multi-layered threat detection: Suricata/Snort/Palo Alto Threat Prevention IPS, Wazuh EDR (31+ endpoints), CrowdSec behavioral, Zeek protocol metadata, ntopng flow analysis, cloud-native ML (GuardDuty, SCC, Sentinel)
- Comprehensive vulnerability management: weekly OpenVAS + monthly Nessus, <72hr critical MTTR — enforced identically across on-premises and cloud nodes

**Technical Architecture Maturity**

- Defense-in-depth across network (VLAN + PA-VM zone segmentation, pfSense/OPNsense/Palo Alto firewalls, IDS/IPS), application (WAF, reverse proxy), endpoint (EDR, FIM), and identity (SSO, MFA, PKI) layers
- NSM sensor (Zeek + ntopng/nProbe): SOC-grade network visibility across Prod_LAN, Lab_LAN1, Lab_LAN2 — full protocol metadata + NetFlow v9 from all Cisco devices and firewalls
- IaC (Terraform, Ansible) with version control and audit trails; cloud IaC in same Git repository
- Advanced cryptography: TLS 1.3, AES-256, IPSec IKEv2 AES-256-GCM, ECDSA P-256, Ed25519 SSH keys, Step-CA PKI, WireGuard (ChaCha20-Poly1305)
- High availability: HA firewall cluster, dual SIEM, dual DNS <5s failover, redundant internet

### Framework Compliance Summary

| Framework | Score / Maturity | Key Metric |
|-----------|-----------------|------------|
| NIST CSF 2.0 | Tier 3–4 (Repeatable → Adaptive) | 100% function coverage |
| CIS Controls v8.1 | 93% IG1 / 81% IG2 / 52% IG3 | 159 safeguards mapped |
| ISO 27001:2022 | 77% overall / 91% technological | 55 implemented, 14 partial |
| NIST SP 800-53 Rev 5 | 100% AU / 95% IA / 95% SC / 90% SI / 90% AC | 18 control families |
| CISA ZTMM v2.0 | Advanced (Stage 3/4) | 6 of 8 pillars at Advanced |
| NIST SP 800-207 | Advanced — all 7 ZT tenets | Use Case 2 (Multi-Cloud) advanced to High |
| MITRE ATT&CK v18.1 | 30% technique coverage | 65 of 216 techniques |
| AICPA SOC 2 (TSC) | Strong | 30/33 criteria implemented |

### Infrastructure Updates (v1.2 → v2.0)

| Update | Components | GRC Impact |
|--------|-----------|------------|
| Palo Alto PA-VM NGFW | PAN-OS; App-ID; Threat Prevention; User-ID/AD; IPSec IKEv2; GlobalProtect VPN; security zone architecture | Advances PR, AC-17, SC-7/8, IA-2, CISA Networks/Identity, MITRE T1133/T1190 |
| NSM Sensor: Zeek | 3-worker AF_PACKET cluster; DNS/HTTP/SSL/SSH/SMB/RDP/DCE-RPC analyzers; Notice/Intel/Weird frameworks; JSON to Elastic + Brim/ZUI | Closes CISA Visibility gap; advances DE.CM-01, SI-4, CIS 13.1/13.2 |
| NSM Sensor: ntopng/nProbe | Dual nProbe (Cisco flows UDP/2055, FW flows UDP/2056); ntopng web UI port 3000 | Completes CIS 13.6 NetFlow; advances SI-4, AU-12, DE.CM-01 |
| Multi-Cloud (AWS/Azure/GCP) | 6 nodes via Tailscale WireGuard; Wazuh, PatchMon, Checkmk, Ansible across all providers; cloud-native security services | Extends all 9 frameworks to hybrid cloud scope; adds SA-9, SR-3, CM-8, A.5.23 cloud coverage |
| AICPA SOC 2 Added | CC1-CC9 Trust Services Criteria (Security Common Criteria) | New framework: 30/33 criteria implemented; strong CC5-CC8 coverage |
| Cisco/VLAN Enhancements | OSPF MD5 auth; 3560X DHCP snooping VLANs 10/20/30/100/120/200; uRPF on R3 | Strengthens SC-7, CIS 12.1/12.2, PR.IR-01, network segmentation evidence |

---

## NIST Cybersecurity Framework 2.0 Implementation Summary

**Overall Maturity: Tier 3 (Repeatable) — Approaching Tier 4 (Adaptive)**

### Function Implementation Analysis

| Function | Tier | Implementation Summary | Cloud Extension |
|----------|------|------------------------|-----------------|
| GOVERN (GV) | Tier 3 | CVSS-based risk prioritization; SLAs: Critical <72h, High <7d; policies version-controlled in Git; PAN-OS update lifecycle in supply chain controls. | Cloud policies: no public management ports, Tailscale-only access, CIS SCA via Wazuh, IAM least-privilege per provider. |
| IDENTIFY (ID) | Tier 4 | Automated asset discovery: 30+ hosts, 5,000+ packages (PatchMon), 50+ containers (WUD); MITRE ATT&CK mapping; MISP threat intelligence. | 6 cloud nodes tracked in Checkmk, Wazuh, PatchMon via Tailscale; cloud VPC/VNet topology documented; CloudTrail/GCP Audit/Azure Monitor for asset lifecycle. |
| PROTECT (PR) | Tier 4 | Authentik SSO/MFA; TLS 1.3/AES-256; PA-VM App-ID/User-ID/IPSec/GlobalProtect; Step-CA PKI; IaC (Terraform/Ansible); CIS Benchmark audits. | Wazuh CIS SCA on all 6 cloud nodes; PatchMon/WSUS patch management; Ansible hardening via Tailscale; no public ports on any cloud instance. |
| DETECT (DE) | Tier 3 | 100% network visibility; Zeek NSM (3 segments); ntopng/nProbe (NetFlow); PA-VM Threat Prevention; dual SIEM <5min MTTD. | GuardDuty ML-based detection; GCP SCC asset/vulnerability/IDS; Azure Sentinel KQL rules (NSG spikes, geo sign-in anomalies, AMA data gaps). |
| RESPOND (RS) | Tier 3 | 15+ TheHive playbooks; Shuffle SOAR; Cortex analysis; Wazuh Active Response; Zeek forensic metadata; PA-VM EDL for rapid IOC blocking. | Wazuh Active Response on cloud nodes via Tailscale; GuardDuty/Sentinel auto-create TheHive cases via Shuffle. |
| RECOVER (RC) | Tier 3 | AES-256 encrypted backups (bi-weekly PBS); snapshot rollback; HA DNS failover <5s; IaC rebuild <2hr RTO; documented RTO/RPO. | Cloud node rebuild via Ansible; RTO <2hr validated; Azure Spot eviction/restart documented; Uptime Kuma tunnel health monitoring. |

### Key Achievements

- **100% Function Coverage:** All six CSF 2.0 functions with documented processes and automated controls; now spanning on-premises and multi-cloud (AWS/Azure/GCP) scope
- **Multi-Cloud EDR:** Wazuh agents deployed on all 6 cloud nodes with CIS SCA policies matching on-premises baselines
- **Zero Public Management Exposure:** No public management ports on any cloud instance — all SSH/RDP via Tailscale WireGuard with device-bound authentication
- **Cloud-Native Threat Detection:** GuardDuty (ML, VPC flow/CloudTrail/DNS), GCP SCC (asset, vulnerability, network IDS), Azure Defender for Cloud + Sentinel (KQL rules) operating in parallel with on-premises SIEM/EDR
- **Automated Response:** Shuffle orchestration reduces MTTR by 70% vs manual workflows; Wazuh Active Response containment extended to cloud nodes via Tailscale
- **Cloud Recovery Validated:** Cloud node rebuild from Ansible playbooks tested; RTO <2hr achieved

---

## CIS Critical Security Controls v8.1 Implementation Summary

93% IG1 / 81% IG2 / 52% IG3 compliance. 159 safeguards across 18 control families.

### Implementation Group Compliance

**IG1 (Basic Cyber Hygiene) — 93% Compliant**

52 of 56 safeguards fully implemented. Complete coverage of foundational controls: asset inventory (1–2), data protection (3), patch management (7), centralized logging (8), malware defenses (10), backup/recovery (11). Gaps: application allowlisting (2.5), weekly unauthorized asset reviews (1.2), comprehensive data flow diagrams (3.8), formal secure configuration policy documentation (4.1).

**IG2 (Enhanced Security) — 81% Compliant**

60 of 74 additional safeguards implemented. Advanced monitoring exceeds requirements. Palo Alto App-ID/Threat Prevention advance Controls 12 and 13. Gaps: Network AAA (12.5), allowlisting (2.5–2.7), remote wipe (4.11), pen testing (18.1–18.2), RBAC documentation (6.8).

**IG3 (Advanced Security) — 52% Compliant**

15 of 29 additional safeguards implemented. Host-based IPS (Wazuh Active Response), network IPS (Suricata inline + PA Threat Prevention), WAF (SafeLine). Gaps: 802.1X NAC (13.9), DLP (3.13), mobile containerization (4.12), SAST/DAST (16.12).

### Control-by-Control Analysis

| Control | Score | Notes |
|---------|-------|-------|
| 1: Asset Inventory | 99% | Cloud inventory integrated: 6 nodes in Checkmk, Wazuh, PatchMon, Tailscale admin console. |
| 2: Software Inventory | 70% | Allowlisting gaps remain. PatchMon extended to cloud nodes. |
| 3: Data Protection | 95% | IG1/IG2 complete. Cloud encryption: AWS S3 SSE, GCP disk/GCS, Azure Managed Disk + Log Analytics. |
| 4: Secure Configuration | 75% | PA-VM baseline added. Formal policy documentation needed. |
| 5: Account Management | 100% | Cloud IAM accounts integrated into lifecycle management. |
| 6: Access Control | 90% | Palo Alto User-ID strengthens identity-based access. RBAC documentation needed. |
| 7: Vulnerability Management | 100% | Exceeds all baselines. Cloud scanning: Wazuh SCA, Inspector, SCC, Defender for Cloud. |
| 8: Audit Log Management | 98% | Zeek JSON and ntopng flow data added. Cloud audit logs integrated. |
| 9: Email/Web Protection | 65% | Limited by homelab scope. DNS filtering extended to cloud nodes. |
| 10: Malware Defenses | 100% | ClamAV on Linux cloud nodes; Defender on Windows cloud nodes; GuardDuty/SCC/Defender behavioral detection. |
| 11: Data Recovery | 100% | Cloud node recovery runbooks documented and tested; RTO <2hr. |
| 12: Network Infrastructure | 88% | PA-VM zone architecture + IPSec/GlobalProtect improve 12.2/12.3/12.7. Lacks AAA (12.5). |
| 13: Network Monitoring | 93% | Zeek (13.1/13.2) + ntopng/nProbe (13.6) + PA-VM Threat Prevention (13.8). R2 NetFlow gap closed. Lacks 802.1X (13.9). |
| 16: Application Security | 60% | Infrastructure focus; custom dev minimal. SBOM planned Q2 2026. |
| 17: Incident Response | 85% | Shuffle SOAR + TheHive playbooks. Cloud node IR runbooks documented. |
| 18: Penetration Testing | 40% | Vulnerability scanning substitute; formal testing not conducted. |

---

## ISO 27001:2022 Annex A Implementation Summary

77% overall coverage (55 implemented, 14 partial, 2 not implemented, 22 N/A). 91% applicable technological controls.

### Control Domain Analysis

| Domain | Coverage | Key Highlights |
|--------|----------|----------------|
| 5. Organizational Controls (37 total) | 71% (22/31 applicable) | Threat intel (MISP/CrowdSec/GuardDuty/SCC/Sentinel); asset inventory 5,000+ packages; TLS 1.3 transfer (A.5.14); Authentik SSO (A.5.15); TheHive/Shuffle IR (A.5.24–28); Cloud IaaS security (A.5.23) fully implemented. |
| 6. People Controls (8 total) | 100% (2/2 applicable) | Remote working (A.6.7): Tailscale, GlobalProtect, MFA, TLS 1.3; security event reporting (A.6.8): Discord/email/TheHive + cloud alerting (SNS, GCP alerts, Azure Monitor action group). |
| 7. Physical Controls (14 total) | 33% (2/4 applicable) | Residential homelab constraints. Cloud physical security delegated to provider (AWS/GCP/Azure SOC 2 / ISO 27001 certified data centers). |
| 8. Technological Controls (34 total) | 91% (29/32 applicable) | Wazuh EDR 31+ endpoints; MFA 100% admin; multi-engine malware defense; weekly OpenVAS + monthly Nessus; PA-VM Threat Prevention (A.8.7/A.8.20); Zeek/ntopng NSM (A.8.16/A.8.20). |

**Key Strengths:** Technological excellence at 91%; enterprise-grade NSM; incident response maturity (15+ playbooks, SOAR orchestration); encryption everywhere (TLS 1.3, IPSec IKEv2, AES-256-GCM, Ed25519, DNSSEC); high availability.

**Remaining Gaps:** Formal DLP (A.8.12, planned Q2 2026), information labeling (A.5.13).

---

## NIST SP 800-53 Rev 5 Implementation Summary

324+ requirements across 18 families. High maturity in technical families (AC, AU, IA, SC, SI) at 85%+ implementation.

### Control Family Compliance

| Family | Score | Notes |
|--------|-------|-------|
| Access Control (AC) | 90% | 27/30 implemented. Authentik SSO/MFA, AD RBAC, session management. PA-VM User-ID (AC-3); GlobalProtect + IPSec (AC-17). Cloud: all SSH/RDP restricted to homelab subnets via provider-native firewall rules; Tailscale mandatory. |
| Audit & Accountability (AU) | 100% | 18/18 implemented. Dual SIEM, 100% event coverage, 90-day hot/1-year cold. Cloud: CloudTrail, GCP Admin Activity, Azure Activity Log forwarded to on-premises Splunk via Wazuh agents. |
| Assessment & Authorization (CA) | 80% | Weekly OpenVAS + monthly Nessus. Cloud: GuardDuty, SCC, Defender for Cloud as CA-7 continuous monitoring; cloud findings feed TheHive. |
| Configuration Management (CM) | 95% | Ansible/Terraform IaC, Git, CIS baselines, 5,000+ package inventory. Cloud: ARM templates and cloud Terraform modules in Git; Ansible applies CIS baselines to cloud nodes via Tailscale. |
| Contingency Planning (CP) | 75% | PBS bi-weekly encrypted backups, quarterly restore testing, HA DNS, <2hr IaC RTO. Cloud: cloud node rebuild tested; Azure Spot eviction/restart documented. |
| Identification & Auth (IA) | 95% | Step-CA two-tier PKI, Ed25519 SSH, Authentik OIDC, MFA. Cloud: SSH key-only for Linux cloud nodes; Windows cloud nodes domain-joined via Tailscale (Kerberos, AD CS). |
| Incident Response (IR) | 90% | TheHive 15+ playbooks, Shuffle SOAR, Cortex, Wazuh Active Response on all 31+ endpoints including cloud. |
| Risk Assessment (RA) | 85% | CVSS scoring, daily PatchMon, weekly OpenVAS, monthly Nessus, 75+ assets. Cloud: Inspector, SCC, Defender for Cloud supplement Wazuh scanning. |
| System & Comm Protection (SC) | 95% | TLS 1.3, Ed25519, AES-256-GCM, Step-CA PKI. SC-7 includes PA-VM App-ID + Threat Prevention + cloud boundary protection (Security Groups, VPC firewall policy, NSG, Cloud Armor, DDoS). |
| System & Info Integrity (SI) | 90% | Wazuh FIM/EDR, Suricata/Snort/PA-VM IPS, ClamAV/Defender, automated patching. SI-4 extended with Wazuh agent telemetry from all 6 cloud nodes. |
| Supply Chain (SR) | 40% | Vetted open-source, Docker SHA-256, secure deletion. Cloud: IAM least-privilege, minimal service accounts, ARM securestring params. |

---

## MITRE ATT&CK Enterprise v18.1 Implementation Summary

**Framework version:** ATT&CK v18.1 (October 2025). **Total techniques:** 216. **Total sub-techniques:** 475. **Lab coverage:** 30% (65/216 techniques across 12 tactics).

Coverage decreased from 34% to 30% due to v18.1 adding 25 new techniques (13% denominator growth). T1537 upgraded MINIMAL to PARTIAL with cloud storage monitoring additions.

| Tactic | Coverage | Maturity | Key Notes |
|--------|----------|----------|-----------|
| Initial Access (TA0001) | 67% (6/9) | Strong | Auth anomalies, VPN logging, WAF blocking, phishing workflow (Cortex + MISP), USB monitoring. |
| Execution (TA0002) | 67% (9/13) | Strong | Sysmon process creation, PowerShell script block logging, scheduled task monitoring, LOLBin detection. |
| Persistence (TA0003) | 37% (8/20) | Moderate | AD group changes (4728/4732/4756), Wazuh FIM startup/systemd, service creation monitoring. |
| Privilege Escalation (TA0004) | 38% (5/13) | Moderate | Admin logon correlation, GPO modification auditing (5136/5137/5141), sudo tracking. |
| Defense Evasion (TA0005) | 21% (13/46) | Weak | Immutable SIEM logs, registry tracking, security tool tamper detection. Cloud: CloudTrail alerts on GuardDuty disablement; GCP audit logs capture SCC changes; Azure Sentinel monitors Defender policy modifications. |
| Credential Access (TA0006) | 28% (4/15) | Weak | Brute force multi-source detection, LSASS monitoring (Sysmon EID 10). Cloud: GuardDuty CredentialAccess; Sentinel new-location sign-in detection. |
| Discovery (TA0007) | 32% (10/32) | Moderate | Suricata port scan/sweep/ARP; Zeek conn.log + ntopng improve T1046; AD LDAP auditing (4662). |
| Lateral Movement (TA0008) | 56% (5/9) | Strong | RDP (Suricata + EID 4624 type 10), SMB (5140/5145), SSH; Zeek rdp/smb/ssh logs. |
| Collection (TA0009) | 20% (4/18) | Weak | Archive detection, USB insertion (EID 2003), Wazuh FIM sensitive dirs. No DLP. |
| Exfiltration (TA0010) | 46% (4/9) | Moderate | C2 channel monitoring, MISP IOC, Zeek DNS/ntopng outbound. T1537: AWS S3 CloudTrail DataEvent logging, GCP Cloud Logging GCS access, Azure Monitor Storage account access (PARTIAL). |
| Command & Control (TA0011) | 42% (6/16) | Moderate | Suricata HTTP/HTTPS/DNS/SMTP, Unbound DGA detection, Zeek analyzers, PA-VM App-ID tunneling blocks. |
| Impact (TA0040) | 46% (6/13) | Moderate | Ransomware: Wazuh mass file modification + Shuffle workflow; cryptomining: Prometheus CPU/process detection. |

**v18.1 critical new techniques requiring implementation:** T1059.013 (Container CLI/API), T1678 (Delay Execution), T1679 (Selective Exclusion), T1036.012 (Browser Fingerprint Masquerading), T1562.013 (Network Device Firewall), T1546.018 (Python Startup Hooks), T1213.006 (Database Exfiltration).

---

## CISA Zero Trust Maturity Model v2.0 Summary

**Overall:** Advanced (Stage 3/4). 87% of functions at Advanced or higher. Hybrid deployment: device agent/gateway (Authentik + Traefik), enclave gateway (pfSense/OPNsense/PA-VM), resource portal (Traefik).

| Pillar | Maturity | Cloud Extension | Next Steps |
|--------|----------|-----------------|------------|
| Identity | Advanced | Tailscale device-bound WireGuard key as phishing-resistant MFA equivalent; SSH key-only Linux nodes; domain Kerberos for Windows nodes via Tailscale; cloud IAM least-privilege; GuardDuty CredentialAccess; Sentinel geo sign-in anomaly. | WebAuthn/FIDO2 deployment |
| Devices | Advanced | Wazuh CIS SCA on 6 cloud nodes daily (Amazon Linux, Debian 12/13, Ubuntu 22.04/24.04, Win Server 2025); PatchMon 4 Linux; WSUS 2 Windows; ClamAV + Defender; cloud-native behavioral detection. | SBOM tracking Trivy/Grype Q2 2026 |
| Networks | Advanced | Cloud: Tailscale ACL default-deny; GCP Threat Intelligence blocking (TOR, malicious IPs, sanctioned countries); Cloud Armor WAF/DDoS; Azure DDoS Protection; cloud VPC flow logs to SIEM. | mTLS for service-to-service |
| Applications & Workloads | Advanced | Tailscale ACL gates cloud node access; GuardDuty, SCC, Sentinel auto-create TheHive cases via Shuffle; GCP Cloud Armor app-layer WAF; Azure DDoS; Ansible rebuild RTO <2hr. | CI/CD security scanning Q2 2026 |
| Data | Advanced | Cloud: AWS S3 SSE CloudTrail (90-day); GCP disk default encryption; Azure Managed Disk + Log Analytics encrypted; Tailscale WireGuard for cloud mgmt; Wazuh FIM 6 cloud nodes. | Formal DLP Q2 2026 |
| Visibility & Analytics | Advanced | CloudTrail, GCP Admin Activity/Data Access, Azure Activity Log; VPC/NSG flow logs to SIEM; Wazuh agents on 6 cloud nodes forward to Splunk; GuardDuty/SCC/Sentinel behavioral analytics. | ML/UEBA platform |
| Automation & Orchestration | Advanced | Wazuh Active Response on 6 cloud nodes via Tailscale; GuardDuty and Sentinel auto-create TheHive cases via Shuffle; Ansible cloud rebuild RTO <2hr; Terraform/ARM IaC. | Automated cloud network isolation |
| Governance | Advanced | Cloud policies version-controlled; AWS Security Hub, GCP SCC security health, Azure Defender Secure Score; cloud compliance visible in unified Wazuh dashboard. | Automated policy generation from threat intel |

---

## NIST SP 800-207 Zero Trust Architecture Summary

**Overall:** Advanced maturity across all 7 ZT tenets. Deployment model: hybrid device agent/gateway (Authentik + Traefik), enclave gateway (pfSense/OPNsense/PA-VM/FortiGate), resource portal (Traefik). Trust algorithm: hybrid score-based and criteria-based with contextual evaluation.

| Tenet | Status | Cloud Evidence |
|-------|--------|----------------|
| 1. All resources explicitly defined | Advanced | 6 cloud nodes tracked in Checkmk, Wazuh, PatchMon, Tailscale admin console |
| 2. Communication secured regardless of location | Advanced | Tailscale WireGuard (ChaCha20-Poly1305) mandatory; no public management ports; default-deny cloud firewall policies |
| 3. Per-session least privilege access | Advanced | No passwords on cloud SSH nodes; Windows nodes require domain Kerberos; cloud IAM scoped per provider; no persistent elevated privileges |
| 4. Dynamic policy from observable state | Advanced | GuardDuty ML-based detection; GCP SCC threat findings; Azure Sentinel KQL rules; all cloud findings forwarded to on-premises SIEM |
| 5. Asset integrity monitoring | Advanced | Wazuh CIS SCA on all 6 cloud nodes daily; PatchMon CVE correlation; WSUS Windows cloud nodes; cloud-native scanning supplements Wazuh |
| 6. Dynamic authentication/authorization | Advanced | SSH key-only Linux; domain Kerberos Windows; cloud console enforces provider MFA; Tailscale device-bound key for all cloud access |
| 7. Comprehensive telemetry collection | Advanced | CloudTrail, GCP Admin Activity/Data Access, Azure Activity Log; VPC/NSG flow logs; Wazuh agents on 6 cloud nodes forward to Splunk; unified telemetry across on-premises and cloud |

**Use Case 2 (Multi-Cloud)** advanced from Medium to High applicability. Tailscale connects AWS (172.31.0.0/16), GCP (10.128.0.0/16), and Azure (10.130.0.0/16) into unified overlay with consistent policy enforcement.

---

## AICPA SOC 2 Trust Services Criteria (CC1-CC9) Summary

**Framework:** Trust Services Criteria (Security / Common Criteria). **Scope:** On-premises + hybrid cloud (AWS, Azure, GCP, 6 nodes). **Overall:** Strong (30/33 criteria implemented).

| Category | Criteria | Assessment | Key Evidence |
|----------|----------|------------|--------------|
| CC1: Control Environment | CC1.1-CC1.5 | Partial | Security-first policies in Git; quarterly GRC reviews; RBAC via Authentik/AD; immutable SIEM audit trails; Git commit attribution. Organizational governance limited by single-admin lab context. |
| CC2: Communication and Information | CC2.1-CC2.3 | Implemented | Multi-channel alerting (Discord, SMTP, TheHive); MISP bi-directional IOC sharing; Shuffle notification routing; cloud: AWS SNS, GCP alerting, Azure Monitor action group integrated. |
| CC3: Risk Assessment | CC3.1-CC3.4 | Implemented | CVSS base/temporal/environmental scoring; weekly OpenVAS + monthly Nessus; MISP threat feeds; Wazuh FIM detects unauthorized changes; cloud: CloudTrail, GCP Audit, Azure Activity Log. |
| CC4: Monitoring of Controls | CC4.1-CC4.2 | Implemented | Dual SIEM 100+ correlation rules <5min MTTD; Wazuh SCA CIS audits continuous on 31+ endpoints; Uptime Kuma 50+ monitors; TheHive tracks deficiencies with SLA enforcement. |
| CC5: Control Activities | CC5.1-CC5.3 | Implemented | 7-layer defense-in-depth; TLS 1.3 mandatory, SSH passwords disabled globally, MFA 100% admin, default-deny all platforms; controls deployed as IaC via Ansible/Terraform; extended to cloud nodes. |
| CC6: Logical and Physical Access | CC6.1-CC6.8 | Implemented | Authentik SSO + Traefik ForwardAuth; Ed25519 SSH key-only; PA-VM User-ID; Step-CA PKI; 30-min idle timeout; SafeLine WAF + Suricata IPS. Cloud: no public management ports; Tailscale device-bound access; provider-native firewall default-deny. |
| CC7: System Operations | CC7.1-CC7.5 | Implemented | Prometheus 15s scrape; Uptime Kuma 50+ monitors; Checkmk; Zeek NSM + ntopng; Wazuh SCA 92-98% CIS; Shuffle SOAR 15+ playbooks <30min MTTR; cloud node rebuild RTO <2hr validated. |
| CC8: Change Management | CC8.1 | Implemented | Git commit required for all IaC; Terraform plan review; Ansible dry-run; WSUS approval; snapshot-before-patch; branch protection + PR review. Cloud: ARM template and Terraform IaC in Git with same review workflow. |
| CC9: Risk Mitigation | CC9.1-CC9.2 | Partial | CVSS-based remediation; network segmentation; Wazuh Active Response; MISP proactive blocking. CC9.2 partial: no formal vendor contracts; SBOM (Trivy/Grype) planned Q2 2026. |

---

## Strategic Roadmap

| Priority | Action | Framework Impact |
|----------|--------|-----------------|
| Critical | Enable Kerberos event logging (EID 4768/4769) | MITRE T1558; NIST AU-2; CIS 8.5 |
| Critical | Implement pass-the-hash/ticket detection (EID 4624/4625 type 9) | MITRE T1550; NIST SI-4; CIS 13.6 |
| Critical | Enable comprehensive WMI logging | MITRE T1047; CIS 8.5 |
| High | Deploy Trivy/Grype SBOM tracking | NIST SR-3; CIS 2.5; OWASP A03; MITRE T1195 |
| High | Implement PA-VM NetFlow/IPFIX export to ntopng | CIS 13.6; SI-4; DE.CM-01 |
| High | Configure User-ID for Linux hosts (syslog-based mapping) | NIST AC-3; CIS 6.8; CISA Identity pillar |
| High | Deploy formal DLP solution | NIST MP-2; CIS 3.13; ISO A.8.12; MITRE T1048/T1537 |
| High | Azure Spot instance restart automation | Azure BC/DR; RC.HL-01; NIST CP-10 |
| Medium | Implement FIDO2/WebAuthn deployment | NIST IA-2(1); CISA Identity Optimal; CC6.1 |
| Medium | Deploy UEBA capabilities in SIEM | MITRE T1078/T1110; DE.AE-03; CIS 13.1 |
| Medium | Implement TLS inspection/JA3S fingerprinting | MITRE T1573; CIS 13.10; NIST SC-7 |
| Medium | Implement share enumeration monitoring (T1135) | MITRE T1135; CIS 8.5; NIST SI-4 |
| Low | Deploy firmware integrity checks (UEFI/BIOS monitoring) | MITRE T1495; NIST SI-7; CIS 10.5 |
| Low | Implement 802.1X port-level NAC | CIS 13.9 (IG3); NIST AC-3; CISA Networks Optimal |

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0 | January 2026 | Initial release covering six frameworks: NIST CSF 2.0, CIS Controls v8.1, ISO 27001:2022, NIST SP 800-53 Rev 5, CISA ZTMM v2.0, NIST SP 800-207. |
| 1.1 | January 2026 | Corrected N/A controls and coverage percentages across framework summaries. |
| 1.2 | March 2026 | Added Palo Alto PA-VM NGFW, NSM sensor (Zeek/ntopng), Cisco/VLAN enhancements. Updated PROTECT, DETECT, Zero Trust pillar evidence. |
| 2.0 | April 2026 | Added AICPA SOC 2 Trust Services Criteria (CC1-CC9). Integrated multi-cloud hybrid scope (AWS, Azure, GCP — 6 nodes via Tailscale). Updated all framework summaries. Consolidated executive overview. |
