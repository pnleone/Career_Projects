# SOC 2 Trust Services Criteria (Common Criteria CC1-CC9)

**Document Control:** 

**Version:** 1.0
**Last Updated:** April 2026
**Owner:** Paul Leone 

**Framework Version:** 2017 Trust Services Criteria (TSC)  
**Scope:** On-premises homelab + hybrid cloud (AWS, Azure, GCP — 6 nodes via Tailscale)

---

## Overview

SOC 2 is an attestation framework developed by the AICPA that evaluates whether a service organization's controls meet the Trust Services Criteria (TSC). The Security criteria (Common Criteria CC1-CC9) are required for every SOC 2 engagement; Availability, Confidentiality, Processing Integrity, and Privacy are optional based on the services provided. This document maps the Security Common Criteria to lab controls, demonstrating familiarity with the SOC 2 control framework from an audit-readiness and implementation perspective.

The Common Criteria are organized across nine categories aligned to the COSO internal control framework: Control Environment (CC1), Communication and Information (CC2), Risk Assessment (CC3), Monitoring of Controls (CC4), Control Activities (CC5), Logical and Physical Access Controls (CC6), System Operations (CC7), Change Management (CC8), and Risk Mitigation (CC9). Each criterion includes one or more Points of Focus that describe how effective implementation is demonstrated.

**Important context:** SOC 2 is designed for service organizations handling customer data. This lab is a personal research environment with no customer data in scope. The mapping below demonstrates control design and implementation capability aligned to SOC 2 criteria; it is not equivalent to a formal Type I or Type II attestation.

---

## Overall Assessment

| Category | Criteria | Assessment |
|----------|----------|------------|
| CC1: Control Environment | CC1.1-CC1.5 | **Partial** |
| CC2: Communication and Information | CC2.1-CC2.3 | **Implemented** |
| CC3: Risk Assessment | CC3.1-CC3.4 | **Implemented** |
| CC4: Monitoring of Controls | CC4.1-CC4.2 | **Implemented** |
| CC5: Control Activities | CC5.1-CC5.3 | **Implemented** |
| CC6: Logical and Physical Access | CC6.1-CC6.8 | **Implemented** |
| CC7: System Operations | CC7.1-CC7.5 | **Implemented** |
| CC8: Change Management | CC8.1 | **Implemented** |
| CC9: Risk Mitigation | CC9.1-CC9.2 | **Partial** |
| **Overall** | **33 criteria** | **Strong** |

---

## CC1: Control Environment

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC1.1 | COSO Principle 1: Demonstrates Commitment to Integrity and Ethical Values | Lab mission statement defines security-first architecture principles with documented ethical guidelines for security research. Security policy documentation (version-controlled in Git) establishes acceptable use standards, responsible disclosure principles, and research boundaries. All security testing confined to owned infrastructure with no unauthorized scanning of external systems. Offensive tooling (Kali Linux, Parrot OS) isolated to dedicated test VMs on separate VLANs with explicit traffic controls. | Partial |
| CC1.2 | COSO Principle 2: Exercises Oversight Responsibility | Security architecture reviewed quarterly against NIST CSF, CIS Controls, and ISO 27001 baselines. GRC documentation suite (eight frameworks) provides structured oversight of control effectiveness. Vulnerability remediation SLAs defined (Critical <72h, High <7d) with tracking via TheHive. Grafana dashboards (20+) provide continuous posture visibility. Quarterly access reviews validate RBAC group assignments in Authentik. Cloud posture tracked via AWS Security Hub, GCP SCC security health, Azure Defender for Cloud Secure Score. | Partial |
| CC1.3 | COSO Principle 3: Establishes Structure, Authority, and Responsibility | RBAC via Authentik groups with documented permission assignments per role (Admin, SOC Analyst, Read-Only). Separate privileged accounts for administrative operations; no dual-use accounts. Least-privilege enforced via Authentik OAuth2 scopes, SSH sudo policies, and firewall ACLs. Cloud: AWS IAM instance profiles (no wildcard actions), GCP minimal service account roles (no owner/editor on Compute), Azure RBAC per resource group. | Implemented |
| CC1.4 | COSO Principle 4: Demonstrates Commitment to Competence | Lab purpose-built to develop competency across security domains: network defense (pfSense/OPNsense/Palo Alto PA-VM), endpoint detection (Wazuh EDR), identity management (Authentik, Active Directory, Step-CA PKI), threat intelligence (MISP, CrowdSec), SIEM/SOAR (Splunk, Elastic, Shuffle, TheHive), vulnerability management (OpenVAS, Nessus), infrastructure automation (Terraform, Ansible), and multi-cloud security (AWS GuardDuty, GCP SCC, Azure Defender for Cloud). Continuous learning validated through GRC documentation aligned to eight industry frameworks. | Implemented |
| CC1.5 | COSO Principle 5: Enforces Accountability | All administrative actions logged to dual SIEM (Splunk + Elastic) with 90-day hot retention and 1-year cold storage. Immutable audit trails (Splunk read-only indexes, Elastic immutable streams) prevent log tampering. Sudo usage logged to SIEM; privileged SSH sessions tracked per session. Git commit history provides immutable record of all IaC and configuration changes with author attribution. Wazuh Active Response logs all automated containment actions (firewall-drop, host-deny, account-disable) with timestamps. Cloud: AWS CloudTrail, GCP Admin Activity logs, Azure Activity Log provide immutable control-plane audit trails. | Implemented |

---

## CC2: Communication and Information

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC2.1 | COSO Principle 13: Uses Relevant Information | Vulnerability scan results (OpenVAS weekly, Nessus monthly) feed patch prioritization workflows. SIEM correlation rules (100+ active) generate actionable alerts from raw log data. MISP threat intelligence correlates IOCs across network logs, endpoint telemetry, and application data. CIS Benchmark compliance scores (92-98% across 30+ hosts) drive remediation backlog. PatchMon tracks 5,000+ packages with daily CVE correlation to NVD. Cloud: GuardDuty findings, GCP SCC asset/threat data, Azure Defender for Cloud recommendations all surface actionable security intelligence. | Implemented |
| CC2.2 | COSO Principle 14: Communicates Internally | Multi-channel alerting: Discord private server (dedicated channels per tool: #wazuh, #suricata, #pfsense, #grafana, #openvas, #prometheus); SMTP relay via Gmail; TheHive case management for structured incident communication; Shuffle SOAR workflows automate notification routing based on alert severity. Cloud: AWS SNS, GCP alerting policies, Azure Monitor action group (RecommendedAlertRules-AG-1) integrated into Discord/email notification chain. | Implemented |
| CC2.3 | COSO Principle 15: Communicates Externally | Responsible disclosure practices for vulnerabilities identified during research. MISP threat intelligence platform supports bi-directional IOC sharing with external threat intelligence communities. Cloudflare email routing configured for external alert delivery. No customer-facing services in scope. | Implemented |

---

## CC3: Risk Assessment

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC3.1 | COSO Principle 6: Specifies Suitable Objectives | Security objectives defined in lab mission statement: threat detection and response (sub-30-minute MTTR), defense-in-depth architecture, continuous monitoring (100% security event coverage), vulnerability management (Critical <72h MTTR). Service criticality tiers defined (Tier 1: SIEM/EDR, Tier 2: Firewalls/DNS/Identity, Tier 3: Supporting services). Compliance objectives documented per framework with measurable targets. Cloud nodes classified as Tier 2; cloud-native security services (GuardDuty, SCC, Defender for Cloud) classified as Tier 1 alongside Splunk and Wazuh. | Implemented |
| CC3.2 | COSO Principle 7: Identifies and Analyzes Risk | Weekly OpenVAS network scans (52/year), monthly Nessus authenticated scans (12/year), daily PatchMon CVE correlation for 5,000+ packages. CVSS base, temporal, and environmental scoring with asset criticality weighting. MISP threat intelligence feeds surface emerging risks. CrowdSec community signals identify active threat campaigns. Cloud: same CVSS-based SLAs applied to cloud node findings from PatchMon, AWS Inspector, GCP SCC, Azure Defender for Cloud. | Implemented |
| CC3.3 | COSO Principle 8: Assesses Fraud Risk | Insider threat detection via behavioral analytics: Splunk correlation searches detect anomalous login times, geographic anomalies, impossible travel, and unusual access patterns. Wazuh monitors account lifecycle events with alerts for high-risk activities. Authentik session management (30-minute idle timeout) limits exposure window. All privileged actions require explicit MFA re-authentication. Cloud: Azure Sentinel KQL detects sign-in from new geographic location; GuardDuty CredentialAccess findings; GCP SCC IAM anomaly detection. | Implemented |
| CC3.4 | COSO Principle 9: Identifies and Analyzes Significant Change | Configuration drift detection via Ansible playbooks. Wazuh FIM detects unauthorized changes to critical system files and configurations in real time. Git version control provides full change history for all IaC and configuration files. SIEM alerts on policy-relevant changes: firewall rule modifications, user account changes, software installations outside approved channels. Cloud: CloudTrail, GCP Admin Activity logs, Azure Activity Log capture all control-plane changes. Cloud infrastructure changes require Terraform plan review before apply; no ad-hoc console modifications. | Implemented |

---

## CC4: Monitoring of Controls

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC4.1 | COSO Principle 16: Conducts Ongoing and/or Separate Evaluations | Dual SIEM (Splunk + Elastic) with 100+ active correlation rules, real-time detection, sub-5-minute MTTD for critical alerts. Wazuh SCA runs CIS Benchmark audits on all 31+ endpoints (25 on-premises + 6 cloud) continuously. Uptime Kuma monitors 50+ services with 60-second health check intervals. Prometheus node exporters provide 15-second metric collection. Grafana dashboards track compliance posture, vulnerability trends, and authentication patterns. Cloud: AWS CloudWatch Agent, GCP Cloud Monitoring Ops Agent, Azure Monitor VM metric alert rules (7 active) provide cloud device metrics. | Implemented |
| CC4.2 | COSO Principle 17: Evaluates and Communicates Deficiencies | Vulnerability findings routed to TheHive with SLA enforcement (Critical <72h, High <7d). Shuffle SOAR automates escalation: high-severity Wazuh alerts auto-create TheHive cases with Cortex enrichment (VirusTotal, AbuseIPDB, Shodan) and MISP correlation. CIS Benchmark deficiencies surfaced in Wazuh SCA reports with specific remediation guidance per failed check. Discord and email notifications ensure deficiencies reach the right channel within seconds of detection. Cloud: AWS GuardDuty and Azure Sentinel incidents automatically create TheHive cases via Shuffle SOAR webhook; GCP SCC findings trigger alerting policy notifications. | Implemented |

---

## CC5: Control Activities

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC5.1 | COSO Principle 10: Selects and Develops Control Activities | Defense-in-depth architecture with overlapping controls at every layer: network perimeter (pfSense HA cluster, OPNsense, Palo Alto PA-VM with App-ID/Threat Prevention/User-ID, FortiGate 30D), network detection (Suricata inline IPS, Snort passive IDS, CrowdSec behavioral, Zeek NSM, ntopng/nProbe flow analysis), application layer (SafeLine WAF, Traefik ForwardAuth, NGINX Ingress), identity (Authentik SSO, Active Directory, Step-CA PKI, MFA enforcement), endpoint (Wazuh EDR, ClamAV, Microsoft Defender, FIM, rootkit detection). Cloud: AWS Security Groups, GCP VPC firewall policy (Google Threat Intelligence blocking), Azure NSG, Cloud Armor three-tier WAF/DDoS, and cloud-native EDR all extend the defense-in-depth model to cloud nodes. Controls selected based on MITRE ATT&CK technique coverage gaps and CIS Controls guidance. | Implemented |
| CC5.2 | COSO Principle 11: Selects and Develops General Controls over Technology | TLS 1.3 mandatory for all web services via Traefik (no protocol downgrade permitted), SSH password authentication globally disabled (key-based only), MFA enforced for 100% of administrative accounts via Authentik TOTP, default-deny firewall rules across all platforms (pfSense, OPNsense, Palo Alto, GCP VPC firewall, AWS Security Groups, Azure NSG). Step-CA automated certificate lifecycle (90-day rotation, ACME protocol). DNSSEC validation enforced on all recursive resolvers. Weak cipher detection via automated Nessus compliance scans. | Implemented |
| CC5.3 | COSO Principle 12: Deploys Control Activities Through Policies and Procedures | Controls deployed as code: Ansible playbooks enforce CIS Benchmark baselines across 31+ hosts with drift detection alerting. Terraform defines network infrastructure (Security Groups, VPC firewall policies, NSG rules) as version-controlled IaC. Git branch protection and pull request requirements enforce peer review before policy changes. Wazuh SCA policies (CIS Amazon Linux, Debian 12/13, Ubuntu 22.04/24.04, Windows Server 2025) continuously validate control implementation on all on-premises and cloud nodes. Policy exceptions require documented compensating controls and approval workflow. | Implemented |

---

## CC6: Logical and Physical Access Controls

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC6.1 | Logical Access Security Software, Infrastructure, and Architectures | Authentik SSO provides OAuth2/OIDC/SAML federation for 50+ services with centralized session management (30-minute idle timeout). Traefik ForwardAuth validates identity at the edge before proxying requests. SSH access restricted to Ed25519 key-based authentication (passwords disabled globally via Ansible). Palo Alto PA-VM User-ID integration maps Active Directory group membership to firewall security policy, enforcing identity-aware network access. Step-CA PKI provides certificate-based device and service authentication. RBAC via Authentik groups with least-privilege scoping per application. Cloud: Tailscale device-bound WireGuard key authentication is the access gate for all cloud node management; no public management ports on any cloud instance. | Implemented |
| CC6.2 | Prior to Issuance of System Credentials, the Entity Registers and Authorizes New Users | User account provisioning requires explicit authorization via Authentik with automated deprovisioning workflows. Privileged account creation requires manual approval with documented justification. SSH key distribution centralized via Ansible with authorized_keys managed as IaC; no ad-hoc key additions. Cloud: AWS IAM instance profiles assigned at provisioning time with minimum required permissions; GCP service account roles defined; Azure Managed Identity documented. Windows cloud node accounts provisioned via Active Directory with OU-based GPO. Account lifecycle tracked with automated expiration for time-limited access. | Implemented |
| CC6.3 | The Entity Removes Access to Protected Information Assets When Appropriate | Authentik account deactivation disables SSO access across all integrated services simultaneously. SSH key revocation deployed via Ansible playbook to all authorized_keys files within minutes. Cloud: Tailscale node key expiry/revocation removes cloud node access; AWS IAM role disassociation, GCP service account removal, and Azure Entra ID deactivation documented in decommissioning runbook. Wazuh monitors account lifecycle events. Quarterly access reviews identify dormant accounts (45-day threshold) for deactivation. | Implemented |
| CC6.4 | The Entity Restricts Physical Access to Facilities and Protected Information Assets | On-premises: server hardware in dedicated locked area with residential physical security controls. Proxmox management interface accessible only from homelab subnets. BIOS/UEFI passwords configured on physical hosts. Backup drives stored in locked enclosure with AES-256 encryption. Cloud: physical security delegated to provider data centers (AWS, GCP, Azure maintain SOC 2 Type II / ISO 27001 certified physical access controls). | Implemented |
| CC6.5 | The Entity Discontinues Logical Access to Protected Information Assets | Authentik session timeout (30-minute idle) automatically invalidates access tokens across all SSO-integrated services. SSH ClientAliveInterval=300 disconnects idle sessions. OAuth2 access tokens have short expiration with refresh tokens rotated on use. Wazuh Active Response can disable accounts (account-disable action) in response to behavioral anomalies. Cloud: cloud console sessions governed by provider MFA re-authentication requirements; Tailscale key expiry revokes cloud node access automatically. | Implemented |
| CC6.6 | The Entity Implements Logical Access Security Measures to Protect Against Threats from Sources Outside Its System Boundaries | SafeLine WAF (OWASP CRS) blocks SQL injection, XSS, command injection, path traversal, and RFI/LFI with 25%+ attack block rate. Suricata IPS with 40,000+ Emerging Threats signatures provides inline blocking. CrowdSec behavioral detection blocks brute-force and exploit attempts via pfSense bouncer (<5 second enforcement). pfBlockerNG IP reputation blocking with 15+ curated feeds. GeoIP blocking for high-risk source countries. Cloudflare Tunnels expose no direct inbound ports. Cloud: no inbound management ports on any cloud node; all cloud access via Tailscale WireGuard; GCP Cloud Armor (SQLi/XSS blocking, DDoS rate limiting); Azure DDoS Protection plan homelab-ddos; AWS Security Groups default-deny. | Implemented |
| CC6.7 | The Entity Restricts Transmission, Movement, and Removal of Information | TLS 1.3 mandatory for all web services. syslog-ng TLS encrypts all log transmission. VPN encryption via Tailscale WireGuard (ChaCha20-Poly1305) and PIA OpenVPN (AES-256). SSH AES-256-GCM for terminal access. Backup data encrypted with AES-256-GCM before transmission. Removable media restricted via Windows GPO (USB access denied by default). Cloud: all cloud management traffic exclusively via Tailscale WireGuard; no plaintext management paths across any cloud provider; AWS S3 SSE for CloudTrail; GCP persistent disk and GCS default encryption; Azure Managed Disk and Log Analytics workspace encrypted at rest. | Implemented |
| CC6.8 | The Entity Implements Controls to Prevent or Detect and Act Upon the Introduction of Unauthorized or Malicious Software | Wazuh EDR provides FIM (real-time file hash comparison), rootkit detection, and process monitoring on 31+ endpoints (25 on-premises + 6 cloud). VirusTotal integration validates suspicious files via multi-engine analysis with automated quarantine on positive detections (rule_id 87105). YARA rules detect malware signatures. ClamAV (Linux) and Microsoft Defender (Windows) with automated signature updates. Suricata/Snort IDS signatures detect malware C2 communication. Docker image SHA-256 verification and package GPG signature validation. Cloud: ClamAV on 4 Linux cloud nodes; Microsoft Defender on 2 Windows cloud nodes updated via WSUS; GuardDuty, GCP SCC, Azure Defender for Cloud provide cloud-native behavioral detection layer. | Implemented |

---

## CC7: System Operations

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC7.1 | To Meet Its Objectives, the Entity Uses Detection and Monitoring Procedures | Dual SIEM (Splunk primary, Elastic secondary) ingests 100% of security events from 30+ data sources. Prometheus (15-second scrape interval) collects infrastructure metrics from all hosts. Uptime Kuma monitors 50+ services with 60-second health checks and TLS certificate expiration alerts. Checkmk provides deep infrastructure monitoring via agents on all managed hosts including cloud nodes. Zeek NSM (3-worker AF_PACKET cluster) captures protocol metadata across Prod_LAN, Lab_LAN1, Lab_LAN2. ntopng/nProbe aggregates NetFlow v9 from all Cisco routers and firewall platforms. Wazuh vulnerability assessment cross-references installed software against NVD daily. Cloud: AWS CloudWatch Agent and GuardDuty, GCP Cloud Monitoring Ops Agent and SCC, Azure Monitor metric alerts and Sentinel KQL detection rules all extend monitoring to cloud nodes. | Implemented |
| CC7.2 | The Entity Monitors System Components and the Operation of Those Controls | CIS Benchmark compliance tracked via Wazuh SCA (92-98% pass rate). Correlation rule effectiveness measured by alert-to-incident conversion rate in TheHive. WAF block rate (SafeLine: 25%+ of inspected requests) monitored via dashboard. IDS signature hit rates tracked per interface. Certificate expiration monitored via Uptime Kuma (30/7/1-day warning thresholds). Patch compliance tracked in PatchMon with MTTR trending. All 6 cloud nodes enrolled in Checkmk and visible in the same on-premises dashboard as on-premises hosts. | Implemented |
| CC7.3 | The Entity Evaluates Security Events to Determine Whether They Could or Have Resulted in a Failure to Meet Its Objectives | Splunk SPL correlation searches aggregate events across multiple sources with severity scoring. TheHive provides structured case management with MITRE ATT&CK technique tagging and incident classification taxonomy. Cortex multi-engine analysis (VirusTotal, AbuseIPDB, Shodan, MISP, YARA, Hybrid Analysis) enriches observables. Shuffle SOAR automates initial triage: Wazuh alerts above severity threshold (level 4+) automatically create enriched TheHive cases within 45-60 seconds of detection. Alert suppression and deduplication reduce analyst fatigue. Cloud: GuardDuty finding types mapped to MITRE ATT&CK; GCP SCC findings aligned to cloud attack taxonomy; Azure Sentinel analytics rules tagged with MITRE ATT&CK techniques. | Implemented |
| CC7.4 | The Entity Responds to Identified Security Incidents by Executing a Defined Incident Response Program | 15+ documented playbooks in TheHive covering phishing, malware, ransomware, lateral movement, brute force, vulnerability exploitation, and data exfiltration. Shuffle SOAR orchestrates automated containment: Wazuh Active Response executes firewall-drop, host-deny, and account-disable with sub-30-minute MTTR. Cortex responders provide automated evidence collection and IOC blocking. MISP integration enables rapid IOC correlation and sharing. Multi-channel notification (Discord, email, PagerDuty). Cloud: Wazuh Active Response executes on cloud nodes via Tailscale using same containment playbooks as on-premises; AWS Security Group modification, GCP Terraform firewall update, Azure NSG modification available for rapid cloud node containment. | Implemented |
| CC7.5 | The Entity Identifies, Develops, and Implements Activities to Recover from Identified Security Incidents | Proxmox snapshot-before-patch enables rollback to known-good state within minutes. PBS bi-weekly automated backups (AES-256) with Synology NAS offsite redundancy; sub-15-minute RTO for critical VMs. IaC (Terraform, Ansible) enables full lab rebuild from Git repository in <2 hours. Quarterly restore testing validates recovery procedures. Post-incident Wazuh SCA scan confirms security baseline compliance post-recovery. Cloud: cloud node rebuild via Ansible new_install_baseline_roles.yml, Tailscale re-enrollment, and Wazuh agent reinstallation; RTO <2 hours validated. Azure Spot instance eviction handled by Deallocate policy with documented restart procedure. | Implemented |

---

## CC8: Change Management

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC8.1 | The Entity Authorizes, Designs, Develops or Acquires, Configures, Documents, Tests, and Approves Infrastructure, Data, Software, and Procedures | All infrastructure changes require Git commit with descriptive message (immutable audit trail). Terraform plan review required before cloud infrastructure changes applied; no ad-hoc console modifications. Ansible dry-run (--check mode) validates playbook impact before production execution. WSUS approval workflow requires explicit administrator sign-off before Windows patches deploy. Snapshot-before-patch captures pre-change state. Pre-deployment vulnerability scanning (OpenVAS, Nessus) validates new services. Container images verified via SHA-256. Git branch protection and pull request reviews enforce peer approval for policy changes. Cloud: ARM template (Azure) and cloud Terraform modules version-controlled in Git with same review workflow as on-premises IaC. | Implemented |

---

## CC9: Risk Mitigation

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC9.1 | The Entity Identifies, Selects, and Develops Risk Mitigation Activities | CVSS-based prioritization determines remediation sequence (Critical <72h, High <7d, Medium <30d). Virtual patching via SafeLine WAF rules provides immediate coverage for unpatched vulnerabilities. Network segmentation (VLAN isolation, firewall default-deny, Palo Alto zone architecture) contains blast radius. Wazuh Active Response provides automated real-time mitigation (firewall-drop, account-disable) before manual response. Threat intelligence (MISP IOC correlation, CrowdSec community feeds) enables proactive blocking. HA firewall cluster (pfSense CARP, <5 second failover) and dual DNS (<5 second failover) mitigate availability risk. Cloud: same CVSS SLAs apply; GCP Cloud Armor virtual patching (WAF rule updates without instance restart); AWS Security Hub findings tracked; Azure Defender for Cloud recommendations tracked in homelab-log. | Implemented |
| CC9.2 | The Entity Assesses and Manages Risks Associated with Vendors and Business Partners | Open-source software selected from vetted, actively maintained projects. Docker images pulled from official repositories with SHA-256 signature verification. Package signature validation (GPG keys) enforced for all software installations. MISP tracks vendor compromise campaigns and supply chain IOCs. PatchMon monitors all 5,000+ installed packages for CVEs including third-party dependencies. Cloud: AWS GuardDuty, GCP SCC, Azure Defender for Cloud assess cloud provider workloads continuously. AWS IAM instance profiles (no long-lived keys on EC2), GCP minimal service account roles, Azure ARM securestring parameters reduce supply chain risk on cloud nodes. SBOM implementation (Trivy/Grype) planned Q2 2026 for comprehensive dependency visibility. No formal vendor contracts in scope (personal lab). | Partial |

---

## Coverage Summary

### Status by Category

| Category | Criteria | Implemented | Partial | Not Impl. | N/A | Assessment |
|----------|----------|-------------|---------|-----------|-----|------------|
| **CC1 Control Environment** | 5 | 3 | 2 | 0 | 0 | Partial |
| **CC2 Communication** | 3 | 3 | 0 | 0 | 0 | Implemented |
| **CC3 Risk Assessment** | 4 | 4 | 0 | 0 | 0 | Implemented |
| **CC4 Monitoring** | 2 | 2 | 0 | 0 | 0 | Implemented |
| **CC5 Control Activities** | 3 | 3 | 0 | 0 | 0 | Implemented |
| **CC6 Logical/Physical Access** | 8 | 8 | 0 | 0 | 0 | Implemented |
| **CC7 System Operations** | 5 | 5 | 0 | 0 | 0 | Implemented |
| **CC8 Change Management** | 1 | 1 | 0 | 0 | 0 | Implemented |
| **CC9 Risk Mitigation** | 2 | 1 | 1 | 0 | 0 | Partial |
| **TOTAL** | 33 | 30 | 3 | 0 | 0 | Strong |

### Key Strengths

- **CC6 (Logical Access)** fully implemented: Authentik SSO, MFA enforcement, SSH key-based auth, Traefik ForwardAuth, Palo Alto User-ID AD group policy, session timeout, and per-service access control — extended to 6 cloud nodes via Tailscale.
- **CC7 (System Operations)** fully implemented: dual SIEM with 100+ correlation rules, sub-5-minute MTTD, Shuffle SOAR with 15+ playbooks, sub-30-minute MTTR, Wazuh Active Response automated containment on all 31+ endpoints.
- **CC5 (Control Activities)** fully implemented: defense-in-depth architecture spanning 7 security layers, controls deployed as IaC with version-controlled policy enforcement, extended to cloud via Terraform/Ansible.
- **CC8 (Change Management)** fully implemented: Git-enforced IaC workflow, Terraform plan review, Ansible dry-run, WSUS approval workflows, snapshot-before-patch rollback.
- Comprehensive cryptographic controls: TLS 1.3 mandatory, AES-256-GCM, Ed25519 SSH, Step-CA PKI with automated 90-day certificate rotation, DNSSEC validation.
- **Cloud scope (AWS, Azure, GCP — 6 nodes):** all Common Criteria controls extended to cloud nodes via Tailscale WireGuard, Wazuh EDR, Ansible, and provider-native security services (GuardDuty, SCC, Defender for Cloud).

### Gaps and Observations

- **CC1.1 / CC1.2 (Control Environment)** rated Partial: formal policies, oversight structure, and board-level accountability are constrained by the single-administrator personal lab context. In a service organization these would be addressed through executive governance, audit committees, and formal risk committees.
- **CC9.2 (Vendor Risk)** rated Partial: no formal vendor assessment program or contractual security requirements. SBOM tracking via Trivy/Grype planned Q2 2026 to close the dependency visibility gap.
- **SOC 2 context note:** criteria requiring organizational governance structures (CC1.1-CC1.2), formal vendor agreements (CC9.2), and customer-facing privacy commitments are inherently limited by the personal lab scope. The underlying security controls are implemented; the organizational framework around them is not applicable.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | April 2026 | Initial release. Full Common Criteria (CC1-CC9) coverage. Hybrid cloud scope (AWS, Azure, GCP) included. |
