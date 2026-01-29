# NIST Cybersecurity Framework 2.0

**Document Control:**   
Version: 1.0  
Last Updated: January 2026  
Owner: Paul Leone 
 
**Framework Version:** NIST CSF 2.0

---

## Table of Contents

1. [GOVERN (GV)](#govern-gv)
   - 1.1 [GV.OC - Organizational Context](#gvoc---organizational-context)
   - 1.2 [GV.OV - Oversight](#gvov---oversight)
   - 1.3 [GV.RM - Risk Management Strategy](#gvrm---risk-management-strategy)
   - 1.4 [GV.RR - Roles, Responsibilities, and Authorities](#gvrr---roles-responsibilities-and-authorities)
   - 1.5 [GV.PO - Policy](#gvpo---policy)
   - 1.6 [GV.SC - Cybersecurity Supply Chain Risk Management](#gvsc---cybersecurity-supply-chain-risk-management)
2. [IDENTIFY (ID)](#identify-id)
   - 2.1 [ID.AM - Asset Management](#idam---asset-management)
   - 2.2 [ID.RA - Risk Assessment](#idra---risk-assessment)
   - 2.3 [ID.IM - Improvement](#idim---improvement)
3. [PROTECT (PR)](#protect-pr)
   - 3.1 [PR.AA - Identity Management, Authentication and Access Control](#praa---identity-management-authentication-and-access-control)
   - 3.2 [PR.AT - Awareness and Training](#prat---awareness-and-training)
   - 3.3 [PR.DS - Data Security](#prds---data-security)
   - 3.4 [PR.IR - Technology Infrastructure Resilience](#prir---technology-infrastructure-resilience)
   - 3.5 [PR.PS - Platform Security](#prps---platform-security)
4. [DETECT (DE)](#detect-de)
   - 4.1 [DE.AE - Adverse Event Analysis](#deae---adverse-event-analysis)
   - 4.2 [DE.CM - Continuous Monitoring](#decm---continuous-monitoring)
5. [RESPOND (RS)](#respond-rs)
   - 5.1 [RS.AN - Analysis](#rsan---analysis)
   - 5.2 [RS.CO - Communications](#rsco---communications)
   - 5.3 [RS.MA - Incident Management](#rsma---incident-management)
   - 5.4 [RS.MI - Incident Mitigation](#rsmi---incident-mitigation)
6. [RECOVER (RC)](#recover-rc)
   - 6.1 [RC.CO - Incident Recovery Communications](#rcco---incident-recovery-communications)
   - 6.2 [RC.HL - Incident Recovery Plan Execution](#rchl---incident-recovery-plan-execution)
   - 6.3 [RC.RP - Recovery Planning](#rcrp---recovery-planning)

---
---

## GOVERN (GV)

### GV.OC - Organizational Context

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| GV.OC-01 | Context of organization and security strategy **established** | Lab mission statement defines security-first architecture principles; documented security objectives aligned with learning goals; compliance requirements documented |
| GV.OC-02 | Internal and external stakeholders understood | N/A (Personal lab) |
| GV.OC-03 | Legal/regulatory/contractual requirements understood | Conceptual compliance with NIST, CIS, ISO 27001, PCI-DSS frameworks; no actual regulatory obligations (personal lab) |
| GV.OC-04 | Critical objectives, capabilities, services understood | Core services documented (SIEM, EDR, firewalls, DNS, identity management); criticality tiers defined (Tier 1: SIEM/EDR, Tier 2: firewalls/DNS, Tier 3: supporting services) |
| GV.OC-05 | Outcomes of cybersecurity strategy communicated | Documented in lab architecture documents; security metrics tracked in dashboards; quarterly reviews conducted |

---

### GV.OV - Oversight

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| GV.OV-01 | Cybersecurity strategy/expectations overseen | N/A (Personal lab) |
| GV.OV-02 | Responsibilities for outcomes overseen | N/A (Personal lab) |
| GV.OV-03 | Legal/regulatory compliance overseen | N/A (Personal lab) |

---

### GV.RM - Risk Management Strategy

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| GV.RM-01 | Risk management objectives established | Risk-based vulnerability prioritization (CVSS scoring); patch management SLAs by severity; threat-informed security architecture |
| GV.RM-02 | Risk appetite/tolerance defined | Critical CVEs: MTTR <72h; High CVEs: MTTR <7 days; acceptable false positive rate <5%; 95% patch compliance target |
| GV.RM-03 | Cybersecurity added to enterprise risk management | N/A (Personal lab) |
| GV.RM-04 | Strategic direction updated based on risk info | N/A (Personal lab) |
| GV.RM-05 | Lines of communication established | N/A (Personal lab) |
| GV.RM-06 | Workforce understands roles/responsibilities | N/A (Personal lab) |
| GV.RM-07 | Mission/business supported by strategic cybersecurity | N/A (Personal lab) |

---

### GV.RR - Roles, Responsibilities, and Authorities

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| GV.RR-01 | Leadership roles/responsibilities established | N/A (Personal lab) |
| GV.RR-02 | Roles/responsibilities coordinated among stakeholders | N/A (Personal lab) |
| GV.RR-03 | Adequate resources ensured | N/A (Personal lab) |
| GV.RR-04 | Cybersecurity integrated into planning/operations | N/A (Personal lab) |

---

### GV.PO - Policy

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| GV.PO-01 | Policy establishes behavioral expectations | SSH hardening policy (CIS Benchmark); TLS 1.3 minimum policy; vulnerability remediation SLAs; comprehensive logging policy (100% security event coverage) |
| GV.PO-02 | Policy reviewed/updated | N/A (Personal lab) |

---

### GV.SC - Cybersecurity Supply Chain Risk Management

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| GV.SC-01 | Supply chain risk management established | N/A (Personal lab) |
| GV.SC-02 | Suppliers/third parties included in risk mgmt | Limited implementation (Personal lab): Vetted open-source projects used; trusted Docker Hub publishers; official OS repositories |
| GV.SC-03 | Contracts specify security requirements | N/A (no commercial contracts in personal lab); demonstrates understanding through software selection criteria (security reputation, update frequency, community support) |
| GV.SC-04 | Suppliers/partners routinely assessed | Partial implementation: GitHub security alerts monitored; software update frequency tracked; planned CVE monitoring for dependencies |
| GV.SC-05 | Response/recovery planning for supply chain | Limited implementation (Personal lab): Snapshot-before-update strategy; rollback procedures documented |

---

## IDENTIFY (ID)

### ID.AM - Asset Management

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| ID.AM-01 | Inventories of hardware managed | Checkmk inventory; Prometheus node exporters (30+ hosts); Proxmox asset database; external Excel inventory |
| ID.AM-02 | Inventories of software/applications managed | PatchMon tracks 5,000+ packages; WUD tracks 50+ containers; Nessus software inventory; Wazuh agent inventory (25+ endpoints) |
| ID.AM-03 | Network diagrams/organizational communication flows | Network topology documented; Traefik routing architecture; VLAN segmentation diagrams; data flow maps |
| ID.AM-04 | External systems/network connections cataloged | VPN connections documented (Tailscale, PIA, Cloudflare Tunnels); external DNS resolvers tracked; internet egress points mapped |
| ID.AM-05 | Resources prioritized by classification/criticality | Tier 1: SIEM, EDR, firewalls; Tier 2: DNS, identity management; Tier 3: supporting services; documented in asset inventory |
| ID.AM-07 | Inventories of data/information managed | Sensitive data classification (logs, credentials, backups); data flow mapping; retention policies documented |
| ID.AM-08 | Systems/hardware/software/services authorized | Authorized software list maintained; unauthorized application detection via Nessus/Wazuh; procurement approval process |

---

### ID.RA - Risk Assessment

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| ID.RA-01 | Vulnerabilities identified/documented | OpenVAS + Nessus vulnerability scanning; CVSS scoring; CVE correlation with NVD; TheHive vulnerability tracking |
| ID.RA-02 | Cyber threat intelligence received | MISP threat intelligence platform; CrowdSec community feeds; AlienVault OTX, abuse.ch, Emerging Threats; Shuffle threat aggregation |
| ID.RA-03 | Threats identified/documented | MISP threat events; Cortex IOC analysis; threat actor TTPs tracked; MITRE ATT&CK mapping |
| ID.RA-04 | Potential impacts/likelihoods identified | Risk-based remediation prioritization; exploit availability assessed; CVSS temporal scoring; asset criticality factored |
| ID.RA-05 | Threats/vulnerabilities/likelihoods/impacts determined | CVSS base + temporal + environmental scoring; exploit maturity assessment; attack surface analysis |
| ID.RA-06 | Risk responses identified/prioritized | Critical: MTTR <72h; High: MTTR <7d; virtual patching for zero-day; compensating controls documented |
| ID.RA-07 | Changes managed using risk management process | Pre-deployment vulnerability scans; snapshot-before-patch; change approval workflows (WSUS); rollback procedures |
| ID.RA-08 | Processes for receiving/analyzing/responding to vulnerability disclosures | Shuffle vulnerability disclosure workflow; NIST NVD monitoring; vendor advisory tracking; CVE analysis pipeline |
| ID.RA-09 | Response/recovery from identified incidents evaluated | Post-incident reviews in TheHive; MTTR tracking; lessons learned documentation; workflow optimization |
| ID.RA-10 | Critical suppliers/dependencies included in risk assessments | Planned: SBOM tracking; dependency vulnerability scanning; third-party risk assessments |

---

### ID.IM - Improvement

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| ID.IM-01 | Improvements identified from detection/response activities | Vulnerability trends tracked in Grafana; CIS Benchmark compliance scores monitored; patch compliance dashboard; continuous security posture improvement |
| ID.IM-02 | Response/recovery plans tested | Tabletop exercises documented in TheHive; Shuffle workflow testing; playbook dry-runs; quarterly BC/DR testing planned |
| ID.IM-03 | Response/recovery plans incorporate lessons learned | Post-incident reviews drive playbook updates; TheHive lessons learned tracking; Shuffle workflow optimization based on execution data |
| ID.IM-04 | Improvements integrated into updating policy/planning | Annual policy reviews incorporate lessons learned; architecture updates based on incident findings; continuous improvement cycle |

---

## PROTECT (PR)

### PR.AA - Identity Management, Authentication and Access Control

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| PR.AA-01 | Identities/credentials issued/managed/verified | Authentik SSO integration; centralized SSH key management via Ansible; individual user accounts (no shared credentials); MFA enforcement (Authentik TOTP) |
| PR.AA-02 | Identities authenticated | SSH key-based authentication; Authentik SSO; MFA enforcement; certificate-based authentication (Step-CA) |
| PR.AA-03 | Service provider identities authenticated | Traefik ForwardAuth SSO; OAuth2/OIDC integration; API key authentication; certificate validation |
| PR.AA-04 | Identity assertions verified | SAML/OIDC token validation; JWT signature verification; session token validation; certificate chain verification |
| PR.AA-05 | Access permissions/authorizations managed | Authentik RBAC groups; SSH sudo enforcement; Traefik middleware access control; least-privilege principle |
| PR.AA-06 | Physical access managed | Physical security (personal lab): locked server rack, limited access; environmental monitoring; backup power (UPS) |

---

### PR.AT - Awareness and Training

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| PR.AT-01 | Personnel aware of cybersecurity risks | Security awareness demonstrated through lab documentation; threat hunting queries documented; incident response playbooks |
| PR.AT-02 | Privileged users understand roles/responsibilities | SOC analyst role documented; incident commander responsibilities defined; escalation procedures established |
| PR.AT-03 | Third-party stakeholders understand roles/responsibilities | N/A (personal lab); demonstrates understanding through vendor security assessment criteria |
| PR.AT-04 | Senior executives understand roles/responsibilities | N/A (personal lab); role segregation demonstrated through documented workflows |
| PR.AT-05 | Personnel aware of/trained on physical security | Physical security awareness; environmental monitoring; backup procedures |

---

### PR.DS - Data Security

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| PR.DS-01 | Data-at-rest protected | Encrypted backups (AES-256); TLS in transit; scan credential encryption; SSH private keys encrypted; encrypted log transmission (syslog-ng TLS to SIEM); immutable SIEM indexes |
| PR.DS-02 | Data-in-transit protected | TLS 1.3 encryption (Traefik); Ed25519 SSH keys; DNSSEC validation; encrypted VPN tunnels (Tailscale, WireGuard) |
| PR.DS-10 | Integrity/authenticity of hardware/software verified | Package signature verification; container image verification (SHA-256); Step-CA certificate validation |
| PR.DS-11 | Data disposal practices established | Secure deletion procedures; backup rotation policies; log retention limits (90 days); expired certificate cleanup |

---

### PR.IR - Technology Infrastructure Resilience

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| PR.IR-01 | Networks/environments protected | HA DNS failover (dual Pi-hole); Traefik zero-downtime reloads; firewall clustering; network segmentation |
| PR.IR-02 | Security architectures established/maintained | Defense-in-depth architecture; zero-trust principles; documented security controls; continuous assessment |
| PR.IR-03 | Hardware/software disposal practices established | Limited -- homelab. Secure wiping procedures; decommissioning checklists |
| PR.IR-04 | Adequate capacity ensured | Prometheus capacity monitoring; Pulse hypervisor monitoring; disk space alerts; resource trending |
| PR.IR-05 | Continuity prioritized by business criticality | Service prioritization (Tier 1-3); documented recovery priorities; RTO/RPO defined |

---

### PR.PS - Platform Security

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| PR.PS-01 | Configuration management practices established | SSH config via Ansible; Traefik YAML in Git; DNS zones version-controlled; PatchMon configuration tracking; CIS Benchmark audits; Terraform IaC; configuration drift detection |
| PR.PS-02 | Secure software development practices integrated | Infrastructure as Code (Terraform, Ansible); Git version control; CI/CD security linting (planned); code review processes |
| PR.PS-03 | Hardware/software maintained | Multi-platform patch management (PatchMon, WSUS, WUD, Watchtower); vulnerability remediation workflows; automated updates where appropriate |
| PR.PS-04 | Log records generated/managed | 100% security event logging to SIEM; 90-day retention; structured JSON format; comprehensive audit trails |
| PR.PS-05 | Installation/execution of software restricted | Approved software list; unauthorized application detection; AppLocker policies (Windows); sudo restrictions (Linux) |
| PR.PS-06 | Secure configuration of network infrastructure | SSH hardened per CIS Benchmark; Traefik secure headers; firewall hardening; secure DNS configuration |

---

## DETECT (DE)

### DE.AE - Adverse Event Analysis

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| DE.AE-02 | Potentially adverse events analyzed | Vulnerability trending; exploit likelihood assessment; Cortex automated enrichment; MISP threat intelligence correlation; Shuffle orchestrated analysis workflows |
| DE.AE-03 | Information on adverse events correlated | Multi-source correlation (Splunk + Elastic + Wazuh + network logs); TheHive aggregates alerts from SIEM, EDR, IDS; Shuffle orchestrates cross-platform queries |
| DE.AE-04 | Impact of adverse events understood | TheHive case severity scoring; asset criticality assessment; business impact analysis; risk-based prioritization |
| DE.AE-05 | Incident alert thresholds established | Splunk correlation search thresholds; Wazuh rule severity levels; TheHive case severity matrix; Prometheus alert thresholds; Grafana panel thresholds |
| DE.AE-06 | Information on adverse events provided | Discord/email real-time notifications; TheHive case notifications; Splunk scheduled alerts; Shuffle multi-channel alerting |
| DE.AE-07 | Cyber threat intelligence integrated | MISP threat intelligence feeds; CrowdSec community intelligence; Cortex enrichment; Shuffle threat aggregation workflows |
| DE.AE-08 | Incidents declared when adverse events meet criteria | TheHive automated case creation; Shuffle workflow triggers; severity-based escalation; SOC analyst notification |

---

### DE.CM - Continuous Monitoring

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| DE.CM-01 | Networks/network services monitored | DNS query logging; Traefik access logs to SIEM; pfSense flow logs; Suricata/Snort IDS; NetalertX network monitoring; 100% network traffic visibility |
| DE.CM-02 | Physical environment monitored | Limited: Temperature/humidity sensors; power monitoring (UPS); physical access logging |
| DE.CM-03 | Personnel activity monitored | Active Directory audit logs; Authentik authentication tracking; SSH session logging; privileged access monitoring |
| DE.CM-04 | Malicious code activity monitored | Wazuh FIM; Yara rules; Cortex file analysis; Suricata IDS signatures; ClamAV/Microsoft Defender |
| DE.CM-05 | Unauthorized network connections/mobile code detected | Network device inventory; MAC address tracking; Wazuh agent monitoring; unauthorized access detection via NetalertX |
| DE.CM-06 | External service provider activity monitored | Limited: Cloudflare analytics; VPN logs; public service monitoring; API usage tracking |
| DE.CM-07 | Monitoring for unauthorized activity performed | Failed authentication tracking; privilege escalation detection; lateral movement monitoring; Shuffle automated analysis |
| DE.CM-09 | Vulnerability scans performed | Weekly OpenVAS scans; monthly Nessus authenticated scans; daily PatchMon checks; continuous Wazuh assessment; SIEM correlation of scan results |
| DE.CM-10 | Threat hunting performed | Wazuh threat hunting queries; Splunk SPL searches; Elastic KQL queries; MITRE ATT&CK-based hunting; Cortex IOC pivoting |

---

## RESPOND (RS)

### RS.AN - Analysis

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| RS.AN-01 | Notifications investigated | Cortex multi-engine analysis; MISP correlation; Splunk queries; Wazuh forensic data; TheHive case investigation |
| RS.AN-02 | Impact of incidents understood | Asset inventory correlation; data classification; business impact analysis; TheHive case severity assessment |
| RS.AN-03 | Forensics performed | Wazuh forensic data collection; memory dumps; network captures; Shuffle automated forensic workflows; evidence preservation |
| RS.AN-04 | Incidents categorized | TheHive taxonomy; MITRE ATT&CK mapping; severity scoring; incident classification (confirmed, false positive, benign) |
| RS.AN-05 | Incident analysis processes established | Documented analysis procedures; Cortex analyzer workflows; MISP playbooks; Shuffle investigation templates |

---

### RS.CO - Communications

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| RS.CO-01 | Personnel know roles/responsibilities | N/A (personal lab) |
| RS.CO-02 | Events reported | Discord #incident-response channel; TheHive case creation; Splunk notable events; email notifications |
| RS.CO-03 | Information shared | MISP threat intelligence sharing; CrowdSec community contributions; internal team notifications |

---

### RS.MA - Incident Management

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| RS.MA-01 | Incident response plans activated | TheHive playbooks (15+); Shuffle workflows (phishing, malware, ransomware, vulnerability); automated orchestration |
| RS.MA-02 | Incident reports enriched | Cortex enrichment; MISP correlation; Splunk context; TheHive observable analysis; Shuffle automated data gathering |
| RS.MA-03 | Incidents contained | Wazuh Active Response; Cortex responders; Shuffle automated containment workflows; pfSense API firewall rules; network isolation |
| RS.MA-04 | Incidents eradicated | Malware removal; account lockouts; vulnerability patching; configuration remediation; Shuffle remediation workflows |
| RS.MA-05 | Incidents resolved | TheHive case closure; verification scans; service restoration; post-incident documentation |

---

### RS.MI - Incident Mitigation

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| RS.MI-01 | Vulnerabilities mitigated/documented | Virtual patching (Safeline WAF); IDS signatures; emergency patching via Ansible; TheHive vulnerability tracking |
| RS.MI-02 | Strategies for responding to incidents established | TheHive playbooks; Shuffle workflows; Cortex responder library; documented response procedures |

---

## RECOVER (RC)

### RC.CO - Incident Recovery Communications

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| RC.CO-01 | Public relations managed | N/A (personal lab) |
| RC.CO-02 | Reputation protected | N/A (personal lab) |
| RC.CO-03 | Recovery activities communicated | N/A (personal lab) |

---

### RC.HL - Incident Recovery Plan Execution

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| RC.HL-01 | Recovery plan executed | Backup restoration procedures; system rebuild playbooks; service validation checklists; snapshot rollback |
| RC.HL-02 | Recovery activities completed | Verification testing; service health checks; performance validation; security posture confirmation |

---

### RC.RP - Recovery Planning

| Subcategory | Description | Implementation |
|-------------|-------------|----------------|
| RC.RP-01 | Recovery plan exercised | Recovery procedure testing; RTO/RPO validation |

---

**Document Version:** 2.0  
**Last Updated:** January 14, 2026  
**Classification:** Internal Use