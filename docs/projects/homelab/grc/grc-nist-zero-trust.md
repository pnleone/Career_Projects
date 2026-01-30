# NIST SP 800-207 Zero Trust Architecture

**Document Control:**  
Version: 1.0  
Last Updated: January 2026  
Owner: Paul Leone  
  
**Framework Version:** 

---

## Zero Trust Architecture Implementation Overview

This cybersecurity lab demonstrates comprehensive Zero Trust Architecture (ZTA) principles aligned with **NIST SP 800-207** and **CISA Zero Trust Maturity Model v2.0**. The implementation achieves **Advanced maturity** (Stage 3 of 4) across core Zero Trust pillars through explicit verification of every access request, least-privilege enforcement via RBAC, assume-breach mentality with continuous monitoring, and encrypt-everything policies using modern cryptographic standards.

---

## Zero Trust Tenets Implementation

### Tenet 1: All Data Sources and Computing Services as Resources

**Implementation Status: Advanced**

Lab treats all assets as resources requiring explicit authentication/authorization. 25+ physical hosts, 50+ containers, 30+ VMs, network devices (pfSense, OPNsense, Pi-hole), storage systems, and cloud-hosted services (Authentik planning) all subject to access controls. BYOD consideration planned via Authentik device flow and Wazuh compliance validation. Small footprint devices (IoT sensors, network monitors) send data through authenticated channels to aggregators.

**Evidence:** Proxmox inventory tracking, Docker container registry, Wazuh agent deployment across endpoints, NetalertX network discovery, Checkmk infrastructure monitoring.

**Gap to Optimal:** Limited IoT device integration, incomplete BYOD policy enforcement, need automated asset classification with dynamic policy application.

---

### Tenet 2: All Communication Secured Regardless of Network Location

**Implementation Status: Advanced**

Network location provides no implicit trust. TLS 1.3 mandatory for all web services (Traefik enforcement), SSH encrypted with Ed25519 certificates, VPN encryption via WireGuard/OpenVPN, syslog-ng TLS for log transmission. Internal traffic treated identically to external—Authentik ForwardAuth validates all requests regardless of source VLAN. Step-CA PKI provides certificate-based authentication for service-to-service communication.

**Evidence:** Traefik middleware configuration requiring authentication on all VLANs, syslog-ng TLS certificates, Step-CA certificate issuance logs, VPN encryption audit logs.

**Gap to Optimal:** Mutual TLS (mTLS) not fully deployed for all service-to-service communication, some legacy applications lack modern encryption, need encrypted DNS (DoH/DoT) enterprise-wide.

---

### Tenet 3: Per-Session Resource Access with Least Privilege

**Implementation Status: Advanced**

Access granted per-session via Authentik OAuth2/OIDC with 30-minute session timeouts requiring re-authentication. OAuth2 scopes limit permissions to minimum operations. SSH sessions use temporary sudo elevation with explicit justification. No persistent elevated privileges—all access time-limited and activity-specific. Traefik ForwardAuth validates each request independently.

**Evidence:** Authentik session timeout logs, OAuth2 scope configurations, sudo elevation audit logs, Traefik access validation per-request.

**Gap to Optimal:** Need just-in-time (JIT) access provisioning with automated expiration, dynamic privilege elevation based on real-time risk assessment, continuous session validation beyond timeout intervals.

---

### Tenet 4: Dynamic Policy Based on Observable State

**Implementation Status: Advanced**

Policy engine (Authentik) evaluates user identity, group membership, device compliance (Wazuh status), source IP reputation, time-of-day restrictions, MFA verification, and behavioral patterns. Policies adapt based on threat intelligence (MISP correlation), failed authentication patterns, geoIP anomalies. Environmental attributes include network location, reported active attacks, device patch level.

**Evidence:** Authentik policy configurations incorporating Wazuh compliance data, Splunk behavioral analytics dashboards, MISP threat correlation logs, time-based access restrictions.

**Gap to Optimal:** Need real-time continuous risk scoring with dynamic policy updates without manual intervention, automated behavioral baselines with deviation-triggered policy changes, comprehensive environmental telemetry integration.

---

### Tenet 5: Monitor and Measure All Asset Integrity

**Implementation Status: Advanced**

Wazuh agents on 25+ endpoints provide real-time compliance validation against CIS Benchmarks (92-98% compliance). Nessus authenticated scans monthly, Ansible drift detection, container health checks, VM monitoring via Proxmox. Non-compliant devices quarantined to remediation VLAN. CDM-like capabilities via PatchMon (5,000+ packages tracked), vulnerability correlation to NVD, automated patch workflows.

**Evidence:** Wazuh SCA reports, Nessus scan results, PatchMon vulnerability tracking, Ansible compliance playbooks, automated quarantine workflows in firewall logs.

**Gap to Optimal:** Need real-time asset risk scoring, automated remediation without manual approval for non-critical systems, comprehensive SBOM tracking (Trivy/Grype deployment Q1 2026), continuous hardware/firmware integrity validation.

---

### Tenet 6: Dynamic Authentication and Authorization

**Implementation Status: Advanced**

Authentik provides dynamic ICAM with MFA (TOTP, FIDO2/WebAuthn planning), OAuth2/OIDC integration, LDAP/SAML support. Continuous evaluation via session timeouts, behavioral monitoring (Splunk analytics), threat-triggered re-authentication. Asset management via Wazuh, NetalertX, Checkmk. Policy-based re-authentication on resource changes, time-based intervals, anomalous activity detection.

**Evidence:** Authentik MFA enforcement logs, re-authentication triggers in SIEM, behavioral anomaly detection alerts, dynamic policy application based on threat intelligence.

**Gap to Optimal:** Full passwordless authentication via FIDO2/WebAuthn, continuous authentication beyond session-based model, automated privilege adjustment based on real-time risk, biometric MFA integration.

---

### Tenet 7: Collect and Use Security Posture Data

**Implementation Status: Advanced**

Comprehensive telemetry: Wazuh endpoint data, Suricata/Snort network IDS, pfSense flow logs, Traefik access logs, Pi-hole DNS queries, Prometheus metrics, application logs. Data processed in dual SIEM (Splunk + Elastic) with correlation, behavioral analytics, threat hunting. Insights improve policy via monthly reviews, automated IOC blocking, vulnerability-driven patching.

**Evidence:** SIEM ingestion rates (100% security events), correlation rule effectiveness, policy updates based on SIEM analytics, threat intelligence integration (MISP), automated IOC blocking.

**Gap to Optimal:** Machine learning/UEBA for predictive analytics, comprehensive data lake for long-term analysis, automated policy generation from threat intelligence, real-time feedback loop for policy optimization.

---

## NIST SP 800-207 Logical Components

### Policy Engine (PE)

**Implementation:** Authentik serves as primary PE, evaluating access requests against enterprise policy, user attributes, device compliance (Wazuh integration), threat intelligence (MISP), behavioral baselines (Splunk), and environmental factors. Trust algorithm considers identity confidence, device posture, request context, historical behavior, current threat landscape.

**Trust Algorithm Type:** Hybrid score-based and criteria-based, contextual evaluation considering subject history, access patterns, anomaly detection.

**Evidence:** Authentik policy logs, access decision audit trails, Wazuh compliance integration, Splunk behavioral correlation.

**Gap:** Need fully automated trust scoring, real-time ML-based risk calculation, comprehensive external data source integration.

---

### Policy Administrator (PA)

**Implementation:** Authentik PA configures communication paths via Traefik middleware, generates OAuth2 tokens, manages session lifecycles, coordinates with Step-CA for certificate-based authentication. Controls session establishment/termination based on PE decisions and ongoing monitoring.

**Evidence:** OAuth2 token generation logs, session establishment/teardown events, Traefik dynamic configuration updates, Step-CA certificate issuance coordination.

**Gap:** Need automated PEP configuration at scale, service mesh integration for microservice communication paths, dynamic network path creation.

---

### Policy Enforcement Point (PEP)

**Implementation:** Multi-component PEP architecture:

**Client-side:** Authentik ForwardAuth integration in browsers, SSH certificate-based authentication, Wazuh agent compliance reporting, VPN device authentication

**Resource-side:** Traefik reverse proxy, pfSense/OPNsense firewalls, SafeLine WAF, service-specific gateways

**Control Plane:** Isolated management network for PE/PA/PEP communication

**Data Plane:** Application traffic on segregated VLANs

**Deployment Model:** Hybrid agent/gateway (Authentik + Traefik), enclave gateway (DMZ services), resource portal (web applications).

**Evidence:** Traefik ForwardAuth logs, firewall rule enforcement, WAF block rates, SSH certificate validation, VLAN isolation configs.

**Gap:** Need device agents for comprehensive endpoint coverage, unified PEP management interface, automated PEP deployment for new resources.

---

## Data Sources for Policy Decisions

### Continuous Diagnostics and Mitigation (CDM)

**Implementation:** Wazuh provides CDM capabilities: vulnerability assessment, FIM, rootkit detection, CIS Benchmark compliance (SCA), patch management via PatchMon integration. Nessus authenticated scans complement. Ansible enforces configurations, detects drift. Container/VM monitoring via Proxmox and Docker health checks.

**Evidence:** Wazuh vulnerability reports, compliance scan results (92-98%), PatchMon package tracking (5,000+ packages), Ansible drift detection alerts.

**Gap:** Need comprehensive CDM platform integration, automated non-enterprise device policy enforcement, real-time software inventory with SBOM.

---

### Industry Compliance System

**Implementation:** Policy framework aligned with CIS Benchmarks, NIST 800-53 controls, PCI-DSS requirements (where applicable), ISO 27001 standards. Wazuh SCA enforces CIS policies, vulnerability remediation follows NIST guidelines, encryption standards per NIST/PCI-DSS.

**Evidence:** CIS Benchmark compliance reports, control mapping documentation, policy version control (Git), quarterly compliance reviews.

**Gap:** Automated compliance validation across all frameworks, dynamic policy updates based on regulatory changes, comprehensive audit trail integration.

---

### Threat Intelligence Feeds

**Implementation:** MISP threat intelligence platform correlates IOCs across network logs, endpoint telemetry, application data. Splunk integrates feeds for correlation. Suricata/Snort use threat signatures. GeoIP databases identify suspicious locations. Cortex analyzers (VirusTotal, Hybrid Analysis) provide malware analysis.

**Evidence:** MISP IOC correlation logs, automated IOC blocking (Wazuh Active Response), threat intelligence-driven alerts, malware analysis reports.

**Gap:** Need additional commercial threat feeds, automated STIX/TAXII integration, predictive threat modeling, insider threat detection feeds.

---

### Network and System Activity Logs

**Implementation:** Dual SIEM architecture (Splunk + Elastic) aggregates 100% security events: authentication logs, firewall traffic, DNS queries (Pi-hole), web access (Traefik), endpoint events (Wazuh), network IDS (Suricata), infrastructure metrics (Prometheus). Real-time correlation detects multi-stage attacks, lateral movement, data exfiltration patterns.

**Evidence:** SIEM ingestion statistics, correlation rule effectiveness, alert volumes, retention compliance (90-day hot, 1-year cold), multi-source event correlation.

**Gap:** Need unified logging schema, comprehensive cloud service log integration, enhanced UEBA capabilities, longer retention with efficient archival.

---

### Data Access Policies

**Implementation:** RBAC via Authentik groups mapped to resource permissions. Filesystem ACLs, database role-based permissions, application-level authorization. Policies encoded in Authentik, enforced via Traefik middleware, validated quarterly. Sensitivity-based policies (Public, Internal, Confidential, Restricted) with handling requirements.

**Evidence:** Authentik RBAC configurations, quarterly access reviews, policy documentation (version-controlled), filesystem/database ACL audits.

**Gap:** Need attribute-based access control (ABAC), automated policy generation from data classification, dynamic policies based on data sensitivity changes.

---

### Enterprise PKI

**Implementation:** Step-CA provides automated certificate lifecycle: issuance, renewal, rotation (90-day lifetimes). SSH certificate-based authentication, TLS certificates for services, mutual TLS planning. Integration with Authentik for identity certificates. No reliance on external CA for internal services.

**Evidence:** Step-CA issuance logs, certificate rotation compliance, SSH cert validation logs, TLS certificate inventory, cryptographic algorithm compliance (TLS 1.3, Ed25519).

**Gap:** Need Federal PKI integration for inter-agency collaboration, hardware security module (HSM) for root CA protection, comprehensive certificate transparency monitoring.

---

### ID Management System

**Implementation:** Authentik serves as authoritative identity source: user accounts, attributes, group memberships, device identities, service accounts. LDAP/OAuth2/OIDC/SAML support for federated identity. Integration with Step-CA for certificate binding. Account lifecycle management with automated provisioning/deprovisioning (standard users), manual approval for privileged accounts.

**Evidence:** Authentik user database, group assignment logs, federated identity configurations, account lifecycle audit trails, integration logs with downstream systems.

**Gap:** Need full automation of privileged account lifecycle, federated identity with external partners, comprehensive identity governance platform, automated role mining.

---

### SIEM System

**Implementation:** Dual architecture—Splunk (primary analytics) and Elastic (secondary/redundancy) collect security-centric data for policy refinement, attack detection, forensics. 90-day hot retention, 1-year cold storage. Dashboards track vulnerabilities, patch compliance, authentication patterns, threat indicators. Alerts feed TheHive case management, Shuffle SOAR orchestration.

**Evidence:** SIEM correlation rules (100+ active), dashboard usage, alert-to-incident conversion rates, retention compliance, SOAR integration workflows.

**Gap:** Need automated playbook optimization, comprehensive use case coverage, advanced analytics (UEBA/ML), threat hunting automation, extended retention for regulatory compliance.

---

## ZTA Deployment Model Assessment

### Primary Model: Device Agent/Gateway (Hybrid)

**Implementation:** Authentik acts as central policy administrator. Client-side enforcement via browser-based ForwardAuth (no installed agent for web resources), SSH certificate agents for terminal access. Resource-side gateways include Traefik (web services), pfSense/OPNsense (network perimeter), SafeLine WAF (application layer).

**Strengths:** No required client software for web access (BYOD-friendly), centralized policy management, defense-in-depth with multiple gateway layers.

**Weaknesses:** Limited endpoint visibility for non-enterprise devices, cannot enforce compliance before web access attempts, relies on network controls for non-web protocols.

**Evidence:** Traefik ForwardAuth integration across 50+ services, SSH certificate distribution via Ansible, gateway configuration management.

---

### Secondary Model: Enclave-Based

**Implementation:** DMZ services protected by enclave gateway (pfSense), application tier isolated behind Traefik, backend services (databases, SIEM, PKI) on dedicated VLANs with restricted access. Cloud services will use cloud-provider gateways when Authentik cloud deployment occurs.

**Evidence:** 3-tier architecture (DMZ, application, backend), VLAN isolation with firewall enforcement, gateway placement protecting service enclaves.

---

### Tertiary Model: Resource Portal

**Implementation:** Web-based access to services via Traefik reverse proxy acting as portal. No client agents required. Authentication/authorization at portal before proxying to resources. Used for contractor access, cross-organization collaboration, public-facing authenticated services.

**Evidence:** Traefik portal configurations, authentication workflows, contractor access logs, session management.

---

## ZTA Use Case Alignment

### Use Case 1: Enterprise with Satellite Facilities (Remote Workers)

**Applicability:** High—supports remote administration, off-site monitoring, telecommuting scenarios.

**Implementation:** Tailscale mesh VPN provides secure remote access without traditional VPN concentrator. Authentik authenticates remote users, validates device compliance via Wazuh remote agent data. Cloud-ready architecture (Authentik cloud planning) enables direct cloud resource access without hairpinning through on-premises infrastructure.

**Evidence:** Tailscale deployment, remote Wazuh agent reporting, Authentik MFA enforcement for remote sessions, direct cloud access configurations.

---

### Use Case 2: Multi-Cloud/Cloud-to-Cloud

**Applicability:** Medium—current cloud usage limited but growing.

**Implementation:** Planning for Authentik cloud deployment enables policy enforcement for cloud resources. Current cloudflare Tunnels provide secure cloud ingress without port forwarding. Future cloud-hosted services will authenticate via Authentik OAuth2/OIDC, enforce same policies as on-premises.

**Evidence:** Cloudflare Tunnel configurations, cloud service authentication planning, policy portability across environments.

**Gap:** Need comprehensive multi-cloud policy orchestration, cloud workload protection platform (CWPP), cloud access security broker (CASB) capabilities.

---

### Use Case 3: Contracted Services/Nonemployee Access

**Applicability:** High—supports guest network, contractor access, IoT device isolation.

**Implementation:** Open guest network with internet access but no enterprise resource visibility. Authentik provides time-limited contractor accounts with restricted resource access. Smart building systems isolated on dedicated VLAN, accessible only to vendor service accounts with MFA. Visitor devices cannot discover internal resources (SDP principles).

**Evidence:** Guest VLAN isolation, contractor account lifecycle (creation, time limits, deactivation), vendor MFA enforcement, network segmentation preventing reconnaissance.

---

### Use Case 4: Cross-Enterprise Collaboration

**Applicability:** Medium—prepared for federated scenarios.

**Implementation:** Authentik supports OAuth2/OIDC/SAML federation, enabling cross-organization collaboration. Can establish federated trust with partner identity providers. Resource-specific policies grant external user access to designated collaboration resources (shared databases, project management tools) while denying access to other systems.

**Evidence:** Authentik federation capabilities, external identity source configurations, resource-specific policy enforcement.

**Gap:** Need formal federated identity agreements, cross-domain trust establishment, collaborative security posture sharing.

---

### Use Case 5: Public/Customer-Facing Services

**Applicability:** Low—limited public-facing services currently.

**Implementation:** Public web services (if deployed) would use Traefik with optional authentication. No enforcement of device posture for anonymous public access. Registered user portals (future) could enforce password policies, optional MFA, browser type validation. Metadata collection for attack detection (rate limiting, browser fingerprinting, bot detection).

**Evidence:** Traefik rate limiting, WAF rules blocking automated attacks, access pattern analysis.

---

## Threats and Mitigations

### Threat 1: Subversion of ZTA Decision Process

**Risk Level:** High—PE/PA compromise undermines entire architecture.

**Mitigations:**

- Authentik access restricted to dedicated administrator accounts with MFA
- All configuration changes logged to SIEM with alerting
- Git version control for policy configurations with approval workflow
- Quarterly access reviews for administrative privileges
- Authentik deployed on hardened, isolated systems with minimal attack surface

**Evidence:** Admin account audit logs, SIEM alerting on policy changes, Git commit history, privilege review documentation.

**Gap:** Need HSM-backed key material, multi-person approval for critical policy changes, immutable audit logging with tamper detection.

---

### Threat 2: Denial-of-Service or Network Disruption

**Risk Level:** Medium—disruption impacts business continuity.

**Mitigations:**

- HA firewall cluster (pfSense CARP) with <5-second failover
- Dual DNS (Pi-hole) with automatic failover
- Dual SIEM architecture (Splunk + Elastic) for resilience
- Redundant internet connections with automatic failover
- Load balancing via Traefik across multiple backends

**Evidence:** Failover testing logs, uptime statistics (99.9% DNS availability), redundant service configurations, load balancer health checks.

**Gap:** Need distributed PEP deployment across geographic locations, DDoS mitigation service, automated failover testing, comprehensive disaster recovery testing.

---

### Threat 3: Stolen Credentials/Insider Threat

**Risk Level:** Medium—valid credentials bypass many controls.

**Mitigations:**

- MFA enforcement (TOTP current, FIDO2/WebAuthn planned) reduces credential theft impact
- Contextual trust algorithm detects anomalous behavior (unusual times, locations, access patterns)
- Session timeouts (30 minutes) limit exposure window
- Behavioral analytics (Splunk) identify compromised account indicators
- Least privilege limits blast radius—stolen HR credentials cannot access financial systems
- Lateral movement prevention via network segmentation, least privilege

**Evidence:** MFA enforcement logs, behavioral anomaly alerts, session timeout enforcement, privilege restriction audit logs, lateral movement detection in SIEM.

**Gap:** Need continuous authentication beyond session-based, risk-based step-up authentication, automated account suspension on high-risk activity, comprehensive insider threat program.

---

### Threat 4: Visibility Limitations on Encrypted Traffic

**Risk Level:** Low to Medium—cannot inspect all traffic.

**Mitigations:**

- Metadata collection from encrypted sessions (source, destination, timing, volume)
- Certificate inspection for TLS connections (Step-CA issued certificates trusted, external certificates scrutinized)
- DNS query logging (Pi-hole) identifies suspicious domains even with encrypted payloads
- Endpoint visibility via Wazuh agents provides process-level context
- Network behavior analysis detects anomalies without decryption

**Evidence:** Flow log analysis, DNS-based threat detection, endpoint telemetry correlation, encrypted traffic metadata dashboards.

**Gap:** Need TLS inspection capabilities with appropriate privacy controls, DNS over HTTPS (DoH) traffic handling, encrypted malware detection capabilities.

---

### Threat 5: Stored Data Compromise

**Risk Level:** Medium—reconnaissance data valuable to attackers.

**Mitigations:**

- SIEM data, network diagrams, configuration files stored with encryption at rest (AES-256)
- Access to security data repositories restricted to security team with MFA
- Configuration management tools (Ansible, Terraform) protected with vault encryption
- Most restrictive access policies on security infrastructure components
- Regular access reviews for security data access

**Evidence:** Encryption-at-rest configurations, access restriction logs, security data access audit trails, vault usage logs.

**Gap:** Need data loss prevention (DLP) for security data, comprehensive data classification, automated security data access reviews, honeypot/deception technology.

---

### Threat 6: Vendor Lock-in/Proprietary Formats

**Risk Level:** Medium—impacts flexibility and resilience.

**Mitigations:**

- Open-source focus (Authentik, Wazuh, Traefik, Suricata) reduces vendor lock-in
- Standard protocols (OAuth2, OIDC, SAML, LDAP) enable interoperability
- Infrastructure-as-code (Terraform, Ansible) allows migration to alternative platforms
- Multi-vendor approach for critical functions (dual SIEM, multiple authentication methods)
- Regular evaluation of alternative solutions

**Evidence:** Open-source tool selection, standard protocol usage, IaC repositories, vendor diversity in architecture.

**Gap:** Need formal vendor evaluation framework, migration plans for critical dependencies, comprehensive data portability validation.

---

### Threat 7: Automated Agent/NPE Compromise

**Risk Level:** Medium—service accounts have elevated privileges.

**Mitigations:**

- Service account credentials stored in Vaultwarden with automated retrieval
- API keys rotated quarterly with automated expiration
- Service account activity logged and monitored for anomalies
- Principle of least privilege for automation accounts (read-only where possible)
- Automated agent authentication via certificate-based methods (Step-CA)

**Evidence:** Service account activity logs, API key rotation schedules, certificate-based automation authentication, anomaly detection for NPE accounts.

**Gap:** Need just-in-time service account provisioning, short-lived credentials for all automation, comprehensive NPE behavior baselines, automated agent attestation.

---

## Deployment Maturity Assessment

**Overall NIST ZTA Maturity: Advanced**

**Strengths:**

- Comprehensive implementation of ZT tenets 1-7
- Mature logical component deployment (PE, PA, PEP)
- Rich data sources for policy decisions (CDM, threat intel, SIEM, PKI, IAM)
- Hybrid deployment model supporting diverse use cases
- Strong threat mitigation posture
- Open standards and interoperability focus

**Gaps to Optimal:**

- Device agents for comprehensive endpoint coverage
- Full passwordless authentication (FIDO2/WebAuthn)
- Continuous authentication beyond session-based model
- Machine learning/UEBA for predictive analytics
- Comprehensive cloud security integration
- Automated policy generation from threat intelligence
- Just-in-time access provisioning enterprise-wide
- Hardware security modules for critical key material

**Recommended Priorities Q1-Q2 2026:**

- FIDO2/WebAuthn deployment for passwordless MFA
- Trivy/Grype for comprehensive SBOM tracking
- UEBA capabilities in SIEM platforms
- Mutual TLS for all service-to-service communication
- Comprehensive DLP implementation
- Formal federated identity program

**Framework Alignment:**

- NIST SP 800-207: Advanced maturity, comprehensive tenet implementation
- NIST RMF: Access policies risk-based, continuous monitoring aligned
- NIST Privacy Framework: Privacy controls for monitoring data, user consent mechanisms
- FICAM: Strong identity governance, MFA enforcement, lifecycle management
- TIC 3.0: Network security capabilities aligned, PEP-based enforcement
- EINSTEIN/NCPS: Telemetry compatible, incident response integration ready
- CDM: Mature diagnostics and mitigation capabilities via Wazuh/PatchMon
- Cloud Smart: Cloud-ready architecture, hybrid deployment support

This Zero Trust implementation demonstrates advanced alignment with NIST SP 800-207 principles, providing production-ready capabilities for federal civilian executive branch agencies and enterprise environments pursuing comprehensive ZTA adoption.