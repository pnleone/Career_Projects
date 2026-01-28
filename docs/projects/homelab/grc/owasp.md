# OWASP Top 10 (2025) Framework

**Document Control:**  
Version: 1.0  
Last Updated: January 2026  
Owner: Paul Leone  
Classification: Internal Use  

**Framework Version:** OWASP Top 10:2025

---

## Table of Contents

1. [A01:2025 - Broken Access Control](#a012025---broken-access-control)
2. [A02:2025 - Security Misconfiguration](#a022025---security-misconfiguration)
3. [A03:2025 - Software Supply Chain Failures](#a032025---software-supply-chain-failures)
4. [A04:2025 - Cryptographic Failures](#a042025---cryptographic-failures)
5. [A05:2025 - Injection](#a052025---injection)
6. [A06:2025 - Insecure Design](#a062025---insecure-design)
7. [A07:2025 - Authentication Failures](#a072025---authentication-failures)
8. [A08:2025 - Software or Data Integrity Failures](#a082025---software-or-data-integrity-failures)
9. [A09:2025 - Security Logging and Alerting Failures](#a092025---security-logging-and-alerting-failures)
10. [A10:2025 - Mishandling of Exceptional Conditions](#a102025---mishandling-of-exceptional-conditions)
11. [OWASP Top 10:2025 - Compliance Summary](#owasp-top-102025---compliance-summary)

---

## A01:2025 - Broken Access Control

**Risk Description:** Failures in access control allow unauthorized users to access, modify, or delete resources beyond their intended permissions. This includes SSRF (Server-Side Request Forgery), which has been rolled into this category.

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Authentication | Authentik ForwardAuth enforces authentication for all Traefik-routed services; SSH key-only access (passwords disabled globally) | NIST AC-3, ISO 27001 A.5.15 |
| Authorization | Authentik RBAC groups; OAuth2 scopes; SSH sudo policies; least-privilege principle | NIST AC-2(7), CIS Control 6.1 |
| Network Controls | Traefik IP allowlisting; firewall ACLs per VLAN; pfSense default-deny rules | NIST SC-7, PCI-DSS 1.2.1 |
| SSRF Prevention | DNS rebinding protection; Traefik backend validation; SSH tunnel restrictions; network segmentation; egress filtering | OWASP Prevention |
| API Security | API key authentication; rate limiting; request validation; certificate-based authentication | NIST IA-5, ISO 27001 A.14.1 |
| Monitoring | Wazuh monitors unauthorized access attempts; Splunk authentication dashboard tracks access requests; TheHive case creation for access violations | NIST AU-6, CIS Control 6.1 |

---

## A02:2025 - Security Misconfiguration

**Risk Description:** Improperly configured security settings, default credentials, unnecessary features, verbose error messages, and missing security headers.

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Baseline Hardening | SSH hardened per CIS Benchmark; Traefik secure defaults; DNSSEC enabled; pfSense/OPNsense hardened configurations | NIST CM-6, CIS Control 4.1 |
| Configuration Management | Ansible playbooks define baselines; Terraform IaC; Git version control; configuration drift detection | NIST CM-2, ISO 27001 A.8.9 |
| Default Credentials | SSH root login disabled; default Traefik dashboard credentials changed; validated via authenticated Nessus scans; Wazuh SCA detects default accounts | NIST IA-5(1), CIS Control 4.7 |
| Unnecessary Services | Unnecessary services disabled; verified via authenticated Nessus scans; minimal attack surface | NIST CM-7, PCI-DSS 2.2.2 |
| Security Headers | Traefik secure headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options); NGINX security configurations | OWASP Prevention |
| Continuous Auditing | Weekly OpenVAS scans; monthly Nessus authenticated scans; Wazuh SCA compliance audits (CIS Benchmarks); configuration deviation alerts | NIST CA-2, CIS Control 4.1 |

---

## A03:2025 - Software Supply Chain Failures

**Risk Description:** Expanded scope from A06:2021 to include compromises occurring within or across the entire ecosystem of software dependencies, build systems, and distribution infrastructure.

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Software Sources | Official Docker images; maintained open-source projects (Traefik, Authentik, OpenVAS); trusted repositories only | CIS Control 16.5 |
| Package Verification | Package signature verification; container image verification (SHA-256); GPG key validation | NIST CM-8, ISO 27001 A.8.32 |
| Dependency Tracking | Not Implemented: SBOM tracking via Trivy/Grype; dependency vulnerability scanning; automated CVE monitoring for dependencies | NIST RA-5, OWASP Prevention |
| Update Management | Coordinated patching via PatchMon, WSUS, Watchtower; vulnerability-driven update prioritization; rollback capability | NIST SI-2, CIS Control 7.4 |
| Build Security | Not Implemented: CI/CD security linting; container scanning in pipelines; Infrastructure as Code validation | NIST SA-10 |
| Threat Intelligence | MISP tracks vendor compromises; Shuffle vulnerability disclosure workflow monitors supply chain risks; GitHub security alerts | NIST PM-16, ISO 27001 A.5.7 |

---

## A04:2025 - Cryptographic Failures

**Risk Description:** Failures related to cryptography (or lack thereof) that often lead to sensitive data exposure or system compromise. Falls from #2 to #4 in ranking.

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Encryption in Transit | TLS 1.3 mandatory (Traefik); SSH AES-256-GCM; DNS-over-TLS (planned); VPN encryption (WireGuard, OpenVPN) | NIST SC-8, PCI-DSS 4.2.1 |
| Encryption at Rest | Encrypted backups (AES-256); SSH private keys encrypted; database encryption where applicable | NIST SC-28, ISO 27001 A.8.24 |
| Key Management | Step-CA automated certificate issuance; SSH key generation (Ed25519); centralized key management via Ansible; Vaultwarden secrets management | NIST SC-12, ISO 27001 A.8.24 |
| Cipher Suites | Modern algorithms only (Ed25519, AES-256-GCM, TLS 1.3); weak cipher detection via vulnerability scans; SSL/TLS configuration hardening | NIST SC-13, CIS Control 13.10 |
| Certificate Management | Step-CA PKI (Root + Intermediate CA); Traefik cert distribution; automated renewal; zero certificate expiry incidents | NIST SC-17, ISO 27001 A.8.24 |
| Monitoring | Certificate expiry monitoring (Uptime Kuma, Prometheus); weak cipher detection (Nessus); TLS configuration validation | NIST AU-6, CIS Control 8.6 |

---

## A05:2025 - Injection

**Risk Description:** Injection vulnerabilities from Cross-site Scripting (high frequency/low impact) to SQL Injection (low frequency/high impact). Falls from #3 to #5.

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Input Validation | DNS query validation; SSH input sanitization; Traefik header injection prevention; WAF input filtering (Safeline) | OWASP Prevention |
| Parameterized Queries | Parameterized queries in custom applications; ORM usage where applicable; prepared statements | OWASP Prevention |
| WAF Protection | Safeline WAF (OWASP CRS rules); Traefik middleware stack; NGINX Ingress annotations; request filtering | NIST SI-4(23), PCI-DSS 6.6 |
| Command Injection Prevention | SSH command validation; shell escaping in scripts; Ansible playbook validation; restricted shell access | OWASP Prevention |
| XSS Prevention | Content Security Policy (CSP) headers; X-XSS-Protection headers; input sanitization; output encoding | OWASP Prevention |
| Monitoring | Suricata IDS signatures for injection attempts; WAF logs to SIEM; Splunk correlation for attack patterns; TheHive case creation for confirmed attacks | NIST SI-4, CIS Control 13.1 |

---

## A06:2025 - Insecure Design

**Risk Description:** Focus on design flaws and threat modeling. Slides from #4 to #6 as industry shows improvements in secure design practices.

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Threat Modeling | Defense-in-depth architecture; security architecture review; threat modeling for new services; zero-trust principles | NIST RA-3, ISO 27001 A.14.1 |
| Secure Architecture | DNS 3-tier architecture; reverse proxy isolation; network segmentation; least-privilege access; fail-secure defaults | NIST SA-8, ISO 27001 A.14.2 |
| Security Patterns | Zero-trust network access; Infrastructure as Code; immutable infrastructure; declarative configuration | Industry best practice |
| Defense in Depth | Multiple security layers (network, application, endpoint); redundant detection mechanisms; overlapping controls | NIST SC-7, ISO 27001 A.13.1 |
| Secure Defaults | SSH passwords disabled by default; Traefik secure defaults; services default to encrypted; least-privilege by default | NIST SA-4, OWASP Prevention |
| Documentation | Architecture diagrams maintained; security controls documented; design decisions recorded; threat model updates | NIST SA-17, ISO 27001 A.12.1.1 |

---

## A07:2025 - Authentication Failures

**Risk Description:** Authentication-related failures including weak passwords, credential stuffing, session management issues. Remains at #7 with name change from "Identification and Authentication Failures."

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Strong Authentication | MFA (Authentik TOTP); SSH key-based auth (passwords disabled); certificate-based authentication (Step-CA) | NIST IA-2(1), PCI-DSS 8.3 |
| Credential Management | Vaultwarden secrets management; Ansible Vault encrypted vars; no hardcoded credentials; centralized SSH key management | NIST IA-5(7), CIS Control 6.2 |
| Account Lockout | SSH MaxAuthTries=3; Authentik account lockout after 5 failures; Wazuh Active Response for brute force; CrowdSec automated blocking | NIST AC-7, ISO 27001 A.9.4.2 |
| Session Management | Authentik session tokens; SSH session IDs; TLS session tickets; session timeout (30 min idle) | NIST SC-23, PCI-DSS 8.1.8 |
| Password Policies | Authentik enforces complexity requirements; no password reuse; WebAuthn/FIDO2 support (planned) | NIST IA-5(1), CIS Control 6.3 |
| Monitoring | Failed login tracking; brute force detection (multi-source correlation); Wazuh monitors MFA bypass attempts; Splunk admin login dashboard | NIST AU-6, CIS Control 8.6 |

---

## A08:2025 - Software or Data Integrity Failures

**Risk Description:** Failure to maintain trust boundaries and verify the integrity of software, code, and data artifacts. Continues at #8.

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Code Integrity | Git version control; commit signing (planned); Infrastructure as Code validation; Terraform plan review | NIST SI-7, ISO 27001 A.12.1.2 |
| Software Verification | Package signature verification; container image verification (SHA-256); GPG key validation; Step-CA certificate validation | NIST CM-8, CIS Control 2.3 |
| Data Integrity | File integrity monitoring (Wazuh FIM); checksum verification; immutable SIEM indexes; database integrity checks | NIST SI-7, ISO 27001 A.12.3.1 |
| Certificate Validation | Traefik cert validation; SSH host key verification; DNSSEC; OCSP validation; CRL distribution | NIST SC-17, ISO 27001 A.8.24 |
| Change Control | Snapshot-before-patch; approval workflows (WSUS); pre-scan snapshots for critical systems; Git version control; rollback capability | NIST CM-3, ISO 27001 A.8.32 |
| Monitoring | Wazuh FIM alerts on file modifications; Splunk correlation for unauthorized changes; TheHive case creation for integrity violations | NIST AU-6, CIS Control 8.6 |

---

## A09:2025 - Security Logging and Alerting Failures

**Risk Description:** Insufficient logging, monitoring, and alerting can prevent or significantly delay the detection of security incidents. Name change emphasizes alerting functionality. Remains at #9.

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Comprehensive Logging | 100% security events logged to SIEM; DNS queries logged (Pi-hole); SSH sessions logged (auth.log); Traefik access logs (JSON format); Wazuh security events; patch deployment events logged; 90-day retention | NIST AU-2, PCI-DSS 10.2 |
| Log Protection | Immutable SIEM indexes; encrypted log transmission (syslog-ng TLS); write-once Elasticsearch indexes; tamper detection; centralized SIEM storage | NIST AU-9, PCI-DSS 10.5.1 |
| Real-Time Alerting | Discord webhooks; Splunk scheduled alerts; Wazuh Discord/email integration; Prometheus Alertmanager; TheHive case notifications; Cortex analysis completion; MISP event alerts; Shuffle notification actions; multi-channel redundancy | NIST SI-4(5), CIS Control 13.1 |
| Alert Tuning | False positive rate <3%; dynamic thresholds; alert suppression (max 1 per source per hour); 30-day baseline period | Operational efficiency |
| Correlation | Multi-source correlation (Splunk + Elastic + Wazuh + network logs); TheHive aggregates alerts; Shuffle orchestrates cross-platform queries; MITRE ATT&CK mapping | NIST AU-6(3), CIS Control 8.11 |
| Audit Trail | Structured JSON format for SIEM ingestion; full audit trails (user, timestamp, source IP, action, result); searchable correlation for forensics | NIST AU-3, PCI-DSS 10.3 |

---

## A10:2025 - Mishandling of Exceptional Conditions

**Risk Description:** NEW category for 2025. Contains 24 CWEs focusing on improper error handling, logical errors, failing open, and other related scenarios stemming from abnormal conditions.

**Lab Implementation:**

| Control Type | Implementation | Framework Alignment |
|-------------|----------------|---------------------|
| Error Handling | Traefik error handling (circuit breakers); graceful degradation; fail-secure defaults (firewall default-deny); proper exception handling in scripts | OWASP Prevention |
| Input Validation | Comprehensive input validation; boundary checking; type validation; range checking; malformed request handling | OWASP Prevention |
| Fail-Secure Design | pfSense default-deny rules; Traefik rejects invalid requests; SSH connection limits; services fail-closed on errors | NIST SC-24, OWASP Prevention |
| Resource Limits | Connection limits (SSH, Traefik); timeout configurations; rate limiting; resource quotas (Kubernetes); memory/CPU limits | NIST SC-5, CIS Control 13.3 |
| Logging Edge Cases | Exception logging; error condition logging; unusual state logging; Wazuh monitors service failures; Prometheus alerts on anomalies | NIST AU-2, CIS Control 8.5 |
| Monitoring | Service health checks (Uptime Kuma); Prometheus alerting for failures; Grafana anomaly dashboards; Pulse hypervisor monitoring; application error rates tracked | NIST SI-4, CIS Control 8.6 |
| Recovery Procedures | Automatic service restarts (systemd, Kubernetes); health check-based recovery; documented recovery procedures; Pulse backup integrity monitoring | NIST CP-10, ISO 27001 A.17.1 |

---

## OWASP Top 10:2025 - Compliance Summary

| OWASP 2025 Category | Coverage | Key Controls | Maturity |
|---------------------|----------|--------------|----------|
| A01: Broken Access Control | Strong | Authentik SSO, MFA, RBAC, IP allowlisting, SSRF prevention | Advanced |
| A02: Security Misconfiguration | Strong | CIS Benchmarks (92-98%), IaC, configuration drift detection | Advanced |
| A03: Software Supply Chain Failures | Moderate | Trusted sources, package verification, planned SBOM tracking | Developing |
| A04: Cryptographic Failures | Strong | TLS 1.3, Ed25519, Step-CA PKI, encrypted backups | Advanced |
| A05: Injection | Strong | WAF (25% block rate), input validation, parameterized queries | Advanced |
| A06: Insecure Design | Strong | Threat modeling, defense-in-depth, zero-trust architecture | Advanced |
| A07: Authentication Failures | Strong | MFA enforcement (100% admin), SSH keys only, account lockout | Advanced |
| A08: Software/Data Integrity Failures | Strong | FIM (100% critical paths), signature verification, immutable logs | Advanced |
| A09: Security Logging and Alerting Failures | Strong | 100% event logging, 90-day retention, multi-channel alerting | Advanced |
| A10: Mishandling of Exceptional Conditions | Strong | Fail-secure defaults, error handling, service health monitoring | Advanced |

**Overall OWASP 2025 Compliance: 9/10 Strong (1 Moderate - Supply Chain)**

### OWASP Top 10 (2025) Mitigation Summary

| OWASP Risk | Mitigation |
|-----------|------------|
| A01: Broken Access Control | Authentik ForwardAuth + MFA; SSH key-only access (passwords disabled); Traefik IP allowlisting; Authentik RBAC groups; OAuth2 scopes; pfSense default-deny firewall ACLs; SSRF prevention (DNS rebinding protection, backend validation, egress filtering) |
| A02: Security Misconfiguration | SSH hardened per CIS Benchmark; Traefik secure defaults; DNSSEC enabled; Ansible/Terraform IaC; configuration drift detection; default credentials eliminated; weekly OpenVAS + monthly Nessus authenticated scans; Wazuh SCA compliance audits |
| A03: Software Supply Chain Failures | Official Docker images only; package signature verification (SHA-256, GPG); trusted repositories; coordinated patching (PatchMon/WSUS/Watchtower); MISP vendor compromise tracking; Not Implemented: SBOM tracking via Trivy/Grype |
| A04: Cryptographic Failures | TLS 1.3 mandatory (Traefik); SSH AES-256-GCM; Ed25519 keys; Step-CA PKI (Root + Intermediate CA); encrypted backups (AES-256); automated cert renewal; weak cipher detection; certificate expiry monitoring |
| A05: Injection | Safeline WAF (OWASP CRS rules); DNS query validation; SSH input sanitization; Traefik header injection prevention; parameterized queries; CSP headers; Suricata IDS signatures; WAF logs to SIEM |
| A06: Insecure Design | Defense-in-depth architecture; DNS 3-tier design; zero-trust network access; threat modeling for new services; network segmentation; fail-secure defaults; least-privilege by default; documented architecture diagrams |
| A07: Authentication Failures | MFA (Authentik TOTP); SSH key-based auth only; Vaultwarden secrets management; account lockout (SSH MaxAuthTries=3, Authentik 5 failures); CrowdSec automated blocking; session timeout (30 min idle); no hardcoded credentials |
| A08: Software/Data Integrity Failures | Wazuh FIM (100% critical paths); Git version control; package signature verification; SHA-256 container verification; Step-CA certificate validation; snapshot-before-patch; immutable SIEM indexes; DNSSEC; change control workflows |
| A09: Security Logging and Alerting Failures | 100% security events logged to SIEM; 90-day retention; immutable Elasticsearch indexes; encrypted log transmission (syslog-ng TLS); real-time alerting (Discord, Splunk, Wazuh); multi-source correlation; TheHive case creation; structured JSON format |
| A10: Mishandling of Exceptional Conditions | Traefik circuit breakers; pfSense default-deny rules; fail-secure defaults; comprehensive input validation; connection limits (SSH, Traefik); rate limiting; exception logging; service health checks (Uptime Kuma); automatic restarts (systemd/Kubernetes) |

**Strengths:**

- Comprehensive coverage across all 10 categories
- Quantifiable metrics for each risk area
- Defense-in-depth approach to mitigation
- Continuous monitoring and alerting