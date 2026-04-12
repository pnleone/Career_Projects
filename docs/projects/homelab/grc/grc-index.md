# Governance, Risk and Compliance

<img src="/Career_Projects/assets/misc/homelab-banner2.png"
     alt="GRC Framework Documentation"
     style="width: 100%; height: auto; display: block; margin: 0 auto;">

## **Table of Contents**

| Section | Description |
|---------|-------------|
| :material-file-document: **[GRC Executive Summary](/Career_Projects/projects/homelab/grc/01-summary/)** | Comprehensive framework alignment summary across eight industry-standard frameworks. Covers on-premises and multi-cloud hybrid scope (AWS, Azure, GCP). |
| :material-shield-check: **[NIST Cybersecurity Framework 2.0](/Career_Projects/projects/homelab/grc/grc-nist-csf/)** | Risk-based framework implementation across six core functions (Govern, Identify, Protect, Detect, Respond, Recover). Tier 3–4 maturity. Cloud extension integrated per subcategory. |
| :material-shield-star: **[CIS Critical Security Controls v8.1](/Career_Projects/projects/homelab/grc/grc-cis-controls/)** | Prescriptive, prioritized safeguards organized into three Implementation Groups (IG1/IG2/IG3). 93% IG1, 81% IG2, 52% IG3. Cloud inventory, monitoring, and patch management integrated. |
| :material-certificate: **[ISO 27001:2022 Annex A](/Career_Projects/projects/homelab/grc/grc-iso27001/)** | ISMS with 93 controls across organizational, people, physical, and technological domains. 77% overall coverage; 91% technological controls. Cloud IaaS scope added in v2.0. |
| :material-file-chart: **[NIST SP 800-53 Rev 5](/Career_Projects/projects/homelab/grc/grc-nist-800/)** | Comprehensive control catalog across 20 families. 100% AU, 95% IA/SC/CM, 90% AC/SI. Cloud controls integrated per family in Notes column. |
| :material-sword-cross: **[MITRE ATT&CK Enterprise v18.1](/Career_Projects/projects/homelab/grc/grc-mitre/)** | Adversary TTPs across 216 techniques / 475 sub-techniques. 30% coverage (65/216). Cloud detection and containment integrated where applicable. |
| :material-web: **[AICPA, SOC 2 Trust Services Criteria (CC1-CC9)](/Career_Projects/projects/homelab/grc/grc-soc2/)** | Security Common Criteria (CC1-CC9) mapping. 30/33 criteria implemented. Hybrid cloud scope (AWS, Azure, GCP) included from initial release. |
| :material-lock-reset: **[CISA Zero Trust Maturity Model v2.0](/Career_Projects/projects/homelab/grc/grc-cisa-zero-trust/)** | Four maturity stages across five pillars and three cross-cutting capabilities. Advanced (Stage 3/4). 87% of functions at Advanced or higher. Cloud content integrated per pillar. |
| :material-shield-lock-outline: **[NIST SP 800-207 Zero Trust Architecture](/Career_Projects/projects/homelab/grc/grc-nist-zero-trust/)** | Seven ZT tenets, logical components (PE/PA/PEP), deployment models, use cases, and threats. Advanced maturity. Multi-cloud Use Case 2 rated High applicability. |

---

## **Summary**

This cybersecurity lab demonstrates production-ready security capabilities aligned with eight industry frameworks across on-premises and multi-cloud hybrid infrastructure (AWS us-east-2, Azure North Central US, GCP us-central1).

**Core Strengths:**

- **Operational Security Excellence:** 100% security event logging with dual SIEM, <5min MTTD, <30min MTTR via automated SOAR workflows
- **Technical Architecture Maturity:** Defense-in-depth across network/application/endpoint/identity layers; Infrastructure as Code automation spanning on-premises and cloud
- **Multi-Cloud Coverage:** 6 cloud nodes (2 AWS, 2 Azure, 2 GCP) connected via Tailscale WireGuard; unified Wazuh EDR, PatchMon, Checkmk, Ansible management toolchain; no public management ports on any cloud instance
- **Framework Compliance:** Tier 3-4 NIST CSF, 93% CIS IG1, 77% ISO 27001, Advanced CISA ZTMM and NIST 800-207 maturity; Strong SOC 2 CC1-CC9
- **Zero Trust Implementation:** Explicit verification, micro-segmentation, encrypted communications, continuous monitoring — Advanced (Stage 3/4) maturity with cloud enforcement via provider-native firewall policies, Tailscale ACL, and Wazuh CIS SCA

**Cloud Infrastructure:**

| Provider | Nodes | OS | Native Security Services |
|----------|-------|-----|--------------------------|
| AWS (us-east-2) | 2 | Amazon Linux 2, Windows Server 2025 | GuardDuty, Security Hub, CloudTrail, VPC Flow Logs |
| Azure (North Central US) | 2 | Ubuntu 24.04 LTS, Windows Server 2025 | Defender for Cloud, Sentinel, Entra ID, DDoS Protection |
| GCP (us-central1) | 2 | Debian 13.4, Ubuntu | Security Command Center, Cloud Armor, VPC Firewall Policy, Cloud Logging |

## Documentation Downloads

!!! info "Files"
    * [:material-file-download: GRC Executive Summary (PDF)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc-summary-20260411.pdf){ download="grc-summary-20260411.pdf" }
    * [:material-file-download: NIST Cybersecurity Framework 2.0 (PDF)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc-nist-crf2-20260403.pdf){ download="grc-nist-crf2-20260403.pdf" }
    * [:material-file-download: CIS Critical Security Controls v8.1 (PDF)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc-cis-controls-v81020260404.pdf){ download="grc-cis-controls-v81020260404.pdf" }
    * [:material-file-download: ISO 27001:2022 Annex A (PDF)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc-iso27001-2022-annexa-20260404.pdf){ download="grc-iso27001-2022-annexa-20260404.pdf" }
    * [:material-file-download: NIST SP 800-53 Rev 5 (PDF)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc-nist-sp-800-53-rev5-20260407.pdf){ download="grc-nist-sp-800-53-rev5-20260407.pdf" }
    * [:material-file-download: MITRE ATT&CK Enterprise v18.1 (PDF)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc-mitre-v18-1-20260409.pdf){ download="grc-mitre-v18-1-20260409.pdf" }
    * [:material-file-download: CISA Zero Trust Maturity Model v2.0 (PDF)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc-cisa-ztmmv2-20260406.pdf){ download="grc-cisa-ztmmv2-20260406.pdf" }
    * [:material-file-download: NIST SP 800-207 Zero Trust Architecture (PDF)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc-nist-sp-800-207-20260407.pdf){ download="grc-nist-sp-800-207-20260407.pdf" }
    * [:material-file-download: AICPA, SOC 2 Trust Services Criteria (CC1-CC9)  (PDF)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc-aicpa-soc2-20260405.pdf){ download="grc-aicpa-soc2-20260405.pdf" }
    * [:material-file-download: GRC - All Documents (ZIP)](https://raw.githubusercontent.com/pnleone/Career_Projects/main/docs/grc_lab_documentation.zip){ download="grc_lab_documentation.zip" }    