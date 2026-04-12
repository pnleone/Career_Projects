# CIS Critical Security Controls v8.1

**Document Control:**

**Version:** 2.0
**Last Updated:** April 2026
**Owner:** Paul Leone
**Framework Version:** CIS Controls v8.1

---

## CIS Control 1: Inventory and Control of Enterprise Assets

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 1.1 | Establish and maintain detailed enterprise asset inventory | External Excel Inventory, Checkmk inventory, Wazuh agent inventory (31+ endpoints), Prometheus node exporters, PatchMon tracking (30+ hosts), DNS records, SSH host keys in Ansible | Compliant — Cloud inventory integrated: 8 cloud nodes across AWS (EC2 t3.micro Amazon Linux 2, c7i-flex.large Windows Server 2025), GCP (2× e2.micro, us-central1-c), and Azure (Standard_B2ats_v2 Ubuntu 24.04, Standard_E2s_v3 Windows Server 2025) — all enrolled in Checkmk, Wazuh, and PatchMon via Tailscale |
| 1.2 | Address unauthorized assets weekly | Partial — NetAlertX network discovery identifies unknown on-premises devices. Cloud asset weekly review documented: Tailscale admin console (tailf07c05.ts.net) lists all enrolled nodes; AWS EC2, GCP Compute, and Azure VM consoles serve as authoritative cloud inventory sources reviewed weekly | N/A — Single user lab environment |
| 1.3 | Utilize an active discovery tool (IG2) | NetAlertX network discovery, nmap scans, custom Python scanner | Compliant — On-premises active scanning in place; cloud-native discovery via provider instance APIs and Tailscale admin console |
| 1.4 | Use DHCP logging to update inventory (IG2) | Asus Router DHCP logs (192.168.1.0/24) + pfSense DHCP logs (192.168.100.0/24) forwarded to Splunk/Elastic | Compliant — Cloud nodes use private IPs assigned via provider DHCP (AWS 172.31.x, GCP 10.128.x, Azure 10.130.x); IP assignments logged in provider VPC/VNet DHCP lease records |
| 1.5 | Use passive asset discovery tool (IG3) | NetAlertX provides real-time alerts for new MAC/IP associations; Suricata performs deep packet inspection to identify asset types | Compliant — Passive discovery via traffic analysis extended to cloud segments via Flow Logs |

**Control 1 Overall Status:** Compliant — Cloud node inventory integrated; minor process documentation gap in combined review procedure

---

## CIS Control 2: Inventory and Control of Software Assets

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 2.1 | Establish and maintain software inventory | External Excel Inventory, PatchMon Software Inventory (5,000+ packages across 30+ hosts + 6 Linux cloud nodes), Checkmk inventory, Nessus software scanning, Wazuh agent software tracking | Compliant — PatchMon extended to Amazon Linux 2, Debian 13.4, and Ubuntu 24.04 LTS cloud nodes with daily NVD CVE correlation. Windows cloud nodes (AWS, Azure) tracked via WSUS |
| 2.2 | Ensure authorized software is currently supported | PatchMon tracks EOL software; vulnerability scanners flag unsupported versions; documented exceptions for necessary legacy software | Compliant — AWS Amazon Linux 2 EOL status monitored; Azure/GCP OS image currency tracked via Checkmk and Wazuh vulnerability assessment; WSUS validates Windows Server 2025 support currency |
| 2.3 | Address unauthorized software monthly | N/A — Single-user lab environment | N/A |
| 2.4 | Utilize automated software inventory tools (IG2) | PatchMon agent-based inventory, Checkmk, Wazuh software tracking, Nessus authenticated scans | Compliant — PatchMon agents deployed on all 6 Linux cloud nodes; Wazuh agents on all 8 cloud nodes provide real-time package and process inventory; automated daily checks |
| 2.5 | Allowlist authorized software (IG2) | Not Implemented — No application allowlisting solution deployed on-premises or cloud nodes | Gap — Implement AppLocker/WDAC (Windows), or CrowdSec allowlisting |
| 2.6 | Allowlist authorized libraries (IG2) | Not Implemented — No DLL/library allowlisting on-premises or cloud nodes | Gap — IG2 requirement not addressed |
| 2.7 | Allowlist authorized scripts (IG3) | Not Implemented — No script execution control (PowerShell Constrained Language Mode, etc.) | Gap — IG3 requirement not addressed |

**Control 2 Overall Status:** Partially Compliant — IG1 fully compliant including cloud scope; IG2/IG3 gaps in allowlisting remain

---

## CIS Control 3: Data Protection

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 3.1 | Establish and maintain a data management process | Documented in GRC document; data classification, retention, disposal procedures defined | Compliant — Cloud scope added: AWS S3 CloudTrail log buckets (SSE, 90-day retention), GCP Cloud Storage (default encryption, audit logging), Azure Log Analytics workspace homelab-log (90-day retention, encrypted at rest) |
| 3.2 | Establish and maintain data inventory | Sensitive data tracked in inventory; backup data cataloged; scan credentials documented | Compliant — Cloud data inventory: AWS S3 buckets, GCP GCS buckets, Azure Log Analytics workspace, and cloud node EBS/Managed Disk/persistent disk volumes documented with owner, sensitivity classification, and retention policy |
| 3.3 | Configure data access control lists | File system ACLs; SSH key-based access; database access controls; Authentik RBAC | Compliant — AWS IAM instance profiles with least-privilege roles (no wildcard actions, no long-lived access keys on EC2); GCP service accounts with minimal role assignments (no owner/editor on Compute instances); Azure RBAC scoped per resource group; Tailscale ACL policy governs all inter-node access |
| 3.4 | Enforce data retention | 90-day log retention; backup retention policies; automated cleanup | Compliant — AWS CloudTrail logs delivered to S3 with 90-day lifecycle policy; GCP Admin Activity logs retained per GCP defaults; Azure Log Analytics homelab-log configured for 90-day retention |
| 3.5 | Securely dispose of data | Secure deletion procedures; encrypted backup disposal; NIST SP 800-88 alignment | Compliant — AWS EC2 EBS volume deletion documented in decommissioning runbook; GCP persistent disk deletion policy documented; Azure Managed Disk cleanup included in decommissioning checklist |
| 3.6 | Encrypt data on end-user devices | Windows BitLocker, Linux LUKS, encrypted laptop drives | Compliant — Cloud nodes not classified as end-user devices; cloud storage encryption covered under 3.11 |
| 3.7 | Establish data classification scheme (IG2) | Sensitivity tiers (Public, Internal, Confidential, Restricted) defined with handling requirements; used in documentation | Compliant — Cloud data classified under same scheme: CloudTrail logs (Confidential), GCP audit logs (Confidential), Wazuh agent telemetry (Internal) |
| 3.8 | Document data flows (IG2) | Partial — Network architecture documented; full data flow diagrams not comprehensive | Gap — Cloud flow paths added: Wazuh agent telemetry (cloud nodes → Tailscale → Wazuh Manager 192.168.1.219), CloudTrail (AWS API → S3), GCP Audit Logs, Azure Monitor (Azure API → Log Analytics homelab-log → Sentinel); comprehensive on-premises data flow diagrams still needed |
| 3.9 | Encrypt data on removable media (IG2) | USB drives encrypted; backup tapes encrypted | Compliant — Cloud nodes have no removable media |
| 3.10 | Encrypt sensitive data in transit (IG2) | TLS 1.3 (Traefik), SSH encryption, syslog-ng TLS, VPN encryption | Compliant — All management traffic encrypted via Tailscale WireGuard (ChaCha20-Poly1305); SSH AES-256-GCM for Linux cloud node terminal access; no plaintext management paths exist |
| 3.11 | Encrypt sensitive data at rest (IG2) | Encrypted backups, database encryption, scan credential encryption | Compliant — AWS S3 SSE for CloudTrail logs; GCP persistent disks encrypted by default (Google-managed keys); Azure Managed Disks and Log Analytics workspace encrypted at rest by default |
| 3.12 | Segment data processing based on sensitivity (IG2) | VLAN segmentation; backend isolation (Traefik); network segmentation | Compliant — Per-provider network isolation: AWS VPC (172.31.0.0/16), GCP VPC (10.128.0.0/16), Azure VNet homelab-vnet2 (10.130.0.0/16) each isolated; inter-cloud communication only via Tailscale overlay |
| 3.13 | Deploy Data Loss Prevention solution (IG3) | Not Implemented — No DLP solution deployed on-premises or for cloud egress paths. Cloud egress filtering: AWS Security Group outbound rules restrict to required management destinations; GCP VPC firewall policy limits egress; Azure NSG outbound rules enforce explicit allow-list | Gap — IG3 requirement; provider egress filtering provides partial compensating control; planned Q2 2026 |
| 3.14 | Log sensitive data access (IG3) | Partial — File access logged via Wazuh FIM; database query logging not comprehensive | Gap — AWS CloudTrail logs all S3 data access; GCP Data Access audit logs capture GCS bucket access; Azure Log Analytics access logged via Azure Monitor; Wazuh FIM on all 8 cloud nodes monitors file access in configured sensitive paths. On-premises database audit logging incomplete |

**Control 3 Overall Status:** IG1/IG2 Compliant including cloud scope; IG3 Partial (DLP not deployed, cloud egress filtering provides compensating control)

---

## CIS Control 4: Secure Configuration of Enterprise Assets and Software

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 4.1 | Establish and maintain secure configuration process | CIS Benchmark audits via Wazuh SCA; configuration drift detection; automated remediation via Ansible; Ansible baselines; IaC version control | Action Required — Formal secure configuration policy document needed; cloud scope: Ansible linux_hardening.yml and new_install_baseline_roles.yml applied to all 6 Linux cloud nodes via SSH over Tailscale; Azure ARM template (azuredeploy.json) version-controlled in Git |
| 4.2 | Establish secure configuration process for network infrastructure | Network device hardening standards documented; SSH hardening policy; firewall rule standards | Compliant — AWS Security Group rules documented (tailscale-access + lab-services with explicit inbound/outbound allow-list); GCP VPC network firewall policy (homelab, 17 rules, Google Threat Intelligence blocking for TOR exit nodes, malicious IPs, and sanctioned countries); Azure NSG homelab-nsg2 (explicit allow-list, DenyAllInBound at priority 65500) |
| 4.3 | Configure automatic session locking | 15-min timeout (general OS); 2-min timeout (mobile devices); enforced via GPO/Ansible | Compliant — Windows cloud nodes (AWS, Azure) subject to same GPO session lock policy via domain join to home.com over Tailscale |
| 4.4 | Implement firewall on servers | UFW (Linux), Windows Firewall, iptables rules managed via Ansible | Compliant — AWS Security Groups serve as host-level firewall for EC2 instances; GCP VPC network firewall policy applies to all Compute instances; Azure NSG homelab-nsg2 applied at subnet level; Ansible linux_hardening.yml configures UFW on Linux cloud nodes as additional host-based layer |
| 4.5 | Implement firewall on end-user devices | Host-based firewalls enabled on all endpoints; default-deny ruleset | Compliant — Cloud nodes are servers; host-based firewalls covered under 4.4 |
| 4.6 | Securely manage enterprise assets | SSH key-based admin access; IaC version control (Git); HTTPS-only management interfaces | Compliant — All SSH/RDP to cloud nodes restricted to homelab subnets (192.168.0.0/16) via provider-native firewall rules; Tailscale WireGuard mandatory for all cloud management access; no public management ports exposed on any cloud instance |
| 4.7 | Manage default accounts | Root login disabled (SSH); default vendor accounts removed; validated via Nessus scans | Compliant — Ansible new_install_baseline_roles.yml disables root SSH login and removes default accounts on Linux cloud nodes; Windows cloud nodes joined to domain and local Administrator account managed via GPO |
| 4.8 | Uninstall unnecessary services (IG2) | Minimal service footprint; unnecessary services disabled; verified via authenticated scans | Compliant — Cloud nodes provisioned with minimal base images; Wazuh SCA validates running services against CIS benchmarks on all cloud nodes |
| 4.9 | Configure trusted DNS servers (IG2) | Enterprise-controlled DNS (Technitium DNS/Unbound); DNSSEC validation | Compliant — All Linux cloud nodes configured with on-premises Unbound resolvers (192.168.1.153, 192.168.1.154) as DNS servers via Tailscale tunnel; Windows cloud nodes (domain-joined) use on-premises AD DNS (192.168.1.152, 192.168.1.142) via Tailscale |
| 4.10 | Enforce automatic lockout on portable devices (IG2) | Failed auth lockout (laptops: 20 attempts; mobile: 10 attempts) via GPO/MDM | Compliant — Windows cloud nodes subject to same account lockout GPO (5 failed attempts, 10-minute lockout) applied via domain policy over Tailscale |
| 4.11 | Enforce remote wipe capability (IG2) | Not Implemented — Mobile/laptop remote wipe via planned MDM; laptops rely on full-disk encryption | Gap — Mobile/laptop remote wipe; cloud instance termination provides equivalent data destruction for cloud nodes |
| 4.12 | Separate enterprise workspaces on mobile devices (IG3) | Not Implemented — No Android Work Profile/iOS Managed App separation | Gap — IG3 mobile device management; not applicable to cloud nodes |

**Control 4 Overall Status:** Needs Process Documentation (4.1 critical); cloud node configuration management integrated into existing IaC

---

## CIS Control 5: Account Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 5.1 | Establish and maintain account inventory | Authentik user database, Active Directory accounts, SSH key inventory (Ansible), Wazuh user tracking | Compliant — AWS IAM users/roles and service accounts inventoried; GCP service accounts listed in GCP IAM; Azure Entra ID accounts (cloud-only and domain-synced) tracked in Azure Active Directory; Wazuh agents on all cloud nodes report active local accounts |
| 5.2 | Use unique passwords | Vaultwarden password manager; 8-char minimum (MFA accounts); 14-char minimum (non-MFA) | Compliant — No shared credentials on cloud nodes; SSH key-based auth for Linux (no passwords); Windows cloud nodes use domain accounts managed by GPO password policy |
| 5.3 | Disable dormant accounts after 45 days | Automated via Active Directory account expiration policies; Authentik account lifecycle management | Compliant — AWS IAM access keys reviewed quarterly (no long-lived keys on EC2 — instance profiles used); GCP service accounts audited via IAM recommender; Azure Entra ID accounts subject to same 45-day dormancy policy |
| 5.4 | Restrict admin privileges to dedicated accounts | Separate admin accounts (no dual-use); SSH sudo enforcement; Authentik RBAC | Compliant — AWS IAM instance profiles scoped to minimum required actions (no AdministratorAccess policy); GCP service accounts use minimal roles (no owner/editor); Azure subscription admin access MFA-enforced via Entra Conditional Access |
| 5.5 | Establish service account inventory (IG2) | Service accounts documented in inventory; ownership tracked; quarterly reviews | Compliant — AWS IAM instance profiles (terraform-token, ansible) documented; GCP compute service accounts listed; Azure Managed Identity or service principals documented with assigned roles |
| 5.6 | Centralize account management (IG2) | Authentik SSO + Active Directory; centralized SSH key management (Ansible) | Compliant — Linux cloud nodes centralized via Ansible-managed SSH keys; Windows cloud nodes centralized via Active Directory (domain-joined over Tailscale); cloud console access centralized via provider IAM with MFA |

**Control 5 Overall Status:** Fully Compliant — Cloud node accounts integrated into existing lifecycle management

---

## CIS Control 6: Access Control Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 6.1 | Establish access granting process | Documented onboarding procedures; Authentik provisioning; SSH key distribution workflow | Compliant — Cloud node access provisioned via Ansible playbook (SSH key deployment for Linux, domain join for Windows); AWS IAM role assignment documented; GCP service account grant process documented |
| 6.2 | Establish access revocation process | Offboarding checklist; Authentik account deactivation; SSH key revocation (Ansible); Wazuh Active Response | Compliant — Cloud node access revocation: SSH key removal via Ansible, Tailscale node key expiry/revocation, AWS IAM instance profile disassociation; cloud node termination as final revocation step |
| 6.3 | Require MFA for externally-exposed applications | Authentik enforces MFA via TOTP; all external services require MFA | Compliant — AWS console access enforces MFA via IAM policy; GCP console access requires Google account MFA; Azure portal access enforces MFA via Entra Conditional Access. Cloud node management interfaces (SSH/RDP) require Tailscale device authentication (device-bound key, no shared credential) |
| 6.4 | Require MFA for remote network access | VPN (Tailscale) requires device authentication; SSH keys + optional passphrase | Compliant — All cloud node management access routes through Tailscale WireGuard; Tailscale device authentication requires MFA at enrollment; no direct internet-facing management ports on any cloud node |
| 6.5 | Require MFA for administrative access | 100% admin accounts require Authentik MFA; SSH key-based auth for privileged access | Compliant — AWS IAM admin users require MFA (enforced via IAM policy); GCP admin access requires Google MFA; Azure subscription administrators enforce MFA via Entra Conditional Access |
| 6.6 | Establish authentication/authorization system inventory (IG2) | Authentik, Active Directory, SSH key infrastructure documented; annual review | Compliant — AWS IAM, GCP IAM, Azure Entra ID added to auth system inventory |
| 6.7 | Centralize access control (IG2) | Authentik SSO for Traefik-routed services; Active Directory domain authentication | Compliant — Linux cloud nodes centralized via Ansible-managed SSH keys; Windows cloud nodes centralized via Active Directory (domain-joined over Tailscale); cloud console access centralized via provider IAM with MFA |
| 6.8 | Define and maintain role-based access control (IG3) | Not Implemented — Requires enterprise-wide RBAC documentation | Action Required — RBAC documentation needed; AWS IAM instance profiles define EC2 role boundaries; GCP IAM service account roles defined; Azure RBAC role assignments documented per resource group. Formal RBAC matrix across all systems including cloud not yet documented |

**Control 6 Overall Status:** Mostly Compliant; 6.8 needs broader RBAC documentation including cloud IAM roles

---

## CIS Control 7: Continuous Vulnerability Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 7.1 | Establish vulnerability management process | Documented dual-scanner approach (OpenVAS + Nessus); remediation SLAs; CVSS prioritization | Compliant — Same CVSS-based SLAs (Critical <72h, High <7d) applied to cloud node findings from PatchMon, AWS Inspector, GCP SCC, and Azure Defender for Cloud; TheHive tracks cloud node vulnerabilities alongside on-premises findings |
| 7.2 | Establish remediation process | Risk-based remediation strategy; documented SLAs; monthly reviews; TheHive tracking | Compliant — Ansible update_linux_hosts.yml provides emergency patching for Linux cloud nodes via Tailscale; WSUS manages Windows cloud nodes; cloud-native remediation tools available as supplemental |
| 7.3 | Perform automated OS patch management | PatchMon (Linux), WSUS (Windows), monthly cadence; automated approvals | Compliant — WSUS manages Windows cloud nodes (AWS Windows Server 2025, Azure Windows Server 2025) with same approval workflow and schedule as on-premises Windows hosts. Ansible update_linux_hosts.yml patches Linux cloud nodes monthly via Tailscale |
| 7.4 | Perform automated application patch management | Watchtower (containers), WUD monitoring, monthly cadence | Compliant — Watchtower and WUD monitor container images on cloud nodes where Docker is deployed |
| 7.5 | Perform automated vulnerability scans — internal (IG2) | Weekly OpenVAS (52/year); monthly Nessus authenticated scans (12/year) | Compliant — Wazuh CIS SCA on all 8 cloud nodes daily; AWS Inspector; GCP SCC vulnerability assessment; Azure Defender for Cloud recommendations. Exceeds quarterly requirement; cloud scanning added |
| 7.6 | Perform automated vulnerability scans — external (IG2) | Monthly Nessus scans of externally-exposed assets; OpenVAS external scans | Compliant — AWS Inspector external-facing assessment; GCP SCC external threat detection; Azure Defender for Cloud internet-exposed resource assessment. No cloud management ports publicly exposed — attack surface is minimal |
| 7.7 | Remediate detected vulnerabilities (IG2) | MTTR <72h (Critical); <7 days (High); 95% patched within SLA; verification scans | Compliant — Same MTTR SLAs enforced across cloud nodes via PatchMon tracking; Ansible emergency patching available for Linux cloud nodes via Tailscale; WSUS auto-approval for critical Windows cloud node patches |

**Control 7 Overall Status:** Fully Compliant — Exceeds industry standards; cloud node vulnerability management integrated

---

## CIS Control 8: Audit Log Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 8.1 | Establish audit log management process | Documented logging policy; 90-day retention; centralized SIEM; review procedures | Compliant — Cloud audit logging policy extended to AWS CloudTrail, GCP Admin Activity, Azure Activity Log with 90-day retention requirement matched across all providers |
| 8.2 | Collect audit logs | 100% security event coverage (DNS, SSH, Traefik, vulnerability scans, patches, Wazuh, Sysmon) | Compliant — AWS CloudTrail collects all management events (delivered to S3 with SSE); GCP Admin Activity logs always-on; Azure Activity Log and Monitor collect all ARM deployments and resource changes; Wazuh agent on all 8 cloud nodes forwards endpoint security events to on-premises Splunk |
| 8.3 | Ensure adequate log storage | SIEM storage capacity planning; immutable indexes; compressed archival | Compliant — AWS S3 lifecycle policies manage CloudTrail log retention; Azure Log Analytics homelab-log workspace storage monitored; cloud-native log storage supplementary to on-premises SIEM |
| 8.4 | Standardize time synchronization (IG2) | NTP sync across all assets; centralized time sources | Compliant — All Linux cloud nodes configured with NTP (time.google.com, time.cloudflare.com) via Ansible; Windows cloud nodes sync via domain NTP policy; cloud provider hypervisors provide host-level time sync as a baseline |
| 8.5 | Collect detailed audit logs (IG2) | Logs include timestamp, user, source IP, action, result, SSH key fingerprints, DNS query details | Compliant — AWS CloudTrail includes IAM identity, source IP, user agent, request/response detail; GCP audit logs include principal identity, resource, method, source IP; Azure Activity Log includes caller identity, resource, operation, source IP |
| 8.6 | Collect DNS query logs (IG2) | Unbound/Technitium DNS query logging; forwarded to SIEM | Compliant — All cloud nodes resolve via on-premises Unbound resolvers (192.168.1.153/154) over Tailscale — DNS queries logged at Unbound and forwarded to SIEM; AWS Route 53 Resolver DNS query logging enabled for VPC; GCP Cloud DNS logging for internal queries |
| 8.7 | Collect URL request logs (IG2) | Traefik access logs (JSON format); proxy logs; forwarded to SIEM | Compliant — Cloud-hosted services log via Traefik or cloud-native application logging; GCP Cloud Armor access logs capture HTTP request details |
| 8.8 | Collect command-line logs (IG2) | Sysmon Event ID 1 (process creation); PowerShell logging; Bash history; Wazuh command monitoring | Compliant — Wazuh agents on all 8 cloud nodes collect process execution, command-line arguments, and shell history; Windows cloud nodes have Sysmon deployed with same configuration as on-premises Windows hosts; Bash audit logging via auditd on Linux cloud nodes |
| 8.9 | Centralize audit logs (IG2) | Dual SIEM (Splunk + Elastic); syslog-ng encrypted forwarding; centralized storage | Compliant — Wazuh Universal Forwarder from all 8 cloud nodes forwards to on-premises Splunk via Tailscale; AWS CloudTrail logs stored in S3 (provider-managed); GCP audit logs in Cloud Logging; Azure logs in homelab-log Log Analytics workspace; all cloud node endpoint events centralized in on-premises SIEM |
| 8.10 | Retain audit logs 90 days minimum (IG2) | 90-day retention policy; immutable SIEM indexes | Compliant — AWS S3 CloudTrail bucket lifecycle policy set to 90 days; GCP Cloud Logging default retention (400 days for admin activity); Azure Log Analytics homelab-log retention set to 90 days |
| 8.11 | Conduct audit log reviews weekly (IG2) | Splunk dashboards; Wazuh alerts; weekly correlation searches; automated reviews | Compliant — AWS GuardDuty findings reviewed as generated (real-time); GCP SCC security health findings reviewed monthly; Azure Sentinel dashboard includes cloud node events |
| 8.12 | Collect service provider logs (IG3) | Partial — IaaS cloud audit logging comprehensive (AWS CloudTrail, GCP Admin Activity, Azure Activity Log); SaaS platform log collection limited | IG3 Partial — IaaS cloud audit logging comprehensive; SaaS platform logging limited |

**Control 8 Overall Status:** Fully Compliant (IG1/IG2) — Cloud audit logs integrated; IG3 improved with IaaS log coverage

---

## CIS Control 9: Email and Web Browser Protections

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 9.1 | Ensure only fully supported browsers/email clients | Latest browser versions enforced; unsupported clients blocked | Compliant — Cloud nodes are servers; no browser/email client deployment on cloud instances |
| 9.2 | Use DNS filtering services | Unbound integrated blocklists (1M+ blocked domains); malware/phishing domain blocking | Compliant — All cloud nodes resolve via on-premises Unbound (192.168.1.153/154) over Tailscale, inheriting DNS-layer malware and phishing domain blocking |
| 9.3 | Maintain network-based URL filters (IG2) | Traefik URL filtering; SafeLine WAF; category-based blocking; reputation filtering | Compliant — GCP Cloud Armor application-level policy blocks malicious URL patterns; AWS Security Group egress rules restrict outbound destinations; Azure NSG outbound rules limit egress to documented management services |
| 9.4 | Restrict browser/email extensions (IG2) | Partial — GPO restricts extensions on managed Windows devices; Linux/personal devices rely on user compliance | Gap — Applies to endpoints; cloud nodes not affected |
| 9.5 | Implement DMARC (IG2) | DMARC policy published; SPF + DKIM implemented for outbound mail | Compliant |
| 9.6 | Block unnecessary file types (IG2) | Partial — Email gateway blocks .exe/.scr/.bat attachments; not comprehensive | Gap — Expand blocked file type list on email gateway |
| 9.7 | Deploy email server anti-malware (IG3) | Not Implemented — No dedicated email gateway anti-malware | Gap — IG3 N/A (no on-prem email server) |

**Control 9 Overall Status:** IG1 Compliant; IG2 Partial; IG3 N/A. Cloud DNS filtering extended to all cloud nodes.

---

## CIS Control 10: Malware Defenses

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 10.1 | Deploy and maintain anti-malware software | Wazuh FIM + VirusTotal integration; ClamAV; Microsoft Defender; rootkit detection | Compliant — Wazuh FIM and rootkit detection deployed on all 8 cloud nodes; ClamAV on Linux cloud nodes (Amazon Linux 2, Debian 13.4, Ubuntu 24.04 LTS); Microsoft Defender active on Windows Server 2025 (AWS, Azure); GuardDuty, SCC, Azure Defender for Cloud provide cloud-native behavioral detection |
| 10.2 | Configure automatic anti-malware signature updates | Automated signature updates (daily); ClamAV freshclam; Defender definition updates | Compliant — ClamAV freshclam runs on Linux cloud nodes; Windows Defender definitions updated via WSUS on Windows cloud nodes; cloud-native tools update threat intelligence automatically |
| 10.3 | Disable autorun/autoplay for removable media | GPO disables autorun; Linux udev rules block autoplay; verified compliance | Compliant — Cloud nodes have no removable media |
| 10.4 | Configure automatic scanning of removable media (IG2) | Wazuh FIM monitors USB insertions; ClamAV on-access scanning | Compliant — Cloud nodes have no removable media; not applicable |
| 10.5 | Enable anti-exploitation features (IG2) | Windows DEP/WDEG enabled; Linux ASLR/PIE; macOS SIP/Gatekeeper | Compliant — Linux cloud nodes have ASLR enabled (enforced via Ansible sysctl hardening); Windows cloud nodes (Windows Server 2025) have DEP, ASLR, and Control Flow Guard enabled by default |
| 10.6 | Centrally manage anti-malware software (IG2) | Wazuh central management; Group Policy for Windows Defender; centralized config | Compliant — Wazuh manager (192.168.1.219) centrally manages all cloud node agents; Windows cloud nodes managed via Group Policy over Tailscale domain connection |
| 10.7 | Use behavior-based anti-malware (IG2) | Wazuh behavioral analysis; Windows Defender behavior monitoring; Suricata IDS behavioral detection | Compliant — AWS GuardDuty ML-based behavioral detection; GCP SCC threat detection; Azure Defender for Cloud behavioral analytics all provide cloud-native behavioral malware detection independent of signature databases |

**Control 10 Overall Status:** Fully Compliant — Anti-malware coverage extended to all cloud nodes; cloud-native behavioral detection supplements on-premises

---

## CIS Control 11: Data Recovery

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 11.1 | Establish and maintain data recovery process | Documented backup procedures; restore workflows; recovery prioritization; annual reviews | Compliant — Cloud recovery procedures added: ARM template (Azure), Ansible new_install_baseline_roles.yml, and Tailscale re-enrollment documented as cloud node rebuild runbooks; RTO target <2hr for cloud nodes |
| 11.2 | Perform automated backups | Proxmox automated backups (bi-weekly); Docker volume backups; database backups | Compliant — Cloud node OS-level backups via provider snapshots (AWS EBS snapshots, GCP disk snapshots, Azure VM snapshots); application data backed up to on-premises PBS/NAS via Tailscale where applicable |
| 11.3 | Protect recovery data | Encrypted backups (AES-256); offsite storage; access controls; encrypted transmission | Compliant — AWS EBS snapshots encrypted (account default KMS key); GCP disk snapshots encrypted at rest; Azure VM snapshots encrypted; all cloud snapshot access controlled via provider IAM |
| 11.4 | Establish isolated instance of recovery data | Offsite backups (cloud + offline USB); air-gapped backup copies; versioned backups | Compliant — Cloud node rebuild from code (Git + Ansible) provides infrastructure-as-code recovery path independent of backup images; Tailscale pre-authorized keys stored offline for re-enrollment |
| 11.5 | Test data recovery (IG2) | Quarterly restore testing; documented test results; validation procedures | Compliant — Azure Spot instance eviction scenario tested (Deallocate policy, restart procedure documented); AWS EC2 stop/start tested; GCP Compute stop/start tested; Ansible cloud node rebuild timing validated against <2hr RTO target |

**Control 11 Overall Status:** Fully Compliant — Cloud node recovery procedures documented and tested

---

## CIS Control 12: Network Infrastructure Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 12.1 | Ensure network infrastructure is up-to-date | Network device patch management; monthly version checks; automated update notifications | Compliant — AWS VPC, GCP VPC, and Azure VNet are provider-managed infrastructure (automatically patched by provider); Tailscale client updated via package manager on all cloud nodes |
| 12.2 | Establish secure network architecture (IG2) | Documented network architecture; segmentation design; least-privilege network design | Compliant — Cloud architecture documented: Tailscale mesh routing tables (9 enrolled nodes), per-provider VPC/VNet CIDR allocations, subnet router configurations, and cloud-to-on-premises routing tables. No cloud management ports publicly exposed; default-deny posture on all cloud firewall configurations |
| 12.3 | Securely manage network infrastructure (IG2) | SSH key-based management; HTTPS-only interfaces; IaC version control (Git) | Compliant — Cloud network infrastructure (Security Groups, VPC firewall policy, NSG rules) managed via Terraform IaC and version-controlled in Git; no console-based ad-hoc changes |
| 12.4 | Establish architecture diagrams (IG2) | Network topology diagrams; Subnet/VLAN documentation; NetAlertX networking mapping | Compliant — Cloud diagrams added: Tailscale node inventory (9 nodes with Tailscale IPs and roles), subnet advertisement table (pfSense, AWS, GCP, Azure subnet routers), cloud-to-on-premises routing documentation, per-provider VPC/VNet topology |
| 12.5 | Centralize network AAA (IG2) | Not Implemented — Lab does not have a dedicated AAA service deployed for on-premises network devices | Gap — Traditional AAA not deployed; Tailscale ACL policy serves as de-facto AAA for cloud node access (device-bound authentication, per-node authorization rules, access logging); provides partial compensating control for cloud |
| 12.6 | Use secure network protocols (IG2) | 802.1X port security (planned); WPA3 wireless; TLS 1.3; SSH v2 only | Compliant — All cloud management communication via Tailscale WireGuard (ChaCha20-Poly1305); SSH v2 AES-256-GCM enforced on all Linux cloud nodes via Ansible; TLS 1.3 for all cloud-hosted HTTPS services |
| 12.7 | Ensure remote devices use VPN + AAA (IG2) | Tailscale mesh VPN requires device authentication; Cloudflare Tunnels; no direct internet exposure | Compliant — All cloud nodes connected exclusively via Tailscale WireGuard; no public management ports; cloud nodes access on-premises management stack via Tailscale; device-bound key authentication enforced |
| 12.8 | Establish dedicated admin workstations (IG3) | Partial — Dedicated admin VM; not fully air-gapped from internet | Gap — Implement fully isolated admin workstation |

**Control 12 Overall Status:** IG1/IG2 Compliant — Cloud network architecture integrated; 12.5 AAA gap remains; IG3 Partial

---

## CIS Control 13: Network Monitoring and Defense

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 13.1 | Centralize security event alerting (IG2) | Dual SIEM (Splunk + Elastic); TheHive case management; Discord/email alerting | Compliant — AWS GuardDuty findings → CloudWatch Events → SNS; GCP SCC findings → alerting policies; Azure Sentinel KQL detection rules → automated incident creation → Shuffle SOAR webhook → on-premises TheHive case creation. All cloud security events also forwarded to on-premises Splunk via Wazuh agents |
| 13.2 | Deploy host-based IDS (IG2) | Wazuh EDR on 25+ on-premises endpoints; FIM monitoring; rootkit detection; process monitoring | Compliant — Wazuh EDR deployed on all 8 cloud nodes (same configuration as on-premises) providing FIM, rootkit detection, CIS SCA, vulnerability assessment, and process monitoring |
| 13.3 | Deploy network IDS (IG2) | Suricata (IPS inline); Snort (IDS passive); CrowdSec (behavioral) | Compliant — AWS GuardDuty analyzes VPC flow logs for network-based threat patterns; GCP network IDS endpoint configured for gcp-debian-host1 mirroring traffic at high severity threshold; Azure Sentinel NSG flow log analysis detects network anomalies |
| 13.4 | Perform traffic filtering between segments (IG2) | pfSense/OPNsense inter-VLAN ACLs; firewall rules per segment; default-deny policies | Compliant — AWS Security Groups enforce default-deny; GCP VPC firewall policy (homelab) with Google Threat Intelligence blocking (TOR exit nodes, malicious IPs, sanctioned countries); Azure NSG homelab-nsg2 applies explicit allow-list with DenyAllInBound and DenyAllOutBound defaults |
| 13.5 | Manage access control for remote assets (IG2) | NAC principles applied; Tailscale device posture checks; Wazuh agent compliance verification | Compliant — Tailscale ACL policy enforces per-device/per-subnet explicit allow rules (default deny for all inter-node traffic); Wazuh agent compliance verification extended to all 8 cloud nodes |
| 13.6 | Collect network traffic flow logs (IG2) | pfSense/OPNsense flow logs; Suricata EVE JSON; packet captures (tcpdump); SIEM ingestion | Compliant — AWS VPC flow logs (fl-03179f74e54bf1aa4 → CloudWatch Logs) capturing all accepted/rejected traffic; GCP VPC flow logs enabled on default network (Flow Analyzer); Azure NSG flow logs via Network Watcher (homelab-nsg2); Tailscale tunnel telemetry supplements provider flow data |
| 13.7 | Deploy host-based IPS (IG3) | Wazuh Active Response (firewall-drop, host-deny); EDR blocking capabilities | Compliant — Wazuh Active Response executes on cloud nodes via Tailscale — same containment playbooks as on-premises (firewall-drop via iptables/UFW on Linux, host-deny, account-disable) |
| 13.8 | Deploy network IPS (IG3) | Suricata inline blocking mode; CrowdSec automated firewall rules; pfSense IPS integration | Compliant — GCP Cloud Armor application-level policy provides WAF blocking (SQLi/XSS via preconfigured expression sets v33-stable) and DDoS rate limiting; AWS Security Group acts as stateful IPS at the VPC perimeter; Azure DDoS Protection plan (homelab-ddos) protects Azure VNet |
| 13.9 | Deploy port-level access control (IG3) | Not Implemented — Network switching replacement required | Gap — Implement 802.1X NAC for on-premises; cloud nodes not applicable (no physical switchports) |
| 13.10 | Perform application layer filtering (IG3) | SafeLine WAF (OWASP CRS rules); Traefik middleware filtering; NGINX Ingress rules | Compliant — GCP Cloud Armor three-tier application-level WAF (edge policy, backend policy, application-level policy with SQLi/XSS blocking) |
| 13.11 | Tune security event alerting thresholds (IG3) | Monthly tuning of Splunk/Wazuh/Suricata thresholds; false positive reduction tracking | Compliant — AWS GuardDuty finding suppression rules configured for known-good activity; GCP SCC security marks used to suppress known-good findings; Azure Sentinel analytics rule tuning via scheduled review |

**Control 13 Overall Status:** IG2 Fully Compliant; IG3 Mostly Compliant (802.1X gap for on-premises only; cloud nodes well-covered by provider controls)

---

## CIS Control 14: Security Awareness and Skills Training

All safeguards (14.1-14.9): **N/A — Single-user lab environment**

---

## CIS Control 15: Service Provider Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 15.1 | Establish service provider inventory | Cloud providers documented | Compliant — Inventory updated: AWS (us-east-2, 2 EC2 instances, GuardDuty + Security Hub enabled), Azure (North Central US, 2 VMs, Defender for Cloud + Sentinel enabled), GCP (us-central1, 2 Compute instances, SCC + Cloud Armor enabled), Cloudflare (DNS, Tunnels, CDN, R2), Tailscale (WireGuard mesh VPN, 9 enrolled nodes), PIA (egress VPN). Security posture tools documented per provider |
| 15.2–15.7 | Additional safeguards | N/A — Single-user lab environment | N/A |

**Control 15 Overall Status:** 15.1 Compliant — Service provider inventory expanded to include AWS, Azure, GCP; remainder N/A for single-user lab

---

## CIS Control 16: Application Software Security

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 16.1 | Establish secure application development process (IG2) | Informal — IaC follows security best practices; no formal SDLC documentation | Gap — ARM templates and Ansible playbooks follow security-by-default patterns; cloud node provisioning IaC reviewed before apply |
| 16.2 | Establish vulnerability disclosure process (IG2) | N/A — Single-user lab environment | N/A |
| 16.3 | Perform root cause analysis on vulnerabilities (IG2) | Informal — Post-incident reviews conducted; no formal RCA process | Gap — Document RCA procedures |
| 16.4 | Establish third-party software component inventory (IG2) | Partial — Docker images tracked; no comprehensive SBOM tracking | Gap — Cloud node base images (AMIs, GCP images, Azure Marketplace images) tracked by version; no formal SBOM for cloud node packages. Trivy/Grype SBOM implementation planned Q1 2026 |
| 16.5 | Use up-to-date third-party components (IG2) | Watchtower auto-updates; WUD monitoring; trusted sources (official Docker images) | Compliant — Cloud node base OS images kept current via PatchMon/WSUS; provider-maintained base images (Amazon Linux 2, Ubuntu, Debian) used — security patches available same-day |
| 16.6 | Establish vulnerability severity rating system (IG2) | CVSS scoring; risk-based prioritization; documented remediation SLAs | Compliant — Same CVSS-based severity rating and SLAs applied to cloud node findings from Wazuh, Inspector, SCC, and Defender for Cloud |
| 16.7 | Use standard hardening templates (IG2) | CIS Benchmarks for application infrastructure; IaC templates (Ansible/Terraform) | Compliant — Same CIS Benchmark hardening templates applied to cloud Linux nodes via Ansible; Wazuh SCA validates compliance against CIS Amazon Linux, CIS Debian, CIS Ubuntu, and CIS Windows Server 2025 policies |
| 16.8–16.9 | Production separation; developer training | N/A — Single-user lab environment | N/A |
| 16.10 | Apply secure design principles (IG2) | Least privilege; input validation; defense-in-depth architecture; secure defaults | Compliant — Cloud nodes provisioned with no public management ports (secure default); IAM least-privilege; provider-native security services enabled by default (GuardDuty, SCC, Defender for Cloud) |
| 16.11 | Leverage vetted security modules (IG2) | Authentik (IAM); Step-CA (PKI); Traefik (reverse proxy); trusted open-source security libraries | Compliant — Provider-managed security services (AWS GuardDuty, GCP SCC, Azure Defender for Cloud) used — all are vetted, maintained security modules |
| 16.12 | Implement code-level security checks (IG3) | Limited — Infrastructure code linting (Ansible-lint/Terraform validate); no comprehensive SAST/DAST | Gap — No automated SAST scanning of IaC |
| 16.13 | Conduct application penetration testing (IG3) | Informal — Vulnerability scanning covers web apps; Kali/Parrot OS pen testing | Gap — Formal pen testing (IG3); cloud scope not included in informal testing |
| 16.14 | Conduct threat modeling (IG3) | Informal — Security architecture design considers threats; no formal STRIDE/DREAD modeling | Gap — Document threat models (IG3) including cloud attack surface |

**Control 16 Overall Status:** IG2 Mostly Compliant (infrastructure focus); IG3 Partial; cloud scope integrated where applicable

---

## CIS Control 17: Incident Response Management

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 17.1 | Designate incident handling personnel | N/A — Single-user lab environment | N/A |
| 17.2 | Establish contact information for reporting | Discord channels; SMTP relay; Cloudflare email routing | Compliant — AWS SNS notifications, GCP alerting policy notifications, and Azure Monitor action group (RecommendedAlertRules-AG-1) integrated into notification chain |
| 17.3 | Establish enterprise incident reporting process | TheHive case creation process; reporting timeframes defined; multi-channel reporting (Discord, email, API) | Compliant — AWS GuardDuty findings and Azure Sentinel incidents automatically create TheHive cases via Shuffle SOAR webhook; GCP SCC findings trigger alerting policy notifications |
| 17.4 | Establish incident response process (IG2) | Documented IR plan; TheHive playbooks | Compliant — Cloud node IR: Wazuh Active Response (firewall-drop, host-deny, account-disable) on cloud nodes via Tailscale; AWS Security Group modification for isolation; GCP/Azure firewall rule update for cloud node containment. Runbooks documented |
| 17.5 | Assign key roles and responsibilities (IG2) | N/A — Single-user lab environment | N/A |
| 17.6 | Define communication mechanisms (IG2) | Primary: Discord; Secondary: SMTP/Cloudflare email routing; multi-path redundancy | Compliant — AWS SNS, GCP alerting policies, Azure Monitor action group feed Discord/email channels |
| 17.7–17.8 | IR exercises; post-incident reviews | N/A — Single-user lab environment | N/A |
| 17.9 | Establish incident thresholds (IG3) | Severity matrix documented; CVSS thresholds; Splunk alert severities; MISP threat levels; Prometheus thresholds | Compliant — AWS GuardDuty severity (High/Medium/Low); GCP SCC severity ratings; Azure Sentinel analytics rule severity levels — all mapped to same severity matrix |

**Control 17 Overall Status:** Mostly Compliant; limited IR playbooks and SOAR workflows for both on-premises and cloud workloads.

---

## CIS Control 18: Penetration Testing

| Safeguard | Requirement | Implementation | Notes |
|-----------|-------------|----------------|-------|
| 18.1 | Establish penetration testing program (IG2) | Informal — Vulnerability scanning exceeds pen testing frequency; no formal pen testing engagement | Gap — Cloud node attack surface is minimal (no public management ports); cloud-native threat detection provides continuous threat detection equivalent to some pen testing functions |
| 18.2 | Perform external penetration tests annually (IG2) | Informal — Weekly OpenVAS/monthly Nessus scans; no dedicated external pen test | Gap — Cloud public IPs (used only for Tailscale UDP handshake) represent minimal external attack surface; no cloud management ports internet-exposed |
| 18.3 | Remediate penetration test findings (IG2) | Vulnerability remediation process covers pen test findings; documented remediation workflows | Compliant — Process exists; same remediation SLAs and TheHive tracking applied to any cloud findings |
| 18.4 | Validate security measures post-test (IG3) | Informal — Re-scanning validates remediation; no formal security control validation | Gap — Post-remediation validation testing needed |
| 18.5 | Perform internal penetration tests annually (IG3) | Informal — No formal internal pen testing; local scanning, enumeration, and vulnerability testing conducted | Gap — IG3 requirement; cloud nodes should be included in scope |

**Control 18 Overall Status:** IG2 Partial (vulnerability scanning substitutes); IG3 Not Implemented. Cloud minimal attack surface noted.

---

## Summary of Compliance Status

Overall CIS Controls v8.1.2 Compliance — v2.0 (April 2026)

| Implementation Group | Controls Fully Compliant | Controls Partially Compliant | Controls Not Implemented | Overall Score |
|---------------------|--------------------------|------------------------------|-------------------------|---------------|
| **IG1** (56 safeguards) | 52 (93%) | 4 (7%) | 0 (0%) | 93% Compliant |
| **IG2** (74 additional safeguards) | 60 (81%) | 12 (16%) | 2 (3%) | 81% Compliant |
| **IG3** (29 additional safeguards) | 15 (52%) | 8 (28%) | 6 (20%) | 52% Compliant |

Note: Compliance scores unchanged from v1.0. Cloud integration strengthens evidence for existing compliant safeguards but does not introduce new gaps or close existing open items in IG2/IG3.
