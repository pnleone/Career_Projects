## 3. Configuration Management with Ansible

### 3.1 Architecture Overview

Ansible provides agentless configuration management through SSH-based automation, enforcing consistent baselines across all managed hosts (Linux, Windows, Cisco, VMware, FreeBSD), managing secrets securely via Ansible Vault, and orchestrating complex multi-host operations using declarative playbooks and Galaxy roles.

**Security Impact**

- Configuration drift eliminated through automated enforcement across 40+ hosts
- SSH hardening applied consistently via dedicated playbooks (PermitRootLogin no, key-only auth)
- Credential exposure prevented through Ansible Vault encryption (AES-256) and vault_* variable pattern
- Audit trail established via Git-based version control
- Manual errors eliminated through playbooks and connectivity pre-tasks
- Multi-platform coverage: Linux, Windows, Cisco IOS, VMware ESXi, FreeBSD (pfSense/OPNsense)

**Deployment Rationale:** In enterprise environments with 40+ mixed-platform hosts, manual configuration becomes error-prone and time-consuming. This approach reduces configuration time from hours to minutes while ensuring 100% consistency across systems. The lab implementation covers Linux (Debian/RHEL families), Windows Server, Cisco IOS devices, VMware ESXi, and FreeBSD firewalls, demonstrating cross-platform automation capabilities.

**Architecture Principles Alignment**

- **Defense in Depth:** SSH hardening playbooks disable weak ciphers and enforce key-based auth; firewall rules (UFW/firewalld) deployed uniformly; fail2ban configured consistently; kernel hardening via sysctl parameters; multi-platform audit playbooks provide visibility across the entire infrastructure stack
- **Secure by Design:** Ansible Vault encrypts sensitive variables (vault_ansible_password, vault_root_password); no plaintext credentials in playbooks; SSH keys distributed securely via cloud-init; vault.yml encrypted with AES-256
- **Zero Trust:** Every configuration change logged to Git; playbooks verify current configuration before making changes; connectivity pre-tasks skip unreachable hosts gracefully; password rotation workflow requires explicit vault updates

---

### 3.2 Setup Overview

**Control plane: Ansible running in a Proxmox LXC**

- Deployed from a Proxmox Debian-based LXC ("ansible"), using a Python virtual environment
- SSH auth is key-based via an "ansible" user
- Handles initial configuration management to achieve a standard template across all hosts
  - Standard base packages, DNS, PKI and SSH configurations plus user accounts and permissions

### Control Plane Configuration

| Component | Details |
|-----------|---------|
| Ansible Controller | Debian 12 LXC (192.168.x.x) |
| Ansible Version | 2.16.x (core) |
| Python Environment | venv isolated (Python 3.11) |
| Authentication | SSH key-based (ed25519) |
| Privilege Escalation | sudo (passwordless for ansible user) |
| Inventory | Dynamic (Proxmox API) + static YAML |
| Vault Encryption | ansible-vault with AES-256 |

---

### 3.3 Inventory and Variable Structure

**Inventory Design Principles**

The inventory uses a hierarchical group structure with NO host duplication. Each host appears exactly once in a platform-specific group, then aggregated via [group:children] declarations for flexible targeting.

- Host Type Groups: [lxc], [vm], [new]
- OS Family Groups: [debian_lxc], [debian_vm], [redhat_lxc], [redhat_vm]
- OS Aggregate Groups: [debian], [redhat] (children of lxc+vm OS groups)
- Platform Groups: [windows], [cisco], [vmware], [freebsd], [fortigate]
- Function Groups: [monitoring], [dns], [proxy], [pki], [docker], [k3s]
- Meta Groups: [linux] (all managed Linux hosts – excludes [new])

**Inventory Code Snippets (hosts.ini)**
```text
placeholder
```

**Targeting Examples:**
```bash
ansible-playbook playbook.yml --limit linux          # All Linux hosts
ansible-playbook playbook.yml --limit lxc            # All LXCs
ansible-playbook playbook.yml --limit debian         # All Debian (LXC + VM)
ansible-playbook playbook.yml --limit debian_lxc     # Debian LXCs only
ansible-playbook playbook.yml --limit lxc --skip-tags reboot  # Skip reboot on LXCs
```

**Variable Structure**
```text
placeholder
```

**Vault Structure (group_vars/vault.yml - Encrypted)**
```text
placeholder
```

**Galaxy Roles and Collections**

Ansible Galaxy provides pre-built roles and collections for common tasks. The lab uses officially maintained roles for Wazuh, CheckMK agent deployment, plus support for Windows, VMware, and Cisco hosts.

---

### 3.4 Core Playbooks - Detailed Overview

#### Playbook 1: Multi-Platform System Audit (sys_audit_n8n.yml)

**Purpose:** Comprehensive infrastructure audit across Linux, Windows, and FreeBSD hosts with JSON output for n8n workflow processing.

**Key Features:**

- Single-play design for all platforms (Linux/Windows/FreeBSD)
- Connectivity pre-checks skip unreachable hosts gracefully
- Platform-specific data collection with conditional blocks
- Consolidated JSON output to /tmp/audit_report.json
- Integration with n8n for HTML report generation and alerting

**Data Collected:**

- System: CPU cores, memory, disk usage %, memory usage %, uptime
- Network: Default gateway, nameservers, listening ports count
- Security: SSH keys count, Windows Defender status, running services
- Software: Kernel version, available updates count

**Code Snippet - Connectivity Pre-Tasks**
```text
placeholder
```

**Code Snippet - Linux Data Collection**
```text
placeholder
```

**Code Snippet - Windows Data Collection**
```text
placeholder
```

**Code Snippet - JSON Consolidation**
```text
placeholder
```

**Use Cases:**

- Weekly infrastructure audits via n8n automation
- Pre-maintenance compliance checks
- Capacity planning via disk/memory trending
- Security baseline validation (SSH keys, services, updates)

---

#### Playbook 2: User Management (user_mgmt.yml)

**Purpose:** Centralized user account and credential management across all Linux hosts with Ansible Vault integration.

**Key Features:**

- Sets ansible user password from vault_ansible_password
- Sets root password from vault_root_password
- Manages paul user with sudo access (password-based)
- Deploys SSH keys for authorized users
- Verifies ansible key-based auth after password rotation

**Code Snippet - Ansible User Password Management**
```text
placeholder
```

**Code Snippet - Paul User with Sudo Configuration**
```text
placeholder
```

**Password Rotation Workflow:**

- Generate 32-char token: `openssl rand -base64 24`
- Update vault_ansible_password in vault.yml: `ansible-vault edit group_vars/vault.yml`
- Run playbook: `ansible-playbook user_mgmt.yml --tags ansible_user`
- Test connectivity: `ansible linux -m ping`

**Use Cases:**

- Quarterly credential rotation (automated via n8n)
- Emergency password resets
- New host bootstrap user provisioning
- SSH key distribution after key rotation

---

#### Playbook 3: Linux Package Updates (update_linux_hosts.yml)

**Purpose:** Update all Linux hosts with dist-upgrade/dnf update and reboot detection.

**Key Features:**

- Debian: apt dist-upgrade with autoremove/autoclean
- RedHat: dnf update with latest packages
- Reboot detection for kernel updates
- Free strategy for parallel execution
- Update summary with reboot status

**Code Snippet - Debian Package Updates & Reboot Detection**
```text
placeholder
```

**Use Cases:**

- Weekly package updates (n8n automation)
- Security patch deployment
- Post-vulnerability scanning remediation
- Compliance maintenance (keep systems current)

---

#### Playbook 4: Linux Hardening (linux_hardening.yml)

**Purpose:** Docker-aware SSH and system hardening with automatic Docker detection.

**Key Features:**

- SSH hardening: disable root login, enforce key-only auth
- TCP/Agent forwarding enabled for Docker/DevOps workflows
- Automatic Docker detection preserves IP forwarding
- Safe kernel parameters (sysctl hardening)
- Login banner deployment

**Code Snippet - Docker Detection**
```text
placeholder
```

**Code Snippet - SSH Hardening**
```text
placeholder
```

**Use Cases:**

- New host security baseline
- Docker host specialized hardening
- Compliance enforcement (CIS benchmarks)
- Post-compromise hardening

---

#### Playbook 5: New Install Baseline (new_install_baseline_roles.yml)

**Purpose:** Bootstrap new hosts with baseline configuration using Galaxy roles.

**Roles Used:**

- wazuh.wazuh_agent (version: 4.14.2)
- Custom bootstrap tasks (user creation, SSH, sudo)

**Key Features:**

- Creates ansible service account with passwordless sudo
- Deploys SSH keys for ansible and paul users
- Configures sudoers with validation
- Installs Wazuh agent and registers with manager
- Installs utility packages (curl, nano, dig, traceroute)
- Enables qemu-guest-agent for Proxmox integration

**Code Snippet - User Creation**
```text
placeholder
```

**Use Cases:**

- Fresh install bootstrap (first playbook to run)
- Wazuh agent deployment across new hosts
- Monitoring stack integration
- Standardized user/SSH configuration

---

## 5. Workflow Automation with n8n

### 5.1 Platform Overview

n8n is a self-hosted, low-code workflow automation platform enabling visual workflow design with conditional logic, error handling, loops, and data transformation. Deployed as a containerized service behind Traefik reverse proxy with Authentik SSO.

**Security Impact**

- Security operations accelerated through automated SOAR workflows
- Manual triage eliminated via automated alert enrichment
- MTTR reduced through auto-generated remediation playbooks
- Alert fatigue minimized through intelligent deduplication and correlation
- Compliance audit trails automatically documented throughout the incident lifecycle

**Deployment Rationale:** Security operations generate thousands of events daily, manual triage is unsustainable. n8n demonstrates Security Orchestration, Automation and Response (SOAR) capabilities where vulnerability scans trigger automated ticket creation, threat intelligence enrichment queries multiple APIs, and incident response playbooks execute without human intervention. This mirrors enterprise SOAR platforms (Splunk SOAR, Palo Alto Cortex XSOAR) where analyst efficiency is multiplied through automation.

**Architecture Principles Alignment**

- **Defense in Depth:** Automated vulnerability remediation workflows execute Ansible playbooks; firewall rule changes logged and reviewed; failed automation triggers manual fallback procedures
- **Secure by Design:** Credentials stored in n8n credential vault (encrypted at rest); webhook endpoints authenticated via Authentik tokens; workflow execution logs forwarded to SIEM
- **Zero Trust:** Every automation action logged with timestamp/user; no hardcoded credentials; API tokens expire and rotate automatically

### n8n Configuration

- Version: n8n v2.7.5 (latest stable)
- Execution Mode: Main process (not queue mode for simplicity)
- Webhook URL: https://n8n.home.com
- TLS Certificate: Step-CA issued, auto-renewed
- Authentication: SSO via Authentik (no local passwords)
- Monitoring: Uptime Kuma
- Notifications: Discord webhooks, SMTP relay

### Security Controls

- Credential Encryption: All API tokens encrypted at rest, Ansible automated (ansible-vault)
- Webhook Security: HMAC signature validation on inbound webhooks
- Audit Trail: All workflow executions logged with timestamp and user

---

### 5.2 Workflow 1: Lab Infrastructure Audit

**Purpose:** Automated weekly configuration audit and system updates across lab infrastructure with HTML reporting and dual alerting (Discord + Email).

This workflow runs weekly on Sunday at 2 AM, executes the Ansible sys_audit_n8n.yml playbook, transforms the JSON output into a styled HTML report, deploys it to the Apache webserver, and sends notifications via Discord and email.

**Workflow Summary:**

- **Scheduled Execution:** Triggered weekly via n8n's Cron node (Sunday 2 AM)
- **Ansible Playbook:** Executes sys_audit_n8n.yml via SSH to collect system metrics
- **Data Transformation:** Parses JSON and generates HTML report with CSS styling
- **Apache Upload:** Deploys HTML to /var/www/html/ and updates index page
- **Discord Alert:** Sends formatted notification with report link and summary stats
- **Email Alert:** Sends HTML email template with audit summary

### Workflow Nodes

| Node Type | Configuration | Purpose |
|-----------|---------------|---------|
| Schedule Trigger | Cron: 0 2 * * 0 (Sunday 2 AM) | Weekly execution |
| SSH Node 1 | ansible-playbook sys_audit_n8n.yml | Run audit playbook |
| SSH Node 2 | cat /tmp/audit_report.json | Read JSON output |
| Code Node 1 | Parse JSON from stdout | Extract audit data |
| Code Node 2 | Generate HTML with CSS | Create styled report |
| SSH Node 3 | Write HTML to webserver | Deploy to Apache |
| SSH Node 4 | Update index.html | Add report to index |
| Code Node 3 | Generate Discord markdown | Format alert message |
| Discord Webhook | POST to webhook URL | Send Discord notification |
| Code Node 4 | Generate email HTML | Format email template |
| Email Node | SMTP send | Send email notification |

**HTML Report Features:**

- Responsive grid layout with host cards
- Platform-specific color coding (Linux/Windows/FreeBSD)
- Visual metrics with progress bars for disk/memory usage
- Warning/critical thresholds highlighted (>75% yellow, >90% red)
- Summary statistics cards (total hosts, high disk/memory usage counts)
- Timestamp and audit metadata in footer

<div class="grid cards" markdown>
- <figure>
    <img src="/Career_Projects/assets/screenshots/n8n-audit-landing.png" alt="Apache Webserver Landing Page">
    <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">Apache Webserver Landing Page.</figcaption>
  </figure>
- <figure>
    <img src="/Career_Projects/assets/screenshots/n8n-audit-report.png" alt="Example Audit Report">
    <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">Example Audit Report.</figcaption>
  </figure>
</div>

<div class="grid cards" markdown>
- <figure>
    <img src="/Career_Projects/assets/screenshots/n8n-audit-email.png" alt="Example Email Alert">
    <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">Example Email Alert.</figcaption>
  </figure>
- <figure>
    <img src="/Career_Projects/assets/screenshots/n8n-audit-discord.png" alt="Example Discord Alert">
    <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">Example Discord Alert.</figcaption>
  </figure>
</div>

---

### 5.3 Workflow 2: Threat Intelligence Aggregation

**Purpose:** Daily ingestion and distribution of curated cybersecurity threat intelligence with AI-powered summarization.

This workflow runs daily at 8 AM to ingest and distribute curated threat intelligence from multiple cybersecurity RSS feeds. It supports situational awareness and IOC enrichment across the lab environment.

**Workflow Summary:**

- **Scheduled Execution:** Triggered daily via n8n's Cron node (6 AM)
- **RSS Feed Polling:** Pulls entries from curated list of cybersecurity sources
- **Feed Limiting:** Filters each feed to articles added in the last 24 hours to reduce noise
- **ChatGPT Integration:** NIST feed summarized via OpenAI API
- **Discord Notification:** Formatted aggregated feed summary to #threat-intel channel

**RSS Feeds:**

- Darknet Diaries (https://podcast.darknetdiaries.com/)
- NIST (https://www.nist.gov/blogs/cybersecurity-insights/rss.xml)
- Krebs on Security (https://krebsonsecurity.com/feed/)
- Threat Post (https://threatpost.com/feed/)
- BleepingComputer (https://www.bleepingcomputer.com/feed/)
- CIS (https://www.cisecurity.org/feed/advisories)
- NAO SEC (https://nao-sec.org/feed)

### Workflow Nodes

| Node Type | Configuration | Purpose |
|-----------|---------------|---------|
| Schedule Trigger | Cron: 0 8 * * * (Daily 6 AM) | Daily execution |
| RSS Feed Reader | URLs: CIS, NIST, Krebs, ThreatPost, BleepingComputer, etc | Ingest threat intel |
| Filter Node | Limit each feed to the last 24 hours | Reduce noise |
| Merge Node | Combine all feeds | Aggregate data |
| OpenAI Node | Summarize NIST feed with ChatGPT | AI-powered summary |
| Format Node | Create Discord embed message | Visual formatting |
| Discord Webhook | POST to #threat-intel channel | Distribute to team |

**Workflow Benefits:**

- Centralized threat intelligence (7 sources → 1 channel)
- AI-powered summarization reduces information overload
- Daily cadence ensures timely awareness of emerging threats
- Supports incident response and vulnerability management

<div class="grid cards" markdown>
- <figure>
    <img src="/Career_Projects/assets/screenshots/n8n-nist-alert.png" alt="NIST Summary Alert">
    <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">NIST Summary Alert.</figcaption>
  </figure>
- <figure>
    <img src="/Career_Projects/assets/screenshots/n8n-discord-alerts.png" alt="Example Discord Alerts">
    <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">Example Discord Alerts.</figcaption>
  </figure>
</div>

---

### 5.4 Workflow 3: Weekly Package Updates with Alerting

**Purpose:** Automated weekly package manager updates across all Linux hosts with Discord and email alerting.

This workflow runs weekly on Friday at 3 AM, executes the update_linux_hosts.yml Ansible playbook, parses the output to categorize update results, and sends formatted notifications via Discord and email.

**Workflow Summary:**

- **Scheduled Execution:** Weekly trigger (Friday 3 AM)
- **Ansible Playbook:** Executes update_linux_hosts.yml for apt/dnf updates
- **Data Parsing:** Converts raw Ansible stdout to structured JSON
- **Update Categorization:** Hosts grouped by status (no updates, updated, reboot required, errors)
- **Markdown Generation:** Creates formatted summary for Discord
- **HTML Generation:** Creates formatted report for email
- **Discord Alert:** Sends markdown summary with status counts
- **Email Alert:** Sends HTML email with detailed update report

### Workflow Nodes

| Node Type | Configuration | Purpose |
|-----------|---------------|---------|
| Schedule Trigger | Cron: 0 3 * * 5 (Friday 3 AM) | Weekly execution |
| SSH Node | ansible-playbook update_linux_hosts.yml | Run package updates |
| Code Node 1 | Parse stdout: extract reachable/unreachable hosts, summaries, recap | Convert to structured JSON |
| Code Node 2 | Generate markdown and HTML summaries with categorization | Format alert content |
| Discord Node | POST markdown summary | Send Discord notification |
| Email Node | SMTP send HTML report | Send email notification |

**Data Flow and Parsing Logic**

The workflow parses Ansible's stdout output to extract comprehensive update information:

- Reachable Hosts: Extracted from 'ok: [hostname]' lines
- Unreachable Hosts: Extracted from 'fatal: [hostname]' lines
- Update Summaries: Parsed from 'msg' fields containing platform, packages updated, reboot status
- Play Recap: Structured data showing ok/changed/failed/skipped counts per host

**Host Categorization**

Hosts are automatically categorized based on update results:

- No Updates Required: Hosts with packages_updated = False
- Updates Applied: Hosts with packages_updated = True and reboot_required = False
- Reboot Required: Hosts with reboot_required = True
- Errors Detected: Hosts with empty/null platform, packages_updated, reboot_required
- Unreachable: Hosts that failed connectivity checks

**Code Snippet - Stdout to JSON Parsing**
```text
placeholder
```

**Code Snippet - Categorization and Formatting**
```text
placeholder
```

**Workflow Benefits:**

- Automated weekly package updates reduce manual maintenance
- Categorized results prioritize attention (errors and reboots first)
- Dual alerting ensures visibility across communication channels
- Structured parsing enables trend analysis over time
- Unreachable host detection prevents silent failures

**Use Cases:**

- Weekly security patch deployment
- Compliance maintenance (systems up-to-date)
- Post-vulnerability scanning remediation
- Reboot planning based on kernel updates
- Infrastructure health monitoring

<div class="grid cards" markdown>
- <figure>
    <img src="/Career_Projects/assets/screenshots/n8n-updates-discord.png" alt="Discord Alert Example">
    <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">Discord Alert Example.</figcaption>
  </figure>
- <figure>
    <img src="/Career_Projects/assets/screenshots/n8n-updates-email.png" alt="Email Alert Example">
    <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">Email Alert Example.</figcaption>
  </figure>
</div>

---

### 5.5 Workflow 4: Monthly Automated Ansible Token Rotation

**[PLACEHOLDER - Implementation Pending]**

**Purpose:** Automated monthly credential rotation for Ansible vault with random token generation, vault file update, user management playbook execution, and dual alerting.

**Planned Workflow Summary:**

- **Scheduled Execution:** Monthly trigger (1st of month at 4 AM)
- **Token Generation:** Create cryptographically random 32-char token (base64)
- **Vault Update:** SSH to Ansible controller and update vault_ansible_password in vault.yml
- **Playbook Execution:** Run user_mgmt.yml --tags ansible_user to propagate new password
- **Connectivity Test:** Verify Ansible can still connect to all hosts via ping
- **Discord Alert:** Send success/failure notification with rotation summary
- **Email Alert:** Send HTML email confirming rotation and test results

### Planned Workflow Nodes

| Node Type | Configuration | Purpose |
|-----------|---------------|---------|
| Schedule Trigger | Cron: 0 4 1 * * (1st of month 4 AM) | Monthly execution |
| Code Node 1 | Generate token: crypto.randomBytes(24).toString('base64') | Create new password |
| SSH Node 1 | Backup current vault.yml | Create vault backup |
| SSH Node 2 | ansible-vault edit vault.yml (update vault_ansible_password) | Update vault variable |
| SSH Node 3 | ansible-playbook user_mgmt.yml --tags ansible_user | Propagate new password |
| SSH Node 4 | ansible linux -m ping | Test connectivity |
| Code Node 2 | Parse ping results for success count | Verify all hosts accessible |
| IF Node | Check if ping success == total hosts | Route to success/failure |
| Code Node 3 | Generate Discord success message | Format success alert |
| Discord Webhook | POST rotation success to Discord | Send Discord notification |
| Code Node 4 | Generate HTML email template | Format email report |
| Email Node | SMTP send with rotation details | Send email notification |
| Error Handler | Rollback vault.yml and alert on failure | Handle rotation errors |

**Security Considerations for Token Rotation:**

- Token generation uses crypto.randomBytes (cryptographically secure)
- Vault backup created before each rotation for rollback capability
- Connectivity test verifies all hosts accessible before confirming rotation
- Error handler automatically reverts to backup vault on failure
- Credentials never logged or displayed in workflow execution history
- n8n credential vault stores vault password with AES-256 encryption

**Expected Alert Content:**

- Rotation timestamp
- Token generation success
- Vault update status
- User management playbook execution result
- Connectivity test results (hosts reachable/unreachable)
- Rollback status (if applicable)

---

### 5.6 Best Practices and Lessons Learned

**Error Handling and Resilience:**

- All SSH nodes include timeout settings (30-60 seconds)
- Workflow execution logs retained for 30 days in n8n database

**Credential Management:**

- All credentials stored in n8n vault (never hardcoded)
- SSH credentials use key-based auth where possible
- Webhook URLs stored as environment variables
- SMTP credentials encrypted with AES-256 at rest

**Notification Design:**

- Discord: Concise markdown with key metrics and report links
- Email: Detailed HTML templates with embedded CSS for compatibility
- Critical alerts include @ mentions for immediate attention
- All notifications include timestamp and workflow execution ID

**Integration Patterns:**

- Ansible workflows use SSH node for remote execution
- JSON output from playbooks parsed in Code nodes
- HTML and Markdown generation via JavaScript templates
- Apache webserver deployment via SSH file write operations
- Multi-platform support handled through conditional Ansible blocks