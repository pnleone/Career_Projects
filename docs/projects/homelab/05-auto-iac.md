# Automation and Infrastructure as Code (IaC)

**Created By:** Paul Leone  
**Date:** January 9, 2026  

---

## Table of Contents

1. [Automation and Infrastructure as Code (IaC)](#automation-and-infrastructure-as-code-iac)
2. [Infrastructure Provisioning with Terraform](#infrastructure-provisioning-with-terraform)
3. [Configuration Management with Ansible](#configuration-management-with-ansible)
   - 3.1 [Architecture Overview](#architecture-overview)
   - 3.2 [Setup Overview](#setup-overview)
   - 3.3 [Playbook Architecture](#playbook-architecture)
4. [Version Control and GitOps](#version-control-and-gitops)
5. [Workflow Automation with n8n](#workflow-automation-with-n8n)
   - 5.1 [Platform Overview](#platform-overview)
   - 5.2 [Workflow 1: Ansible Playbook Automation](#workflow-1-ansible-playbook-automation)
   - 5.3 [Workflow 2: Threat Intelligence Aggregation](#workflow-2-threat-intelligence-aggregation)
6. [Scripting for Advanced Automation](#scripting-for-advanced-automation)
   - 6.1 [PowerShell & Bash Scripting](#powershell--bash-scripting)
   - 6.2 [Cron Job Scheduling Strategy](#cron-job-scheduling-strategy)
   - 6.3 [Python Scripting for Advanced Automation](#python-scripting-for-advanced-automation)
   - 6.4 [Script Integration & Orchestration](#script-integration--orchestration)
7. [Automation Security Controls](#automation-security-controls)
8. [Operational Resilience & Disaster Recovery](#operational-resilience--disaster-recovery)
9. [Practical Use Cases and Workflows](#practical-use-cases-and-workflows)
10. [Standards Alignment](#standards-alignment)
11. [Security Homelab Section Links](#security-homelab-section-links)

---

## 1. Automation and Infrastructure as Code (IaC)

### Architecture Overview

The lab implements a comprehensive automation strategy using infrastructure as code principles, configuration management, and workflow orchestration. This approach provides repeatable deployments, consistent configurations, and automated operations across the entire infrastructure stack.

**Security Impact**

- Configuration drift eliminated through code‑driven enforcement
- Human error reduced via automated validation
- Credential exposure prevented through integrated secret management
- Unauthorized changes blocked through Git‑based approval workflows
- Disaster recovery enabled through fully reproducible infrastructure
- Audit compliance maintained via immutable version history

**Deployment Rationale:** Infrastructure as Code eliminates manual configuration drift, reduces human error, and enables rapid disaster recovery. The automation stack transforms a complex 40+ host lab environment into a reproducible, documented system that can be rebuilt from code within hours instead of weeks. This mirrors enterprise DevOps practices and demonstrates proficiency with industry-standard automation tools (Terraform, Ansible, CI/CD pipelines). Enterprise environments leverage IaC to manage hundreds or thousands of servers with consistent security baselines—manual approaches become impossible at scale. This implementation demonstrates understanding of GitOps principles where infrastructure state is declared in version control, changes are peer-reviewed via pull requests, and deployments are automated through CI/CD pipelines.

### Architecture Principles Alignment

- **Defense in Depth:** Infrastructure changes peer-reviewed before deployment; Terraform plan reviewed for security impact; Ansible playbooks enforce CIS Benchmarks; automated testing validates security controls before production
- **Secure by Design:** Least-privilege service accounts for automation tools; secrets stored in Ansible Vault/Vaultwarden; SSH keys rotated via automated playbooks; no hardcoded credentials in version control
- **Zero Trust:** Every infrastructure change logged to Git with committer identity; Terraform state files encrypted; API tokens short-lived and rotated; automation execution audited via SIEM

### Strategic Value

- **Reduced provisioning time:** VM deployment from 30 minutes (manual) to <5 minutes (Terraform automation)
- **Configuration consistency:** Ansible ensures identical baselines across all hosts (100% CIS Benchmark compliance)
- **Audit trail:** Git commits provide full history of infrastructure changes (who, what, when, why)
- **Disaster recovery:** Entire lab can be rebuilt from GitHub repository (<2 hours full recovery)
- **Learning platform:** Hands-on experience with tools used in production environments (transferable to enterprise roles)
- **Compliance automation:** Security controls codified and version-controlled (auditable evidence of control implementation)

---

## 2. Infrastructure Provisioning with Terraform

### Architecture Overview

Terraform manages the complete lifecycle of Proxmox virtual machines and LXC containers using declarative configuration files. The infrastructure is defined as code, version-controlled, and applied through a dedicated automation controller VM running Ubuntu Server.

**Security Impact**

- Least‑privilege automation enforced through Proxmox API tokens
- Infrastructure changes tracked and auditable via Git commit history
- Unauthorized modifications prevented through Terraform's stateful resource management
- Disaster recovery enabled through declarative rebuilds directly from code
- Credential exposure eliminated through encrypted Terraform variables
- Change validation performed prior to execution using terraform plan

**Deployment Rationale:** Manual VM creation is time-consuming, error-prone, and undocumented—scaling to 40+ VMs/containers requires automation. Terraform demonstrates infrastructure-as-code where VM specifications (CPU, RAM, storage, network) are declared in HCL configuration files, version-controlled, and applied idempotently. This mirrors enterprise infrastructure management (AWS CloudFormation, Azure Resource Manager) where infrastructure is treated as software with code review, testing, and CI/CD deployment. The approach enables rapid environment replication (dev/staging/production), consistent resource configurations, and automated disaster recovery.

**Architecture Principles Alignment**

- **Defense in Depth:** Terraform state stored remotely with access controls; API tokens scoped to minimal permissions; plan review catches misconfigurations before apply; resource tagging enables compliance auditing
- **Secure by Design:** Proxmox API tokens instead of passwords; Terraform variables encrypted; no secrets in Git repositories; automated validation via pre-commit hooks
- **Zero Trust:** Every Terraform execution logged; state file modifications tracked; API calls authenticated via tokens; infrastructure changes require explicit approval

### Deployment Architecture

| Component | Technology | Purpose |
|-----------|------------|---------|
| Terraform Controller | CentOS LXC (192.168.x.x) | Isolated automation host |
| Terraform Version | v1.6.x | Infrastructure provisioning engine |
| Provider | Telmate/proxmox v2.9.x | Proxmox VE API integration |
| State Backend | Local file, Cloudflare R2 | State persistence and locking |
| Secrets Management | terraform.tfvars (gitignored) | API tokens and credentials |

### Authentication & Authorization

**Proxmox Service Account:**

- Username: terraform@pve
- Authentication: API token (non-password, scoped)
- Token ID: terraform-token
- Permission Group: TerraformProvisioners
- Granted Privileges:
  - VM.Allocate (create VMs)
  - VM.Config.* (modify VM settings)
  - VM.PowerMgmt (start/stop/shutdown)
  - Datastore.AllocateSpace (provision storage)
  - SDN.Use (network assignment)
- Principle: Least privilege - cannot modify Proxmox cluster config or other users

### Security Controls

- Secrets management: Proxmox API token stored in env variable
- State File Protection: Contains sensitive data, stored with restrictive permissions (0600)
- TLS Verification: pm_tls_insecure = false enforces valid certificate checks
- Separate Workspaces: VM and LXC builds isolated to prevent cross-contamination
- Gitignore Enforcement: terraform.tfvars, *.tfstate excluded from version control

**Diagram Placeholder: Terraform Project Structure Screenshots (2 images)**

**Project Structure:**
```
terraform/
├── vm/
│   ├── main.tf              # VM resource definitions
│   ├── variables.tf         # Input variable declarations
│   ├── terraform.tfvars     # Sensitive values (gitignored)
│   ├── outputs.tf           # Return values (IP, VMID)
│   └── .terraform.lock.hcl  # Provider version lock
├── lxc/
│   ├── main.tf              # LXC resource definitions
│   ├── variables.tf         # Input variable declarations
│   ├── terraform.tfvars     # Sensitive values (gitignored)
│   └── outputs.tf           # Return values
└── modules/
    └── common/              # Reusable module components
```

### Terraform Configuration Deep Dive

#### LXC Container Provisioning (main.tf)

**Diagram Placeholder: Terraform LXC Configuration Screenshot**

**Purpose:** Deploy unprivileged Debian 12 containers with security isolation and resource limits suitable for containerized workloads.

**Key sections:**

- **Provider declaration** → Uses Terraform-for-Proxmox/proxmox provider
- **Authentication variables** → API token ID & secret, plus root password for the container
- **Proxmox provider block** → Points to the PVE API over HTTPS with certificate validation (pm_tls_insecure = false)
- **LXC resource** (proxmox_lxc):
  - Hostname & VMID variable arguments provided in the terraform plan command
  - Template source (ostemplate) from Proxmox storage
  - Unprivileged mode for added security isolation
  - Resource limits: 2 CPU cores, 512 MB RAM + swap
  - Disk allocation: 8 GB on local-lvm storage
  - Networking: virt‑bridge to vmbr0 via DHCP
  - Features: nesting enabled (allowing Docker/Kubernetes inside the LXC)
  - Boot & start flags so it powers up with the node

**Resource Allocation Strategy:**

- CPU: 2 cores (sufficient for most containerized apps)
- Memory: 512MB + 512MB swap (low footprint for density)
- Disk: 8GB (expandable, allocated on local-lvm for performance)
- Network: DHCP with VLAN tagging support via bridge

**Security Features:**

- Unprivileged Containers: UID/GID mapping prevents root escalation to host
- Nesting Enabled: Allows Docker-in-LXC for lab flexibility
- AppArmor Profile: Default Proxmox profile applied
- Resource Limits: Prevent resource exhaustion attacks

#### VM Provisioning (main.tf - QEMU)

**Purpose:** Clone cloud-init ready Ubuntu VMs with optimized storage and network configuration for performance and manageability.

**Diagram Placeholder: Terraform VM Configuration Screenshot**

**Key sections:**

- **Provider declaration** → Same Terraform‑for‑Proxmox provider as above
- **Authentication variables** → API token ID & secret; cloud-init user and password
- **Proxmox provider block** → HTTPS API endpoint with TLS verification
- **VM resource** (proxmox_vm_qemu):
  - Clones from ubuntu-cloud template (must be cloud-init ready)
  - full_clone = true → independent disk image
  - OS type set to l26 → Linux kernel 2.6+ (optimized for modern distros)
  - Hostname & VMID variable arguments provided in the terraform plan command
  - Boot settings:
    - Boot from scsi0 (OS disk) before ide2 (cloud-init)
    - Force virtio-scsi-single controller for best Linux I/O performance
  - CPU/memory: 2 vCPUs, 2 GB RAM, 1 socket
  - QEMU guest agent enabled for status reporting & IP detection
  - Networking: virtio NIC on vmbr0 with firewall disabled in guest config
  - Cloud-init parameters for provisioning user and password
  - clone_wait = 0 → Terraform doesn't block on post-clone boot readiness

**Cloud-Init Integration:**

- User Creation: Provisions non-root user via ciuser parameter
- SSH Keys: Injects public keys for passwordless authentication
- Network Config: Configures DHCP or static IP via ipconfig parameters
- Package Updates: Can specify packages to install on first boot

**Performance Optimizations:**

- VirtIO-SCSI-Single: Modern SCSI controller with single queue (reduces overhead)
- IOThread: Dedicated I/O thread improves disk throughput
- SSD Flag: Enables TRIM for better SSD performance
- VirtIO NIC: Para-virtualized network driver (near-native performance)

### Terraform Plan Output

**Diagram Placeholder: Terraform Plan Output Screenshot**

### Terraform Workflow

| Step | Command | Purpose |
|------|---------|---------|
| Initialize | `terraform init` | Download provider plugins |
| Validate | `terraform validate` | Check syntax errors |
| Plan | `terraform plan -var="hostname=test01" ...` | Preview changes |
| Apply | `terraform apply -var="hostname=test01" ...` | Execute provisioning |
| Destroy | `terraform destroy -var="vmid=200"` | Delete resources |
| Show State | `terraform show` | View current state |
| Refresh State | `terraform refresh` | Sync state with reality |

**Example Provisioning Command:**
```bash
terraform apply \
  -var="hostname=docker-vm-01" \
  -var="vmid=201" \
  -auto-approve
```

**Output:** IP address, VMID, MAC address assigned

### State Management Strategy

**Current Implementation:**

- State File: Local terraform.tfstate in working directory
- Locking: None (single operator environment)
- Backup: Automated weekly backups to Proxmox Backup Server and Synology NAS

---

## 3. Configuration Management with Ansible

### 3.1 Architecture Overview

Ansible provides agentless configuration management through SSH-based automation, enforcing consistent baselines across all Linux hosts, managing secrets securely, and orchestrating complex multi-host operations using declarative playbooks.

**Security Impact**

- Configuration drift eliminated through automated enforcement
- SSH hardening applied consistently across all managed hosts
- Credential exposure prevented through Ansible Vault encryption
- Audit trail established via Git‑based version control
- Manual errors eliminated through idempotent playbooks

**Deployment Rationale:** In enterprise environments with 30+ Linux hosts, manual configuration becomes error-prone and time-consuming. Ansible demonstrates infrastructure-as-code principles where security baselines (CIS Benchmarks) are codified, version-controlled, and automatically enforced. This approach reduces configuration time from hours to minutes while ensuring 100% consistency across systems—critical for maintaining security posture at scale.

**Architecture Principles Alignment**

- **Defense in Depth:** SSH hardening playbooks disable weak ciphers and enforce key-based auth; firewall rules deployed uniformly; fail2ban configured consistently across all systems
- **Secure by Design:** Ansible Vault encrypts sensitive variables; no plaintext credentials in playbooks; SSH keys distributed securely via initial bootstrap
- **Zero Trust:** Every configuration change logged to Git; no implicit trust of system state; playbooks verify current configuration before making changes

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

### SSH Key Architecture

- Key Type: ed25519 (modern, secure, performant)
- Key Location: /home/ansible/.ssh/id_ed25519
- Passphrase: Stored in Vaultwarden, loaded to ssh-agent
- Distribution: Public key deployed via cloud-init or initial playbook
- Rotation: Annual key rotation with documented rollover procedure

### Ansible User Configuration

The "ansible" service account is created on all managed hosts with these attributes:

- Username: ansible
- Shell: /bin/bash
- Groups: ansible, sudo (or wheel on RHEL)
- Sudo Access: NOPASSWD for all commands (required for automation)
- Home Directory: /home/ansible
- SSH AuthorizedKeys: Controller public key only

**Security Considerations:**

Sudo Without Password: Required for unattended automation. Mitigated by:

- ansible user cannot authenticate via password (PasswordAuthentication no)
- SSH key private key is passphrase-protected
- Access limited to Ansible controller IP via SSH config
- All actions logged via auditd and forwarded to Splunk

---

### 3.3 Playbook Architecture

#### Bootstrap Playbook (new_install.yaml)

**Diagram Placeholder: Ansible Bootstrap Playbook Screenshot**

**Purpose:** Initial host configuration to establish Ansible management capability.

**Execution:** Run once after Terraform provisions new host.

**What it does:**

- Updates the repositories, applies any software updates
- Creates the "ansible" user with a login shell and hashed password
- Ensures OpenSSH server is installed
- Backs up /etc/ssh/sshd_config and sets key options:
  - PermitRootLogin no
  - PasswordAuthentication no
  - PubkeyAuthentication yes
  - AuthorizedKeysFile .ssh/authorized_keys
  - PermitEmptyPasswords no
  - ChallengeResponseAuthentication no
  - UsePAM yes
- Restarts and enables the SSH service (service name differs by distro: "ssh" on Debian/Ubuntu, "sshd" on RHEL/CentOS)
- Creates /home/ansible/.ssh with strict permissions
- Adds the control node's public key to ansible's authorized_keys
- Installs sudo, ensures /etc/sudoers.d exists (0750), and drops a validated sudoers entry for "ansible" (via visudo -cf)
- Restart SSH only when the config changes (handler) to reduce risk during provisioning
- Configures the lab DNS nameservers in the resolv.conf file

### Additional Playbooks

**Hardening Playbook (security_baseline.yaml):**

- Configures firewall rules (ufw/firewalld)
- Installs fail2ban for brute force protection
- Enables automatic security updates
- Configures auditd for system logging
- Deploys CrowdSec agent for threat intelligence

**PKI Certificate Deployment (deploy_certificates.yaml):**

- Distributes Step-CA root certificate to trust store
- Configures automatic cert renewal via ACME client
- Updates TLS configurations for services

**User Management (manage_users.yaml):**

- Creates standard user accounts across hosts
- Deploys SSH keys from centralized source
- Configures user-specific sudo permissions

---

## 4. Version Control and GitOps

### Version Control Strategy

**Diagram Placeholder: GitHub Repository Screenshots (3 images)**

All infrastructure‑as‑code assets for this solution — including Ansible playbooks, Terraform configurations, and related modules — are stored in a dedicated GitHub repository using Git on the local host.

This [central repository](https://github.com/pnleone/Lab-Configs) provides:

- **Version history** — Every change is committed with a message on what changed, enabling full audit trails for infrastructure modifications
- **Consistency across environments** — Ansible roles and Terraform modules are version‑locked so the same codebase can be applied to multiple hosts
- **Rollback capability** — Previous commits can be checked out to restore infrastructure to a known good state quickly in case of issues

Configuration files for hosted and platform services — including YAML, JSON, HTML, CSS, Python, and PowerShell scripts — are stored in a separate repository. This repository is fully integrated with Visual Studio Code, allowing seamless local and remote (via SSH) integration editing.

By keeping both provisioning (Terraform) and configuration management (Ansible) in one repository, and separating hosted/platform service configs into another, the architecture ensures that each layer of the stack is versioned, auditable, and maintainable.

---

## 5. Workflow Automation with n8n

### 5.1 Platform Overview

n8n is a self-hosted, low-code workflow automation platform enabling visual workflow design with conditional logic, error handling, loops, and data transformation. Deployed as a containerized service behind Traefik reverse proxy with Authentik SSO.

**Security Impact**

- Security operations accelerated through automated SOAR workflows
- Manual triage eliminated via automated alert enrichment
- MTTR reduced through auto‑generated remediation playbooks
- Alert fatigue minimized through intelligent deduplication and correlation
- Compliance audit trails automatically documented throughout the incident lifecycle

**Deployment Rationale:** Security operations generate thousands of events daily, manual triage is unsustainable. n8n demonstrates Security Orchestration, Automation and Response (SOAR) capabilities where vulnerability scans trigger automated ticket creation, threat intelligence enrichment queries multiple APIs, and incident response playbooks execute without human intervention. This mirrors enterprise SOAR platforms (Splunk SOAR, Palo Alto Cortex XSOAR) where analyst efficiency is multiplied through automation.

**Architecture Principles Alignment**

- **Defense in Depth:** Automated vulnerability remediation workflows execute Ansible playbooks; firewall rule changes logged and reviewed; failed automation triggers manual fallback procedures
- **Secure by Design:** Credentials stored in n8n credential vault (encrypted at rest); webhook endpoints authenticated via Authentik tokens; workflow execution logs forwarded to SIEM
- **Zero Trust:** Every automation action logged with timestamp/user; no hardcoded credentials; API tokens expire and rotate automatically

### n8n Configuration

- Version: n8n v1.x (latest stable)
- Execution Mode: Main process (not queue mode for simplicity)
- Webhook URL: https://n8n.home.com
- TLS Certificate: Step-CA issued, auto-renewed
- Authentication: SSO via Authentik (no local passwords)
- Monitoring: Uptime Kuma
- Notifications: Discord webhooks

### Security Controls

- Credential Encryption: All API tokens encrypted at rest
- Webhook Security: HMAC signature validation on inbound webhooks
- Audit Trail: All workflow executions logged with timestamp and user

### Lab Use Cases

- Daily threat Intelligence Alerts
- Ansible Playbook automation

**Diagram Placeholder: n8n Dashboard Screenshot**

---

### 5.2 Workflow 1: Ansible Playbook Automation

**Purpose:** Automated weekly configuration audit and system updates across lab infrastructure.

This automated workflow runs two playbooks, a weekly schedule and performs a configuration audit across lab hosts and a Linux repository update and upgrade cycle. It collects key system metadata and securely publishes the results for review and alerting.

**Workflow Summary:**

- **Scheduled Execution**: Triggered weekly via n8n's Cron node
- **Ansible Playbook**:
  - Gathers hostnames, nameservers, SSH keys, and other configuration details across all Linux hosts
  - (sudo) apt update && apt upgrade -y / (sudo) dnf check-update && (sudo) dnf update -y
- **GitHub Upload**: Converts playbook output to a structured JSON file and commits it to the n8n-Ansible-playbook-results/ folder in the lab GitHub repository
- **Discord Alert**: Sends a formatted notification to a private Discord channel upon successful upload, including timestamp and file reference

### Workflow Nodes

| Node Type | Configuration | Purpose |
|-----------|---------------|---------|
| Schedule Trigger | Cron: 0 2 * * 6 (Saturday 2 AM) | Weekly execution |
| SSH Node 1 | Host: ansible-controller.home.com; Command: ansible-playbook config_audit.yml | Run audit playbook |
| SSH Node 2 | Host: ansible-controller.home.com; Command: ansible-playbook linux_updates.yml | Run update playbook |
| Function Node | Parse JSON output from playbooks | Extract results |
| HTTP Request | GitHub API: Create file in repo | Upload results JSON |
| Discord Webhook | Send formatted message | Alert on completion |
| Error Handler | Catch failures; send alert | Notify on errors |

**Diagram Placeholder: n8n Ansible Workflow Screenshot**

**Audit Playbook Output (JSON):**
```json
{
  "timestamp": "2024-11-06T02:00:00Z",
  "hosts_scanned": 25,
  "findings": {
    "ssh_keys": "All hosts have valid keys",
    "dns_config": "Correct nameservers on 23/25 hosts",
    "failed_updates": []
  }
}
```

**Update Playbook Execution:**

- Debian/Ubuntu: apt update && apt upgrade -y
- RHEL/Fedora: dnf check-update && dnf update -y
- Success Rate: Tracked in Discord notification
- Failed Updates: Logged for manual review

**Workflow Benefits:**

- Eliminates manual audit tasks (saves ~2 hours/week)
- Ensures timely security updates across all hosts
- Provides audit trail via GitHub commits
- Immediate notification of issues via Discord

**Diagram Placeholder: n8n Workflow Results Screenshots (2 images)**

---

### 5.3 Workflow 2: Threat Intelligence Aggregation

**Purpose:** Daily ingestion and distribution of curated cybersecurity threat intelligence.

This workflow runs daily to ingest and distribute curated threat intelligence from multiple cybersecurity RSS feeds. It supports situational awareness and IOC enrichment across the lab environment.

**Workflow Summary:**

- Scheduled Execution: Triggered daily via n8n's Cron node
- RSS Feed Polling: Pulls entries from a curated list of cybersecurity sources
- Feed Limiting: Filters each feed to the 5 most recent entries to reduce noise and maintain relevance
- Discord Notification: Formats and sends the aggregated feed summary to a dedicated Discord channel on the private lab server for daily review
- The NIST RSS feed is also fed through ChatGPT for a summary notification in Discord

### Workflow Nodes

| Node Type | Configuration | Purpose |
|-----------|---------------|---------|
| Schedule Trigger | Cron: 0 8 * * * (Daily 8 AM) | Daily execution |
| RSS Feed Reader | URLs: CISA Alerts; NIST NVD; Krebs on Security; Threat Post; BleepingComputer | Ingest threat intel |
| Filter Node | Limit each feed to 5 most recent | Reduce noise |
| Merge Node | Combine all feeds | Aggregate data |
| OpenAI Node | Summarize NIST feed with ChatGPT | AI-powered summary |
| Format Node | Create Discord embed message | Visual formatting |
| Discord Webhook | Post to #threat-intel channel | Distribute to team |

**Diagram Placeholder: n8n Threat Intel Workflow Screenshot**

**ChatGPT Integration:**

**Prompt:** "Summarize the following NIST vulnerability in 2-3 sentences suitable for a security team. Focus on severity, affected systems, and recommended actions: {{ $json.content }}"

**Response Example:** "CVE-2024-12345: Critical remote code execution vulnerability in Apache Log4j 2.x. Affects versions 2.0-2.17.0. Immediate patching recommended; workaround available via environment variable. CVSS 9.8/10."

**Workflow Benefits:**

- Centralized threat intelligence (15 sources → 1 channel)
- AI-powered summarization reduces information overload
- Daily cadence ensures timely awareness of emerging threats
- Supports incident response and vulnerability management

**Workflow Error Handling:**

- RSS Feed Timeout: Skip feed, log error, continue
- Discord Webhook Failure: Send email fallback alert
- All Errors: Logged to n8n execution history

**Diagram Placeholder: Discord Threat Intel Feed Screenshots (4 images)**

---

## 6. Scripting for Advanced Automation

### Script Development Strategy

Custom scripts supplement configuration management tools for tasks requiring complex logic, performance optimization, or specialized functionality. All scripts are version-controlled in Git, documented with inline comments, and integrated into broader automation workflows.

**Security Impact**

- Complex security operations automated where configuration‑management tools lack native functionality
- Performance‑critical tasks (log parsing, threat‑intelligence queries) optimized beyond built‑in tool capabilities
- Security tool APIs integrated through custom automation wrappers for expanded functionality
- Rapid prototyping enables validation of security concepts before production‑grade implementation

**Deployment Rationale:** While Ansible/Terraform handle declarative configuration, procedural logic (API rate-limiting, stateful workflows, real-time processing) requires traditional scripting. Enterprise environments use scripts for custom integrations, API gateways, and performance-critical operations. This demonstrates ability to select appropriate automation tools—declarative vs. imperative—based on task requirements.

**Architecture Principles Alignment**

- **Defense in Depth:** Scripts validate input parameters; error handling prevents cascading failures; execution logs audited for anomalies
- **Secure by Design:** No hardcoded credentials (environment variables or secret managers); input sanitization prevents injection attacks; least-privilege execution (non-root where possible)
- **Zero Trust:** Every script execution logged with user/timestamp; API calls authenticated via short-lived tokens; output validation before downstream processing

### Script Language Selection Criteria

| Language | Use Cases | Advantages |
|----------|-----------|------------|
| Bash | Linux system administration; cron jobs | Native; fast; no dependencies |
| PowerShell | Windows management; AD operations | Deep Windows integration; objects |
| Python | API integration; data processing; ML | Rich libraries; cross-platform |

---

### 6.1 PowerShell & Bash Scripting

Custom automation scripts are developed in both PowerShell (for Windows systems) and Bash (for Linux systems) to handle repetitive administrative tasks, enforce configuration standards, and respond to system events. These scripts automate activities such as user account provisioning, log rotation, backup verification, certificate renewal checks, and security baseline enforcement. PowerShell scripts leverage native Windows management frameworks like Active Directory modules and WMI, while Bash scripts utilize standard Unix utilities and interact with system APIs. Scripts are version-controlled in GitHub alongside infrastructure code, enabling rollback capability and documentation of automation logic.

#### Bash Script Example: Backup Automation

**Diagram Placeholder: Bash Backup Script Screenshot**

This Bash script is designed to perform a backup using rsync, with versioned backups stored by date. It validates input, checks for dependencies, and logs the simulated operation.

**Script:** /usr/local/bin/backup_web.sh

**Purpose:** Incremental rsync backup with versioning and logging

| Line(s) | Purpose | Explanation |
|---------|---------|-------------|
| #!/bin/bash | Script interpreter | Ensures the script runs using Bash |
| if [ $# -ne 2 ] | Argument check | Verifies that exactly two arguments are provided |
| echo "Usage:..." | Usage message | Informs the user of correct syntax if arguments are missing |
| exit 1 | Exit on error | Terminates with exit code 1 for incorrect usage |
| command -v rsync | Dependency check | Verifies that rsync is installed and available in $PATH |
| exit 2 | Exit on missing dependency | Terminates with exit code 2 if rsync is not found |
| current_date=$(date +%Y-%m-%d) | Timestamp | Captures the current date in YYYY-MM-DD format for versioning |
| rsync_options=... | Backup options | Sets rsync flags: -a: archive mode; -v: verbose; -b: backup files; --backup-dir: dated subdirectory; --delete: remove obsolete files; --dry-run: simulate |
| $(which rsync) ... | Execute rsync | Runs rsync with defined options, syncing from $1 to $2/current |
| >> /var/log/backup_$current_date.log | Logging | Appends output to a date-stamped log file for auditability |

#### Linux Upgrade Script Overview

**Diagram Placeholder: Linux Upgrade Script Screenshots (2 images)**

This Bash script performs a distribution-aware system upgrade, logging all output and errors to dedicated log files. It supports Debian/Ubuntu, Fedora, CentOS, and RHEL, and includes error checking after each upgrade step.

| Line(s) | Purpose | Explanation |
|---------|---------|-------------|
| #!/bin/bash | Interpreter declaration | Ensures the script runs with Bash |
| logfile=/var/log/update_script.log; errorlog=/var/log/update_script_errors.log | Log file setup | Defines paths for standard output and error logs |
| echo "START SCRIPT" | Start marker | Logs the beginning of the script execution |
| check_exit_status() | Error handler | Function that checks the last command's exit code and prints an error message if non-zero |
| if [ -d /etc/apt ]; then | Distro detection | Checks for Debian/Ubuntu by presence of APT directory |
| apt update; apt dist-upgrade -y | Debian/Ubuntu upgrade | Runs update and full upgrade, logs output and errors |
| elif [ -f /etc/redhat-release ]; then | Red Hat-based detection | Checks for Fedora, CentOS, or RHEL using release file |
| cat /etc/redhat-release | Distro name | Reads the release file to identify the specific variant |
| dnf upgrade --refresh -y | Fedora upgrade | Refreshes metadata and upgrades packages |
| yum update -y | CentOS/RHEL upgrade | Performs system update using yum |
| echo "Unsupported distro" | Fallback | Handles unknown or unsupported systems |
| echo "Script completed at: $(date)" | Completion timestamp | Logs the end time of the script |
| echo "END SCRIPT" | End marker | Logs the conclusion of the script execution |

#### PowerShell Script Example: Windows Update Automation

**Diagram Placeholder: PowerShell Update Script Screenshots (2 images)**

This script performs a comprehensive update sweep across a Windows system, covering:

- Windows Store apps
- Chocolatey packages
- Winget packages
- Windows OS updates

It logs all output to a transcript file and timestamps each operation for auditability and runtime tracking.

**Script:** C:\Scripts\Update-System.ps1

**Purpose:** Comprehensive Windows update across multiple package managers

| Line(s) | Purpose | Explanation |
|---------|---------|-------------|
| $ErrorActionPreference = "Continue" | Error handling | Ensures the script continues execution even if a command fails |
| $logPath = "C:\Logs\update_log.txt" | Log file path | Defines where the transcript will be saved |
| Start-Transcript -Path $logPath -Append | Start logging | Begins capturing all console output to the log file |
| function Write-Timestamped { ... } | Timestamp helper | Prints messages with a timestamp prefix for clarity and tracking |
| function Update-WindowsStoreApps { ... } | Windows Store updates | Uses CIM to trigger an update scan for Store apps via MDM interface |
| Update-WindowsStoreApps | Execute function | Runs the Store app update function |
| function Update-ChocoApps { ... } | Chocolatey updates | Checks if choco is installed, then upgrades all packages with -y. Logs start, completion, or skip |
| Update-ChocoApps | Execute function | Runs the Chocolatey update function |
| function Update-WingetApps { ... } | Winget updates | Checks if winget is installed, then upgrades all packages. Logs start, completion, or skip |
| Update-WingetApps | Execute function | Runs the Winget update function |
| Import-Module PSWindowsUpdate | OS update module | Loads the PSWindowsUpdate module for managing Windows updates |
| Install-WindowsUpdate -MicrosoftUpdate -AcceptAll | OS updates | Installs all available Microsoft updates silently |
| Stop-Transcript | End logging | Stops the transcript and finalizes the log file |

---

### 6.2 Cron Job Scheduling Strategy

Cron is used extensively across Linux systems to schedule automated tasks at defined intervals, ensuring that maintenance activities, monitoring checks, and data collection occur reliably without manual intervention. Typical cron jobs include nightly backup verification scripts, hourly certificate expiration checks, daily vulnerability scan initiation, periodic log archival and rotation, and regular system health assessments. Cron jobs are documented with inline comments explaining purpose, frequency, and dependencies, and critical jobs send success/failure notifications to the centralized Discord alerting system to ensure failures are promptly identified and addressed.

**Webserver Crontab**

| Minute | Hour | Day | Month | Weekday | Command | Description | Last Run Timestamp |
|--------|------|-----|-------|---------|---------|-------------|-------------------|
| 0 | 2 | * | * | 5 | /usr/local/bin/upgrade.sh | Weekly system upgrade | Fri, Nov 1, 2025 02:00 AM |
| 30 | 1 | * | * | 6 | /usr/local/bin/backup_web.sh /var/www/lab /backup | Weekly web backup via rsync | Sat, Nov 2, 2025 01:30 AM |

- The first job runs every Friday at 2:00 AM and executes upgrade.sh with no arguments
- The second job runs every Saturday at 1:30 AM and executes backup_web.sh with two arguments: /var/www/lab (Source directory) and /backup (Target directory)

---

### 6.3 Python Scripting for Advanced Automation

Python scripts are deployed where more complex logic, data processing, or API interaction is required. Python's extensive library ecosystem makes it ideal for tasks like parsing and correlating log data, interacting with REST APIs for service configuration, processing vulnerability scan results, generating custom reports from multiple data sources, and implementing custom security tools. Python's cross-platform nature allows scripts to run consistently across Windows and Linux systems, and virtual environments ensure dependency isolation and reproducibility.

#### Python Script Example: Network Scanner

**Diagram Placeholder: Python Network Scanner Script Screenshots (2 images)**

A custom Python-based network scanner has been developed to provide tailored reconnaissance capabilities specific to the lab environment. The scanner performs several functions:

- **Host Reachability Testing** — Pings target hosts before attempting port scans to verify they are online, reducing wasted scan time and providing quick network inventory validation
- **Port Scanning** — Uses multi-threaded socket connections to rapidly identify open TCP ports across the full port range (1-65535) or targeted subsets based on scan objectives
- **Service Identification** — Labels discovered open ports using a custom service mapping file (common_ports.txt) that includes both standard services (SSH, HTTP, HTTPS) and lab-specific applications (Proxmox, Traefik, Authentik). This makes scan results immediately actionable by identifying what application is likely running on each open port

---

### 6.4 Script Integration & Orchestration

Scripts are integrated into broader workflows through several mechanisms. Some scripts are triggered directly by cron jobs for time-based execution. Others are called by monitoring systems in response to alerts or threshold violations (for example, a Grafana alert triggering a remediation script). Ansible playbooks orchestrate multi-step automation by calling shell scripts and Python utilities in sequence, passing parameters and handling error conditions. This layered approach combines the flexibility of custom scripts with the orchestration capabilities of configuration management tools, enabling sophisticated automation scenarios while maintaining maintainability and reusability.

---

## 7. Automation Security Controls

### Control Framework

| Control Domain | Implementation | Coverage |
|----------------|----------------|----------|
| Secrets Management | Ansible Vault + Vaultwarden | All credentials encrypted |
| Access Control | SSH keys only; sudo with NOPASSWD | Ansible service account |
| Code Integrity | Git version control with commit signing | All IaC assets |
| Privilege Escalation | Least privilege Proxmox service account | Terraform API access |
| Input Validation | Regex validation in scripts | Prevents injection attacks |
| Audit Logging | Syslog + Git commits + n8n execution logs | Full audit trail |
| Change Management | Git | Controlled deployments |
| Backup & Recovery | GitHub + NAS + PBS | Multiple restore points |

### Authentication & Authorization

| Technology | Authentication Method | Authorization Scope |
|------------|----------------------|---------------------|
| Terraform | Proxmox API token (non-password) | VM/LXC provisioning only |
| Ansible | SSH key (ed25519; passphrase) | sudo NOPASSWD on managed hosts |
| n8n | Authentik SSO (OAuth2) | Workflow admin access |
| GitHub | Personal access token (PAT) | Repository push/pull |
| Scripts | User context (ansible/root) | File system and service control |

### Secrets Protection

| Secret Type | Storage Location | Encryption Method |
|-------------|------------------|-------------------|
| Terraform API tokens | terraform.tfvars (gitignored) | File permissions 0600 |
| Ansible passwords | ansible-vault encrypted files | AES-256 with master key |
| n8n credentials | Vaultwarden database | Application-level encryption |
| SSH private keys | ~/.ssh/ with 0600 perms | Passphrase-protected |
| Script API tokens | Environment variables | Not persisted to disk |

### Audit Trail Components

| Event Type | Logging Mechanism | Retention |
|------------|-------------------|-----------|
| Git Commits | GitHub repository | Indefinite |
| Terraform Apply | Local state file + stdout log | 90 days |
| Ansible Playbook Runs | Ansible log + syslog | 90 days |
| n8n Workflow Executions | PostgreSQL + execution history | 30 days |
| Script Executions | Syslog + individual log files | 30 days |
| Cron Job Runs | /var/log/cron + job-specific logs | 30 days |

---

## 9. Practical Use Cases and Workflows

### Scenario 1: New VM Provisioning

**Objective:** Deploy new Docker host in <5 minutes

**Workflow:**

- Developer updates Terraform variables:
  - hostname: docker-vm-03
  - vmid: 203
- Run Terraform:
  - cd terraform/vm
  - terraform apply -var="hostname=docker-vm-03" -var="vmid=203" -auto-approve
- Terraform clones ubuntu-cloud template, provisions VM
- Output displays IP address: 192.168.100.203
- Run Ansible bootstrap:
  - ansible-playbook -i hosts.yml new_install.yaml --limit docker-vm-03.home.com
- Ansible configures SSH, creates ansible user, installs packages
- VM ready for application deployment

**Result:** Consistent, reproducible VM provisioning with full audit trail

---

### Scenario 2: Weekly Security Update Cycle

**Objective:** Keep all systems patched without manual intervention

**Workflow:**

- Saturday 2 AM: n8n workflow triggers
- n8n executes SSH command on Ansible controller
- Ansible playbook runs across all Linux hosts:
  - Debian/Ubuntu: apt update && apt upgrade -y
  - RHEL/Fedora: dnf update -y
- Playbook output converted to JSON
- JSON uploaded to GitHub (audit trail)
- Discord notification sent with summary:
  - 23/25 hosts updated successfully
  - 2 hosts require reboot
- Admin reviews notification and schedules reboots if needed

**Result:** Automated patch management with centralized reporting and alerting

---

### Scenario 3: Rapid Disaster Recovery

**Objective:** Rebuild compromised VM from code

**Workflow:**

- Incident detected: VM compromised via vulnerability
- Admin destroys compromised VM:
  - terraform destroy -var="vmid=205"
- Review Git history to find last known-good configuration:
  - git log terraform/vm/main.tf
- Checkout previous commit if needed:
  - git checkout abc123def terraform/vm/main.tf
- Rebuild VM with Terraform:
  - terraform apply -var="hostname=web-vm-01" -var="vmid=205"
- Re-run Ansible playbooks to restore configuration:
  - ansible-playbook -i hosts.yml site.yml --limit web-vm-01.home.com
- Restore application data from NAS backup
- VM back online with clean configuration

**Result:** Complete rebuild in <30 minutes vs. hours of manual work

---

### Scenario 4: Threat Intelligence Distribution

**Objective:** Daily security awareness for lab operations

**Workflow:**

- Daily 8 AM: n8n workflow executes
- RSS feeds polled from multiple cybersecurity sources
- Each feed limited to 5 most recent entries
- NIST feed sent to ChatGPT for AI summarization
- Aggregated digest posted to Discord #threat-intel channel

**Result:** Consolidated threat intelligence reduces information overload

---

### Scenario 5: Configuration Drift Detection

**Objective:** Ensure compliance with security baseline

**Workflow:**

- Weekly: n8n triggers Ansible audit playbook
- Playbook gathers configuration from all hosts:
  - SSH config settings
  - Firewall rules
  - Installed packages
  - User accounts
  - DNS configuration
- Output compared against baseline in Git
- Drift detected on 2 hosts (unauthorized package installed)
- Discord alert sent with details

**Result:** Proactive detection of configuration drift and unauthorized changes

---

## 10. Standards Alignment

### Automation and DevOps Standards

### Industry Framework Alignment

| Framework/Standard | Alignment | Implementation Evidence |
|--------------------|-----------|------------------------|
| Infrastructure as Code (IaC) | High | Terraform for all infrastructure |
| GitOps Principles | Moderate | Git as source of truth; automated workflows |
| CIS Controls v8 | High | Control 4.1 (Config management) |
| NIST SP 800-53 (CM-2) | High | Configuration baseline enforcement |
| 12-Factor App Methodology | Moderate | Config externalization; stateless processes |
| ISO 27001 (A.12.1) | Moderate | Documented operational procedures |

### CIS Controls Implementation

| Control | Description | Implementation |
|---------|-------------|----------------|
| 4.1 | Establish config management | Terraform + Ansible baseline |
| 4.2 | Enforce config standards | Ansible playbooks validate compliance |
| 4.3 | Document configuration | Git commits; inline YAML comments |
| 4.4 | Perform config change control | Git branches; PR workflow |
| 4.7 | Manage default accounts | Ansible removes/disables defaults |
| 4.8 | Uninstall unauthorized software | Ansible package management playbooks |

### NIST SP 800-53 Configuration Management

| Control | Requirement | Lab Implementation |
|---------|-------------|-------------------|
| CM-2 | Baseline configuration | Ansible playbooks define baseline |
| CM-3 | Configuration change control | Git version control; commit messages |
| CM-5 | Access restrictions | GitHub repo private; SSH key auth |
| CM-6 | Configuration settings | Documented in Ansible vars |
| CM-7 | Least functionality | Ansible removes unnecessary packages |
| CM-8 | System component inventory | Terraform state; Ansible facts |

---

## 11. Security Homelab Section Links

- **[Executive Summary and Security Posture](/Career_Projects/projects/homelab/01-exec-summary/)**
- **[Infrastructure Platform, Virtualization Stack and Hardware](/Career_Projects/projects/homelab/02-platform/)** 
- **[Network Security, Privacy and Remote Access](/Career_Projects/projects/homelab/03-network/)** 
- **[Identity, Access, Secrets and Trust Management](/Career_Projects/projects/homelab/04-iam-secrets/)** 
- **[Automation and IaC](/Career_Projects/projects/homelab/05-auto-iac/)**
- **[Applications and Services](/Career_Projects/projects/homelab/06-apps-service/)**
- **[Observability and Response, Part 1](/Career_Projects/projects/homelab/07-vis-response-pt1/)**
- **[Observability and Response, Part 2](/Career_Projects/projects/homelab/07-vis-response-pt2/)**

---

**Document Version:** 1.0  
**Last Updated:** January 24, 2026  


---

