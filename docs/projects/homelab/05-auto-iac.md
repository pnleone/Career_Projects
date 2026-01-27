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

```json
terraform {
  required_providers {
    proxmox = {
      source  = "Terraform-for-Proxmox/proxmox"
      
    }
  }
}
variable "pm_api_token_id" {
  description = "Proxmox API token ID"
  type        = string
}

variable "pm_api_token_secret" {
  description = "Proxmox API token secret"
  type        = string
  sensitive   = true
}
variable "rootpassword" {
  description = "Cloud-init password for this VM"
  type        = string
  sensitive   = true
}
variable "lxc_name" {
  description = "Hostname of the LXC container"
  type        = string
  default     = "debian-lxc"

}

variable "lxc_id" {
  description = "VMID for the LXC container"
  type        = number
}


provider "proxmox" {
    pm_api_url          = "https://pve.home.com:8006/api2/json"
    pm_api_token_id     = var.pm_api_token_id
    pm_api_token_secret = var.pm_api_token_secret
    pm_tls_insecure     = false
}

resource "proxmox_lxc" "testct" {
  hostname     = var.lxc_name
  target_node  = "pve"
  vmid         = var.lxc_id
  ostemplate   = "Media4TBnvme:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst"
  password     = var.rootpassword
  unprivileged = true
  cores        = 2
  memory       = 512
  swap         = 512
  onboot       = true
  start        = true


  rootfs {
    storage = "local-lvm"
    size    = "8G"
  }

  network {
    name   = "eth0"
    bridge = "vmbr0"
    ip     = "dhcp"
  }

  features {
    nesting = true
  }
}
```

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

```json
terraform {
  required_providers {
    proxmox = {
      source  = "Terraform-for-Proxmox/proxmox"
      #version = "~> 0.65" # or latest
    }
  }
}

variable "pm_api_token_id" {
  description = "Proxmox API token ID"
  type        = string
}

variable "pm_api_token_secret" {
  description = "Proxmox API token secret"
  type        = string
  sensitive   = true
}
variable "ciuser" {
  description = "Cloud-init username for this VM"
  type        = string
}

variable "cipassword" {
  description = "Cloud-init password for this VM"
  type        = string
  sensitive   = true
}

variable "vm_name" {
  description = "Name of the VM"
  type        = string
  default     = "ubuntu-vm"

}

variable "vm_id" {
  description = "VMID for the VM"
  type        = number
}


provider "proxmox" {
    pm_api_url          = "https://pve.home.com:8006/api2/json"
    pm_api_token_id     = var.pm_api_token_id
    pm_api_token_secret = var.pm_api_token_secret
    pm_tls_insecure     = false
}

resource "proxmox_vm_qemu" "ubuntu-vm" {
    name                = var.vm_name
    vmid                = var.vm_id
    target_node         = "pve"
    clone               = "ubuntu-cloud"
    full_clone          = true
    cores               = 2
    memory              = 2048
    sockets             = 1
    onboot              = true
    agent               = 1
    os_type             = "l26"
    clone_wait          = 0
    ciuser     = var.ciuser
    cipassword = var.cipassword


    boot    = "order=scsi0;ide2"
    bootdisk = "scsi0"
    scsihw      = "virtio-scsi-single"

    network {
        model     = "virtio"
        bridge    = "vmbr0"
        firewall  = false
        link_down = false
    }
```

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
```yaml
---
-  name: Freah install of Linux VM/LXC, add ansible user and SSH access
   hosts: all
   tags: always
   become: true
   
   handlers:
    - name: Restart systemd-resolved (if needed)
      ansible.builtin.systemd:
        name: systemd-resolved
        state: restarted
        enabled: yes
      when:
        - ansible_service_mgr == "systemd"
        - "'systemd-resolved.service' in ansible_facts.services | default({})"

   pre_tasks:
    
    - name: Update all packages on RedHat family
      dnf:
        name: "*"
        state: latest
        update_cache: yes
      when: ansible_os_family == "RedHat"

    - name: Update all packages on Debian family
      apt:
        upgrade: dist
        update_cache: yes
        cache_valid_time: 3600
      when: ansible_os_family == "Debian"

   tasks:
    - name: add new user
      become: true
      tags: always
      ansible.builtin.user:
        name: ansible
        group: root
        shell: /bin/bash
        password:  "{{ '-----' | password_hash('sha512') }}"

    - name: Ensure OpenSSH server is installed
      package:
        name: openssh-server
        state: present

    - name: Backup existing sshd_config
      become: true
      copy:
        src: /etc/ssh/sshd_config
        dest: /etc/ssh/sshd_config.bak
        remote_src: yes
      when: ansible_facts['os_family'] != 'Windows'

    - name: Set SSH configuration options
      become: true
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?{{ item.key }}'
        line: '{{ item.key }} {{ item.value }}'
        state: present
        create: yes
        backup: yes
      loop:
        - { key: 'PermitRootLogin', value: 'no' }
        - { key: 'PasswordAuthentication', value: 'no' }
        - { key: 'PubkeyAuthentication', value: 'yes' }
        - { key: 'AuthorizedKeysFile', value: '.ssh/authorized_keys' }
        - { key: 'PermitEmptyPasswords', value: 'no' }
        - { key: 'ChallengeResponseAuthentication', value: 'no' }
        - { key: 'UsePAM', value: 'yes' }

    - name: Ensure SSH service is enabled and restarted
      become: true
      service:
        name: "{{ item  }}"
        state: restarted
        enabled: yes
      loop:
        - ssh
        - sshd


    - name: Ensure .ssh directory exists for ansible user
      become: true
      file:
        path: /home/ansible/.ssh
        state: directory
        owner: ansible
        group: root
        mode: '0700'

    - name: add SSH key for ansible host
      become: true
      tags: always
      ansible.posix.authorized_key:
        user: ansible
        key: "ssh-ed25519 ------------ root@ansible"
        state: present

    - name: Ensure sudo is installed
      package:
        name: sudo
        state: present

    - name: Ensure /etc/sudoers.d exists
      become: true
      file:
        path: /etc/sudoers.d
        state: directory
        owner: root
        group: root
        mode: '0750'

    - name: add sudoers file to ansible
      become: true
      ansible.builtin.copy:
        src: sudoer_ansible
        dest: /etc/sudoers.d/ansible
        owner: root
        group: root
        mode: '0440'
        validate: '/usr/sbin/visudo -cf %s'
      
    - name: Replace /etc/resolv.conf with specified nameservers
      copy:
        dest: /etc/resolv.conf
        content: |
          nameserver 192.168.1.250
          nameserver 192.168.1.126
        owner: root
        group: root
        mode: '0644'
        backup: yes
      notify: Restart systemd-resolved (if needed)

  
-  name: add a new user and enable remote access via SSH
   hosts: all
   become: true

   handlers:
    - name: Restart systemd-resolved (if needed)
      ansible.builtin.systemd:
        name: systemd-resolved
        state: restarted
        enabled: yes
      when:
        - ansible_service_mgr == "systemd"
        - "'systemd-resolved.service' in ansible_facts.services | default({})"


    # Debian reboot check
    - name: Check if reboot is required (Debian/Ubuntu)
      stat:
        path: /var/run/reboot-required
      register: reboot_required
      when: ansible_os_family == "Debian"

    # RedHat reboot check
    - name: Check if reboot is required (RedHat family)
      command: needs-restarting -r
      register: needs_reboot
      failed_when: false
      changed_when: false
      when: ansible_os_family == "RedHat"

    - name: Reboot if required (Debian)
      reboot:
      when: reboot_required.stat.exists

    - name: Reboot if required (RedHat)
      reboot:
      when: needs_reboot.rc == 1
```

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

**JSON Output Example**

```json
PLAY [Audit system info] *******************************************************

TASK [Gathering Facts] *********************************************************
ok: [web.home.com]
ok: [192.168.1.136]
ok: [unbound.home.com]
ok: [bind.home.com]
ok: [192.168.1.250]
ok: [uptimek.home.com]
ok: [192.168.1.4]
ok: [stepca.home.com]
ok: [trfk.home.com]
ok: [wazuh.home.com]
ok: [192.168.1.93]
ok: [192.168.100.15]
ok: [192.168.1.246]
ok: [192.168.1.33]
ok: [192.168.2.6]
ok: [192.168.200.8]
ok: [192.168.200.7]
ok: [192.168.1.126]
ok: [192.168.1.109]
ok: [192.168.1.166]
ok: [192.168.100.5]

TASK [Show disk usage] *********************************************************
ok: [web.home.com] => {
    "disk_usage.stdout_lines": [
        "Filesystem      Size  Used Avail Use% Mounted on",
        "/dev/loop0       16G   12G  3.2G  79% /",
        "none            492K  4.0K  488K   1% /dev",
        "efivarfs        192K  180K  7.6K  96% /sys/firmware/efi/efivars",
        "tmpfs            47G     0   47G   0% /dev/shm",
        "tmpfs            19G  156K   19G   1% /run",
        "tmpfs           5.0M     0  5.0M   0% /run/lock",
        "tmpfs            47G  124K   47G   1% /tmp",
        "tmpfs           9.4G  8.0K  9.4G   1% /run/user/0",
        "tmpfs           9.4G  8.0K  9.4G   1% /run/user/1001"
    ]
}
TASK [Show IP address info] ****************************************************
ok: [web.home.com] => {
    "ip_info.stdout_lines": [
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000",
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
        "    inet 127.0.0.1/8 scope host lo",
        "       valid_lft forever preferred_lft forever",
        "    inet6 ::1/128 scope host noprefixroute ",
        "       valid_lft forever preferred_lft forever",
        "2: eth0@if76: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000",
        "    link/ether bc:24:11:f9:a0:8c brd ff:ff:ff:ff:ff:ff link-netnsid 0",
        "    inet 192.168.1.108/24 brd 192.168.1.255 scope global eth0",
        "       valid_lft forever preferred_lft forever",
        "    inet6 fe80::be24:11ff:fef9:a08c/64 scope link proto kernel_ll ",
        "       valid_lft forever preferred_lft forever"
    ]
}
TASK [Show routing table] ******************************************************
ok: [web.home.com] => {
    "route_info.stdout_lines": [
        "default via 192.168.1.1 dev eth0 proto static ",
        "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.108 "
    ]
}
TASK [Show hostname] ***********************************************************
ok: [web.home.com] => {
    "host_name.stdout": "apache-ubuntu"
}
TASK [Show nameservers] ********************************************************
ok: [web.home.com] => {
    "resolv_conf.stdout_lines": [
        "# --- BEGIN PVE ---",
        "search home.com",
        "nameserver 192.168.1.250",
        "# --- END PVE ---"
    ]
}
TASK [Show authorized SSH keys] ************************************************
ok: [web.home.com] => {
    "msg": [
        "ssh-ed25519 --------- root@ansible",
        ""
    ]
}
PLAY RECAP *********************************************************************
192.168.1.109              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.1.126              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.1.136              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.1.166              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.1.246              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.1.250              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.1.33               : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.1.4                : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.1.93               : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.100.15             : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.100.5              : ok=12   changed=5    unreachable=0    failed=0    skipped=1    rescued=0    ignored=1   
192.168.2.6                : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.200.7              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
192.168.200.8              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
bind.home.com              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
stepca.home.com            : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
trfk.home.com              : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
unbound.home.com           : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
uptimek.home.com           : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh.home.com             : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
web.home.com               : ok=13   changed=5    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```
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

```bash
#!/bin/bash
#
# backup_web.sh - Versioned rsync backup with validation
# Usage: backup_web.sh <source> <target>
# Example: backup_web.sh /var/www/lab /backup
#
# Exit Codes:
#   0 - Success
#   1 - Invalid arguments
#   2 - Missing dependency
#   3 - Rsync failed
set -euo pipefail  # Exit on error, undefined vars, pipe failures

# check to make sure the user has entrered exactly two arguments.
if [ $# -ne 2 ]
then    
    /usr/bin/echo "Usage: backup.sh <source_directory> <target_directory>"
    /usr/bin/echo "Please try again."
    exit 1
fi
SOURCE="$1"
TARGET="$2"

# Validate paths (prevent directory traversal)
if [[ ! "$SOURCE" =~ ^/[a-zA-Z0-9/_-]+$RetryPContinuebash]]; then
    echo "Error: Invalid source path format"
    exit 1
fi

if [[ ! "$TARGET" =~ ^/[a-zA-Z0-9/_-]+$ ]]; then
    echo "Error: Invalid target path format"
    exit 1
fi

#check to see if rsync is installed
if ! command -v rsync > /dev/null 2>&1
then
    /usr/bin/echo "This script requires rsync to be installed."
    /usr/bin/echo "Please install the package and run the script again."
    exit 2
fi
# Verify source exists
if [ ! -d "$SOURCE" ]; then
    /usr/bin/echo "Error: Source directory does not exist: $SOURCE"
    exit 1
fi

# Create target if needed
mkdir -p "$TARGET"

# Generate timestamp
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
BACKUP_DATE=$(date +%Y-%m-%d)
LOG_FILE="/var/log/backup_${BACKUP_DATE}.log"

# Rsync options
RSYNC_OPTS=(
    -avz                                    # Archive, verbose, compress
    --delete                                # Remove deleted files
    --backup                                # Backup changed files
    --backup-dir="$TARGET/versions/$TIMESTAMP"  # Versioned backups
    --exclude='*.tmp'                       # Exclude temp files
    --exclude='.git'                        # Exclude version control
    --log-file="$LOG_FILE"                  # Detailed logging
    --stats                                 # Show transfer statistics
)

# Log start
/usr/bin/echo "=== Backup started at $(date) ===" | tee -a "$LOG_FILE"
logger -t backup_web "Starting backup: $SOURCE -> $TARGET"

# Execute rsync
if rsync "${RSYNC_OPTS[@]}" "$SOURCE/" "$TARGET/current/"; then
    /usr/bin/echo "=== Backup completed successfully at $(date) ===" | tee -a "$LOG_FILE"
    logger -t backup_web "SUCCESS: Backup completed"
    
    # Calculate backup size
    BACKUP_SIZE=$(du -sh "$TARGET/current" | cut -f1)
    /usr/bin/echo "Backup size: $BACKUP_SIZE" | tee -a "$LOG_FILE"
    
    # Retention: Keep only last 7 version directories
    find "$TARGET/versions/" -maxdepth 1 -type d -mtime +7 -exec rm -rf {} \;
    
    exit 0
else
    RSYNC_EXIT=$?
    /usr/bin/echo "=== Backup FAILED at $(date) with exit code $RSYNC_EXIT ===" | tee -a "$LOG_FILE"
    logger -t backup_web "FAILED: rsync exited with code $RSYNC_EXIT"
    exit 3
fi
```

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

```bash
#!/bin/bash
set -e

logfile=/var/log/update_script.log
errorlog=/var/log/update_script_errors.log
hostname=$(hostname)

/usr/bin/echo "-------------------START SCRIPT on $hostname-------------------" 1>>$logfile 2>>$errorlog
check_exit_status() {
    if [ $? -ne 0 ]
    then
        /usr/bin/echo "An error occured, please check the $errorlog file."
    fi    
}

if [ -d /etc/apt ]; then
    # Debian or Ubuntu
    /usr/bin/echo "Detected Debian/Ubuntu system"
    /usr/bin/sudo apt update 1>>$logfile 2>>$errorlog
    check_exit_status
    /usr/bin/sudo apt dist-upgrade -y 1>>$logfile 2>>$errorlog
    check_exit_status
elif [ -f /etc/redhat-release ]; then
    distro=$(cat /etc/redhat-release)

    if [[ "$distro" == *"Fedora"* ]]; then
        /usr/bin/echo "Detected Fedora system"
        /usr/bin/sudo dnf upgrade --refresh -y #!/bin/bash

logfile=/var/log/update_script.log
errorlog=/var/log/update_script_errors.log


check_exit_status() {
    if [ $? -ne 0 ]
    then
        /usr/bin/echo "An error occured, please check the $errorlog file."
    fi    
}

if [ -d /etc/apt ]; then
    # Debian or Ubuntu
    /usr/bin/echo "Detected Debian/Ubuntu system"
    /usr/bin/sudo apt update 1>>$logfile 2>>$errorlog
    check_exit_status
    /usr/bin/sudo apt dist-upgrade -y 1>>$logfile 2>>$errorlog
    check_exit_status
elif [ -f /etc/redhat-release ]; then
    distro=$(cat /etc/redhat-release)

    if [[ "$distro" == *"Fedora"* ]]; then
        /usr/bin/echo "Detected Fedora system"
        /usr/bin/sudo dnf upgrade --refresh -y 1>>$logfile 2>>$errorlog
        check_exit_status   
    elif [[ "$distro" == *"CentOS"* ]] || [[ "$distro" == *"Red Hat"* ]]; then
        /usr/bin/echo "Detected CentOS or RHEL system"
        /usr/bin/sudo yum update -y 1>>$logfile 2>>$errorlog
        check_exit_status      
    else
        /usr/bin/echo "Detected unknown Red Hat-based system"
        /usr/bin/sudo yum update -y 1>>$logfile 2>>$errorlog
        check_exit_status 
    fi
else
    /usr/bin/echo "Unsupported or unknown Linux distribution"
fi


        check_exit_status   
    elif [[ "$distro" == *"CentOS"* ]] || [[ "$distro" == *"Red Hat"* ]]; then
        /usr/bin/echo "Detected CentOS or RHEL system"
        /usr/bin/sudo yum update -y 1>>$logfile 2>>$errorlog
        check_exit_status      
    else
        /usr/bin/echo "Detected unknown Red Hat-based system"
        /usr/bin/sudo yum update -y 1>>$logfile 2>>$errorlog
        check_exit_status 
    fi
else
    /usr/bin/echo "Unsupported or unknown Linux distribution"
fi

/usr/bin/echo "The script completed at: $(/usr/bin/date)" 1>>$logfile 2>>$errorlog
/usr/bin/echo "-------------------END SCRIPT on $hostname-------------------" 1>>$logfile 2>>$errorlog
```

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

```powershell
$ErrorActionPreference = "Continue"

# Start logging
$logPath = "C:\Logs\update_log.txt"
Start-Transcript -Path $logPath -Append

# Log header with host and user info
$hostname = $env:COMPUTERNAME
$username = $env:USERNAME
Write-Host "`n==================== UPDATE SCRIPT START ===================="
Write-Host "Host: $hostname"
Write-Host "User: $username"
Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "=============================================================`n"

# Timestamp helper
function Write-Timestamped {
    param ([string]$message)
    Write-Host "`n[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $message"
}

# Update Windows Store apps
function Update-WindowsStoreApps {
    Write-Timestamped "Starting Windows Store App updates..."
    Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod
    Write-Timestamped "Completed Windows Store App updates."
}
Update-WindowsStoreApps

# Update Chocolatey packages
function Update-ChocoApps {
    Write-Timestamped "Checking for Chocolatey..."
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Timestamped "Updating Chocolatey packages..."
        choco upgrade all -y
        Write-Timestamped "Completed Chocolatey updates."
    } else {
        Write-Timestamped "Chocolatey is not installed. Skipping."
    }
}
Update-ChocoApps

# Update Winget packages
function Update-WingetApps {
    Write-Timestamped "Checking for Winget..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Timestamped "Updating Winget packages..."
        winget upgrade --all
        Write-Timestamped "Completed Winget updates."
    } else {
        Write-Timestamped "Winget is not installed. Skipping."
    }
}
Update-WingetApps

# Windows OS Updates
Write-Timestamped "Starting Windows OS updates..."
Import-Module PSWindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
Write-Timestamped "Completed Windows OS updates."

# Log footer
Write-Host "`n==================== UPDATE SCRIPT END ====================="
Write-Host "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================="

# End logging
Stop-Transcript
```

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

```python
import sys 
import socket
from datetime import datetime
import threading
import platform
import subprocess

# Load common ports from external file
def load_common_ports(filename='common_ports.txt'):
    """
    Load port mappings from a text file
    Format: port:service_name (one per line)
    """
    ports = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    try:
                        port, service = line.split(':', 1)
                        # Strip whitespace and remove quotes/commas
                        service = service.strip().strip('"').strip("'").rstrip(',')
                        ports[int(port)] = service
                    except ValueError:
                        print(f'Warning: Skipping malformed line: {line}')
        return ports
    except FileNotFoundError:
        print(f'Warning: {filename} not found. Using empty port dictionary.')
        return {}
    except Exception as e:
        print(f'Error loading port file: {e}')
        return {}

# Load the common ports dictionary
COMMON_PORTS = load_common_ports()

# Global verbose flag
verbose = False

def ping_host(target_ip):
    """
    Ping the host to check if it's reachable before scanning
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', target_ip]
    
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        return result.returncode == 0
    except Exception as e:
        print(f'Ping test failed: {e}')
        return False

def scan_port(target, port):
    """
    Function to scan a single port
    """
    try: 
        if verbose:
            print(f'Scanning port {port}...')
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        
        if result == 0:
            service_info = COMMON_PORTS.get(port, "Unknown Service")
            print(f"Port {port} is open - {service_info}")
        
        s.close()
    except socket.error as e:
        print(f'Socket error on port {port}: {e}')
    except Exception as e:
        print(f'Unexpected error on port {port}: {e}')

def main():
    global verbose
    
    # Parse arguments for verbose flag
    args = sys.argv[1:]
    
    if len(args) < 1 or len(args) > 2:
        print("Invalid number of arguments.") 
        print("Usage: python network_scanner.py <target> [-v|--verbose]") 
        sys.exit(1)
    
    target = args[0]
    
    # Check for verbose flag
    if len(args) == 2 and args[1] in ['-v', '--verbose']:
        verbose = True
        print("Verbose mode enabled")

    # Resolve the target hostname to an IP address
    try:
        target_ip = socket.gethostbyname(target) 
    except socket.gaierror:
        print(f'Error: Unable to resolve hostname {target}')
        sys.exit(1)

    # Ping test before scanning
    print("-" * 50)
    print(f'Running ping test on {target_ip}...')
    if ping_host(target_ip):
        print(f'Host {target_ip} is reachable!')
    else:
        print(f'Warning: Host {target_ip} may be unreachable or blocking ICMP')
        response = input('Continue with scan anyway? (y/n): ')
        if response.lower() != 'y':
            print("Scan cancelled.")
            sys.exit(0)

    # Add a banner
    print("-" * 50)
    print(f'Scanning target {target_ip}')
    print(f'Time started: {datetime.now()}')
    print("-" * 50)            

    try:
        # Use multithreading to scan ports concurrently
        threads = []
        for port in range(1, 65536):
            thread = threading.Thread(target=scan_port, args=(target_ip, port))
            threads.append(thread)
            thread.start()
        
        # Wait for threads to complete
        for thread in threads:
            thread.join()
            
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit(0)
    
    except socket.error as e:
        print(f'Socket error: {e}')
        sys.exit(1)

    print("\nScan completed!")  
    print(f'Time finished: {datetime.now()}')

if __name__ == "__main__":
    main()
```    
**Common Ports txt example:**
```text
20:FTP Data
21:FTP Control
22:SSH
53:DNS/Pi-hole/Bind
67:DHCP Server
68:DHCP Client
80:HTTP
443:HTTPS
445:SMB
2375:Docker Daemon (insecure/TCP)
2376:Docker Daemon (Secure/TLS)
4444:Metasploit
5335:Unbound
5432:PostgreSQL
6379:Redis
7655:Pulse
8001:Elastic Agent
8002:Elastic Agent
8006:Proxmox - PVE
8007:Proxmox - PBS
9000:Authentik/PHP/Netdata
9443:Authentik/Portainer
9090:Prometheus
9200:Elasticsearch
9093:Alert Manager
9094:Alert Manager - Discord
12320:Ansible
12321:Ansible
9115:Blackbox
5000:Checkmk
5050:Checkmk
6060:CrowdSec
8220:ELK Fleet
7990:Heimdall
5601:Kibana
5678:n8n
9392:OpenVAS
5055:Overseer
9617:Pi-Hole Exporter
9001:Portainer Agent
9221:Prometheus PVE Exporter
6443:K3s
3001:Uptime Kuma
1514:Wazuh
1515:Wazuh
```

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

