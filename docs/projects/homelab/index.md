# Security Lab Overview

  <img src="/Career_Projects/assets/misc/homelab-banner2.png"
       alt="Homelab"
       style="width: 100%; height: auto; display: block; margin: 0 auto;">

## **Table of Contents**

| Section | Description |
|---------|-------------|
| :material-home-analytics: **[Executive Summary and Security Posture](/Career_Projects/projects/homelab/01-exec-summary/)** | Enterprise-grade security laboratory demonstrating production-ready capabilities across SecOps, systems engineering, and network defense. Multi-layered architecture with SIEM, IDS/IPS, SOAR automation, and zero trust controls. |
| :material-shield-lock: **[Infrastructure Platform, Virtualzation Stack and Hardware](/Career_Projects/projects/homelab/02-platform/)** | Proxmox virtualization stack, Workload deployment, VMware, Cisco and Container envionment overview |
| :material-shield-lock: **[Network Security, Pirvacy and Remote Access](/Career_Projects/projects/homelab/03-network/)** | Network security architecture (Firewall/IPS/WAF), Privacy and remote access |
| :material-shield-lock: **[Identity, Access, Secrets and Trust Management](/Career_Projects/projects/homelab/04-iam-secrets/)** | PKI/Certificate Authority Overview, Identity and Access Management (Authentik/Active Directory), Secrets Management |
| :material-shield-lock: **[Automation and Infrastructure as Code (IaC)](/Career_Projects/projects/homelab/05-auto-iac/)** | Infrastructure provision with Terraform, Configuration Management with Ansible, Workflow automation with n8n, PowerShell, Bash and Python scripting |
| :material-shield-lock: **[Applications and Services](/Career_Projects/projects/homelab/06-apps-service/)** | DNS, Reverse Proxy, Web Services and Ingress Controller Architecture, Secure Shell (SSH) Access, Malware, Vulnerability and Software Patch Management |
| :material-shield-lock: **[Observability and Response, Part 1 ](/Career_Projects/projects/homelab/07-vis-response-pt1/)** | Security Information and Event Management (SIEM) Platforms, Endpoint Detection and Response (EDR) |
| :material-shield-lock: **[Observability and Response, Part 2 ](/Career_Projects/projects/homelab/08-vis-response-pt2/)** | Security Orchestration, Automation and Response (SOAR), Monitoring, Alerting and Notification Architecture |
| :material-chart-box-outline: **[ Governance, Risk and Compliance Landing Page](/Career_Projects/projects/homelab/grc/grc-index/)** | Governance, Risk and Compliance Sections TBD |



## **Security Homelab Network Overview**

  <img src="/Career_Projects/assets/diagrams/SecurityLab_Network-2026-01-22.png"
       alt="Homelab Network Overview Diagram"
       style="width: 100%; height: auto; display: block; margin: 0 auto;">

[:material-file-account: Download Diagram (png)](https://github.com/pnleone/Career_Projects/blob/2b9f8a8b99ed76adf1b7c67fc59aad9b91dbf623/docs/assets/diagrams/SecurityLab_Network-2026-01-22.png)

### PROD_LAN, ISO_LAN1 and ISO_LAN2

  <img src="/Career_Projects/assets/diagrams/lab-network-prod_lan.png"
       alt="Homelab Network Prod_LAN Diagram"
       style="width: 100%; height: auto; display: block; margin: 0 auto;">

#### Main lab LAN Hosting the following workloads:
- **Docker** engines supporting container services 
- **Microsoft Active Directory** Domain Services
- Reverse Proxy and DNS Services
- **FortiGate** Management Services
- Integration to ISO LANs
    - **Cisco** ISO LAN
    - **OPNsense** ISO LAN

### LAB_LAN1 and EXT_LAN

  <img src="/Career_Projects/assets/diagrams/lab-network-lab_lan.png"
       alt="Homelab Network LAB_LAN1-EXT_LAN Diagram"
       style="width: 100%; height: auto; display: block; margin: 0 auto;">

#### Lab/Ext LANs Hosting the following workloads:
- PKI Services
- **VMware** ESXi
- Test external workloads 

### LAB_LAN2

  <img src="/Career_Projects/assets/diagrams/lab-network-lab_lan2.png"
       alt="Homelab Network LAB_LAN2 Diagram"
       style="width: 100%; height: auto; display: block; margin: 0 auto;">   

#### Lab2 LAN Hosting the following workloads:
- **Kubernetes/K3s** Cluster Services (SOC Services)
- ELK Stack and Lab Dashboard 