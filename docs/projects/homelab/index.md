 # Security Homelab 
  <img src="/Career_Projects/assets/misc/homelab-banner2.png"
       alt="Homelab"
       style="width: 100%; height: auto; display: block; margin: 0 auto;">

## **Table of Contents**

| Section | Description |
|---------|-------------|
| :material-home-analytics: **[Security Homelab: Executive Summary and Security Posture](/Career_Projects/projects/homelab/01-exec-summary/)** | Enterprise-grade security laboratory demonstrating production-ready capabilities across SecOps, systems engineering, and network defense. Multi-layered architecture with SIEM, IDS/IPS, SOAR automation, and zero trust controls. |
| :material-home-analytics: **[Security Homelab: Infrastructure Platform, Virtualzation Stack and Hardware](/Career_Projects/projects/homelab/02-platform/)** | Proxmox virtualization stack, Workload deployment, VMware, Cisco and Container envionment overview |
| :material-home-analytics: **[Security Homelab: Network Security, Pirvacy and Remote Access](/Career_Projects/projects/homelab/03-network/)** | Network security architecture (Firewall/IPS/WAF), Privacy and remote access |
| :material-home-analytics: **[Security Homelab: Identity, Access, Secrets and Trust Management](/Career_Projects/projects/homelab/04-iam-secrets/)** | PKI/Certificate Authority Overview, Identity and Access Management (Authentik/Active Directory), Secrets Management |
| :material-home-analytics: **[Security Homelab: GRC Landing Page](/Career_Projects/projects/homelab/grc/grc-index/)** | Governance, Risk and Compliance Sesctions |



## **Security Homelab Network Overview**

  <img src="/Career_Projects/assets/diagrams/SecurityLab_Network-2026-01-22.png"
       alt="Homelab Network Overview Diagram"
       style="width: 100%; height: auto; display: block; margin: 0 auto;">


### Management and Production LAN — 192.168.3.0/24

**Purpose**  
Primary production and office network for physical workstations, NAS, backup servers, and management interfaces.

**Key hosts and services**  
- OfficePC (multi‑interface)  
- Synology NAS; Backup Server  
- DC Manager; Mail Gateway  
- FortiGate 30D; Cisco routers and switches; TP‑Link switch  
- Proxmox management interfaces

**Top priorities**  
1. **Strict segmentation** — move management interfaces to a dedicated management VLAN or jump host.  
2. **Access control** — enforce MFA and RBAC for admin accounts; limit SSH/RDP to bastion hosts.  
3. **Backup integrity** — isolate backup traffic and verify offsite/immutable backups.  
4. **Network device hardening** — secure Cisco/FortiGate, disable unused services, enable centralized logging.  
5. **Monitoring** — forward logs to SIEM and enable IDS alerts for lateral movement.

**Immediate risks and mitigations**  
- **Risk:** Management interfaces exposed to broader LAN. **Mitigation:** Restrict admin access via firewall rules and a management VLAN.  
- **Risk:** NAS/backup compromise. **Mitigation:** Immutable snapshots, offsite copies, least‑privilege access.

---

### Lab and Workload VLAN — 192.168.100.0/24

**Purpose**  
Primary lab and workload network hosting many Windows test VMs, step CA, Fedora server, and pfSense VIPs.

**Key hosts and services**  
- Numerous Windows test hosts  
- stepca; Fedora server  
- pfSense VIPs and Proxmox nodes

**Top priorities**  
1. **Microsegmentation** — reduce east‑west risk by breaking the /24 into smaller segments or strict firewall rules.  
2. **Control plane protection** — protect step CA and pfSense VIPs with ACLs and monitoring.  
3. **Patch and snapshot discipline** — enforce automated snapshots and baseline images.  
4. **Network address management** — document host roles and avoid ad‑hoc IP reuse.

**Immediate risks and mitigations**  
- **Risk:** Lateral movement across Windows hosts. **Mitigation:** Host EDR, network ACLs, VLAN isolation for risky testbeds.  
- **Risk:** Step CA compromise. **Mitigation:** Harden CA, restrict access, store keys in a protected vault.

---

### Management Services and Tooling VLAN — 192.168.1.0/24

**Purpose**  
Service and tooling zone for DNS, Traefik, Pi‑hole, Wazuh, detection tooling, web services, and management VMs.

**Key hosts and services**  
- Traefik, Pi‑hole, Wazuh, Bind/Unbound, Apache, MISP, SafeIntel, detection/ingest services

**Top priorities**  
1. **Service hardening and least privilege** — run services with minimal privileges and service accounts.  
2. **Ingress control** — place reverse proxy and ingress behind hardened edge; validate TLS termination.  
3. **Centralized logging and alerting** — ensure Wazuh/Elastic ingest logs from all zones.  
4. **DNS security** — restrict zone transfers and monitor DNS anomalies.

**Immediate risks and mitigations**  
- **Risk:** Public exposure of management services. **Mitigation:** Cloudflare access rules, IP allowlists, authentication for dashboards.  
- **Risk:** Service chaining after compromise. **Mitigation:** Network ACLs and strict egress rules between services.

---

### Production Services and MetalLB Addresses — 192.168.200.0/24

**Purpose**  
Production service endpoints and MetalLB IPs for externally reachable services and production VLAN.

**Key hosts and services**  
- Ubuntu and Red Hat hosts; MetalLB IPs mapped to mail, API, MISP, shuffle, front, etc.  
- pfSense VIP for PROD LAN

**Top priorities**  
1. **Edge protection** — firewall rules and Cloudflare WAF protecting MetalLB‑exposed services.  
2. **Service isolation** — dedicate namespaces and ingress ACLs per service.  
3. **High availability** — pfSense HA and service redundancy for critical services.  
4. **Secure DNS and TLS** — validate Cloudflare DNS and certificate management.

**Immediate risks and mitigations**  
- **Risk:** Direct exposure of internal services via MetalLB. **Mitigation:** Cloudflare WAF, source IP restrictions, authentication for management endpoints.  
- **Risk:** Inconsistent firewall rules between LAB and PROD. **Mitigation:** Centralize rule management and document differences.

---

### DMZ and Web Zone — 192.168.2.0/24

**Purpose**  
Public‑facing web services and demo hosts.

**Key hosts and services**  
- Web‑cc‑ubuntu; Web‑desk; front‑end web services

**Top priorities**  
1. **Strict DMZ firewalling** — allow only necessary ports from the internet and restrict flows to backends.  
2. **Application hardening** — patch web servers, run minimal services, apply WAF rules.  
3. **Logging and monitoring** — forward web logs to SIEM and enable alerts for suspicious requests.

**Immediate risks and mitigations**  
- **Risk:** Web server compromise leading to pivot. **Mitigation:** Isolate web servers in DMZ with no direct management access from PROD/LAB; use bastion hosts.  
- **Risk:** Misconfigured ingress exposing internal APIs. **Mitigation:** Validate ingress rules and use mTLS where appropriate.

---

### External Access VPNs and Security Controls

**Purpose**  
Perimeter connectivity, remote access, and perimeter security controls.

**Key components**  
- Cloudflare DNS/WAF; Verizon Fios uplink; Tailscale and mesh VPNs; pfSense HA; Suricata and Snort sensors





    