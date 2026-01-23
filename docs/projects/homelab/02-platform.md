# Infrastructure, Platform and Hardware Summary

**Created By:** [Your Name]  
**Date:** January 19, 2026  
**Organization:** [Organization Name]

---

## Table of Contents

1. [Core Virtualization Stack](#core-virtualization-stack)
   - 1.1 [Proxmox Virtual Environment (VE)](#proxmox-virtual-environment-ve)
   - 1.2 [Proxmox Backup Server](#proxmox-backup-server)
   - 1.3 [Proxmox Datacenter Manager](#proxmox-datacenter-manager)
   - 1.4 [Physical Network Attached Storage (NAS) Integration](#physical-network-attached-storage-nas-integration)
   - 1.5 [Virtual Network Attached Storage (NAS) Integration](#virtual-network-attached-storage-nas-integration)
   - 1.6 [Proxmox Host Hardware](#proxmox-host-hardware)
   - 1.7 [Lab Switch](#lab-switch)
   - 1.8 [Proxmox Workload Overview](#proxmox-workload-overview)
   - 1.9 [Infrastructure Visualization](#infrastructure-visualization)
   - 1.10 [Proxmox Node PVE Summary](#proxmox-node-pve-summary)
   - 1.11 [OS Platform and Distribution/Edition Summary](#os-platform-and-distributionedition-summary)
2. [VMware vSphere r8 Environment](#vmware-vsphere-r8-environment)
3. [Cisco Virtual Infrastructure](#cisco-virtual-infrastructure)
   - 3.1 [Network Topology & Configuration](#network-topology--configuration)
   - 3.2 [Technical Capabilities Demonstrated](#technical-capabilities-demonstrated)
4. [Container Orchestration Architecture](#container-orchestration-architecture)
   - 4.1 [Multi-Engine Docker Deployment](#multi-engine-docker-deployment)
   - 4.2 [Cloud-Native Kubernetes Cluster Deployment](#cloud-native-kubernetes-cluster-deployment)
5. [Network Services Summary](#network-services-summary)
6. [Version Control Strategy](#version-control-strategy)
7. [Security Homelab Section Links](#security-homelab-section-links)
---

## 2. Core Virtualization Stack

### 2.1 Proxmox Virtual Environment (VE)

#### Deployment Overview

The lab's foundation is a single-node Proxmox Virtual Environment (VE) cluster running on enterprise-class bare-metal hardware, serving as the Type-1 hypervisor for the entire security operations platform. Proxmox provides KVM-based full virtualization for operating systems (Windows, BSD, Linux, MacOS) and LXC containerization for lightweight Linux workloads. The platform hosts approximately 30+ concurrent virtual machines and containers, supporting everything from high-availability pfSense firewalls to Kubernetes clusters, SIEM platforms, and malware analysis environments. Automated backup infrastructure via Proxmox Backup Server ensures rapid disaster recovery, while Proxmox Datacenter Manager provides centralized orchestration and monitoring.

#### Security Impact

- Bare-metal Type-1 hypervisor minimizes attack surface compared to Type-2 hosted solutions
- KVM hardware-assisted virtualization provides strong isolation between tenant workloads
- LXC containerization delivers near-native performance for network services with reduced overhead
- Snapshot and backup capabilities enable rapid rollback after security testing or compromise
- Centralized management reduces configuration drift and unauthorized system modifications
- ZFS storage backend provides data integrity verification and encryption at rest
- Network segmentation via virtual bridges isolates security zones (management, production, DMZ)

#### Deployment Rationale

Proxmox VE mirrors enterprise virtualization platforms (VMware vSphere, Microsoft Hyper-V, Red Hat Virtualization) while providing open-source flexibility and zero licensing costs. This enables building an enterprise-scale lab environment demonstrating production-grade infrastructure without commercial hypervisor expenses. Proxmox's integrated backup solution, clustering capabilities, and API-driven automation align with modern Infrastructure as Code (IaC) practices used in DevSecOps environments. The platform supports Docker and Kubernetes workloads alongside traditional VMs, demonstrating hybrid cloud architecture patterns increasingly common in enterprise security operations.

#### Architecture Principles Alignment

**Defense in Depth:**

- Hypervisor layer enforces hardware-based isolation between security zones
- Virtual network bridges segment traffic flows with firewall enforcement at each boundary
- Backup infrastructure resides on separate physical hosts (VMware Workstation, Synology NAS)
- Multiple authentication layers (Proxmox RBAC, Authentik SSO/OAuth2, VM-level access controls, application SSO)

**Secure by Design:**

- Default-deny network policies on all virtual bridges
- Mandatory TLS encryption for Proxmox web UI and API access
- Automated security updates via unattended-upgrades on Debian base OS
- PKI integration for certificate-based authentication across all services
- Immutable infrastructure through snapshot-based deployments

**Zero Trust:**

- No implicit trust between VMs or containers; all inter-service communication authenticated
- API access requires token-based authentication with scoped permissions
- Network policies enforce explicit allow rules; no "trusted" VLANs
- User access governed by role-based permissions (PVEAdmin, PVEAuditor, etc.)

#### Key Capabilities Demonstrated

**Enterprise Infrastructure Operations:**

- High-density virtualization supporting 30+ concurrent workloads on single node
- Mixed workload management (full VMs, containers, nested hypervisors and containers)
- Automated provisioning via Terraform and Ansible integration

**Security Operations Platform:**

- Isolated security tool deployment (SIEM, SOAR, threat intelligence, vulnerability scanners)
- Forensic analysis environments with snapshot-based evidence preservation
- Purple team infrastructure supporting both red and blue team operations

**Disaster Recovery & Business Continuity:**

- Automated weekly backups to Proxmox Backup Server with deduplication
- Off-host backup replication to Synology NAS for redundancy
- Rapid VM restoration (sub-15-minute RTO for critical services)
- Configuration-as-code enables full infrastructure rebuild from Git repository

**Advanced Storage & Networking:**

- ZFS mirrored storage pools providing data integrity and high IOPS
- NVMe-based VM storage for database and container workloads
- Link Aggregation (LAG) with 802.3ad for high-throughput data transfers
- VLAN segmentation supporting isolated testing environments

---

### 2.2 Proxmox Backup Server

Integrated for automated, deduplicated backups of all virtual machines and containers. Backup jobs are scheduled to run weekly, with retention policies aligned to provide redundancies without taking up a lot of space since the server has been deployed within VMware Workstation running on my main production PC.

- Proxmox Backup Server deployed as nested VM within VMware Workstation
- Host: Production workstation (separate from lab infrastructure)
- Purpose: Off-host backup target with deduplication and compression
- Rationale: Leverages existing production hardware for cost-effective DR solution

**Diagram Placeholder: Proxmox Backup Server Screenshot**

---

### 2.3 Proxmox Datacenter Manager

Centralized management solution to oversee and manage multiple nodes and clusters of Proxmox-based virtual environments.

**Diagram Placeholder: Proxmox Datacenter Manager Screenshots (2 images)**

---

### 2.4 Physical Network Attached Storage (NAS) Integration

A shared Synology NAS is configured to receive automated backups from the Proxmox Backup Server. This ensures off-host redundancy and supports rapid restoration in case of lab-wide failure or rollback testing.

- Target: Synology NAS (DSM 6.x) via SMB/NFS mount
- Encryption: AES-256 at rest, TLS in transit
- Purpose: rapid VM restoration, long-term archival, K3s off-host PVCs

**Diagram Placeholder: Synology NAS Configuration Screenshots (2 images)**

---

### 2.5 Virtual Network Attached Storage (NAS) Integration

Proxmox virtual machine running TrueNAS to support Windows (SMB) and Linux (NFS) mounts for data sharing and redundancy. The single storage pool is configured for mirroring across the two NVMe drives.

**Diagram Placeholder: TrueNAS Configuration Screenshots (4 images)**

---

### 2.6 Proxmox Host Hardware

| Component | Specification | Justification |
|-----------|---------------|---------------|
| CPU | Intel Core Ultra 9 285K (24c) | Performance/efficiency cores for mixed workloads |
| Cooling | AIO liquid cooling | Sustained thermal management under load |
| Memory | G.Skill 96 GB DDR5-6400 CL32 | High-density RAM for ~50 concurrent VMs/containers |
| OS Storage | Samsung 990 PRO 2TB (PCIe 4.0) | Low-latency boot and snapshot operations |
| VM Storage | Samsung 9100 PRO 4TB (PCIe 5.0) | High IOPS for database and container workloads |
| Network Interfaces | 3× 2.5GbE + WiFi 7 | Redundant connectivity and traffic segregation |
| GPU | Intel Arc A770 (16GB) | PCIe passthrough for transcoding |
| Motherboard | ASUS ROG Strix Z890-I (mITX) | Compact form factor with enterprise features |

#### Network Interface Design

**Physical Interfaces:**

- eth0 (2.5GbE): Proxmox management network (192.168.1.x)
- eth1 (2.5GbE): LAG member - VLAN3 trunk (192.168.3.x)
- eth2 (2.5GbE): LAG member - VLAN3 trunk (192.168.3.x)
- wlan0 (WiFi 7): Bridged to Lab_LAN1 virtual network

**Virtual Bridges:**

- vmbr0: Management and Prod_LAN workloads (192.168.1.x) (default gateway)
- vmbr1: Lab_LAN1 network workloads (192.168.100.x)
- vmbr2: LAG bond0 ISO_LAN2 network workloads (192.168.3.x)
- vmbr3: Lab_LAN2 network workloads (192.168.200.x)
- vmbr4: Ext_LAN2 network workloads (192.168.2.x)
- vmbr5: Ext_LAN network workloads (10.20.0.x)
- vmbr7: pfSense HA Sync (10.10.0.x)
- vmbr8: Cisco Point-to-Point Network (10.30.0.x)

**Diagram Placeholder: Network Interface Configuration Screenshot**

---

### 2.7 Lab Switch

TP-Link TL-SG108E Smart Switch

Used for VLAN and Link Aggregation (LAG) testing between The Proxmox host server and a Windows 11 Pro workstation.

**Configuration:**

- Link Aggregation: Static LAG (802.3ad equivalent) on ports 2-3
- Lab server NICs 1-2 bonded (LACP mode balance-rr)
- Aggregate bandwidth: 5 Gbps

**Diagram Placeholder: Switch Configuration Screenshot**

**VLAN Segmentation:**

- VLAN 3 (192.168.3.0/24): Isolated testing subnet
- Ports 2, 3, 7: Tagged VLAN3 members
- Purpose: Dedicated high-speed link between office PC and lab server
- Use case: Large file transfers, iSCSI testing, backup replication

**Diagram Placeholder: VLAN Configuration Screenshot**

---

### 2.8 Proxmox Workload Overview

The majority of hosts and services run within the Proxmox environment and run within one of the two integrated technologies supported:

#### 🖥️ Virtual Machines (VMs)

- **Tech Stack**: KVM (Kernel-based Virtual Machine) + QEMU
- **Use Case**: Full OS virtualization—ideal for Windows, BSD, or isolated Linux environments

#### 📦 Linux Containers (LXC)

- **Tech Stack**: LXC (Linux Containers)
- **Use Case**: Lightweight virtualization for Linux apps with near-native performance

---

### 2.9 Infrastructure Visualization

#### PowerBI Dashboards

Custom-built Power BI reports provide real-time visibility into lab operations:

**Diagram Placeholder: PowerBI Dashboard Screenshots (2 images)**

Application Inventory: Per-host service mapping with version tracking

- Resource Utilization: CPU/memory/storage trends across Proxmox nodes
- OS Distribution Analysis: Platform breakdown (RHEL, Ubuntu, Debian, Windows)

---

### 2.10 Proxmox Node PVE Summary

**Diagram Placeholder: Proxmox Node Summary Screenshot**

---

### 2.11 OS Platform and Distribution/Edition Summary

**Diagram Placeholder: OS Distribution Screenshots (2 images)**

---

## 3. VMware vSphere r8 Environment

#### Deployment Overview

The lab operates a hybrid virtualization architecture combining Proxmox as the primary Type-1 hypervisor with VMware vSphere r8 for specialized workloads. VMware Workstation Pro 25H2 runs on the production workstation, hosting critical backup infrastructure (Proxmox Backup Server, Datacenter Manager, Mail Gateway) and malware analysis environments (REMnux). ESXi r8 hypervisor provides enterprise-grade virtualization for Windows Server 2019 Hyper-V nested environments and Debian Live systems.

#### Security Impact

- Isolated backup infrastructure prevents contamination of production Proxmox environment
- REMnux sandbox provides safe malware analysis without risking lab infrastructure
- Hyper-V nested virtualization enables Windows-specific security testing (AD exploitation, PowerShell analysis)
- Multi-hypervisor architecture reduces vendor lock-in risk and single-point-of-failure scenarios

#### Deployment Rationale

Enterprise environments frequently operate multiple virtualization platforms where VMware handles legacy workloads, specific compliance requirements, or vendor-mandated infrastructure. This deployment demonstrates proficiency with multi-vendor hypervisor management, cross-platform migration strategies, and vendor-neutral infrastructure design. Running Proxmox Backup Server on VMware Workstation mirrors enterprise DR architectures where backup infrastructure resides on separate physical hosts or geographic locations.

#### Architecture Principles Alignment

- **Defense in Depth:** Backup infrastructure physically separated from production hypervisor; malware analysis isolated in disposable VMs
- **Secure by Design:** Nested virtualization enforces additional isolation layers; backup encryption at rest and in transit
- **Zero Trust:** No implicit trust between hypervisor platforms; each VM authenticated independently

**Diagram Placeholder: VMware Environment Screenshot**

#### Configuration Details

**VMware Workstation Pro 25H2 (Build 24995812):**

- Proxmox Backup Server v4.1.0 - Deduplicated backup target with AES-256 encryption
- Proxmox Datacenter Manager v1.0.1 - Centralized multi-cluster orchestration
- Proxmox Mail Gateway - Email security gateway testing
- REMnux Linux - Malware analysis and reverse engineering toolkit

**ESXi r8 (Build 24677879-standard):**

- Windows Server 2019 Hyper-V - Nested hypervisor for AD security research
- Debian Live r13 - Ephemeral forensics and incident response platform

**Diagram Placeholder: ESXi Configuration Screenshot**

**Diagram Placeholder: VMware Infrastructure Screenshots (3 images)**

---

## 4. Cisco Virtual Infrastructure

#### Deployment Overview

The lab operates a three-node Cisco virtual network infrastructure providing enterprise-grade routing and switching simulation. Two vRouters (R1 and R2) running Cisco IOS Software Version 15.9(3)M6 (VIOS-ADVENTERPRISEK9-M) implement dynamic routing via OSPF, while a vSwitch operates experimental Version 15.2 (vios_l2-ADVENTERPRISEK9-M) for Layer 2 operations. All instances run as KVM virtual machines within the Proxmox environment, enabling full-featured network protocol testing, routing policy validation, and security hardening without physical hardware dependencies.

The topology implements a hub-and-spoke design where R1 and R2 connect via a dedicated point-to-point link (10.30.0.0/30) and exchange routing information through OSPF Area 0. R1 serves as the primary gateway for production lab networks (192.168.1.0/24, 192.168.100.0/24, 192.168.200.0/24), while R2 handles isolated test networks (192.168.2.0/24, 192.168.3.0/24). Two Ubuntu 25.10 LXC containers (cisco-host1 and cisco-host2) validate routing functionality by using their respective local routers as default gateways.

**Diagram Placeholder: Cisco Topology Diagram**

#### Security Impact

- **Isolated Routing Domain:** Virtual infrastructure creates air-gapped routing environment preventing production network disruption during protocol testing and failure scenario simulation
- **Policy Validation Sandbox:** Enables safe testing of ACLs, prefix lists, route maps, and firewall rules before pfSense/OPNsense deployment
- **Attack Path Analysis:** Simulates multi-hop routing scenarios for lateral movement detection and network segmentation validation
- **Protocol Security Research:** Provides hands-on environment for OSPF authentication, routing protocol poisoning prevention, and neighbor relationship hardening
- **Network Forensics Training:** Supports packet capture analysis, routing loop detection, and convergence behavior observation during security incidents

#### Deployment Rationale

Cisco IOS powers the majority of enterprise routers and Layer 3 switches globally. Virtual IOS infrastructure demonstrates production-ready proficiency with Cisco CLI, dynamic routing protocols, and network automation while avoiding physical hardware costs. This deployment mirrors enterprise network engineering labs where virtual routers support CI/CD pipelines for network configuration validation, automated testing workflows, and infrastructure-as-code development. Running vIOS in KVM enables integration with Ansible network modules, Terraform providers, and Python network automation libraries (Netmiko, NAPALM) used in DevOps-driven network operations.

#### Architecture Principles Alignment

**Defense in Depth:**

- Virtual network infrastructure physically isolated from production routing
- OSPF authentication prevents route injection attacks (future enhancement)
- ACLs on router interfaces enforce inter-subnet access control
- Separate routing domain enables secure testing of dangerous configurations

**Secure by Design:**

- SSH-only access enforced on all routers (Telnet disabled)
- Enable secret passwords hashed with SHA256 (Type 9)
- Console and VTY lines require authentication
- Logging enabled for all configuration changes and security events

**Zero Trust:**

- No implicit routing trust between subnets; OSPF neighbors explicitly configured
- Inter-VLAN routing requires explicit permit statements
- Default-deny ACLs block unauthorized cross-subnet traffic
- Each router authenticates independently to management infrastructure

---

### 4.1 Network Topology & Configuration

#### Physical Connectivity

**Diagram Placeholder: R1 Configuration Screenshot**

**R1 (192.168.200.6) - Primary Router:**

- G0/0: 192.168.1.6/24 - Production network uplink
- G0/1: 192.168.100.6/24 - Primary lab network (K3s cluster, Docker hosts)
- G0/2: 192.168.200.6/24 - Secondary lab network (SOC namespace, server-admin)
- G0/3: 10.30.0.1/30 - Point-to-point link to R2

**Diagram Placeholder: R2 Configuration Screenshot**

**R2 (192.168.3.9) - Secondary Router:**

- G0/0: 10.30.0.2/30 - Point-to-point link to R1
- G0/1: 192.168.3.9/24 - Management VLAN (FortiGate protected)
- G0/2: 192.168.2.9/24 - External lab network

**vSwitch (Layer 2):**

- Provides VLAN trunking and access port simulation
- Supports STP testing and loop prevention validation
- Enables port security and MAC address filtering research

#### OSPF Routing Configuration

**Protocol:** OSPF Version 2 (OSPFv2 for IPv4)  
**Process ID:** 1  
**Area:** 0 (Backbone area - single-area design)  
**Network Type:** Point-to-point (10.30.0.0/30 link)

**R1 OSPF Configuration:**
```
router ospf 1
router-id 192.168.200.6
network 192.168.1.0 0.0.0.255 area 0
network 192.168.100.0 0.0.0.255 area 0
network 192.168.200.0 0.0.0.255 area 0
network 10.30.0.0 0.0.0.3 area 0
```

**R2 OSPF Configuration:**
```
router ospf 1
router-id 192.168.3.9
network 192.168.2.0 0.0.0.255 area 0
network 192.168.3.0 0.0.0.255 area 0
network 10.30.0.0 0.0.0.3 area 0
```
**Routing Table Verification:**

- R1 learns routes to 192.168.2.0/24 and 192.168.3.0/24 via OSPF (Administrative Distance 110)
- R2 learns routes to 192.168.1.0/24, 192.168.100.0/24, 192.168.200.0/24 via OSPF
- Point-to-point link (10.30.0.0/30) advertised by both routers
- OSPF neighbor adjacency established (Full state) on G0/3 (R1) and G0/0 (R2)

#### Test Host Configuration

**cisco-host1 (192.168.100.4):**

- Platform: Ubuntu 25.10 LXC container
- Default Gateway: 192.168.100.6 (R1 G0/1)
- Purpose: Validate R1 routing to R2-connected subnets
- Test: ping 192.168.3.5 should route via R1 → 10.30.0.0/30 → R2

**cisco-host2 (192.168.3.5):**

- Platform: Ubuntu 25.10 LXC container
- Default Gateway: 192.168.3.9 (R2 G0/1)
- Purpose: Validate R2 routing to R1-connected subnets
- Test: ping 192.168.100.4 should route via R2 → 10.30.0.0/30 → R1

---

### 4.2 Technical Capabilities Demonstrated

#### Dynamic Routing Protocols

**OSPF (Open Shortest Path First):**

- Single-area design (Area 0 backbone)
- Point-to-point network type for optimal convergence
- Router ID assignment using loopback or highest IP
- LSA flooding and LSDB synchronization
- SPF algorithm execution and route calculation
- Neighbor adjacency management (Hello/Dead timers)

---

## 5. Container Orchestration Architecture

#### Deployment Overview

The container orchestration layer consists of two complementary platforms: a multi‑engine Docker deployment for lightweight, isolated workloads and a dual‑node K3s Kubernetes cluster for cloud‑native, scalable applications. Docker engines provide simple, isolated runtime environments ideal for single‑purpose services, while K3s delivers a fully compliant Kubernetes distribution optimized for low‑resource environments. Portainer provides centralized management across both platforms, enabling unified visibility, lifecycle control, and operational consistency. Together, these systems form a hybrid container ecosystem that mirrors modern enterprise architectures where Docker and Kubernetes coexist to support diverse workloads.

#### Security Impact

- Workload isolation across six independent Docker engines reduces blast radius
- Kubernetes network policies and ingress controls enforce strict east‑west and north‑south traffic boundaries
- Portainer centralizes access control and auditability across all container platforms
- K3s certificate automation ensures secure service‑to‑service communication
- Segmented runtimes prevent cross‑container compromise
- MetalLB and NGINX Ingress enforce controlled exposure of internal services

#### Deployment Rationale

Enterprises frequently operate hybrid container environments where Docker supports lightweight services and Kubernetes orchestrates scalable, distributed applications. This architecture demonstrates proficiency with both paradigms—multi‑engine Docker for simplicity and K3s for cloud‑native orchestration. The deployment mirrors real‑world operational patterns including ingress management, persistent storage provisioning, network policy enforcement, and centralized container lifecycle management.

#### Architecture Principles Alignment

**Defense in Depth:** Multiple container runtimes, isolated engines, Kubernetes network policies, and ingress controls

**Secure by Design:** TLS‑enabled Kubernetes control plane, Portainer RBAC, minimal host dependencies

**Zero Trust:** No container or service implicitly trusted; identity, ingress, and network policies enforced continuously

---

### 5.1 Multi-Engine Docker Deployment

#### Deployment Overview

The lab operates six independent Docker engines, each hosting isolated workloads to minimize cross‑service impact. Portainer Community Edition provides a centralized GUI for managing all engines, while Portainer Agents enable secure API communication with remote hosts. Home Assistant remains intentionally standalone to preserve stability and reduce risk from shared infrastructure.

#### Security Impact

- Independent Docker engines prevent lateral movement between workloads
- Portainer RBAC restricts administrative access to container hosts
- Engine‑level isolation reduces the impact of misconfigurations or compromised containers
- Minimal shared dependencies reduce systemic risk

#### Deployment Rationale

Multi‑engine Docker deployments mirror enterprise environments where isolated runtimes support operational segmentation, compliance boundaries, or workload separation. This design demonstrates proficiency with distributed container management, remote engine control, and secure API‑driven orchestration.

#### Architecture Principles Alignment

**Defense in Depth:** Multiple engines create natural segmentation boundaries

**Secure by Design:** Portainer Agents use secure API channels; Home Assistant isolated for safety

**Zero Trust:** No container shares trust with another engine; all access controlled centrally

#### Configuration

| Engine Location | Purpose | Key Containers |
|-----------------|---------|----------------|
| Ubuntu VM (DockerVM1) | Central management & monitoring | Portainer; Prometheus; Checkmk; WUD; Pulse; Cloudflared |
| Debian VM (DockerVM2) | Identity & security services | Authentik; OpenVAS; PostgreSQL; Elastic Agent; n8n |
| LXC-1 (Primary DNS) | Network infrastructure | Pi-hole; prometheus-exporter |
| LXC-2 (Ingress) | Reverse proxy & SSO | Traefik; Authentik outpost |
| Safeline-WAF | Web Application Firewall and Gmail notifications | Safeline stack, SMTP relay |
| Home Assistant VM | Home automation (isolated) | HA core + add-ons |

#### Docker Compose

**Diagram Placeholder: Docker Compose Screenshots (2 images)**

Compose files are created in VS Code and stored in a Github repository for version control.

---

### 5.2 Cloud-Native Kubernetes Cluster Deployment

#### Deployment Overview

The lab runs a dual‑node K3s cluster (one control plane, one worker) on Red Hat Enterprise Linux 10 VMs within the 192.168.200.0/24 subnet. K3s is a fully compliant Kubernetes distribution packaged as a single binary, minimizing external dependencies and simplifying cluster operations. It includes a batteries‑included stack: containerd runtime, Flannel CNI, CoreDNS, Kube‑router, Local‑path‑provisioner, and Spegel registry mirror.

The embedded Traefik ingress controller and ServiceLB load balancer have been intentionally disabled and replaced with NGINX Ingress and MetalLB, providing enterprise‑grade ingress routing and Layer‑2 external IP allocation. Portainer integrates with the cluster via a DaemonSet‑based Portainer Agent for full lifecycle management.

#### Security Impact

- K3s certificate automation secures all control plane and node communications
- NGINX Ingress enforces controlled north‑south traffic with TLS termination
- MetalLB provides predictable, controlled external IP allocation
- Flannel CNI and Kube‑router enforce network segmentation and policy enforcement
- Minimal external dependencies reduce attack surface
- Local‑path‑provisioner isolates persistent volumes per workload

#### Deployment Rationale

K3s is ideal for homelab and edge environments requiring full Kubernetes functionality with reduced operational overhead. This deployment demonstrates proficiency with Kubernetes networking, ingress management, persistent storage provisioning, and cluster lifecycle operations. Replacing Traefik and ServiceLB with NGINX Ingress and MetalLB mirrors enterprise‑grade ingress and load‑balancing patterns.

#### Architecture Principles Alignment

**Defense in Depth:** Network policies, ingress controls, and runtime isolation across pods and namespaces

**Secure by Design:** TLS‑secured control plane, minimal dependencies, automated certificate rotation

**Zero Trust:** Every pod, service, and ingress request authenticated and authorized; no implicit trust between namespaces

**Diagram Placeholder: K3s Cluster Screenshots (4 images)**

#### Core Infrastructure Services

| Component | Namespace | Purpose | Deployment Type |
|-----------|-----------|---------|-----------------|
| MetalLB Controller | metallb-system | Layer 2/BGP load balancer controller for bare-metal Kubernetes | Deployment (1 replica) |
| MetalLB Speaker | metallb-system | Announces LoadBalancer IPs via ARP/BGP | DaemonSet (runs on all nodes) |
| Nginx Ingress Controller | nginx-ingress | HTTP/HTTPS ingress traffic routing and SSL termination | Helm chart (1 replica) |
| Portainer Agent | portainer-agent | Cluster management and monitoring via Portainer UI | DaemonSet (runs on all nodes) |
| Cert-Manager | cert-manager | StepCA/ACME client for nginx-ingress SSL termination | Helm Chart Deployment |
**MetalLB Load Balancer Configuration:**

- **Address Pool:** 192.168.200.30-192.168.200.49 (20 available IPs)
- **Mode:** Layer 2 (ARP-based)
- **Purpose:** Provides external IPs for LoadBalancer-type services in bare-metal environment

**Ingress Architecture:**

- **Controller:** Nginx Ingress Controller (official Kubernetes ingress-nginx)
- **External Access:** LoadBalancer service at 192.168.200.31 (HTTP: 80, HTTPS: 443)
- **Use Case:** Centralized ingress point for HTTP-based services with path-based routing. Provides rate limiting, IP allow list and TLS/HTTPS connectivity to the NGINX Webserver. Certificates are delivered via Cert-Manager service that is auto-generated from StepCA/ACME.  

#### Nginx Namespace - Web Services

| Application | Type | Image | Replicas | External IP | Ports | Purpose |
|-------------|------|-------|----------|-------------|-------|---------|
| nginx | Deployment | linuxserver/nginx:latest | 2/2 | 192.168.200.32 | 80 (HTTP) | Static web server for lab documentation and demos |

#### Infrastructure Namespaces

**metallb-system Namespace:**

| Application | Type | Replicas | Purpose |
|-------------|------|----------|---------|
| controller | Deployment | 1/1 | MetalLB controller managing IP address allocation |
| speaker | DaemonSet | 2/2 | MetalLB speaker announcing IPs via Layer 2 (ARP) |

**nginx-ingress Namespace:**

| Application | Type | Replicas | External IP | Purpose |
|-------------|------|----------|-------------|---------|
| nginx-ingress-controller | Helm | 1/1 | 192.168.200.31 | HTTP/HTTPS ingress controller for path-based routing |

**portainer-agent Namespace:**

| Application | Type | Replicas | Purpose |
|-------------|------|----------|---------|
| portainer-agent | DaemonSet | 2/2 | Portainer agent for cluster management via Portainer UI |

**cert-manager Namespace:**

| Application | Type | Replicas | External IP | Purpose |
|-------------|------|----------|-------------|---------|
| Cert-Manager | Helm | 1/1 | - | StepCA/ACME client for nginx-ingress SSL termination |
| Cert-Manager-cainjector | Helm | 1/1 | - | - |
| Cert-Manager-webhook | Helm | 1/1 | - | - |
#### SOC Namespace - Security Operations Center Platform

The SOC namespace hosts the lab's comprehensive Security Operations Center platform, implementing a modern threat intelligence, incident response, and security orchestration architecture. Integrating threat intelligence sharing (MISP), automated analysis (Cortex), workflow automation (Shuffle), and case management (TheHive).

##### Architecture Overview

**Namespace Purpose:** Centralized security operations platform providing end-to-end incident response capabilities from threat intelligence ingestion through automated workflow execution, observable analysis, case resolution, and IOC sharing.

##### Design Rationale

**Unified Security Platform:** Single namespace for all SOC functions enables tight integration and simplified network policies

**Workflow Automation:** Shuffle SOAR orchestrates complex multi-tool workflows without requiring custom code development

**Scalability:** Kubernetes orchestration allows horizontal scaling of analysis workers (Cortex, Shuffle Orborus) during high-volume incident periods

**Resilience:** StatefulSets ensure data persistence for critical components (Cassandra, Elasticsearch, OpenSearch)

**Integration:** Native Kubernetes networking facilitates service-to-service communication with other lab security tools

##### SOC Namespace - Security Operations Center

| Application | Type | Image | Replicas | External IP | Ports | Purpose |
|-------------|------|-------|----------|-------------|-------|---------|
| thehive | Helm | strangebee/thehive:5.5.13-1 | 1/1 | 192.168.200.33 | 9000 (HTTP), 9095 (metrics) | Security incident response platform and case management


---
## Security Homelab Section Links

- **[Executive Summary and Security Posture](/Career_Projects/projects/homelab/01-exec-summary/)**
- **[Infrastructure Platform, Virtualzation Stack and Hardware](/Career_Projects/projects/homelab/02-platform/)** 
- **[Network Security, Pirvacy and Remote Access](/Career_Projects/projects/homelab/03-network/)** 
- **[Identity, Access, Secrets and Trust Management](/Career_Projects/projects/homelab/04-iam-secrets/)** 
- **[Automation and IaC](/Career_Projects/projects/homelab/05-auto-iac/)**
- **[Applications and Services](/Career_Projects/projects/homelab/06-apps-service/)**
- **[Observability and Response, Part 1](/Career_Projects/projects/homelab/07-vis-response-pt1/)**
- **[Observability and Response, Part 2](/Career_Projects/projects/homelab/07-vis-response-pt2/)**