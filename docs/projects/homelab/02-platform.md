# Infrastructure, Platform and Hardware Summary

**Created By:** Paul Leone  
**Date:** January 19, 2026  

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

<div class="two-col-right">
  <div class="text-col">
    <p>
      The lab's foundation is a single-node Proxmox Virtual Environment (VE) cluster running on enterprise-class bare-metal hardware, serving as the Type-1 hypervisor for the entire security operations platform. Proxmox provides KVM-based full virtualization for operating systems (Windows, BSD, Linux, MacOS) and LXC containerization for lightweight Linux workloads. The platform hosts approximately 30+ concurrent virtual machines and containers, supporting everything from high-availability pfSense firewalls to Kubernetes clusters, SIEM platforms, and malware analysis environments. Automated backup infrastructure via Proxmox Backup Server ensures rapid disaster recovery, while Proxmox Datacenter Manager provides centralized orchestration and monitoring.
    </p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/proxmox.png" alt="Proxmox VE single-node cluster diagram">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Proxmox VE single-node cluster and hosted services.
      </figcaption>
    </figure>
  </div>
</div>
<!-- ![Proxmox overview](../../assets/diagrams/proxmox.png){.float-right width=60%}
The lab's foundation is a single-node Proxmox Virtual Environment (VE) cluster running on enterprise-class bare-metal hardware, serving as the Type-1 hypervisor for the entire security operations platform. Proxmox provides KVM-based full virtualization for operating systems (Windows, BSD, Linux, MacOS) and LXC containerization for lightweight Linux workloads. The platform hosts approximately 30+ concurrent virtual machines and containers, supporting everything from high-availability pfSense firewalls to Kubernetes clusters, SIEM platforms, and malware analysis environments. Automated backup infrastructure via Proxmox Backup Server ensures rapid disaster recovery, while Proxmox Datacenter Manager provides centralized orchestration and monitoring. -->
 
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


<div class="two-col-right">
  <div class="text-col">
    <ul>
      <li>Proxmox Backup Server deployed as nested VM within VMware Workstation</li>
      <li>Host: Production workstation (separate from lab infrastructure)</li>
      <li>Purpose: Off-host backup target with deduplication and compression</li>
      <li>Rationale: Leverages existing production hardware for cost-effective DR solution</li>
    </ul>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/pbs.png" alt="Proxmox Backup Server Screenshot">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Proxmox Backup Server Dashboard.
      </figcaption>
    </figure>
  </div>
</div>

---

### 2.3 Proxmox Datacenter Manager

Centralized management solution to oversee and manage multiple nodes and clusters of Proxmox-based virtual environments.

![Proxmox Datacenter Manager Screenshot](/Career_Projects/assets/screenshots/dcm.png)
<figure>
      <img src="/Career_Projects/assets/screenshots/dcm.png" alt="Proxmox Datacenter Manager Screenshot">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Proxmox Datacenter Manager Screenshot.
      </figcaption>
    </figure>
---

### 2.4 Physical Network Attached Storage (NAS) Integration

A shared Synology NAS is configured to receive automated backups from the Proxmox Backup Server. This ensures off-host redundancy and supports rapid restoration in case of lab-wide failure or rollback testing.

- Target: Synology NAS (DSM 6.x) via SMB/NFS mount
- Encryption: AES-256 at rest, TLS in transit
- Purpose: rapid VM restoration, long-term archival, K3s off-host PVCs

<!-- ![NAS Backups Screenshot](/Career_Projects/assets/screenshots/nas-backups.png) -->
<figure>
      <img class="image-large" src="/Career_Projects/assets/screenshots/nas-backups.png" alt="NAS Backups Screenshot">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Synology NAS Backups Screenshot.
      </figcaption>
    </figure>

---

### 2.5 Virtual Network Attached Storage (NAS) Integration

Proxmox virtual machine running TrueNAS to support Windows (SMB) and Linux (NFS) mounts for data sharing and redundancy. The single storage pool is configured for mirroring across the two NVMe drives.

<figure>
      <img class="image-large" src="/Career_Projects/assets/screenshots/truenas.png" alt="TrueNAS Screenshot">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        TrueNAS Screenshots.
      </figcaption>
    </figure>
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

<div class="two-col-right">
  <div class="text-col">
    <b>Configuration:</B>
    <ul>
      <li>Link Aggregation: Static LAG (802.3ad equivalent) on ports 2-3</li>
      <li>Lab server NICs 1-2 bonded (LACP mode balance-rr)</li>
      <li>Aggregate bandwidth: 2 Gbps</li>
    </ul>
    <b>VLAN Segmentation:</B>
    <ul>
      <li>VLAN 3 (192.168.3.0/24): Isolated testing subnet</li>
      <li>Ports 2, 3, 7: Tagged VLAN3 members</li>
      <li>Purpose: Dedicated high-speed link between office PC and lab server</li>
      <li>Use case: Large file transfers, iSCSI testing, backup replication</li>
    </ul>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/tp-link.png" alt="TP-Link VLAN/LAG Settings">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        tp-link VLAN and LAG Settings.
      </figcaption>
    </figure>
  </div>
</div>
---

### 2.8 Proxmox Workload Overview

The majority of hosts and services run within the Proxmox environment and run within one of the two integrated technologies supported:

<div style="background: white; padding: 1rem; border-radius: 12px; max-width: 350px; margin: 2rem auto;">
  <img src="/Career_Projects/assets/misc/kvm-lxc.png"
       alt="Diagram"
       style="width: 100%; height: auto; display: block; margin: 0 auto;">
</div>


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
### 2.10 OS Platform and Distribution/Edition Summary

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


#### Configuration Details

**VMware Workstation Pro 25H2 (Build 24995812):**

<div class="two-col-right">
  <div class="text-col">
    <ul>
      <li>Proxmox Backup Server v4.1.0 - Deduplicated backup target with AES-256 encryption</li>
      <li>Proxmox Datacenter Manager v1.0.1 - Centralized multi-cluster orchestration</li>
      <li>Proxmox Mail Gateway - Email security gateway testing</li>
      <li>REMnux Linux - Malware analysis and reverse engineering toolkit</li>
    </ul>
    <b>ESXi r8 (Build 24677879-standard):</B>
    <ul>
      <li>Windows Server 2019 Hyper-V - Nested hypervisor for AD security research</li>
      <li>Debian Live r13 - Ephemeral forensics and incident response platform</li>
   </ul>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/vmware.png" alt="VMware ESXi and Workstation Pro Overview">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        VMware ESXi and Workstation Pro Overview.
      </figcaption>
    </figure>
  </div>
</div>

<figure>
      <img class="image-large" src="/Career_Projects/assets/screenshots/vmware-esxi.png" alt="ESXi Screenshot">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        VMware ESXi Screenshots.
      </figcaption>
    </figure>
---

## 4. Cisco Virtual Infrastructure

#### Deployment Overview

The lab operates a three-node Cisco virtual network infrastructure providing enterprise-grade routing and switching simulation. Two vRouters (R1 and R2) running Cisco IOS Software Version 15.9(3)M6 (VIOS-ADVENTERPRISEK9-M) implement dynamic routing via OSPF, while a vSwitch operates experimental Version 15.2 (vios_l2-ADVENTERPRISEK9-M) for Layer 2 operations. All instances run as KVM virtual machines within the Proxmox environment, enabling full-featured network protocol testing, routing policy validation, and security hardening without physical hardware dependencies.

The topology implements a hub-and-spoke design where R1 and R2 connect via a dedicated point-to-point link (10.30.0.0/30) and exchange routing information through OSPF Area 0. R1 serves as the primary gateway for production lab networks (192.168.1.0/24, 192.168.100.0/24, 192.168.200.0/24), while R2 handles isolated test networks (192.168.2.0/24, 192.168.3.0/24). Two Ubuntu 25.10 LXC containers (cisco-host1 and cisco-host2) validate routing functionality by using their respective local routers as default gateways.

<figure>
      <img class="image-large" src="/Career_Projects/assets/screenshots/cisco-r1-r2.png" alt="Cisco Screenshot">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Cisco r1 and r2 Configuration.
      </figcaption>
    </figure>

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

<div class="two-col-text-even">
  <div class="text-left">
   <h3>R1 (192.168.200.6) - Primary Router</h3>
    <ul>
      <li><strong>G0/0:</strong> 192.168.1.6/24 — Production network uplink</li>
      <li><strong>G0/1:</strong> 192.168.100.6/24 — Primary lab network (K3s cluster, Docker hosts)</li>
      <li><strong>G0/2:</strong> 192.168.200.6/24 — Secondary lab network (SOC namespace, server-admin)</li>
      <li><strong>G0/3:</strong> 10.30.0.1/30 — Point-to-point link to R2</li>
    </ul>
  </div>

  <div class="text-right">
   <h3>R2 (192.168.3.9) - Secondary Router</h3>
   <ul>
      <li><strong>G0/0:</strong> 10.30.0.2/30 — Point-to-point link to R1</li>
      <li><strong>G0/1:</strong> 192.168.3.9/24 — Management VLAN (FortiGate protected)</li>
      <li><strong>G0/2:</strong> 192.168.2.9/24 — External lab network</li>
   </ul>
  </div>
</div>
 
### Router R1 Configuration

```
      R1#show ip int br
      Interface                  IP-Address      OK? Method Status                Protocol
      GigabitEthernet0/0         192.168.1.6     YES NVRAM  up                    up
      GigabitEthernet0/1         192.168.100.6   YES NVRAM  up                    up
      GigabitEthernet0/2         192.168.200.6   YES NVRAM  up                    up
      GigabitEthernet0/3         10.30.0.1       YES manual up                    up
      R1#show ip route
      Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
            D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
            N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
            E1 - OSPF external type 1, E2 - OSPF external type 2
            i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
            ia - IS-IS inter area, * - candidate default, U - per-user static route
            o - ODR, P - periodic downloaded static route, H - NHRP, l - LISP
            a - application route
            + - replicated route, % - next hop override, p - overrides from PfR

      Gateway of last resort is not set

            10.0.0.0/8 is variably subnetted, 3 subnets, 3 masks
      S        10.20.0.0/24 [1/0] via 192.168.1.1
      C        10.30.0.0/30 is directly connected, GigabitEthernet0/3
      L        10.30.0.1/32 is directly connected, GigabitEthernet0/3
            192.168.1.0/24 is variably subnetted, 2 subnets, 2 masks
      C        192.168.1.0/24 is directly connected, GigabitEthernet0/0
      L        192.168.1.6/32 is directly connected, GigabitEthernet0/0
      O     192.168.2.0/24 [110/2] via 10.30.0.2, 6d22h, GigabitEthernet0/3
      O     192.168.3.0/24 [110/2] via 10.30.0.2, 6d22h, GigabitEthernet0/3
            192.168.100.0/24 is variably subnetted, 2 subnets, 2 masks
      C        192.168.100.0/24 is directly connected, GigabitEthernet0/1
      L        192.168.100.6/32 is directly connected, GigabitEthernet0/1
            192.168.200.0/24 is variably subnetted, 2 subnets, 2 masks
      C        192.168.200.0/24 is directly connected, GigabitEthernet0/2
      L        192.168.200.6/32 is directly connected, GigabitEthernet0/2
      R1#show ip proto
      *** IP Routing is NSF aware ***

      Routing Protocol is "application"
      Sending updates every 0 seconds
      Invalid after 0 seconds, hold down 0, flushed after 0
      Outgoing update filter list for all interfaces is not set
      Incoming update filter list for all interfaces is not set
      Maximum path: 32
      Routing for Networks:
      Routing Information Sources:
         Gateway         Distance      Last Update
      Distance: (default is 4)

      Routing Protocol is "ospf 1"
      Outgoing update filter list for all interfaces is not set
      Incoming update filter list for all interfaces is not set
      Router ID 192.168.200.6
      It is an autonomous system boundary router
      Redistributing External Routes from,
      Number of areas in this router is 1. 1 normal 0 stub 0 nssa
      Maximum path: 4
      Routing for Networks:
         192.168.1.0 0.0.0.255 area 0
         192.168.100.0 0.0.0.255 area 0
         192.168.200.0 0.0.0.255 area 0
      Routing on Interfaces Configured Explicitly (Area 0):
         GigabitEthernet0/3
      Passive Interface(s):
         GigabitEthernet0/0
         GigabitEthernet0/1
         GigabitEthernet0/2
      Routing Information Sources:
         Gateway         Distance      Last Update
         192.168.3.9          110      6d22h
      Distance: (default is 110)
```

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
```

**R2 OSPF Configuration:**
```
router ospf 1
router-id 192.168.3.9
network 192.168.2.0 0.0.0.255 area 0
network 192.168.3.0 0.0.0.255 area 0
```
**Routing Table Verification:**

- R1 learns routes to 192.168.2.0/24 and 192.168.3.0/24 via OSPF (Administrative Distance 110)
- R2 learns routes to 192.168.1.0/24, 192.168.100.0/24, 192.168.200.0/24 via OSPF
- OSPF neighbor adjacency established (Full state) on G0/3 (R1) and G0/0 (R2)


<div class="two-col-right">
  <div class="text-col">
    <h3>vSwitch (Layer 2):</h3>
    <ul>
      <li>Provides VLAN trunking and access port simulation</li>
      <li>Supports STP testing and loop prevention validation</li>
      <li>Enables port security and MAC address filtering research</li>
    </ul>

   </ul>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/cisco-switch.png" alt="vSwitch Config screenshot">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        vSwitch VLAN and Interface Configuration.
      </figcaption>
    </figure>
  </div>
</div>
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

<div class="two-col-right">
  <div class="text-col">
   <p>
      The lab operates five independent Docker engines, each hosting isolated workloads to minimize cross‑service impact. Portainer Community Edition provides a centralized GUI for managing all engines, while Portainer Agents enable secure API communication with remote hosts. 
   </p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/docker.png" alt="Docker Deployment Overview">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Docker Deployment Overview.
      </figcaption>
    </figure>
  </div>
</div>

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

#### Docker Compose
Compose files are created in VS Code and stored in a Github repository for version control.
```yaml
services:
  postgresql:
    image: docker.io/library/postgres:16-alpine
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d $${POSTGRES_DB} -U $${POSTGRES_USER}"]
      start_period: 20s
      interval: 30s
      retries: 5
      timeout: 5s
    volumes:
      - database:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD: #######
      POSTGRES_USER: #######
      POSTGRES_DB: authentik-db
    
  redis:
    image: docker.io/library/redis:alpine
    
    command: --save 60 1 --loglevel warning
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep PONG"]
      start_period: 20s
      interval: 30s
      retries: 5
      timeout: 3s
    volumes:
      - redis:/data
  server:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2025.10.3}
    restart: unless-stopped
    
    command: server
    environment:
      AUTHENTIK_SECRET_KEY: ########
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: ######
      AUTHENTIK_POSTGRESQL__NAME: authentik-db
      AUTHENTIK_POSTGRESQL__PASSWORD: ######

    volumes:
      - ./media:/media
      - ./custom-templates:/templates
      - /opt/authentik/certs/:/certs/
      
    ports:
      - "80:9000"
      - "443:9443"
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_healthy
  worker:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2025.10.3}
    restart: unless-stopped
    
    command: worker
    environment:
      AUTHENTIK_SECRET_KEY: #######
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: ######
      AUTHENTIK_POSTGRESQL__NAME: authentik-db
      AUTHENTIK_POSTGRESQL__PASSWORD: #######
      AUTHENTIK_ERROR_REPORTING__ENABLED: true
      AUTHENTIK_EMAIL__HOST: 192.168.1.89
      AUTHENTIK_EMAIL__PORT: 25
      AUTHENTIK_EMAIL__FROM: #########

    user: ######
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./media:/media
      - ./custom-templates:/templates
      - /opt/authentik/certs/:/certs/
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_healthy

volumes:
  database:
    driver: local
  redis:
    driver: local

```
---

### 5.2 Cloud-Native Kubernetes Cluster Deployment

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
   <p>
      The lab runs a dual‑node K3s cluster (one control plane, one worker) on Red Hat Enterprise Linux 10 VMs within the 192.168.200.0/24 subnet. K3s is a fully compliant Kubernetes distribution packaged as a single binary, minimizing external dependencies and simplifying cluster operations. It includes a batteries‑included stack: containerd runtime, Flannel CNI, CoreDNS, Kube‑router, Local‑path‑provisioner, and Spegel registry mirror.
   </p>
   <p>
      The embedded Traefik ingress controller and ServiceLB load balancer have been intentionally disabled and replaced with NGINX Ingress and MetalLB, providing enterprise‑grade ingress routing and Layer‑2 external IP allocation. Portainer integrates with the cluster via a DaemonSet‑based Portainer Agent for full lifecycle management.
   </p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/k3s.png" alt="K3s Cluster Deployment Overview">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        K3s Cluster Deployment Overview.
      </figcaption>
    </figure>
  </div>
</div>
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

![K3s Node COnfiguration](/Career_Projects/assets/screenshots/k3s-nodes.png)

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
| nginx-ingress-controller | Helm/DaemonSet | 2/2 | 192.168.200.31 | HTTP/HTTPS ingress controller for path-based routing |

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
| thehive | Helm | strangebee/thehive:5.5.13-1 | 1/1 | 192.168.200.33 | 9000 (HTTP), 9095 (metrics) | Security incident response platform and case management |
| cortex | Deployment | thehiveproject/cortex:latest | 1/1 | 192.168.200.40 | 9001 (HTTP) | Observable analysis engine with automated responders |
| cassandra | StatefulSet | cassandra:4.1.7 | 1/1 | 192.168.200.36 | 9042 (CQL) | Distributed database for TheHive persistent storage |
| elasticsearch | StatefulSet | elasticsearch:9.2.2 | 1/1 | 192.168.200.34 | 9200 (HTTP) | Search and analytics engine for cases and observables |
| misp-core | Deployment | misp-docker/misp-core:latest | 1/1 | 192.168.200.37 | 80/443 (HTTP/HTTPS) | Threat intelligence platform and IOC management |
| misp-db | Deployment | mariadb:10.11 | 1/1 | ClusterIP only | 3306 (MySQL) | MySQL database for MISP data |
| misp-redis | Deployment | valkey/valkey:7.2 | 1/1 | ClusterIP only | 6379 (Redis) | Redis cache for MISP sessions and jobs |
| misp-modules | Deployment | misp-docker/misp-modules:latest | 1/1 | ClusterIP only | 6666 (HTTP) | MISP enrichment and expansion modules |
| misp-guard | Deployment | misp-docker/misp-guard:latest | 1/1 | ClusterIP only | 8888 (HTTP) | Security proxy for MISP core protection |
| misp-mail | Deployment | egos-tech/smtp:latest | 1/1 | 192.168.200.38 | 25 (SMTP) | SMTP relay for threat intelligence email sharing |
| msmtp-relay | Deployment | alpine:latest | 1/1 | ClusterIP only | N/A | Lightweight SMTP relay for internal notifications |
| shuffle-frontend | Deployment | shuffle-frontend:latest | 1/1 | 192.168.200.41 | 80/443 (HTTP/HTTPS) | React-based web UI for visual workflow design, execution monitoring, and SOAR administration |
| shuffle-backend | Deployment | shuffle-backend:latest | 1/1 | ClusterIP only | 5001 | Go-based backend API handling workflow orchestration, webhook processing, and app management |
| shuffle-opensearch | StatefulSet | opensearch:3.2.0 | 1/1 | ClusterIP only | 9200 (HTTP) | Search and analytics engine for workflow definitions, execution history, and audit logs |
| shuffle-orborus | Deployment | shuffle-orborus:latest | 1/1 | none | | Worker orchestration daemon managing Docker containers for workflow app execution |

#### Server-Admin Namespace - Infrastructure Management

| Application | Type | Image | Replicas | External IP | Ports | Purpose |
|-------------|------|-------|----------|-------------|-------|---------|
| patchmon-frontend | Deployment | patchmon-frontend:latest | 1/1 | 192.168.200.35 | 3000 (HTTP) | Web UI for Windows patch management dashboard |
| patchmon-backend | Deployment | patchmon-backend:latest | 1/1 | 192.168.200.39 | 3001 (HTTP API) | Backend API for patch compliance tracking |
| patchmon-database | Deployment | postgres:17-alpine | 1/1 | ClusterIP only | 5432 (PostgreSQL) | PostgreSQL database for patch status data |
| patchmon-redis | Deployment | redis:7-alpine | 1/1 | ClusterIP only | 6379 (Redis) | Redis cache for session management |

---

## 6. Network Services Summary

### LoadBalancer Services (Externally Accessible)

| Service Name | Namespace | Type | External IP | Ports | Application | Access Method |
|--------------|-----------|------|-------------|-------|-------------|---------------|
| nginx-ingress-controller | nginx-ingress | LoadBalancer | 192.168.200.31 | 80, 443 | Ingress Controller | Primary HTTP/HTTPS ingress point |
| nginx | nginx | LoadBalancer | 192.168.200.32 | 80 | Nginx Web Server | Static web content hosting |
| thehive | soc | LoadBalancer | 192.168.200.33 | 9000, 9095 | TheHive SIRP | Case management UI |
| elasticsearch | soc | LoadBalancer | 192.168.200.34 | 9200 | Elasticsearch | Search API (admin only) |
| patchmon-frontend | server-admin | LoadBalancer | 192.168.200.35 | 3000 | PatchMon UI | Patch management dashboard |
| cassandra | soc | LoadBalancer | 192.168.200.36 | 9042 | Cassandra DB | Database access (admin only) |
| misp-core | soc | LoadBalancer | 192.168.200.37 | 80, 443 | MISP Platform | Threat intelligence portal |
| misp-mail | soc | LoadBalancer | 192.168.200.38 | 25 | SMTP Relay | Email-based threat sharing |
| patchmon-backend | server-admin | LoadBalancer | 192.168.200.39 | 3001 | PatchMon API | Backend API (internal) |
| cortex | soc | LoadBalancer | 192.168.200.40 | 9001 | Cortex Engine | Observable analysis API |
| shuffle | soc | LoadBalancer | 192.168.200.41 | 80/443 | Shuffle | Automation UI |

**Access Control:**

- All services accessible only via Tailscale VPN (no direct internet exposure)
- Administrative services (Elasticsearch, Cassandra) require Authentik SSO + MFA
- Network policies enforce namespace isolation and least-privilege access
- pfSense firewall rules restrict access by source IP and service port

### ClusterIP Services (Internal Only)

| Service Name | Namespace | Cluster IP | Ports | Purpose |
|--------------|-----------|------------|-------|---------|
| kubernetes | default | 10.43.0.1 | 6443 | Kubernetes API server |
| patchmon-database | server-admin | 10.43.3.202 | 5432 | PostgreSQL backend for PatchMon |
| misp-db | soc | 10.43.151.59 | 3306 | MariaDB backend for MISP |
| misp-redis | soc | 10.43.131.214 | 6379 | Redis cache for MISP |
| misp-modules | soc | 10.43.234.246 | 6666 | MISP enrichment modules |
| misp-guard | soc | 10.43.97.195 | 8888 | MISP security proxy |
| patchmon-backend | server-admin | 10.43.99.91 | 3001 | PatchMon API (internal routing) |
| patchmon-redis | server-admin | 10.43.126.102 | 6379 | Redis cache for PatchMon |
| metallb-webhook-service | metallb-system | 10.43.122.116 | 9443 | MetalLB webhook validation |
| shuffle-backend | soc | 10.43.189.138 | 5001 | Shuffle backend integration |
| shuffle-opensearch | soc | 10.43.137.30 | 9200 | Shuffle database |
| nginx-ingress-admission | nginx-ingress | 10.43.241.54 | 443 | Ingress admission webhook |
| cert-manager-webhook | cert-manager | 10.43.150.38 | 443 | SSL termination for nginx-ingress |

**Network Policies:**

- Default deny all ingress/egress traffic
- Explicit allow rules for required service-to-service communication
- Database services (PostgreSQL, MariaDB, Redis) accessible only from their respective application pods
- Rate limiting for Ingress HTTP services
- SSL termination for all ingress HTTP services


### Example Workload: PatchMon
- Namspace: server-admin
- Deployments: 1 replica per deployment with anti-affinity rules
- Persistent Storage: local-path-provisioner (hostPath-based PVCs)
- Exposure: MetalLB LoadBalancer with external IPs
- Persistent Volume Claims / Volumes: patchmon-postgres-pvc & patchmon-redis-pvc

#### Namespace
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: server-admin
```

#### Postgres/Redis PVCs
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: patchmon-postgres-pvc
  namespace: server-admin
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: local-path
---
# Redis PVC
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: patchmon-redis-pvc
  namespace: server-admin
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
  storageClassName: local-path
```

##### Postgres Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: patchmon-database
  namespace: server-admin
spec:
  replicas: 1
  selector:
    matchLabels:
      app: patchmon-database
  template:
    metadata:
      labels:
        app: patchmon-database
    spec:
      initContainers:
      - name: init-chown
        image: busybox
        command: ["sh", "-c", "chown -R 999:999 /var/lib/postgresql/data"]
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
      containers:
      - name: database
        image: postgres:17-alpine
        env:
        - name: POSTGRES_DB
          value: patchmon_db
        - name: POSTGRES_USER
          value: patchmon_user
        - name: POSTGRES_PASSWORD
          value: ######
        livenessProbe:
          exec:
            command: ["pg_isready","-U","patchmon_user","-d","patchmon_db"]
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          exec:
            command: ["pg_isready","-U","patchmon_user","-d","patchmon_db"]
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
          subPath: data
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: patchmon-postgres-pvc
```

#### Redis Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: patchmon-redis
  namespace: server-admin
spec:
  replicas: 1
  selector:
    matchLabels:
      app: patchmon-redis
  template:
    metadata:
      labels:
        app: patchmon-redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command: ["redis-server","--requirepass","#####","--appendonly","yes"]
        livenessProbe:
          exec:
            command: ["redis-cli","-a","#####","ping"]
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          exec:
            command: ["redis-cli","-a","#####","ping"]
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: redis-storage
          mountPath: /data
      volumes:
      - name: redis-storage
        persistentVolumeClaim:
          claimName: patchmon-redis-pvc

```

#### Backend Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: patchmon-backend
  namespace: server-admin
spec:
  replicas: 1
  selector:
    matchLabels:
      app: patchmon-backend
  template:
    metadata:
      labels:
        app: patchmon-backend
    spec:
      containers:
      - name: backend
        image: ghcr.io/patchmon/patchmon-backend:latest
        env:
        - name: LOG_LEVEL
          value: info
        - name: DATABASE_URL
          value: postgresql://patchmon_user:#######
        - name: JWT_SECRET
          value: 
        - name: SERVER_PORT
          value: "3001"
        - name: CORS_ORIGIN
          value: "http://192.168.200.35:3000"
        - name: REDIS_HOST
          value: patchmon-redis
        - name: REDIS_PORT
          value: "6379"
        - name: REDIS_PASSWORD
          value: ####### 
        - name: REDIS_DB
          value: "0"
        livenessProbe:
          httpGet:
            path: /health
            port: 3001
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3001
          initialDelaySeconds: 5
          periodSeconds: 5

```
#### Frontend Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: patchmon-frontend
  namespace: server-admin
spec:
  replicas: 1
  selector:
    matchLabels:
      app: patchmon-frontend
  template:
    metadata:
      labels:
        app: patchmon-frontend
    spec:
      containers:
      - name: frontend
        image: ghcr.io/patchmon/patchmon-frontend:latest
        env:
        - name: BACKEND_HOST
          value: patchmon-backend
        - name: BACKEND_PORT
          value: "3001"
        livenessProbe:
          httpGet:
            path: /index.html
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /index.html
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
```
#### Services
```yaml
apiVersion: v1
kind: Service
metadata:
  name: patchmon-frontend
  namespace: server-admin
spec:
  type: LoadBalancer
  loadBalancerIP: 192.168.200.35
  selector:
    app: patchmon-frontend
  ports:
  - port: 3000
    targetPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: patchmon-backend
  namespace: server-admin
spec:
  type: LoadBalancer
  loadBalancerIP: 192.168.200.39
  selector:
    app: patchmon-backend
  ports:
  - port: 3001
    targetPort: 3001
---
apiVersion: v1
kind: Service
metadata:
  name: patchmon-database
  namespace: server-admin
spec:
  selector:
    app: patchmon-database
  ports:
  - port: 5432
    targetPort: 5432
---
apiVersion: v1
kind: Service
metadata:
  name: patchmon-redis
  namespace: server-admin
spec:
  selector:
    app: patchmon-redis
  ports:
  - port: 6379
    targetPort: 6379

```
---

## 7. Version Control Strategy

- Repository: GitHub repo (infrastructure-as-code)
- Structure: Organized by service (docker-compose/, k8s-manifests/, terraform/Ansible)
- Tooling: VS Code with Docker, Kubernetes, SSH, Ansible, Terraform extensions
- Automation: Watchtower monitors container images, WUD provides update alerts
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
---

**Document Version:** 1.0  
**Last Updated:** January 24, 2026  



