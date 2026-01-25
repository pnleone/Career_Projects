# Network Security, Privacy and Remote Access Architecture

**Created By:** Paul Leone  
**Date:** January 19, 2026  

---

## Table of Contents

1. [Network Security Architecture](#network-security-architecture)
2. [Network Firewall/Router Architecture](#network-firewallrouter-architecture)
   - 2.1 [High-Availability pfSense Cluster](#high-availability-pfsense-cluster)
   - 2.2 [OPNsense Microsegmentation Firewall](#opnsense-microsegmentation-firewall)
   - 2.3 [Fortinet FortiGate 30D Appliance](#fortinet-fortigate-30d-appliance)
   - 2.4 [Firewall Policy Architecture](#firewall-policy-architecture)
3. [Intrusion Detection/Prevention Solutions](#intrusion-detectionprevention-solutions)
   - 3.1 [Suricata Intrusion Detection/Prevention System on pfSense](#suricata-intrusion-detectionprevention-system-on-pfsense)
   - 3.2 [Snort Intrusion Detection/Prevention System on pfSense](#snort-intrusion-detectionprevention-system-on-pfsense)
   - 3.3 [CrowdSec Behavioral Threat Intelligence](#crowdsec-behavioral-threat-intelligence)
   - 3.4 [Multi-Engine Intrusion Detection & Prevention](#multi-engine-intrusion-detection--prevention)
4. [SafeLine Web Application Firewall (WAF)](#safeline-web-application-firewall-waf)
5. [Security Control Summary](#security-control-summary)
6. [Operational Resilience](#operational-resilience)
7. [Use Cases & Deployment Scenarios](#use-cases--deployment-scenarios)
8. [Threat Modeling](#threat-modeling)
9. [Privacy and Remote Access Architecture](#privacy-and-remote-access-architecture)
   - 9.1 [Private Internet Access (PIA) - Encrypted Egress VPN](#private-internet-access-pia---encrypted-egress-vpn)
   - 9.2 [Tailscale - Zero-Trust Remote Access](#tailscale---zero-trust-remote-access)
   - 9.3 [Cloudflare - Secure Service Exposure & DNS Management](#cloudflare---secure-service-exposure--dns-management)
   - 9.4 [Tor Browser - Anonymous Outbound Browsing](#tor-browser---anonymous-outbound-browsing)
10. [Summary](#summary)
11. [Security Homelab Section Links](#security-homelab-section-links)

---

## 1. Network Security Architecture

A defense-in-depth edge security architecture implements multiple layers of inspection, filtering, and threat mitigation across network perimeter, application layer, and endpoint boundaries. This multi-engine security stack combines virtualized firewalls (pfSense/OPNsense), intrusion detection/prevention systems (Suricata/Snort), behavioral threat intelligence (CrowdSec), application-layer filtering (SafeLine WAF), and encrypted tunneling (VPN/Zero-Trust access) to provide enterprise-grade network protection.

**Security Impact:** Multi-layer inspection detects threats missed by single-engine solutions; behavioral analysis identifies zero-day attacks before signature updates; high-availability clustering ensures uninterrupted protection during maintenance; centralized logging enables threat correlation across all security layers; encrypted tunneling protects data in transit and provides secure remote access without exposing internal infrastructure.

**Deployment Rationale:** Enterprise networks deploy layered security controls because attackers increasingly use evasion techniques (encryption, polymorphic malware, living-off-the-land tactics) that bypass signature-based detection. This architecture mirrors Fortune 500 security operations centers (SOCs) where multiple detection engines (IDS/IPS, behavior analytics, threat intelligence feeds) provide overlapping coverage. High-availability firewall clustering reflects production network designs where downtime directly impacts business operations. The implementation demonstrates understanding of OSI layer security (Layer 3/4 firewalls, Layer 7 WAF), threat detection methodologies (signature vs. behavioral), and modern zero-trust access patterns.

**Architecture Principles Alignment:**

- **Defense in Depth:** Five security layers (firewall ACLs → IDS/IPS → behavioral detection → WAF → endpoint protection) ensure single-layer bypass doesn't compromise entire network
- **Secure by Design:** Default-deny firewall policies; encrypted VPN tunnels for remote access; automatic security updates for threat signatures
- **Zero Trust:** Identity verification required for all remote access (Tailscale authentication); no implicit trust based on network location; microsegmentation isolates compromised systems

---

## 2. Network Firewall/Router Architecture

### 2.1 High-Availability pfSense Cluster

#### Deployment Overview

Two pfSense virtual machines operate in an active/passive high‑availability configuration using CARP (Common Address Redundancy Protocol). The primary node synchronizes all configuration and state information to the secondary via a dedicated SYNC interface. In the event of failure, CARP provides sub‑second failover with minimal packet loss, ensuring uninterrupted perimeter protection. Both nodes enforce default‑deny firewall policies, NAT rules, VPN termination, and IDS/IPS inspection.

#### Security Impact

- Continuous perimeter protection even during maintenance or node failure
- Stateful failover preserves active connections, preventing session drops
- Inline Suricata/Snort inspection blocks malicious traffic at the edge
- Centralized logging feeds Splunk for correlation with internal telemetry
- VPN termination provides encrypted remote access without exposing internal networks

#### Deployment Rationale

High‑availability firewalls are standard in enterprise networks where downtime directly impacts business operations. This deployment mirrors production‑grade designs using redundant nodes, synchronized configuration, and automated failover. It demonstrates proficiency with CARP, state synchronization, multi‑WAN routing, and perimeter‑level security enforcement.

#### Architecture Principles Alignment

**Defense in Depth:** Redundant perimeter firewalls ensure continuous enforcement of ACLs, NAT, and IDS/IPS  
**Secure by Design:** Default‑deny rules, TLS‑secured VPNs, and synchronized configurations  
**Zero Trust:** Remote access requires identity verification; no implicit trust in network location

#### Cluster Configuration

| Node Role | Management IP | CARP VIP | State Sync |
|-----------|---------------|----------|------------|
| pfSense-Primary | 192.168.100.2/24 | 192.168.100.1/24 | Master |
| pfSense-Secondary | 192.168.100.3/24 | 192.168.100.1/24 | Backup |
| Sync Network | 10.10.0.0/24 | Dedicated | xmlrpc |

<div class="two-col-right">
  <div class="text-col">
    <h4>Interface Design</h4>
    <ul>
      <li>WAN(Prod_LAN) - Eth0</li>
      <li>LAN - WIFI bridge</li>
      <li>Sync - virtual interface for HA sync</li>
      <li>PIA_NY - VPN for outbound traffic</li>
      <li>PIA_CAN_MONT - VPN for outbound traffic</li>
      <li>TSCALE - Mesh VPN for remote access</li>
      <li>LAN2 - virtual interface</li>
      <li>External LAN - virtual interface</li>
    </ul>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/pfsense-interfaces.png" alt="pfSense Interface Configuration">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        pfSense HA Interface Configuration.
      </figcaption>
    </figure>
  </div>
</div>

| Interface | Physical/Virtual | Network | Purpose |
|-----------|------------------|---------|---------|
| Prod_LAN | vtnet0 | 192.168.1.253/24 | Upstream gateway to ISP router |
| Lab_LAN1 | vtnet1 (bridge) | 192.168.100.2/24 | Primary lab network |
| SYNC | vtnet2 | 10.10.0.2/24 | HA state synchronization |
| PIA_NY | ovpnc1 | (Dynamic) | VPN egress - New York endpoint |
| PIA_CA_MONT | ovpnc2 | (Dynamic) | VPN egress - Montreal endpoint |
| TSCALE | tailscale0 | (Dynamic /32) | WireGuard mesh VPN for remote access |
| Lab_LAN2 | vtnet3 | 192.168.200.2/24 | Kubernetes cluster network |
| EXT_LAN | vtnet4 | 192.168.2.2/24 | External lab services (DMZ-style) |

**Traffic Flow Architecture:**

- Default Route: LAN traffic (192.168.100.0/24) → PIA VPN → Internet
- Policy-Based Routing: Selective traffic bypass for latency-sensitive apps
- VPN Failover: Automatic failover between PIA_NY and PIA_CA_MONT on tunnel failure
- Kill Switch: Floating rule blocks LAN egress if all VPN tunnels are down

#### Security Enhancement Packages

**pfBlockerNG - IP Reputation & Geofencing**

Purpose: Network-layer blocking of malicious IPs and geographic regions

Configuration:

- Blocklists: 15+ curated feeds (Emerging Threats, Spamhaus, Abuse.ch)
- Update Frequency: Hourly refresh of threat intelligence feeds
- Geo-blocking: Block inbound from high-risk countries (configurable whitelist)
- Integration: Feeds alias tables used in firewall rules
- Use Case: Prevent C2 callbacks, block known botnets, reduce attack surface

**Suricata IDS/IPS**

Deployment: Active on WAN and LAN interfaces (both pfSense nodes)  
Mode: Inline IPS with legacy blocking (balances performance vs. protection)

Rulesets:

- Emerging Threats Open (ET Open) - 40,000+ signatures
- Suricata Community Rules
- Custom local rules for lab-specific threat patterns

Configuration:

- Action: Drop + Alert on HIGH/CRITICAL severity events
- Performance: Disabled CPU-intensive rules for lab environment constraints
- Logging: JSON output forwarded to Splunk and Elastic via syslog-ng

Use Case: Real-time detection of exploits, malware, and lateral movement attempts

**Snort IDS/IPS**

Deployment: Active on PIA VPN interfaces (monitors encrypted tunnel egress)  
Mode: Inline IPS for outbound traffic inspection

Rulesets:

- Snort Community Rules
- Talos Intelligence Registered User Rules
- Custom rules for data exfiltration patterns

Rationale: While Suricata monitors north-south and east-west traffic, Snort provides additional coverage on VPN tunnels where traffic exits the lab. This dual-engine approach catches threats that might evade a single detection system.

**CrowdSec - Behavioral Threat Intelligence**

Architecture: Remediation Bouncer receives block decisions via LAPI, enforces at firewall

---

### 2.2 OPNsense Microsegmentation Firewall

#### Deployment Overview

A standalone OPNsense VM provides an additional security boundary for sensitive lab assets. Positioned behind the pfSense perimeter, it enforces microsegmentation policies, isolates high‑value systems, and applies independent firewall rules, IDS/IPS policies, and access controls.

#### Security Impact

- Prevents lateral movement into sensitive subnets
- Independent policy engine ensures compromise of pfSense does not expose protected assets
- Additional IDS/IPS layer increases detection coverage
- Segmented logging improves visibility into east‑west traffic

#### Deployment Rationale

Microsegmentation is a core zero‑trust principle used in enterprise environments to isolate critical systems. Deploying OPNsense as a "firewall within a firewall" demonstrates layered security design, redundancy, and compartmentalization of trust domains.

#### Architecture Principles Alignment

**Defense in Depth:** Independent firewall layer behind pfSense perimeter  
**Secure by Design:** Segmented networks, isolated rule sets, and dedicated IDS/IPS  
**Zero Trust:** No internal subnet is implicitly trusted; access requires explicit policy

#### Interface Configuration

| Interface Name | Type | Network | Security Zone | Role |
|----------------|------|---------|---------------|------|
| PROD_LAN | Physical (eth0) | 192.168.1.0/24 | Trusted | Uplink to production network; allows controlled ingress from ISO_LAN |
| ISO_LAN | Virtual (OPTx) | 10.20.0.0/24 | Restricted | Isolated segment for sensitive hosts; tightly scoped egress rules |

**Protected Assets (ISO_LAN):**

- Vulnerability management scanners (OpenVAS, Nessus)
- Configuration management (Ansible control node)
- Security logging infrastructure (Splunk forwarder)
- Certificate authority and PKI services
- Backup repositories with encrypted data

**Firewall Policy Philosophy:**

Default Deny with Explicit Allow - Zero trust model where all traffic is blocked unless explicitly permitted by rule. This inverts traditional firewall logic and ensures unknown traffic patterns are automatically rejected.

---

### 2.3 Fortinet FortiGate 30D Appliance

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>
      The FortiGate 30D serves as a dedicated microsegmentation firewall protecting the management VLAN (192.168.3.0/24). Operating in unlicensed mode as an end-of-support device, it provides basic Layer 3/4 firewall functionality, SSL VPN access, and serves as a hands-on platform for FortiOS CLI and GUI administration. Despite lacking current threat intelligence updates, the appliance demonstrates enterprise firewall concepts including policy-based routing, SSL VPN configuration, and interface-based security zones.
    </p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/misc/fortinet.png" alt="FortiGate 30D Hardware">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        FortiGate 30D Physical Appliance.
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Enforces strict access controls to management subnet (VLAN 3)
- SSL VPN provides encrypted remote access to administrative interfaces
- Policy-based firewall rules segment management traffic from production workloads
- Hands-on experience with enterprise-grade firewall appliance management
- Demonstrates defense-in-depth by adding physical firewall layer behind virtual pfSense/OPNsense

#### Deployment Rationale

Fortinet holds significant market share in enterprise network security, making FortiOS proficiency valuable for security roles. Operating an end-of-life appliance demonstrates understanding of legacy system risk management, compensating controls deployment, and resource-constrained security operations. The appliance serves educational purposes for Fortinet NSE certification preparation and FortiOS command-line interface skill development.

#### Architecture Principles Alignment

- **Defense in Depth:** Physical appliance provides hardware-based firewall enforcement independent of virtual infrastructure
- **Secure by Design:** Default-deny firewall policies; SSL VPN requires certificate-based authentication
- **Zero Trust:** Management VLAN access requires explicit firewall rules; no implicit trust between zones

**Diagram Placeholder: FortiGate Dashboard Screenshot**

#### Configuration Highlights

**SSL VPN Configuration:**

- Certificate-based authentication for remote administrative access
- Split-tunnel routing directs only management traffic through VPN
- FortiClient compatibility for Windows, macOS, Linux endpoints
- Per-user access policies restrict VPN access to authorized administrators

**Firewall Policy Architecture (VLAN 3 Protection):**

- Default-deny ingress from all external zones
- Explicit allow rules for SSH (port 22), HTTPS (port 443) from trusted source IPs
- Stateful inspection tracks connection state for allowed flows
- Logging enabled for all policy hits to support forensic analysis

**Interface Configuration:**

- Internal (port1): 192.168.3.1/24 - Management VLAN gateway
- External (port2): 192.168.1.x/24 - Uplink to production network
- DMZ (port3): Reserved for future isolated services deployment

<figure>
      <img src="/Career_Projects/assets/screenshots/fortigate-int.png" alt="FortiGate Address/Device Configuration">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        FortiGate Address/Device Configuration.
      </figcaption>
    </figure>

<figure>
      <img src="/Career_Projects/assets/screenshots/fortigate-vpn.png" alt="FortiGate VPN Configuration">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        FortiGate VPN Configuration.
      </figcaption>
    </figure>

**Limitations & Compensating Controls**

Due to end-of-support status:

- No current threat intelligence updates - Compensated by pfSense Suricata/Snort IDS/IPS
- No firmware updates available - Mitigated by restricting management VLAN exposure
- Limited UTM features - Supplemented by pfBlockerNG, CrowdSec, SafeLine WAF
- Educational use only - Not relied upon for production-critical security enforcement

**Use Cases**

- Fortinet NSE certification lab environment
- FortiOS CLI command practice and automation scripting
- SSL VPN troubleshooting and configuration testing
- Firewall rule optimization and policy analysis
- Vendor-neutral firewall concepts demonstration

---

### 2.4 Firewall Policy Architecture

#### pfSense Rule Sets

##### LAN Rules Configuration

<figure>
      <img src="/Career_Projects/assets/screenshots/pfs-lab_lan1.png" alt="pfSense Lab_LAN1 Rules">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        pfSense Lab_LAN1 Rules.
      </figcaption>
    </figure>

##### WAN Rules Configuration

<figure>
      <img src="/Career_Projects/assets/screenshots/pfs-prod_LAN1.png" alt="pfSense Prod_LAN Rules">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        pfSense Prod_LAN Rules.
      </figcaption>
    </figure>

##### Floating Rules Configuration

<figure>
      <img src="/Career_Projects/assets/screenshots/pfs-float.png" alt="pfSense Floating Rules">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        pfSense Floating Rules.
      </figcaption>
    </figure>

**VPN Kill Switch Details:**

This critical floating rule ensures that if the PIA VPN tunnel drops (failure, misconfiguration, or provider outage), traffic from LAN/LAN2 networks cannot egress through the unencrypted Verizon WAN connection. The rule triggers when the gateway is not one of the PIA interfaces, immediately blocking traffic to prevent IP leakage or unintended cleartext transmission.

#### OPNsense Rule Sets

<figure>
      <img src="/Career_Projects/assets/screenshots/opn-rules.png" alt="OPNsense Rules">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        OPNsense ISO_LAN and Prod_LAN Rules.
      </figcaption>
    </figure>

**Firewall Rule Logic**

**ISO_LAN Rules**

- **Default Policy**: Deny all; allow only explicitly defined flows.
- **Allowed Destinations**:
  - Webserver1, Proxy on ports defined by alias web_ports (e.g., 80, 443)
  - DNS_Servers via UDP port 53
- **Special Notes**:
  - Automatically generated rules allow traffic to the firewall itself and interface IPs.
  - No blanket LAN-to-any rules—only scoped access to specific services.

**Prod_LAN Rules**

- **Allowed Ingress to ISO_LAN**:
  - Port 22 (SSH) for OfficePC and Ansible access
  - Any for OpenVAS scanning and secure access
- **Logging Enabled**

**Security Considerations:**

- OpenVAS "Allow Any": Required for comprehensive vulnerability scanning across diverse ports and protocols. Traffic is authenticated and logged. Consideration: time-based scheduling to limit exposure window.
- Automatic Rules: OPNsense auto-generates rules for firewall self-management (DHCP, DNS, NTP). These are not shown but are logged in audit trail.

#### FortiGate Firewall Rules

<figure>
      <img src="/Career_Projects/assets/screenshots/fortigate-rules.png" alt="FortiGate Rules">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        FortiGate ISO_LAN2 and Prod_LAN Rules.
      </figcaption>
    </figure>

| Name | From | To | Source | Destination | Service | Action | NAT | Log |
|------|------|-----|--------|-------------|---------|--------|-----|-----|
| VPN-users | SSL-VPN tunnel interface (ssl.root) | Prod_LAN (lan) | all | paul | ALL | **P** | **P** | All |
| Allow MGMT to ISO_LAN | Prod_LAN (lan) | ISO_LAN (wan) | Lab_LAN1;Lab_LAN2;Prod_LAN | ISO_LAN | ALL_ICMP;HTTP;HTTPS;SSH | **P** | **O** | All |
| DNS Access for ISO_LAN | ISO_LAN (wan) | Prod_LAN (lan) | ISO_LAN | DNS Servers | DNS | **P** | **O** | All |
| OpenVAS scanning | Prod_LAN (lan) | ISO_LAN (wan) | OpenVAS | ISO_LAN | ALL | **P** | **O** | UTM |
| Syslog Access | ISO_LAN (wan) | Prod_LAN (lan) | ISO_LAN | Web/Syslog Server | SYSLOG;Web Access | **P** | **O** | UTM |
| Prometheus Metrics | ISO_LAN (wan) | Prod_LAN (lan) | ISO_LAN | Prometheus Server | prometheus | **P** | **O** | UTM |
| Wazuh EDR Monitoring | ISO_LAN (wan) | Prod_LAN (lan) | ISO_LAN | Wazuh Server | ALL | **P** | **O** | UTM |
| Ansible Provisioning | Prod_LAN (lan) | ISO_LAN (wan) | Ansible Server | ISO_LAN | SSH | **P** | **O** | All |
| Elastic Agent to Fleet Server | ISO_LAN (wan) | Prod_LAN (lan) | ISO_LAN | Elastic Server | Elastic Ports | **P** | **O** | UTM |
| StepCA/ACME Access to ISO_LAN | Prod_LAN (lan) | ISO_LAN (wan) | StepCA Server | ISO_LAN | ALL | **P** | **O** | UTM |
| Admin Access to ISO_LAN | Prod_LAN (lan) | ISO_LAN (wan) | iPad Pro;OfficePC | ISO_LAN | ALL | **P** | **O** | All |
| Nessus Scanner Access to ISO | Prod_LAN (lan) | ISO_LAN (wan) | Nessus Server | ISO_LAN | ALL | **P** | **O** | UTM |
| Traefik Proxy Access | Prod_LAN (lan) | ISO_LAN (wan) | Traefik Server | ISO_LAN | Web Access | **P** | **O** | All |
| Implicit Deny | any | any | all | all | ALL | **O** | **O** | |

---

## 3. Intrusion Detection/Prevention Solutions

### 3.1 Suricata Intrusion Detection/Prevention System on pfSense

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>
      Each pfSense node runs Suricata in inline IPS mode, inspecting both WAN and LAN interfaces. Suricata performs deep packet inspection, signature‑based detection, and behavioral anomaly detection. Rule sets include Emerging Threats, custom local rules, and tuned signatures for lab‑specific traffic patterns.
    </p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/suricata-config.png" alt="Suricata Configuration">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Suricata IPS Configuration on pfSense.
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Real‑time blocking of known attack signatures
- Deep packet inspection identifies malicious payloads and protocol anomalies
- Custom rules detect lab‑specific threats and reconnaissance
- Alerts forwarded to Splunk for centralized correlation
- Inline mode prevents malicious traffic before it reaches internal systems

#### Deployment Rationale

Suricata is widely used in enterprise IDS/IPS deployments due to its performance, rule flexibility, and multi‑threaded architecture. Running Suricata inline on pfSense mirrors production edge security designs and demonstrates proficiency with rule tuning, packet inspection, and IPS enforcement.

#### Architecture Principles Alignment

**Defense in Depth:** IDS/IPS layer reinforces firewall ACLs and WAF protections  
**Secure by Design:** Inline blocking, updated rule feeds, and custom signatures  
**Zero Trust:** All traffic inspected; no packet trusted without validation

[Suricata block list Screenshot](#suricata-block-list)

---

### 3.2 Snort Intrusion Detection/Prevention System on pfSense

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>
      Snort runs in inline IPS mode on each pfSense node, monitoring PIA VPN interfaces for malicious traffic. This provides an additional detection engine specifically focused on encrypted or tunneled traffic paths.
    </p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/snort-config.png" alt="Snort Configuration">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Snort IPS Configuration on pfSense.
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Detects threats traversing VPN tunnels
- Provides signature diversity alongside Suricata
- Alerts forwarded to Splunk for unified SOC visibility
- Inline blocking prevents malicious VPN traffic from entering the network

#### Deployment Rationale

Running both Suricata and Snort mirrors enterprise SOC environments where multiple IDS engines provide overlapping detection coverage. This reduces blind spots and increases detection accuracy across encrypted or obfuscated traffic.

#### Architecture Principles Alignment

**Defense in Depth:** Dual IDS engines reduce reliance on a single detection method  
**Secure by Design:** Inline enforcement and updated rule sets  
**Zero Trust:** VPN traffic inspected and validated; no implicit trust in encrypted tunnel

---

### 3.3 CrowdSec Behavioral Threat Intelligence

#### Deployment Overview

CrowdSec analyzes logs from firewalls, web servers, containers, and authentication systems to detect behavioral anomalies. It identifies brute‑force attempts, scanning activity, credential stuffing, and distributed attacks using a community‑driven threat intelligence model. Remediation actions are applied via bouncers across firewalls and services.

#### Security Impact

- Detects zero‑day and behavioral attacks missed by signature‑based IDS
- Community‑driven blocklists provide real‑time global threat intelligence
- Automated remediation reduces response time
- Integrates with pfSense, NGINX, and container workloads

#### Deployment Rationale

Behavior‑based detection is essential in modern environments where attackers use evasion techniques to bypass signature‑based systems. CrowdSec mirrors enterprise UEBA (User and Entity Behavior Analytics) platforms and demonstrates proficiency with log‑driven threat detection.

#### Architecture Principles Alignment

**Defense in Depth:** Behavioral analytics complements IDS/IPS and WAF layers  
**Secure by Design:** Automated remediation and continuous log analysis  
**Zero Trust:** No IP or user trusted without behavioral validation

| Component | Location | Role |
|-----------|----------|------|
| CrowdSec Engine | Debian LXC | Log parsing, scenario evaluation, decision making |
| CrowdSec Logger | Debian LXC | Structured log collection from pfSense, Suricata, SSH |
| Remediation Bouncer | pfSense Firewall | Receives block decisions via LAPI, enforces at firewall |
| Hub Collections | CrowdSec Hub | Pre-configured parsers and scenarios for common attack patterns |

<div class="two-col-right">
  <div class="text-col">
    <ul>
      <li><strong>Engine + Logger in LXC:</strong> The CrowdSec engine is running in a lightweight container. The logger component ensures structured log delivery and supports future expansion to additional sources like Wazuh or OpenVAS.</li>
      <li><strong>pfSense Remediation:</strong> The firewall bouncer on pfSense receives decisions from the LAPI and applies real-time blocks at the network edge. This setup ensures low-latency response to threats and keeps enforcement close to ingress points.</li>
      <li><strong>Hub Collections:</strong> Deployment of curated collections from the CrowdSec Hub, including:
        <ul>
          <li>Blocklists</li>
          <li>Scenarios (SSH brute force, port scans)</li>
          <li>Parsers for pfSense</li>
        </ul>
      </li>
      <li><strong>LAPI Connectivity:</strong> The pfSense bouncer is authenticated via API key and successfully pulling decisions from the LAPI endpoint. The engine is streaming decisions and community intelligence in near real-time.</li>
    </ul>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/crowdsec-config.png" alt="CrowdSec Configuration">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        CrowdSec Engine and Bouncer Configuration.
      </figcaption>
    </figure>
  </div>
</div>

**Scenarios Enabled:**

- SSH brute force detection (10 failed attempts in 60s)
- HTTP scanning and enumeration
- Port scan detection
- CVE-specific exploit attempts

**Community Intelligence:**

- Shares anonymized attack signatures to global CrowdSec network
- Receives proactive blocks for IPs flagged by other CrowdSec users
- Real-time threat feed updates (>1M malicious IPs maintained)

**Integration Points:**

- Log Sources: pfSense (firewall logs), Suricata (IDS alerts), SSH (auth logs)
- Enforcement: Dynamic firewall rules via pfSense bouncer API
- Visibility: Decision stream visible in CrowdSec dashboard

**Diagram Placeholder: CrowdSec Dashboard Screenshot**

---

### 3.4 Multi-Engine Intrusion Detection & Prevention

#### Layered IDS/IPS Strategy

| Engine | Vendor | Deployment Location | Detection Method | Rule Sets | Purpose |
|--------|--------|---------------------|------------------|-----------|---------|
| Suricata | OISF | pfSense WAN interface | Signature + Protocol Anomaly | Emerging Threats, ET Pro | Primary IPS (inline blocking) |
| Snort | Cisco/Talos | pfSense LAN interface | Signature-based | Snort Community, VRT | Secondary IDS (monitoring) |
| CrowdSec | CrowdSec SAS | Dedicated Debian LXC | Behavioral Analytics | Community scenarios + custom | Brute-force/scan detection |

**Why Multiple IDS/IPS Engines?**

- **Evasion Resistance:** Attackers design exploits to bypass specific IDS engines; multiple engines provide redundancy
- **Complementary Coverage:** Suricata excels at protocol analysis (HTTP, TLS, DNS deep inspection); Snort strong on signature matching; CrowdSec detects behavioral patterns (brute force, port scans)
- **Reduced False Negatives:** Single engine misses ~15-20% of threats; dual engines reduce miss rate to <5%
- **Signature Diversity:** Different rule sets (Emerging Threats vs. Snort VRT) cover different threat landscapes

---
## 4. SafeLine Web Application Firewall (WAF)

#### Deployment Overview

SafeLine (SafePoint) is an open‑source, enterprise‑grade WAF protecting multiple web portals, including the Apache external dashboard and NGINX workloads in K3s. It provides real‑time threat detection, automated blocking, and protection against OWASP Top 10 vulnerabilities. SafeLine also includes bot mitigation, HTTP‑flood DDoS protection, and machine‑learning‑based anomaly detection.

#### Security Impact

- Protects against SQL injection, XSS, command injection, and path traversal
- Blocks malicious bots, credential stuffing, and scraping attempts
- Mitigates HTTP flood and application‑layer DDoS attacks
- Detects zero‑day patterns via behavioral analysis
- Adds a dedicated Layer‑7 security boundary before backend services

#### Deployment Rationale

- **Application Layer Protection**: Provides granular inspection and filtering of HTTP/HTTPS traffic that network firewalls and IDS/IPS cannot effectively analyze
- **OWASP Top 10 Coverage**: Protects against SQL injection, cross-site scripting (XSS), command injection, path traversal, and other common web application vulnerabilities
- **Bot Mitigation**: Distinguishes between legitimate users and malicious bots, preventing automated attacks, credential stuffing, and web scraping
- **DDoS Protection**: Mitigates HTTP flood attacks and application-layer DDoS attempts that bypass network-level protections
- **Zero-Day Defense**: Utilizes machine learning and behavioral analysis to detect novel attack patterns not covered by signature-based systems
- **Defense in Depth**: Adds an additional security layer between the reverse proxy (Traefik) and backend applications, implementing the principle of layered security
- **Compliance Requirements**: Meets regulatory requirements for web application security controls (PCI DSS 6.6, HIPAA, SOC 2)
- **Centralized Security Policy**: Provides unified protection for multiple web applications with consistent security policies and centralized management

#### Architecture Principles Alignment

**Defense in Depth:** Adds a Layer‑7 security layer above firewall and IDS/IPS  
**Secure by Design:** OWASP Top 10 protections, bot filtering, and DDoS mitigation  
**Zero Trust:** Every HTTP request inspected; no implicit trust in client behavior

### Component Architecture

Deployed on a Debian 13 host with an embedded Docker engine, the solution follows a microservices architecture pattern with specialized containers handling distinct security and operational functions. The platform operates on a dedicated Docker bridge network (172.22.222.0/24) with internal service-to-service communication.

| Container Name | Image | IP | Description |
|----------------|-------|-----|-------------|
| safeline-chaos | chaitin/safeline-chaos-g:latest | 172.22.222.10 | Chaos testing container used to simulate faults, stress, and unexpected conditions in the system to validate resilience and recovery strategies. |
| safeline-detector | chaitin/safeline-detector-g:latest | 172.22.222.5 | Detector service container responsible for monitoring traffic, analyzing patterns, and identifying potential threats or anomalies in real time. |
| safeline-fvm | chaitin/safeline-fvm-g:latest | 172.22.222.8 | FVM execution container that runs sandboxed function evaluations, often used for analyzing payloads or executing detection logic safely. |
| safeline-luigi | chaitin/safeline-luigi-g:latest | 172.22.222.7 | Luigi workflow container orchestrating background jobs, pipelines, and task dependencies for data processing and system automation. |
| safeline-mgt | chaitin/safeline-mgt-g:latest | 172.22.222.4 | Management interface container providing the admin dashboard, APIs, and configuration endpoints for controlling and monitoring the Safeline system. |
| safeline-pg | chaitin/safeline-postgres:15.2 | 172.22.222.2 | Postgres database container storing persistent data such as configurations, detection logs, and case metadata for the Safeline platform. |
| safeline-tengine | chaitin/safeline-tengine-g:latest | | Tengine web server container acting as the reverse proxy and load balancer, handling inbound traffic and routing requests to the appropriate backend services. |

### Configuration Overview

**Diagram Placeholder: SafeLine Protected Sites Screenshots (2 images)**

SafeLine WAF currently protects four separate web portals:

- Heimdall main lab dashboard
- Apache external lab dashboard
- Nginx web server in K3s
- Proxmox PVE admin portal

**Diagram Placeholder: SafeLine Protection Modules Screenshot**

Active protections include Intelligent web threat detection, bot and HTTP flood DDoS protection. Additional authorization via Authentik/OIDC provided where required.

**Diagram Placeholder: SafeLine Bot Protection Screenshot**

### Active Protection Modules

**1. Intelligent Web Threat Detection**

- **SQL Injection Protection**: Pattern matching and syntax analysis detecting SQL injection attempts across GET/POST parameters, headers, and cookies
- **Cross-Site Scripting (XSS) Prevention**: Context-aware detection of reflected, stored, and DOM-based XSS attacks
- **Command Injection Defense**: Identifies attempts to execute operating system commands through web application vulnerabilities
- **Path Traversal Detection**: Blocks directory traversal attacks attempting to access files outside the web root
- **Remote File Inclusion (RFI/LFI)**: Prevents inclusion of malicious remote or local files
- **XML External Entity (XXE) Prevention**: Detects and blocks XXE injection attempts in XML parsers
- **Server-Side Request Forgery (SSRF)**: Identifies attempts to make the server perform unintended requests
- **Machine Learning Anomaly Detection**: Behavioral analysis identifying zero-day attacks and novel exploitation techniques

**2. Bot and Automated Attack Protection**

- **Bot Classification Engine**: Distinguishes between legitimate bots (search engines, monitoring tools) and malicious bots
- **Credential Stuffing Prevention**: Detects and blocks automated login attempts using compromised credential lists
- **Account Takeover Protection**: Behavioral analysis identifying suspicious authentication patterns
- **Web Scraping Mitigation**: Rate limiting and fingerprinting to prevent data extraction attacks
- **CAPTCHA Integration**: Challenge-response mechanism for suspicious sessions (future roadmap)
- **JavaScript Challenge**: Browser validation ensuring requests originate from legitimate browsers

**3. HTTP Flood DDoS Protection**

- **Connection Rate Limiting**: Per-IP connection limits preventing resource exhaustion (default: 100 connections/IP)
- **Request Rate Limiting**: Application-level rate limiting (30-100 requests/minute depending on endpoint sensitivity)
- **Slowloris Protection**: Timeouts for slow HTTP attacks attempting to exhaust server connections
- **HTTP GET/POST Flood Mitigation**: Detects and blocks high-volume application-layer DDoS attacks
- **Burst Handling**: Allows legitimate traffic spikes while blocking sustained flood attacks
- **Geo-Rate Limiting**: Stricter rate limits for high-risk geographic regions

**Diagram Placeholder: SafeLine HTTP Flood/Rate Limiting Screenshot**

**Diagram Placeholder: SafeLine Anti-Bot Screenshot**

**Diagram Placeholder: SafeLine Attack Protection Screenshots (5 images showing SQLi, Code Injection, File Inclusion, Path Traversal, XSS)**

**Offline Mode:**

**Diagram Placeholder: SafeLine Offline Mode Screenshots (2 images)**

**Password and OIDC Authorization:**

**Diagram Placeholder: SafeLine Authorization Screenshots (2 images)**

---

## 5. Security Control Summary

### Security Control Framework

#### Network Security Controls

| Control Type | Implementation | Coverage |
|--------------|----------------|----------|
| Perimeter Defense | pfSense HA cluster with IDS/IPS | 100% inbound/outbound |
| Microsegmentation | OPNsense and FortiGate isolated zones | Critical assets only |
| Threat Intelligence | CrowdSec + pfBlockerNG | 1M+ malicious IPs blocked |
| Intrusion Detection | Suricata + Snort (dual-engine) | WAN; LAN; VPN interfaces |
| Geographic Blocking | pfBlockerNG GeoIP | 15+ high-risk countries |
| VPN Privacy | PIA multi-region tunnels, FortiGate VPN | 192.168.100.0/24; 192.168.2.0/24 |
| Zero Trust Access | Tailscale mesh VPN + ACLs | Remote administrative access |
| Data Loss Prevention | VPN kill switch floating rule | Prevents cleartext fallback |

#### Detection & Response Capabilities

- Real-Time Alerting: Suricata/Snort alerts forwarded to Splunk within seconds
- Automated Blocking: CrowdSec decisions enforced at firewall in <5 seconds
- Signature Coverage: 40,000+ IDS rules across Suricata and Snort
- Community Intelligence: CrowdSec shares threat data with global network
- Logging Retention: 90 days in Splunk/Elastic, 30 days on firewall local storage
- Incident Response: Playbooks for common scenarios (DDoS, brute force, scanning)

---

## 6. Operational Resilience

### Operational Resilience & High Availability

#### Redundancy Architecture

| Component | Primary Node | Secondary Node | Failover Time | Mechanism |
|-----------|--------------|----------------|---------------|-----------|
| pfSense Firewall | pfSense-01 | pfSense-02 | <5 seconds | CARP + pfsync |
| PIA VPN Tunnels | PIA_NY | PIA_CA_MONT | <10 seconds | Gateway monitoring |
| Suricata IDS | Active | Active | N/A | Distributed |
| CrowdSec LAPI | LXC-Primary | Manual failover | <1 minute | API endpoint change |

#### Failure Scenarios & Response

| Scenario | Detection Method | Automated Response |
|----------|------------------|-------------------|
| pfSense primary failure | CARP heartbeat timeout | Secondary assumes VIP; routing continues |
| PIA VPN tunnel down | Gateway ping monitoring | Failover to alternate tunnel or kill switch |
| Suricata process crash | Service Watchdog package | Automatic restart within 30s |
| CrowdSec engine failure | Systemd watchdog | Service restart; alert to monitoring |
| Network interface failure | Link state monitoring | Traffic reroutes to alternate interface |

#### Monitoring & Alerting

- Prometheus Node Exporter: Collects firewall metrics (CPU, memory, connection count)
- Splunk/Elastic Dashboards: Real-time visibility into blocked threats, VPN status, rule hits
- Service Watchdog: Monitors critical services (OpenVPN, Suricata, Snort, CrowdSec)
- Uptime Kuma: External health checks on firewall management interfaces
- Discord Alerts: Triggered on VPN failure, IPS signature hits (HIGH severity)

#### Backup & Recovery

- Configuration Backups: Weekly to Proxmox Backup Server and Synology NAS
- Disaster Recovery: Restore from backup to new VM in <15 minutes
- Change Management: Version control for rule sets via Git repository

---

## 7. Use Cases & Deployment Scenarios

### Practical Use Cases

#### Scenario 1: Privacy-Enhanced Web Browsing

**Objective:** Anonymize lab traffic and prevent ISP tracking

**Implementation:**

- User traffic from 192.168.100.0/24 → pfSense LAN → PIA VPN → Internet
- Policy-based routing ensures all HTTP/HTTPS uses encrypted tunnel
- Kill switch prevents accidental cleartext transmission
- Geolocation appears as VPN endpoint (New York or Montreal)

**Result:** ISP sees only encrypted VPN tunnel, not individual browsing sessions

#### Scenario 2: Remote Lab Access While Traveling

**Objective:** Securely access lab infrastructure from untrusted networks

**Implementation:**

- Laptop connects to Tailscale mesh VPN (WireGuard)
- Traffic routed through pfSense TSCALE interface
- ACLs restrict access to management subnets only

**Result:** Zero-trust remote access without exposed public IPs or open firewall ports

#### Scenario 3: Threat Intelligence Sharing & Automated Response

**Objective:** Leverage community threat data for proactive blocking

**Implementation:**

- CrowdSec engine analyzes logs from pfSense, Suricata, SSH
- Detects brute force attempt on SSH (10 failed logins in 60s)
- Decision sent to pfSense bouncer via LAPI
- IP immediately blocked at firewall, shared with CrowdSec community

**Result:** Lab benefits from global threat intelligence; contributes to community defense

#### Scenario 4: Multi-Region Content Testing

**Objective:** Test geo-restricted services from different regions

**Implementation:**

- Policy-based routing sends test traffic to PIA_NY or PIA_CA_MONT
- Applications see requests originating from US or Canada
- Used for CDN behavior testing, regional service validation

**Result:** Simulates distributed user base without physical infrastructure in multiple regions

---

## 8. Threat Modeling

### Threat Landscape & Mitigation Strategy

#### Threats Addressed

| Threat Category | Attack Vectors | Mitigation Controls |
|-----------------|----------------|---------------------|
| Network Reconnaissance | Port scans; host enumeration | Suricata port scan detection; pfBlockerNG |
| Brute Force Attacks | SSH; web panel login abuse | CrowdSec behavioral detection; fail2ban integration; Key-based authentication for endpoints; WAF bot-credential stuffing prevention |
| Malware C2 Communication | Botnet callbacks | pfBlockerNG IP reputation; IDS signatures |
| Data Exfiltration | Unauthorized outbound traffic | Egress filtering; VPN kill switch |
| Man-in-the-Middle | ARP spoofing; SSL stripping | Encrypted tunnels (VPN; Tailscale) |
| DDoS / Resource Exhaustion | High-volume flood attacks | Connection limits; SYN flood protection; WAF HTTP flood prevention |
| Lateral Movement | Post-compromise pivoting | Microsegmentation (OPNsense); VLAN isolation |
| Zero-Day Exploits | Unknown vulnerabilities | Multi-engine IDS (overlapping signatures) |
| Web Application Exploits | SQL injection, XSS, XXE, command injection, LDAP injection, template injection | OWASP ModSecurity CRS rules; ML-based anomaly detection; input validation enforcement; output encoding verification |
| Bot Attacks | Web scraping, automated account creation, inventory hoarding, content theft, fake account registration | Bot fingerprinting; JavaScript challenge; CAPTCHA integration; behavioral analysis; rate limiting per user-agent pattern |
| Server-Side Request Forgery (SSRF) | Internal network reconnaissance, cloud metadata access, backend service exploitation | URL validation; whitelist of allowed domains; blocking private IP ranges; DNS rebinding protection |
| Directory Traversal | Path manipulation, file system access, configuration file disclosure | Path normalization; restricted file access; chroot enforcement; symbolic link traversal prevention |
| XML/JSON Attacks | Billion Laughs attack, entity expansion, JSON injection, XML bomb | Entity expansion limits; recursive depth restrictions; parser hardening; size limits |
| Protocol Manipulation | HTTP request smuggling, header injection, response splitting, HTTP/2 desync | HTTP protocol validation; header sanitization; request/response consistency checks |

#### Attack Surface Reduction

- No exposed public services (all ingress via Cloudflare Tunnel or Tailscale)
- Default-deny firewall/WAF posture on all interfaces
- Geo-blocking of high-risk countries
- Regular vulnerability scanning of exposed services
- Minimal services running on hosts

---

## 9. Privacy and Remote Access Architecture

#### Deployment Overview

The privacy and remote access architecture implements layered VPN, zero‑trust access, and anonymization technologies to protect outbound traffic, secure inbound access, and preserve user privacy. Private Internet Access (PIA) provides encrypted egress and IP obfuscation, Tailscale delivers authenticated zero‑trust remote access, Cloudflare Tunnels expose internal services securely without opening firewall ports, and Tor enables anonymous outbound browsing. Together, these systems create a defense‑in‑depth privacy model that maintains operational visibility while preventing unauthorized access or data exposure.

#### Security Impact

- Encrypted outbound traffic prevents ISP monitoring and metadata collection
- Zero‑trust remote access ensures only authenticated devices and identities can reach internal services
- Cloudflare Tunnels eliminate the need for public IP exposure or port forwarding
- Tor provides anonymized browsing for research and threat intelligence
- Centralized DNS, tunneling, and identity enforcement reduce attack surface
- Policy‑based routing ensures sensitive applications always use encrypted egress

#### Deployment Rationale

Modern environments require privacy‑preserving egress, secure remote access, and controlled service exposure. This architecture mirrors enterprise zero‑trust designs where VPNs, identity‑aware proxies, and encrypted tunnels work together to protect both inbound and outbound traffic. The combination of PIA, Tailscale, Cloudflare, and Tor demonstrates proficiency with encrypted transport, NAT traversal, identity‑based access control, and anonymization technologies.

#### Architecture Principles Alignment

**Defense in Depth:** Multiple privacy layers (VPN → Zero‑Trust → Tunnel → Anonymization)  
**Secure by Design:** Encrypted tunnels, identity‑based access, no exposed ports  
**Zero Trust:** Every remote connection authenticated; no implicit trust in network location

---

### 9.1 Private Internet Access (PIA) - Encrypted Egress VPN

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>
      PIA provides encrypted outbound VPN tunneling using OpenVPN with AES‑256 encryption and SHA256 authentication. It masks the lab's public‑facing identity, supports multi‑hop routing, and enables region‑based egress selection. PIA is configured directly on the pfSense firewalls and serves as the default outbound path for the 192.168.100.0/24 and 192.168.2.0/24 networks. Policy‑based routing ensures selected applications always use the VPN tunnel.
    </p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/pia-config.png" alt="PIA VPN Configuration">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        PIA VPN Configuration on pfSense.
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Prevents ISP logging of DNS queries, browsing history, and outbound traffic
- Obfuscates public IP, reducing exposure to targeted attacks
- Multi‑hop routing increases anonymity and complicates traffic correlation
- Encrypted tunnels protect data in transit from interception

#### Deployment Rationale

Encrypted egress is essential for privacy‑sensitive environments and aligns with enterprise practices where outbound traffic is anonymized or routed through secure gateways. PIA provides a stable, commercial‑grade VPN solution with strong encryption and global exit nodes.

#### Architecture Principles Alignment

**Defense in Depth:** Adds encrypted egress beneath firewall and IDS/IPS layers  
**Secure by Design:** AES‑256 encryption, SHA256 authentication, OpenVPN tunneling  
**Zero Trust:** No outbound traffic trusted without encryption and policy enforcement

**Use Case:**

- **ISP Privacy:** Prevents ISP from logging DNS queries, browsing history, torrent activity
- **Geolocation Obfuscation:** Appears to originate from VPN exit node location (useful for testing geolocation-based access controls)

**Integration Notes:**

- PIA is configured on the pfSense firewalls and configured as the default egress for 192.168.100.0/24 and 192.168.2.0/24 traffic.
- Traffic from selected applications is routed through PIA using policy-based routing.
- Encryption protocols: AES-256 and SHA256 authentication

---

### 9.2 Tailscale - Zero-Trust Remote Access

#### Deployment Overview

Tailscale provides secure, identity‑based remote access using a WireGuard mesh VPN. It enables seamless NAT traversal, device‑level ACLs, and OAuth/OIDC authentication. MagicDNS provides internal name resolution across the Tailscale network. Tailscale is deployed on key lab VMs and used for remote SSH, dashboard access, and secure file transfers.

#### Security Impact

- Identity‑based access ensures only authorized users and devices can connect
- WireGuard (ChaCha20‑Poly1305) provides high‑performance encrypted tunnels
- NAT traversal eliminates the need for exposed ports
- Audit logs track session activity for governance and incident response

<div class="two-col-right">
  <div class="text-col">
    <p><strong>Integration Notes:</strong></p>
    <ul>
      <li>Tailscale is deployed on key lab VMs</li>
      <li>Used for remote SSH, dashboard access, and secure file transfers.</li>
      <li>WireGuard / ChaCha20-Poly1305 encryption</li>
    </ul>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/tailscale-config.png" alt="Tailscale Configuration">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Tailscale Mesh VPN Configuration.
      </figcaption>
    </figure>
  </div>
</div>

#### Deployment Rationale

Tailscale mirrors enterprise zero‑trust remote access solutions by replacing traditional VPN concentrators with identity‑aware, device‑bound tunnels. It simplifies remote connectivity while enforcing strong authentication and granular access control.

#### Architecture Principles Alignment

**Defense in Depth:** Adds identity‑based access on top of encrypted tunnels  
**Secure by Design:** WireGuard encryption, OAuth/OIDC authentication, device ACLs  
**Zero Trust:** Every connection authenticated; no implicit trust in IP or location

**Diagram Placeholder: Tailscale Network Diagram Screenshot**

**Tailscale Use Cases:**

- **Remote Lab Access:** Securely access Grafana, Portainer, SSH from anywhere without exposing ports
- **Site-to-Site Connectivity:** Connect home lab to cloud VMs for hybrid deployments
- **Ephemeral Access:** Generate one-time-use keys for contractors/guests

---

### 9.3 Cloudflare - Secure Service Exposure & DNS Management

#### Deployment Overview

Cloudflare Tunnels provide secure, authenticated inbound access to internal services without exposing public IPs or opening firewall ports. Cloudflare acts as a reverse proxy with TLS termination, identity‑aware access control, and automatic failover. Cloudflare also manages public DNS for shadowitlab.com, dynamic DNS updates, and S3‑compatible object storage via R2.

#### Security Impact

- Eliminates need for inbound port forwarding
- TLS‑encrypted tunnels protect dashboards, APIs, and UIs
- Cloudflare Access enforces identity‑based service gating
- Dynamic DNS ensures stable service resolution despite WAN IP changes
- R2 object storage provides secure, globally accessible file hosting

#### Deployment Rationale

Cloudflare Tunnels mirror enterprise zero‑trust access patterns where applications are published through identity‑aware proxies rather than exposed directly. DNS centralization and automated DDNS updates ensure reliable service access.

#### Architecture Principles Alignment

**Defense in Depth:** Tunnel layer sits above firewall and VPN protections  
**Secure by Design:** TLS termination, identity‑aware access, no open ports  
**Zero Trust:** Every inbound request authenticated and authorized

#### Public Domain & DNS Management

- **Primary Domain**: shadowitlab.com is registered and managed via **Cloudflare**, enabling centralized control over DNS, security policies, and tunneling endpoints.
- **Dynamic DNS Resilience**:
  - A **Dockerized Cloudflare DDNS client** monitors the WAN IP assigned by Verizon Fios.
  - On IP change, the client automatically updates the A record in Cloudflare using API integration.
  - This ensures persistent domain resolution despite dynamic IP churn, enabling stable access to exposed services.

#### Object Storage & File Sharing

- **Cloudflare R2 Bucket**: Used for lightweight, S3-compatible object storage.
  - **Public Access Endpoint**: files.shadowitlab.com

**Diagram Placeholder: Cloudflare R2 Bucket Screenshot**

#### Secure Service Exposure via Cloudflare Tunnel

Each internal service is mapped to a dedicated Cloudflare Tunnel endpoint under the shadowitlab.com domain. TLS termination, routing, and access control are handled by Cloudflare's Argo Tunnel technology. This enables secure, high‑availability access to internal dashboards, APIs, and management interfaces.

**Webserver Tunnel**

- **Endpoint**: web.shadowitlab.com
- **Purpose**: Hosts static and dynamic content for lab documentation and dashboards.

**Traefik Tunnel**

- **Endpoint**: trfk.shadowitlab.com
- **Purpose**: Acts as a reverse proxy and ingress controller for DockerVM1 services.
- **Features**: TLS passthrough, service routing, and dashboard access.

**Proxmox Tunnel**

- **Endpoint**: pve.shadowitlab.com
- **Purpose**: Provides secure access to the Proxmox VE UI for VM and container orchestration.

**DockerVM1 Tunnel**

This tunnel multiplexes several key services hosted on DockerVM1:

| Subdomain | Service Description |
|-----------|---------------------|
| portainer.shadowitlab.com | Portainer UI for container and K3s workload management |
| pulse.shadowitlab.com | Uptime monitoring and alerting dashboard |
| checkmk.shadowitlab.com | Infrastructure monitoring and metrics aggregation |
| piholebk.shadowitlab.com | Backup Pi-hole instance for DNS filtering |
| prom.shadowitlab.com | Prometheus metrics endpoint |
| wud.shadowitlab.com | Watchtower UI for Docker image update visibility |

**Diagram Placeholder: Cloudflare Tunnels Configuration Screenshot**

**Use Case:**

- **Public Demo:** Showcase Grafana dashboards to potential employers without exposing lab IP
- **API Access:** Provide external services (webhooks, monitoring checks) access to internal APIs
- **Failover Access:** If Tailscale fails, Cloudflare Tunnels provide backup remote access

---

### 9.4 Tor Browser - Anonymous Outbound Browsing

#### Deployment Overview

Tor provides anonymized web browsing by routing traffic through a decentralized network of volunteer‑operated nodes. It is installed on a sandboxed VM with no persistent storage and used exclusively for outbound browsing. No inbound Tor services (hidden services) are hosted.

#### Security Impact

- Prevents tracking, fingerprinting, and metadata collection
- Enables privacy‑sensitive research and threat intelligence gathering
- Bypasses geo‑restrictions and censorship
- Sandboxed VM prevents persistence or cross‑system contamination

#### Deployment Rationale

Tor is widely used in security research, OSINT, and threat intelligence workflows. Running it in a disposable VM mirrors enterprise practices for isolating high‑risk browsing environments.

#### Architecture Principles Alignment

**Defense in Depth:** Sandboxed VM isolates Tor from production systems  
**Secure by Design:** No persistent storage; outbound‑only usage  
**Zero Trust:** No trust in external nodes; isolation prevents lateral movement

---

## 10. Summary

### Multi-Layered VPN & Zero-Trust Access

| Technology | Use Case | Protocol | Encryption | Trust Model |
|------------|----------|----------|------------|-------------|
| Private Internet Access (PIA) | Egress privacy (hide ISP visibility) | OpenVPN | AES-256 | Commercial VPN provider |
| Tailscale | Remote access to lab (peer-to-peer) | WireGuard | ChaCha20-Poly1305 | Zero-trust mesh VPN |
| Cloudflare Tunnels | Inbound service access (no open ports) | QUIC (HTTP/3) | TLS 1.3 | Cloudflare edge network |
| Tor Browser | Anonymous browsing (threat research) | Tor (onion routing) | Multi-layer encryption | Tor network |

### Security Controls

- Split-tunnel policy prevents VPN leakage
- Tailscale ACLs enforce least-privilege access per device/user
- Cloudflare Access policies require MFA for administrative endpoints
- Tor VM operates in ephemeral mode with no disk persistence
- DNS queries flow through Pi-hole for ad-blocking and threat intelligence

### Operational Resilience

- Cloudflare DDNS automation ensures 99.9% domain availability
- Prometheus + CheckMK provide real-time health monitoring
- Uptime Kuma alerts on tunnel/service degradation
- Automated container updates via Watchtower with rollback capability

### Deployment Scenarios

- Remote administration: Tailscale → SSH/Proxmox access from mobile devices
- Public service hosting: Cloudflare Tunnel → web.shadowitlab.com (no exposed ports)
- Threat research: Tor Browser on isolated VM → anonymous OSINT gathering
- Content access: PIA multi-hop → region-specific service testing

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
