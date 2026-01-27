# Observability and Response Architecture - Part 2

**Document Control:**   
Version: 1.0  
Last Updated: January 27, 2026  
Owner: Paul Leone 

---

## Table of Contents

1. [Security Orchestration, Automation and Response (SOAR) Platform](#security-orchestration-automation-and-response-soar-platform)
2. [Monitoring & Observability Architecture](#monitoring--observability-architecture)
3. [Alerting and Notification Architecture](#alerting-and-notification-architecture)
4. [Security Controls Summary](#security-controls-summary)
5. [Use Cases and Scenarios](#use-cases-and-scenarios)
6. [Standards Alignment](#standards-alignment)
7. [Security Homelab Section Links](#security-homelab-section-links)

---

## 1. Security Orchestration, Automation and Response (SOAR) Platform

### Deployment Overview

The SOAR platform unifies case management, automated enrichment, threat intelligence sharing, and workflow automation across the entire security stack. It integrates SIEM alerts, EDR telemetry, threat intelligence feeds, and infrastructure controls into a coordinated response ecosystem. The platform consists of four primary applications: Shuffle, TheHive, Cortex, and MISP. Each fulfills a specialized role within the incident response lifecycle.

### Security Impact

The SOAR ecosystem dramatically reduces response time by automating repetitive tasks, enriching alerts with contextual intelligence, and orchestrating multi-tool actions. Automated workflows ensure consistent triage, reduce human error, and provide structured case management. Integrated threat intelligence enhances detection accuracy, while automated containment actions limit adversary dwell time.

### Deployment Rationale

Modern SOC operations require more than detection—they require coordinated, automated response. This SOAR architecture mirrors enterprise-grade security operations by combining case management, enrichment engines, threat intelligence platforms, and automation pipelines. It demonstrates proficiency with incident response frameworks, multi-tool orchestration, and automated decision-making.

### Architecture Principles Alignment

**Defense in Depth:**

- Multiple enrichment engines validate IOCs across independent sources
- Automated containment actions complement SIEM/EDR detections
- Case management, enrichment, and threat intelligence form overlapping response layers

**Secure by Design:**

- Structured workflows enforce consistent triage and investigation procedures
- API-based integrations use authenticated, encrypted communication
- Automated playbooks reduce manual error and enforce policy compliance

**Zero Trust:**

- No alert or IOC is implicitly trusted; all are enriched and validated
- Automated workflows enforce least-privilege actions and controlled response steps
- Continuous verification of threat intelligence before actioning

### 1.1 Shuffle - Security Automation Engine

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>Shuffle is the low-code/no-code automation engine that orchestrates workflows across all SOC tools, SIEM platforms, and security infrastructure. It serves as the automation backbone of the SOAR ecosystem, enabling rapid integration, event-driven workflows, and multi-tool response actions. Shuffle processes alerts from Wazuh, Splunk, Elastic, and other sources, automatically enriching them with intelligence from Cortex, VirusTotal, Shodan, and MISP before triggering case creation or containment actions.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/shuffle-logo.png" alt="Shuffle Logo">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Shuffle Automation Engine
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Automates triage, enrichment, and response actions to reduce MTTR
- Executes containment workflows (firewall blocks, host isolation, account disablement)
- Ensures consistent, repeatable response actions across all alerts
- Provides real-time notifications and workflow execution logs

#### Deployment Rationale

Shuffle demonstrates the ability to build enterprise-grade automation pipelines without requiring custom code. It integrates seamlessly with SIEM, EDR, threat intelligence, and case management systems, enabling end-to-end automated response.

#### Architecture Principles Alignment

- **Defense in Depth:** Automates multi-layer response actions across EDR, firewalls, SIEM, and threat intelligence
- **Secure by Design:** API-key isolation, encrypted communication, and controlled workflow execution
- **Zero Trust:** Every alert is enriched and validated before action; no implicit trust in raw telemetry

#### Deployment Architecture

Shuffle is deployed as a multi-container microservices architecture with the following components:

| Component | Image | IP Address | Purpose |
|-----------|-------|------------|---------|
| shuffle-frontend | shuffle-frontend:latest | 192.168.200.41 (LB) | React-based web UI for workflow design, execution monitoring, and administration |
| shuffle-backend | shuffle-backend:latest | 10.43.xxx.xxx (ClusterIP) | Go-based backend API handling workflow execution orchestration, app management, webhook processing |
| shuffle-opensearch | opensearch:3.2.0 | 10.43.xxx.xxx (ClusterIP) | OpenSearch database storing workflow definitions, execution history, app configurations, and audit logs |
| shuffle-orborus | shuffle-orborus:latest | None (internal) | Worker orchestration daemon responsible for spinning up Docker containers to execute workflow app actions |

**External Access:**

- **Web Interface:** https://192.168.200.41 (ports 80/443)
- **Webhook Receiver:** https://192.168.200.41/api/v1/hooks/ (for external trigger integrations)
- **API Endpoint:** https://192.168.200.41/api/v1/ (RESTful API for programmatic workflow management)

#### Integration Points

Shuffle serves as the central orchestration hub connecting:

- **TheHive:** Automated case creation, task assignment, observable enrichment, and case closure workflows
- **Cortex:** Trigger analysis jobs, retrieve results, execute responders based on analysis outcomes
- **MISP:** Automatic IOC submission, threat intelligence queries, event publishing, and feed synchronization
- **Wazuh EDR:** Alert triage, automated response actions (file quarantine, process termination), agent management
- **Splunk SIEM:** Query execution, alert enrichment, dashboard updates, notable event creation
- **Elastic Stack:** Log queries, index management, alert correlation, metric aggregation
- **pfSense Firewall:** Automatic blocklist updates, firewall rule creation, VPN configuration changes
- **Suricata/Snort IDS:** Rule updates, signature deployment, detection tuning based on threat intelligence
- **Safeline WAF:** WAF rule updates, IP blocklist synchronization, virtual patching deployment
- **CrowdSec:** Community blocklist publishing, scenario deployment, bouncer configuration
- **Discord:** Real-time notifications, alert distribution, case status updates, workflow execution reports
- **Email:** Phishing analysis workflows, report distribution, executive summaries, alert forwarding
- **VirusTotal/AbuseIPDB:** Automated reputation checks, malware analysis, IP/domain enrichment

#### Workflow Examples Deployed

**1. Phishing Email Analysis Pipeline:**

- **Trigger:** Email received at phishing@lab.lan
- **Shuffle extracts:** URLs, attachments, sender IP
- **VirusTotal scans:** Attachments and URLs
- **AbuseIPDB checks:** Sender IP reputation
- **Results aggregated:** TheHive case created
- **If malicious:** Block sender IP in pfSense, add to MISP, notify SOC team
- **Execution time:** <2 minutes

**2. Wazuh Alert Enrichment & Response:**

- **Trigger:** Wazuh webhook on critical severity alert
- **Shuffle parses:** Alert JSON, extracts IOCs
- **Cortex enrichment:** IP/domain/hash analysis across 10+ analyzers
- **MISP lookup:** Check for known threat actor TTPs
- **Splunk correlation:** Query for related events in past 24 hours
- **TheHive case created:** With full context
- **Automated response:** If confirmed threat, execute Cortex responders (block IP, isolate host)
- **Discord notification:** To SOC team with case link
- **Execution time:** <5 minutes

**3. Vulnerability Disclosure Response:**

- **Trigger:** Scheduled daily execution (08:00 AM)
- **Query NIST NVD API:** For CVEs published in past 24 hours
- **Filter for CVEs:** Matching lab technologies
- **Enrich with Exploit-DB:** Lookup for public exploits
- **Create TheHive case:** For each critical/high severity CVE
- **Assign tasks:** To security team for impact assessment
- **Update MISP:** With new vulnerability IOCs
- **Execution time:** 5-10 minutes

**4. Threat Intelligence Aggregation:**

- **Trigger:** Hourly scheduled execution
- **Query external feeds:** AlienVault OTX, abuse.ch, Emerging Threats
- **Normalize IOC formats:** IP, domain, hash, URL
- **De-duplicate:** Against existing MISP events
- **Validate IOCs:** Check for false positives using whitelist
- **Submit new IOCs:** To MISP as low-confidence events
- **Update defenses:** pfBlockerNG and Suricata with high-confidence IOCs
- **Execution time:** 10-15 minutes

**5. Incident Response Playbook - Ransomware Detection:**

- **Trigger:** Wazuh FIM alert (mass file encryption detected)
- **Shuffle immediately isolates:** Affected host
  - Disable network adapter via Wazuh active response
  - Add host IP to firewall quarantine VLAN
- **Create critical severity:** TheHive case
- **Capture forensic data:**
  - Memory dump via Wazuh command execution
  - Running process list
  - Network connections snapshot
- **Submit ransomware hash:** To Cortex for family identification
- **Query MISP:** For known ransomware campaigns with matching TTPs
- **Page on-call SOC analyst:** Via PagerDuty integration
- **Send detailed incident report:** To Discord #incident-response channel
- **Execution time:** <3 minutes for containment, <10 minutes full workflow

### 1.2 TheHive - Incident Response and Case Management

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>TheHive provides centralized case management, investigation workflows, and collaborative incident response. It aggregates alerts from SIEM and EDR platforms into structured cases, enabling analysts to track tasks, observables, timelines, and response actions. TheHive acts as the command center for incident response, coordinating investigations across Cortex, MISP, Wazuh, and Shuffle.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/thehive-logo.png" alt="TheHive Logo">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        TheHive Case Management Platform
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Centralizes all incidents into structured, auditable cases
- Enables collaborative investigations with task assignments and timelines
- Correlates alerts from Splunk, Wazuh, and other sources into unified cases
- Provides metrics dashboards for MTTD, MTTR, and case volume trends
- Ensures consistent documentation for forensic and compliance requirements

#### Deployment Rationale

TheHive mirrors enterprise SIRP (Security Incident Response Platform) capabilities, demonstrating proficiency with structured case management, workflow orchestration, and collaborative investigations. It provides the backbone for SOC processes, ensuring every incident is tracked, enriched, and resolved with full accountability.

#### Architecture Principles Alignment

- **Defense in Depth:** Combines SIEM, EDR, and threat intelligence alerts into multi-source cases
- **Secure by Design:** Role-based access, audit logs, and structured workflows
- **Zero Trust:** All observables validated through Cortex/MISP before actioning

#### Deployment Specifications

- **Container Image:** strangebee/thehive:5.5.13-1
- **Deployment Type:** Helm chart (managed deployment)
- **Replicas:** 1 (single instance)
- **External Access:** LoadBalancer service at **192.168.200.33**
  - Port 9000 (HTTP/HTTPS web interface)
  - Port 9095 (Kamon metrics for Prometheus integration)
- **Persistent Storage:** Backed by Cassandra and Elasticsearch for data durability
- **Resource Allocation:**
  - CPU: 2 cores
  - Memory: 4GB
  - Storage: 20GB (application data via Cassandra)

![TheHive Architecture Diagram](/Career_Projects/assets/diagrams/thehive-architecture.png)

#### Key Capabilities

- **Case Management:** Create, assign, and track security incidents with customizable workflows
- **Task Orchestration:** Break down investigations into actionable tasks with assignments and deadlines
- **Observable Analysis:** Submit IOCs (IPs, domains, hashes, URLs) to Cortex for automated analysis
- **Alert Correlation:** Aggregate alerts from SIEM (Splunk, Wazuh) into unified cases
- **Collaboration:** Team-based investigations with real-time updates and commenting
- **Reporting:** Generate executive summaries and technical reports from case data
- **Metrics Dashboard:** Track MTTD (Mean Time to Detect), MTTR (Mean Time to Respond), case volume trends

#### Integration Points

- **Cortex:** Automated observable analysis and enrichment
- **MISP:** Bi-directional IOC sharing (export confirmed threats, import external intelligence)
- **Wazuh:** Automated case creation from EDR alerts (via n8n workflow)
- **Splunk:** SIEM alert ingestion and correlation
- **n8n:** Workflow automation for alert triage and notification distribution
- **Discord:** Real-time notifications for high-severity cases

### 1.3 Cortex - Observable Analysis and Active Response Engine

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>Cortex automates the analysis of observables (IOCs) using a wide range of analyzers and responders. It enriches IPs, domains, hashes, URLs, and files with intelligence from VirusTotal, AbuseIPDB, Shodan, OTX, and internal sources. Cortex responders execute automated containment actions such as firewall rule updates, blocklist modifications, and case escalations.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/cortex-logo.png" alt="Cortex Logo">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Cortex Analysis Engine
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Provides automated, multi-engine IOC analysis
- Executes rapid containment actions via responders
- Enhances detection accuracy through cross-source enrichment
- Supports dynamic malware analysis via sandbox integrations

#### Deployment Rationale

Cortex demonstrates advanced enrichment and automated response capabilities found in enterprise SOCs. Its analyzer/responder model enables modular, scalable intelligence processing and automated containment workflows.

#### Architecture Principles Alignment

- **Defense in Depth:** Multiple analyzer categories validate IOCs across independent sources
- **Secure by Design:** Controlled responder execution; strict API authentication
- **Zero Trust:** No IOC trusted without multi-engine validation

#### Deployment Specifications

- **Container Image:** thehiveproject/cortex:latest
- **Deployment Type:** Kubernetes Deployment
- **Replicas:** 1 (scalable to 3+ for high-volume analysis)
- **External Access:** LoadBalancer service at **192.168.200.40**
  - Port 9001 (HTTP API and web interface)
- **Backend Database:** Elasticsearch (for job history and results)
- **Resource Allocation:**
  - CPU: 2 cores (scales with analyzer concurrency)
  - Memory: 4GB (increases with active jobs)
  - Storage: 10GB (job results and cache)

#### Analyzer Categories

| Category | Examples | Use Case |
|----------|----------|----------|
| Threat Intelligence | VirusTotal, AbuseIPDB, AlienVault OTX, Shodan | Reputation lookups and historical threat data |
| File Analysis | Yara, ClamAV, File_Info, PEInfo | Malware detection and file characterization |
| Network Analysis | Passive DNS, WHOIS, DNS resolution | Domain/IP infrastructure analysis |
| URL Analysis | URLhaus, PhishTank, Google Safe Browsing | Malicious URL detection |
| Sandbox Execution | Cuckoo, Joe Sandbox, ANY.RUN (API) | Dynamic malware analysis |
| Enrichment | MaxMind GeoIP, Tor Project, MISP lookup | Contextual information gathering |

#### Responder Categories

| Category | Examples | Use Case |
|----------|----------|----------|
| Blocking | pfBlockerNG, Suricata, WAF rule updates | Automated threat containment |
| Notification | Email, Discord, Slack, PagerDuty | Alert distribution |
| Ticketing | TheHive case creation, Jira integration | Incident escalation |
| Threat Intelligence | MISP export, CrowdSec block list updates | IOC sharing and coordination |

#### Workflow Example

1. TheHive case created with suspicious IP observable (192.0.2.50)
2. Analyst triggers Cortex analysis job
3. Cortex runs 8 analyzers concurrently:
   - AbuseIPDB: Returns confidence score 95% malicious
   - Shodan: Identifies open ports 22, 80, 443
   - MaxMind GeoIP: Locates IP in high-risk country
   - MISP: No matches in existing threat intelligence
   - Passive DNS: Resolves to known phishing domain
   - VirusTotal: 12/90 vendors flag as malicious
   - CrowdSec: Blocked by 45 community members
   - Tor Exit Node check: Not a Tor exit node
4. Aggregated results returned to TheHive case in <60 seconds
5. Analyst reviews findings and triggers responders:
   - pfBlockerNG: Add IP to firewall blocklist
   - MISP: Export IOC with "High" confidence rating
   - Discord: Notify SOC team of confirmed threat

### 1.4 MISP - Threat Intelligence Sharing Platform

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>MISP provides structured threat intelligence management, IOC sharing, and collaborative intelligence workflows. It stores, correlates, and distributes threat indicators across the SOAR ecosystem. MISP integrates with Cortex, TheHive, Shuffle, and external intelligence feeds to enrich alerts and cases with contextual threat data.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/misp-logo.png" alt="MISP Logo">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        MISP Threat Intelligence Platform
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Enhances detection accuracy through curated threat intelligence
- Enables bi-directional sharing of confirmed IOCs
- Correlates related events to identify campaigns and intrusion sets
- Supports automated enrichment and threat scoring

#### Deployment Rationale

MISP demonstrates proficiency with structured threat intelligence, IOC lifecycle management, and intelligence-driven detection. It mirrors enterprise CTI workflows where intelligence is continuously ingested, validated, enriched, and distributed across SOC tools.

#### Architecture Principles Alignment

- **Defense in Depth:** Adds intelligence-driven detection to complement SIEM/EDR telemetry
- **Secure by Design:** Signed events, role-based access, and controlled feed synchronization
- **Zero Trust:** All intelligence validated before distribution; no implicit trust in external feeds

#### Deployment Specifications

MISP is deployed as a multi-container application stack with the following components:

| Component | Image | IP Address | Purpose |
|-----------|-------|------------|---------|
| misp-core | ghcr.io/misp/misp-docker/misp-core:latest | 192.168.200.37 (LB) | Main MISP application (web UI, API, background workers) |
| misp-db | mariadb:10.11 | 10.43.151.59 (ClusterIP) | MySQL/MariaDB database for MISP data storage |
| misp-redis | valkey/valkey:7.2 | 10.43.131.214 (ClusterIP) | Redis cache for session management and job queuing |
| misp-modules | ghcr.io/misp/misp-docker/misp-modules:latest | 10.43.234.246 (ClusterIP) | Expansion and enrichment modules for automated IOC enrichment |
| misp-guard | ghcr.io/misp/misp-docker/misp-guard:latest | 10.43.97.195 (ClusterIP) | Security proxy protecting MISP core from malicious input |
| misp-mail | registry.gitlab.com/egos-tech/smtp:latest | 192.168.200.38 (LB) | SMTP relay for email notifications and sharing |

**External Access:**

- **Web Interface:** https://192.168.200.37 (ports 80/443)
- **SMTP Server:** 192.168.200.38:25 (for receiving threat intelligence emails)

#### Supporting Infrastructure

**Cassandra - Distributed NoSQL Database:**

- **Purpose:** Scalable, fault-tolerant data store for TheHive case data, observables, and audit logs
- **Container Image:** cassandra:4.1.7
- **Deployment Type:** StatefulSet (ensures stable network identity and persistent storage)
- **Replicas:** 1 (production would use 3+ node cluster for high availability)
- **External Access:** LoadBalancer service at **192.168.200.36** (Port 9042 - CQL native protocol)
- **Persistent Volume:** 100GB SSD-backed storage
- **Replication Strategy:** SimpleStrategy with replication_factor=1 (single node)

**Configuration Highlights:**

- **Keyspace:** TheHive data stored in dedicated keyspace with TTL policies for data retention
- **Consistency Level:** LOCAL_ONE (single node) / LOCAL_QUORUM (production multi-node)
- **Backup Strategy:** Daily snapshots via cron job, retained for 14 days
- **Monitoring:** Exposed JMX metrics for Prometheus scraping

![Cassandra Logo](/Career_Projects/assets/diagrams/cassandra-logo.png)

**Elasticsearch - Search and Analytics Engine:**

- **Purpose:** Full-text search, log aggregation, and analytics for TheHive cases, Cortex job results, and observables
- **Container Image:** docker.elastic.co/elasticsearch/elasticsearch:9.2.2
- **Deployment Type:** StatefulSet (single-node cluster)
- **Replicas:** 1
- **External Access:** LoadBalancer service at **192.168.200.34** (Port 9200 - HTTP REST API)
- **Persistent Volume:** 200GB SSD-backed storage
- **Cluster Name:** soc-elasticsearch
- **Node Roles:** master, data, ingest (combined role in single-node deployment)

**Index Management:**

- **TheHive Indices:** Cases, tasks, observables, audit logs with 90-day retention
- **Cortex Indices:** Analysis jobs, results, analyzer reports with 30-day retention
- **Index Lifecycle Management (ILM):** Automated rollover and deletion based on age/size
- **Snapshots:** Daily backups to NAS via snapshot repository

**Performance Tuning:**

- **Heap Size:** 4GB (50% of allocated memory)
- **Shards:** 1 primary shard per index (low-volume lab environment)
- **Replicas:** 0 (single node, no replication)
- **Refresh Interval:** 5 seconds (balance between real-time search and indexing performance)

![Elasticsearch Logo](/Career_Projects/assets/diagrams/elasticsearch-logo.png)

**OpenSearch - Shuffle Workflow Database:**

- **Purpose:** Storage and retrieval of Shuffle workflow definitions, execution history, app configurations, and audit logs
- **Container Image:** opensearch:3.2.0
- **Deployment Type:** StatefulSet (single-node cluster)
- **Replicas:** 1
- **External Access:** ClusterIP only (internal communication with Shuffle backend) (Port 9200 - HTTP REST API)
- **Persistent Volume:** 100GB SSD-backed storage
- **Cluster Name:** shuffle-opensearch

**Data Storage:**

- **Workflow Definitions:** JSON representations of workflow configurations and app settings
- **Execution History:** Complete audit trail of all workflow runs with timestamps, inputs, outputs, and errors
- **App Cache:** Downloaded app containers and OpenAPI specifications for rapid workflow execution
- **User Activity Logs:** Authentication events, workflow modifications, permission changes

**Performance Characteristics:**

- **Query Performance:** Sub-second search for workflow debugging and historical analysis
- **Retention:** 90-day execution history (configurable based on storage capacity)
- **Backup Strategy:** Daily snapshots to NAS; integrated with Kubernetes backup automation

![OpenSearch Logo](/Career_Projects/assets/diagrams/opensearch-logo.png)

#### Integration Points

- **TheHive:** Bi-directional IOC exchange (TheHive cases → MISP events, MISP feeds → TheHive alerts)
- **Cortex:** MISP lookup analyzer queries threat intelligence database
- **Wazuh:** EDR threat intelligence module queries MISP for known malicious indicators
- **CrowdSec:** Export confirmed threats to CrowdSec community blocklist
- **pfBlockerNG:** Automated firewall rule generation from MISP feeds
- **Suricata/Snort:** IDS rule generation from MISP network indicators
- **Elastic:** SIEM enrichment lookups against MISP database

### Use Cases and Workflows

#### Use Case 1: Automated Threat Intelligence Pipeline (Shuffle-Orchestrated)

**Scenario:** Wazuh EDR detects suspicious process execution on Windows endpoint. Indicator (file hash) automatically enriched and shared across security tools via Shuffle orchestration.

**Shuffle Workflow: "Wazuh Alert Triage & Response"**

**Trigger:** Wazuh webhook on Severity >= 10 alert

**Workflow Steps:**

1. **Parse Wazuh Alert** (Shuffle built-in parser)
   - Extract IOCs: file hash (SHA256), process name, parent process, command line
   - Extract context: hostname, username, timestamp, rule ID
   - Output: Structured JSON object

2. **Cortex Observable Analysis** (TheHive Project app)
   - Submit file hash to Cortex
   - Parallel analyzer execution:
     - VirusTotal: 45/70 vendors detect as malicious (Trojan.Downloader)
     - MISP lookup: No existing matches (new threat)
     - File_Info: PE file, suspicious compilation timestamp
     - Yara rules: Matches "Dropper_Generic" signature
   - Aggregated confidence score: 95% malicious
   - Execution time: 45 seconds

3. **Conditional Branch - If Malicious (>80% confidence)**
   - **Branch A - Automated Containment:**
     - Wazuh Active Response: Isolate host (disable network adapter)
     - pfSense API: Add host IP to quarantine VLAN ACL
     - Execution time: 5 seconds

4. **TheHive Case Creation** (TheHive app)
   - Case title: "Malware Detection - [HOSTNAME] - [HASH]"
   - Severity: Critical
   - Tags: malware, automated-response, trojan-downloader
   - Observables: file hash, process name, C2 domain (if identified)
   - Tasks auto-created:
     - Forensic analysis (assigned to SOC analyst)
     - Scope assessment - other endpoints with same hash
     - Root cause investigation
   - Execution time: 3 seconds

5. **MISP Event Creation** (MISP app)
   - Event title: "Malware Campaign - Trojan Downloader [DATE]"
   - Attributes:
     - File hash (SHA256) - IOC
     - Process name - Artifact
     - C2 domain (extracted from network logs) - Network Activity
   - TLP: Amber (limited sharing)
   - MITRE ATT&CK mapping: T1059 (Command and Scripting Interpreter)
   - Publish to internal sharing group
   - Execution time: 4 seconds

6. **Threat Intelligence Distribution** (Parallel execution)
   - CrowdSec API: Add hash to community blocklist
   - pfBlockerNG: Block C2 domain at firewall perimeter
   - Suricata: Deploy IDS signature for C2 traffic detection
   - Wazuh: Update FIM policy to monitor related file paths
   - Execution time: 8 seconds (parallel)

7. **Notification Dispatch** (Multi-channel)
   - Discord #soc-alerts: Rich embed with case details, analysis summary, response actions taken
   - Email: SOC team distribution list with PDF report
   - TheHive: Internal case comment documenting automated actions
   - Execution time: 2 seconds

8. **Forensic Data Collection** (Conditional - if endpoint still accessible)
   - Wazuh command execution: Capture memory dump
   - Retrieve running process list, network connections, autoruns
   - Upload forensic artifacts to TheHive case as attachments
   - Execution time: 30-60 seconds (depends on memory size)

#### Use Case 2: Phishing Email Analysis & Response (Shuffle-Orchestrated)

**Scenario:** User reports suspicious email to phishing@lab.lan. Shuffle automatically triages, analyzes, and responds to phishing threat.

**Shuffle Workflow: "Phishing Email Triage"**

**Trigger:** Email received at phishing@lab.lan inbox (IMAP polling every 60 seconds)

**Workflow Steps:**

1. **Email Parsing** (Email app)
   - Extract sender address, subject, body text, HTML content
   - Extract all URLs and domains
   - Download attachments (if present)
   - Parse email headers (Received, SPF, DKIM, DMARC results)
   - Output: Structured email object

2. **Observable Extraction** (Regex and parsing subflow)
   - URLs: Extract and defang (hxxps://)
   - Domains: Extract root domains and subdomains
   - IP addresses: Extract from email body and headers
   - File hashes: Calculate SHA256 of attachments
   - Email addresses: Sender and Reply-To
   - Total observables: 8-15 per email average

3. **Threat Intelligence Enrichment** (Parallel Cortex analysis)
   - **URLs:**
     - VirusTotal URL: Check reputation (3/90 vendors flag as phishing)
     - URLhaus: Matches known phishing campaign
     - PhishTank: Not in database (possible zero-day)
   - **Domains:**
     - WHOIS: Registered 2 days ago (high risk indicator)
     - Passive DNS: Domain hosted on bulletproof hosting provider
   - **Sender IP:**
     - AbuseIPDB: Confidence 78% malicious, 15 reports
     - MaxMind GeoIP: Located in high-risk country
   - **Attachments** (if present):
     - VirusTotal File: 12/70 vendors detect macro-enabled document
     - Yara: Matches "Phishing_Document_Macro" rule
   - Aggregated threat score: 92% malicious phishing attempt
   - Execution time: 30-45 seconds

4. **Conditional Branch - If Malicious (>70% confidence)**

**Branch A - Automated Response Actions:**

**5a. Email Infrastructure Blocking:**

- pfBlockerNG: Block sender domain and IP at firewall
- Microsoft 365 (future): Add sender to spam filter blocklist
- Postfix: Update sender blacklist on mail server
- Execution time: 6 seconds

**6a. User Protection:**

- Microsoft 365 API: Search all mailboxes for matching emails
- If found: Soft-delete from all user inboxes (move to Junk)
- Discord notification: Alert users in #security-awareness channel
- Execution time: 15-30 seconds (depends on mailbox count)

**7a. Threat Intelligence Sharing:**

- MISP event creation: "Phishing Campaign - [DATE]"
- Attributes: sender address, URLs, domains, file hashes, email headers
- Tags: phishing, credential-harvesting, zero-day (if applicable)
- Publish to internal + external sharing groups
- CrowdSec: Add sender IP to community blocklist
- Execution time: 8 seconds

5. **TheHive Case Creation**
   - Case title: "Phishing Email - [SUBJECT LINE]"
   - Severity: Medium (High if attachments present)
   - Description: Email content, analysis results, affected users
   - Observables: All extracted IOCs with Cortex analysis attached
   - Tasks:
     - Review user awareness training effectiveness
     - Check for credential compromise (if login page detected)
     - Update email filtering rules
   - Execution time: 4 seconds

6. **User Communication** (Conditional - if user reported email)
   - Email auto-response to reporting user:
     - Thank you message
     - Confirmation of phishing classification
     - Assurance that threat has been blocked
     - Security awareness tip
   - Execution time: 2 seconds

7. **Metrics & Reporting**
   - Update phishing dashboard in Grafana (API call)
   - Increment counters: Total phishing emails, blocked campaigns, user reports
   - Log to Splunk for executive reporting
   - Execution time: 1 second

#### Use Case 3: Vulnerability Disclosure to Remediation (Shuffle-Orchestrated)

**Scenario:** Security team needs to track newly disclosed CVEs affecting lab infrastructure and orchestrate rapid remediation response.

**Shuffle Workflow: "Vulnerability Disclosure Monitoring"**

**Trigger:** Scheduled execution (Daily at 08:00 AM)

**Workflow Steps:**

1. **CVE Feed Aggregation** (HTTP Request apps)
   - Query NIST NVD API: CVEs published in past 24 hours
   - Query Exploit-DB API: Public exploits released
   - Query vendor security advisories: Debian, Ubuntu, Docker, Kubernetes
   - Output: 50-150 new CVEs per day

2. **Relevance Filtering** (Shuffle built-in filter)
   - Keyword matching against lab technology stack:
     - Keywords: nginx, kubernetes, k3s, postgres, redis, mariadb, opensearch, elasticsearch, cassandra, docker, thehive, cortex, misp, shuffle, wazuh, splunk, suricata, pfsense
   - CVSS score filter: Only CVSS >= 7.0 (High/Critical)
   - Exploit availability: Prioritize CVEs with public exploits
   - Output: 5-15 relevant CVEs per day

3. **Vulnerability Enrichment** (Parallel API calls)
   - For each relevant CVE:
     - Exploit-DB: Check for working exploit code
     - GitHub: Search for proof-of-concept exploits in repositories
     - MISP: Query for IOCs related to active exploitation
     - Vendor advisories: Retrieve patch availability and remediation guidance
     - EPSS Score: Exploitation probability (future roadmap)
   - Execution time: 10-15 seconds per CVE

4. **Asset Impact Assessment** (Internal inventory query)
   - Query Ansible inventory: Identify affected systems
   - Query Wazuh agent list: Match vulnerability to installed software versions
   - Query Docker registry: Identify affected container images
   - Priority scoring:
     - Critical services (SIEM, firewall, SOC platform): Priority 1
     - Internet-facing services (web servers, VPN): Priority 2
     - Internal services (databases, monitoring): Priority 3
   - Output: List of affected assets with priority ranking

5. **TheHive Case Creation** (Per high-priority CVE)
   - Case title: "Critical Vulnerability - [CVE-ID] - [AFFECTED SERVICE]"
   - Severity: Based on CVSS + asset criticality + exploit availability
   - Description:
     - CVE summary and technical details
     - Affected assets and versions
     - Exploitation probability and known exploits
     - Remediation guidance from vendor
   - Observables: CVE-ID, affected software versions, exploit URLs
   - Tasks auto-created:
     - **Task 1:** Apply vendor security patch (assigned to DevOps, due: 24 hours for critical)
     - **Task 2:** Verify WAF/IDS rules block exploitation attempts (assigned to Security, due: 4 hours)
     - **Task 3:** Scan for IOCs indicating active exploitation (assigned to SOC analyst, due: immediate)
     - **Task 4:** Rerun vulnerability scan to confirm remediation (assigned to Security, due: post-patch)
   - SLA tracking: Automatic escalation if tasks not completed within deadline
   - Execution time: 5 seconds per case

6. **Temporary Mitigation Deployment** (If exploit available + no patch)
   - **Virtual Patching:**
     - Safeline WAF: Deploy custom rule blocking exploitation attempts
     - Suricata IDS: Deploy detection signature for exploitation traffic
     - pfSense: Network-level access restrictions to vulnerable service
   - **Compensating Controls:**
     - Increase monitoring: Add Wazuh FIM rules for exploitation indicators
     - Splunk: Create correlation search for attack patterns
     - Alert SOC team: Enhanced monitoring for 24-48 hours
   - Execution time: 10-15 seconds

7. **Notification Distribution** (Multi-channel)
   - **Priority 1 (Critical vulnerabilities with exploits):**
     - Discord @security-team: Immediate notification with case link
     - PagerDuty: Page on-call engineer
     - Email: Executive summary to management
   - **Priority 2 (High severity):**
     - Discord #vulnerability-management: Standard notification
     - Email: SOC team distribution list
   - **Priority 3 (Medium severity):**
     - TheHive case only (no immediate notification)
     - Weekly rollup report
   - Execution time: 3 seconds

8. **MISP Threat Intelligence Update**
   - Create MISP event: "Vulnerability [CVE-ID]"
   - Attributes:
     - CVE number
     - Affected software and versions
     - Exploit URLs
     - IOCs for exploitation attempts (if available)
   - Tags: vulnerability, [CVSS-severity], exploit-available
   - Share with internal systems for automated detection
   - Execution time: 4 seconds

9. **Remediation Tracking & Reporting**
   - **Follow-up workflow (separate, triggered daily):**
     - Check TheHive case status for overdue tasks
     - Escalate to management if SLA breach (>24 hours for critical)
     - Run Greenbone OpenVAS targeted scan on patched systems
     - Verify vulnerability no longer present
     - Close case with remediation summary and lessons learned
   - **Weekly Executive Report:**
     - CVE tracking dashboard (Grafana)
     - Remediation SLA compliance metrics
     - Risk reduction trend analysis

#### Use Case 4: Incident Response Playbook - Ransomware Detection (Shuffle-Orchestrated)

**Scenario:** Wazuh FIM (File Integrity Monitoring) detects mass file encryption event indicating ransomware execution. Shuffle orchestrates immediate containment and forensic response.

**Shuffle Workflow: "Ransomware Containment & Response"**

**Trigger:** Wazuh webhook on Rule ID 554 (File Integrity Monitoring - Multiple File Changes) with >50 files modified in <60 seconds

**Workflow Steps (Critical path - optimized for speed):**

1. **Alert Validation** (Shuffle built-in parser - 1 second)
   - Parse Wazuh alert: hostname, username, file paths, process name
   - Verify alert criteria: >50 file modifications, extensions match known ransomware patterns (.encrypted, .locked, .crypt, etc.)
   - Extract process tree: Identify parent process and child processes

2. **IMMEDIATE CONTAINMENT** (Parallel execution - 3-5 seconds total)

**2a. Network Isolation** (Wazuh Active Response + pfSense API):

- Wazuh command: Disable all network adapters on infected host
- pfSense API: Add host IP to quarantine VLAN ACL (block all traffic except management)
- Verify isolation: Ping test fails (confirms network disconnection)

**2b. Process Termination** (Wazuh Active Response):

- Kill identified ransomware process and all child processes
- Suspend suspicious parent processes (e.g., explorer.exe spawning encryption)

**2c. User Account Lockout** (Active Directory API):

- Disable user account that was logged in during encryption event
- Force sign-out of all active sessions
- Prevent lateral movement via compromised credentials

3. **Forensic Data Collection** (Parallel execution - 30-60 seconds)

**3a. Memory Dump** (Wazuh command execution):

- Execute WinPMEM or DumpIt tool remotely
- Capture full memory image (4-16GB depending on system RAM)
- Upload to forensic analysis server via SFTP

**3b. System State Snapshot** (Wazuh batch script execution):

- Running processes: Get-Process | Export-CSV
- Network connections: netstat -anob
- Scheduled tasks: schtasks /query /fo CSV
- Startup items: Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
- Recent file modifications: FIM log excerpt (past 5 minutes)
- Event logs: Security, System, Application (past 1 hour)

**3c. Ransomware Sample Collection:**

- Copy ransomware executable to quarantine directory
- Copy ransom note files (README.txt, DECRYPT-FILES.txt, etc.)
- Calculate file hashes (SHA256) for malware analysis

4. **Threat Intelligence Enrichment** (Cortex analysis - 45 seconds)
   - Submit ransomware hash to Cortex analyzers:
     - VirusTotal: Identify ransomware family (e.g., LockBit, ALPHV/BlackCat)
     - MISP: Check for known campaigns with matching IOCs
     - Yara: Match against ransomware family signatures
     - Hybrid Analysis: Dynamic sandbox execution (if safe)
   - Extract IOCs:
     - C2 domains/IPs
     - Mutex names
     - Registry keys
     - Encryption file extensions

5. **TheHive Critical Incident Case** (3 seconds)
   - Case title: "CRITICAL - Ransomware Infection - [HOSTNAME]"
   - Severity: Critical
   - Status: In Progress
   - Tags: ransomware, active-incident, containment-complete
   - Description: Automated alert details, timeline, containment actions taken
   - Observables: Ransomware hash, C2 domains, affected file paths, user account
   - Tasks (auto-assigned with immediate deadlines):
     - **Immediate (assigned to on-call SOC analyst):**
       - Review forensic data and confirm ransomware family
       - Assess encryption scope (files lost vs. backed up)
       - Check backups for integrity (not encrypted)
     - **Within 1 hour (assigned to IR team):**
       - Scan network for lateral movement indicators
       - Identify patient zero (initial infection vector)
       - Check other endpoints for same ransomware IOCs
     - **Within 4 hours (assigned to IT team):**
       - Restore from backups (last known good before infection)
       - Rebuild infected endpoint from golden image
       - Re-join to domain and verify security baselines

6. **Scope Assessment & Lateral Movement Detection** (Parallel Splunk/Wazuh queries - 30 seconds)
   - **Splunk correlation search:**
     - Query: Same ransomware hash on other endpoints (past 7 days)
     - Query: Same user account logon activity on other systems (past 24 hours)
     - Query: Network connections to identified C2 infrastructure
     - Query: Unusual SMB/RDP connections from infected host
   - **Wazuh query:**
     - Check all agents for ransomware IOCs (file hashes, mutex names)
     - Review FIM logs across all endpoints for mass encryption events
     - Identify common vulnerability or attack vector
   - Output: List of potentially compromised systems (if any)

7. **MISP Threat Intelligence Sharing** (5 seconds)
   - Create MISP event: "Ransomware Incident - [FAMILY] - [DATE]"
   - Attributes:
     - Ransomware hash (SHA256)
     - C2 domains and IPs
     - Ransom note text (for family identification)
     - File extensions used
     - Encryption algorithm (if identified)
     - MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1059 (Execution), T1071 (C2)
   - TLP: Amber (share with trusted partners only)
   - Publish to internal systems + external ISAC

8. **Automated Defense Updates** (Parallel execution - 10 seconds)
   - **Firewall (pfSense):**
     - Block C2 domains and IPs globally
     - Create alias for ransomware infrastructure
   - **IDS/IPS (Suricata):**
     - Deploy signatures for ransomware C2 beaconing
     - Alert on encryption algorithm patterns in network traffic
   - **EDR (Wazuh):**
     - Update FIM rules: Monitor for specific ransomware file extensions
     - Deploy behavioral detection rule: Alert on >20 file modifications/minute
     - Push IOC list to all agents for proactive blocking
   - **Email Security:**
     - Block sender addresses associated with phishing vector (if identified)
     - Update spam filter rules for ransomware delivery campaigns

9. **Notification & Escalation** (Multi-channel - 5 seconds)
   - **Immediate:**
     - Discord @soc-team + @incident-response: Emergency notification
     - PagerDuty: Page on-call incident commander
     - SMS: Send alert to CISO and IT Director
   - **Executive Summary** (auto-generated):
     - Incident timeline
     - Containment actions completed
     - Systems affected
     - Data loss assessment (preliminary)
     - Recovery timeline estimate
     - Next steps and resource requirements

10. **Recovery Workflow Trigger** (Conditional - after 4-hour stabilization period)
    - Trigger separate Shuffle workflow: "Ransomware Recovery"
    - Steps:
      - Verify backups available and not encrypted
      - Restore files from last known good backup (minus ransomware infection time)
      - Rebuild compromised systems from golden images
      - Deploy enhanced monitoring for 30 days
      - Conduct post-incident review (lessons learned)
      - Update incident response playbook based on findings

![Shuffle Workflow Diagrams](/Career_Projects/assets/screenshots/shuffle-workflows.png)

![TheHive Case Screenshots](/Career_Projects/assets/screenshots/thehive-cases.png)

![Cortex Analysis Screenshots](/Career_Projects/assets/screenshots/cortex-analysis.png)

![MISP Events Screenshots](/Career_Projects/assets/screenshots/misp-events.png)

---

## 2. Monitoring & Observability Architecture

### Deployment Overview

The monitoring stack provides comprehensive visibility into the health, performance, and availability of all systems across the lab environment. Unlike SIEM platforms that focus on security events, the monitoring layer captures operational telemetry: CPU, memory, disk, network throughput, service uptime, virtualization metrics, and application-level health checks.

### Security Impact

Monitoring is a critical component of operational security. Performance anomalies often precede or accompany security incidents: unexpected CPU spikes, abnormal network traffic, failing services, or resource exhaustion can indicate brute-force attempts, malware execution, or lateral movement. By correlating infrastructure telemetry with SIEM data, defenders gain a holistic view of system behavior.

### Deployment Rationale

Modern environments require more than log-based security analytics; they require continuous operational awareness. This monitoring architecture demonstrates proficiency with enterprise-grade observability tools, hybrid infrastructure monitoring, and multi-channel alerting.

### Architecture Principles Alignment

**Defense in Depth:**

- Multiple monitoring layers (metrics, uptime, hypervisor, infrastructure) ensure no single blind spot
- Redundant alerting channels prevent missed notifications
- Cross-tool correlation strengthens detection of operational anomalies

**Secure by Design:**

- TLS-secured communication for metrics and alerting pipelines
- Segmented monitoring networks reduce exposure of sensitive telemetry
- Centralized dashboards enforce consistent visibility

**Zero Trust:**

- No host or service is implicitly trusted; all must report health and availability
- Continuous validation of service uptime and performance
- Alerting pipelines enforce accountability and traceability

### 2.1 Prometheus & Grafana - Infrastructure Metrics Platform

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>Prometheus collects high-resolution time-series metrics from servers, containers, network devices, and applications. Grafana visualizes these metrics through customizable dashboards, providing real-time insights into system performance and long-term trends. This stack focuses on operational telemetry—CPU, memory, disk I/O, network throughput, container health, and service latency.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/prometheus-grafana.png" alt="Prometheus and Grafana Logos">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Prometheus & Grafana Monitoring Stack
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Detects resource exhaustion attacks (CPU spikes, memory leaks, disk saturation)
- Identifies anomalous network throughput that may indicate data exfiltration
- Monitors container and Kubernetes health for signs of compromise
- Provides early warning when security tools (SIEM, EDR, IDS) degrade or fail

#### Deployment Rationale

Prometheus and Grafana are industry-standard observability tools used across cloud-native and hybrid environments. Their inclusion demonstrates proficiency with metrics-driven monitoring, dashboard creation, alerting rules, and containerized instrumentation.

#### Architecture Principles Alignment

- **Defense in Depth:** Metrics complement logs and endpoint telemetry for multi-layer detection
- **Secure by Design:** TLS-secured Prometheus endpoints; role-based Grafana access
- **Zero Trust:** Every host must expose metrics; no implicit trust in service health

#### Prometheus Configuration

**Core Prometheus:**

- **Labels:** prom, pve, pihole
- **Intervals:** 1m

**Alert Manager and Blackbox:**

- Notifications and Discord integration

**Exporters:**

- **Node Exporter:** Linux hosts (PVE node, VMs, Docker hosts)
- **Proxmox Exporter:** prometheus-pve-exporter hitting the PVE API
- **Pi-hole Exporter:** Containerized exporter reading FTL metrics
- **Traefik:** Reverse proxy details
- **pfSense Exporter:** System-level monitoring
- **Uptime-Kuma:** Service uptime monitoring

![Prometheus Configuration Screenshot](/Career_Projects/assets/screenshots/prometheus-config.png)

#### Grafana Dashboards

**Dashboards:**

- **Node/Host Overview:** CPU, memory, FS, network, load (per host)
- **Proxmox:** Node status, VM CPU/mem/disk IO, cluster quorum
- **Pi-hole:** Query volume, block rate, upstream latency, cache hit rate, top domains
- **Traefik:** HTTP requests, slow services
- **pfSense:** System monitoring, CPU, RAM, traffic

**Infrastructure Dashboards:**

| Dashboard Name | Data Source | Refresh Rate | Panels |
|----------------|-------------|--------------|--------|
| Node Exporter Full | Prometheus | 30s | CPU, RAM, Disk, Network, Load |
| Proxmox VE Overview | Prometheus | 1m | Cluster status, VM metrics, storage |
| Pi-hole Statistics | Prometheus | 30s | Query rate, block %, cache hits |
| Traefik Overview | Prometheus | 15s | Request rate, latency, error rate |
| pfSense System Metrics | Prometheus | 30s | CPU, RAM, interfaces, throughput |
| Blackbox Exporter | Prometheus | 1m | HTTP status, TLS cert expiry, latency |

#### Proxmox VE Dashboard

- **Exporter:** prometheus-pve-exporter as a service or container
- **Metrics:** Node/VM CPU, memory, storage pools, task failures, HA state
- **Alerts:**
  - **Node pressure:** CPU > 85% for 10m, RAM > 90% for 5m
  - **Storage:** Datastore free < 15%
  - **VM health:** No metrics from a VM for > 5m (down)

![Grafana Proxmox Dashboard](/Career_Projects/assets/screenshots/grafana-proxmox.png)

#### Pi-hole Dashboard

- **Exporter:** Containerized pihole_exporter or FTL-compatible exporter
- **Metrics:** Query rate, block rate, cache hit %, upstream latency, gravity update age
- **Alerts:**
  - **FTL down:** No scrape > 2m
  - **Block rate anomaly:** Sudden drop to near 0% or spike > 95%
  - **Upstream failures:** SERVFAIL/timeout ratio increases

![Grafana Pi-hole Dashboard](/Career_Projects/assets/screenshots/grafana-pihole.png)

#### Traefik Dashboard

- **Exporter:** Direct Prometheus integration
- **Metrics:** Instances, HTTP requests per entrypoint, application and HTTP method, slow services

![Grafana Traefik Dashboard](/Career_Projects/assets/screenshots/grafana-traefik.png)

#### pfSense Dashboard

- **Exporter:** Direct Prometheus integration
- **Metrics:** CPU, RAM, Disk monitoring, network packets by interface, pkt/sec, load avg, traps and system calls

![Grafana pfSense Dashboard](/Career_Projects/assets/screenshots/grafana-pfsense.png)

### 2.2 Uptime Kuma - Service Availability Monitoring

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>Uptime Kuma provides heartbeat monitoring for all lab services using HTTP/S, TCP, and ICMP checks. Each monitored service is continuously probed for availability, latency, and response integrity. Any deviation triggers immediate alerts routed to dedicated Discord channels.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/uptime-kuma-logo.png" alt="Uptime Kuma Logo">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Uptime Kuma Service Monitoring
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Detects service outages caused by attacks, misconfigurations, or resource exhaustion
- Identifies unstable or degraded services before they impact security tooling
- Provides uptime baselines useful for correlating with SIEM events

#### Deployment Rationale

Service uptime is foundational to both operational stability and security visibility. Uptime Kuma offers a lightweight, flexible, and highly responsive monitoring layer that mirrors enterprise heartbeat monitoring systems.

#### Architecture Principles Alignment

- **Defense in Depth:** Adds availability monitoring to complement metrics and logs
- **Secure by Design:** Segmented monitoring probes reduce attack surface
- **Zero Trust:** No service is assumed healthy; continuous validation required

![Uptime Kuma Dashboard Screenshot](/Career_Projects/assets/screenshots/uptime-kuma-dashboard.png)

![Uptime Kuma Status Page Screenshot](/Career_Projects/assets/screenshots/uptime-kuma-status.png)

### 2.3 Checkmk - Deep Infrastructure Monitoring

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>Checkmk delivers comprehensive monitoring across servers, applications, network devices, storage systems, and containerized workloads. It provides granular visibility into multi-layer dependencies and deep host-level inspection.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/checkmk-logo.png" alt="Checkmk Logo">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Checkmk Infrastructure Monitoring
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Detects abnormal system behavior (high load, failing disks, service crashes)
- Monitors critical infrastructure supporting security tools
- Provides granular visibility into multi-layer dependencies

#### Deployment Rationale

Checkmk represents enterprise-grade monitoring with agent-based and agentless capabilities. Its inclusion demonstrates proficiency with large-scale infrastructure monitoring, rule-based alerting, and hybrid environment observability.

#### Architecture Principles Alignment

- **Defense in Depth:** Adds deep host-level inspection to complement Prometheus metrics
- **Secure by Design:** Encrypted agent communication; strict role-based access
- **Zero Trust:** Every host must report detailed health metrics continuously

#### High-Level Configuration

- **Unified Monitoring:** Deployed across physical devices, virtual machines, LXC and Docker containers
- **Agent-Based:** Lightweight agents for Linux, Windows, FreeBSD
- **Custom Checks & Plugins:** Extendable with shell scripts, Python, or Checkmk's plugin framework
- **Security-Aware Monitoring:** Integrates with vulnerability scanners, SIEM platforms, and EDR tools
- **Audit-Friendly Logging:** Every alert, metric, and change is timestamped and traceable

![Checkmk Dashboard Screenshot](/Career_Projects/assets/screenshots/checkmk-dashboard.png)

![Checkmk Services Screenshot](/Career_Projects/assets/screenshots/checkmk-services.png)

![Checkmk Topology Map Screenshot](/Career_Projects/assets/screenshots/checkmk-topology.png)

### 2.4 Pulse - Proxmox Virtual Environment and Backup Server Monitoring

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>Pulse provides real-time monitoring and alerting specifically for Proxmox VE and Proxmox Backup Server. It consolidates hypervisor metrics—VM performance, storage health, cluster state, backup integrity—into a unified dashboard, enabling rapid situational awareness and proactive incident response.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/pulse-logo.png" alt="Pulse Logo">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Pulse Proxmox Monitoring
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Detects hypervisor-level anomalies that may indicate compromise or misconfiguration
- Monitors VM performance for signs of malicious activity
- Ensures backup integrity and cluster stability

![Pulse Architecture Diagram](/Career_Projects/assets/diagrams/pulse-architecture.png)

#### Deployment Rationale

Virtualization is the backbone of the lab environment. Pulse provides hypervisor-specific insights that general monitoring tools cannot, mirroring enterprise virtualization monitoring platforms.

#### Architecture Principles Alignment

- **Defense in Depth:** Adds hypervisor-layer visibility beneath OS-level monitoring
- **Secure by Design:** Dedicated monitoring channel reduces exposure of Proxmox APIs
- **Zero Trust:** No VM or node is implicitly trusted; all must report health

![Pulse Connection Settings Screenshot](/Career_Projects/assets/screenshots/pulse-connection.png)

#### Lab Integration

In this lab environment, Pulse is connected to both the Proxmox VE cluster and the PBS node. Authentication is handled via a dedicated Proxmox service account configured with an API token. This account is assigned minimal, read-only permissions required to:

- Query node, VM, and container status
- Retrieve backup job results
- Report on storage utilization

![Pulse Service Account Configuration](/Career_Projects/assets/screenshots/pulse-service-account.png)

#### Dashboards

The Pulse main dashboard provides a real-time operational view of the Proxmox environment, including:

- **Node statistics:** CPU load, memory consumption, and storage usage for each Proxmox VE host
- **Guest statistics:** Resource usage for all deployed VMs and LXCs
- **Visual threshold indicators:** Color-coded gauges and bars highlight when usage approaches or exceeds configured limits
- **Interactive webhooks:** Clicking on a monitored service or resource can open its corresponding Proxmox web portal page for direct management

**Example Use Cases in the Lab:**

- **Proactive capacity planning:** Identify nodes nearing CPU or memory saturation before performance degrades
- **Backup compliance:** Immediate notification if a PBS backup job fails, allowing for same-day remediation
- **Storage health:** Early warning when datastore usage trends toward capacity, preventing unexpected outages

![Pulse Main Dashboard Screenshot](/Career_Projects/assets/screenshots/pulse-dashboard.png)

#### Backup Dashboard

Reports on the various backup methods. The first screenshot provides details on the snapshot status and the second screenshot outlines the PBS status and history of backups.

![Pulse Backup Dashboard Screenshot](/Career_Projects/assets/screenshots/pulse-backup.png)

#### Alert Dashboard and Notifications

Summary of current alerts, configured thresholds, notifications, schedule, and alert history.

![Pulse Alert Dashboard Screenshot](/Career_Projects/assets/screenshots/pulse-alerts.png)

---

## 3. Alerting and Notification Architecture

### Deployment Overview

The alerting architecture ensures real-time visibility into operational and security events across the entire lab environment. Alerts from monitoring tools, SIEM platforms, EDR agents, and infrastructure services are routed through multiple redundant channels (Discord, SMTP relay, and Cloudflare email routing).

### Security Impact

- Immediate notification of outages, anomalies, or security events
- Redundant channels prevent alert loss due to single-system failure
- Segmented channels reduce noise and improve triage efficiency

### Deployment Rationale

Modern SOC/NOC operations rely on multi-channel alerting to ensure rapid response. This architecture demonstrates proficiency with webhook-based alerting, SMTP relays, email routing, and real-time collaboration platforms.

### Architecture Principles Alignment

- **Defense in Depth:** Multiple alerting paths ensure resilience
- **Secure by Design:** TLS-encrypted SMTP; restricted webhook endpoints
- **Zero Trust:** Alerts validated and routed per-service; no implicit trust in any channel

### 3.1 Discord Private Server - Centralized Notification Hub

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>A private Discord server acts as the real-time alerting hub for the entire environment. Each monitored service has its own dedicated channel, enabling noise isolation, targeted triage, and clear operational separation.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/discord-logo.png" alt="Discord Logo">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Discord Notification Hub
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Instant visibility into outages, anomalies, and security alerts
- Channel segmentation prevents alert overload
- Provides audit trails for incident response

#### Deployment Rationale

Discord offers low-latency notifications, webhook integration, and structured channel organization—mirroring enterprise chat-ops workflows.

#### Architecture Principles Alignment

- **Defense in Depth:** Secondary alerting path alongside email
- **Secure by Design:** Private server; restricted webhook tokens
- **Zero Trust:** No alert is trusted without validation; all events logged

![Discord Channel Structure Screenshot](/Career_Projects/assets/screenshots/discord-channels.png)

#### Notification Flow

[Monitoring Source] → [Alert Trigger] → [Webhook or Script] → [Discord Channel] → [Push Notification]

- Monitoring tools detect anomalies or threshold breaches
- Alerts are triggered via native webhook integrations or custom scripts
- Messages are sent to service-specific Discord channels using Discord's webhook API
- Discord's push notification system delivers alerts to:
  - Windows 11 desktop app
  - iPad and iPhone mobile apps

![Discord Mobile Notifications Screenshot](/Career_Projects/assets/screenshots/discord-mobile.png)

#### Discord Channel Structure

| Channel Name | Source Tool | Alert Type |
|--------------|-------------|------------|
| #proxmox | Proxmox VE | Node status, backup failures |
| #grafana | Grafana | Dashboard alerts, data source issues |
| #splunk | Splunk | Security events, log anomalies |
| #wazuh | Wazuh | Host-based intrusion alerts |
| #pulse | Pulse | OpenSearch monitor triggers |
| #uptime-kuma | Uptime Kuma | Service downtime, latency spikes |
| #openvas | OpenVAS | Vulnerability scan results |
| #pfsense | pfSense | Firewall events, VPN status |
| #prometheus | Prometheus | Node exporter, resource thresholds |
| #authentik | Authentik | Auth flow errors/alarms, auth failures |
| #windowsupdates | Windows VMs | Python script completion |

### 3.2 SMTP Relay - Gmail-Backed Email Alerting

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>An msmtp container provides a secure SMTP relay to Gmail using STARTTLS and application-specific passwords. Internal services send alerts via standard SMTP on port 25, and msmtp handles encrypted delivery to the dedicated alert mailbox.</p>
    <p>Configured services include: Proxmox, pfSense, OPNsense, TheHive, Uptime Kuma, Wazuh, Grafana, n8n, Synology NAS.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/smtp-relay-diagram.png" alt="SMTP Relay Diagram">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        SMTP Relay Architecture
      </figcaption>
    </figure>
  </div>
</div>

Gmail relay to dedicated email address: shad0w1t1a6@gmail.com

#### Security Impact

- Provides a reliable, encrypted alerting channel
- Ensures alerts are preserved even if chat-ops channels fail
- Supports forensic review through email retention

#### Deployment Rationale

Email remains a universal, durable alerting mechanism. This relay demonstrates secure outbound email configuration and multi-service integration.

#### Architecture Principles Alignment

- **Defense in Depth:** Email complements Discord for redundancy
- **Secure by Design:** STARTTLS encryption; app-password authentication
- **Zero Trust:** All alerts validated and logged; no implicit trust in sender

![SMTP Relay Configuration Screenshot](/Career_Projects/assets/screenshots/smtp-relay-config.png)

### 3.3 Cloudflare Email Routing

#### Deployment Overview

<div class="two-col-right">
  <div class="text-col">
    <p>Cloudflare Email Routing provides alias-based forwarding for individual services, enabling clean separation of alert sources and simplified identity management. Each service is assigned a unique alias for traceability.</p>
  </div>

  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/cloudflare-logo.png" alt="Cloudflare Logo">
      <figcaption style="font-size:0.9rem; color:var(--md-secondary-text-color); margin-top:0.5rem;">
        Cloudflare Email Routing
      </figcaption>
    </figure>
  </div>
</div>

#### Security Impact

- Prevents spoofing by enforcing domain-validated routing
- Enables per-service alert attribution
- Provides an additional layer of redundancy

#### Deployment Rationale

Cloudflare's routing service mirrors enterprise email aliasing strategies, improving traceability and reducing operational complexity.

#### Architecture Principles Alignment

- **Defense in Depth:** Adds routing redundancy and identity separation
- **Secure by Design:** Domain-validated forwarding; Cloudflare-managed security
- **Zero Trust:** Each alias treated as an independent identity; no implicit trust

![Cloudflare Email Routing Configuration Screenshot](/Career_Projects/assets/screenshots/cloudflare-email-routing.png)

![n8n Workflow Alert Triggers Screenshot](/Career_Projects/assets/screenshots/n8n-alert-workflows.png)

### Sample Alerts

#### Uptime Kuma Service Status Alerts

**Discord:**

![Uptime Kuma Discord Alert Screenshot](/Career_Projects/assets/screenshots/alert-uptime-kuma-discord.png)

**Gmail:**

![Uptime Kuma Gmail Alert Screenshot](/Career_Projects/assets/screenshots/alert-uptime-kuma-gmail.png)

#### Proxmox PVE and PBS Successful Backup Job Completion Alert

**Discord:**

![Proxmox Backup Success Discord Alert Screenshot](/Career_Projects/assets/screenshots/alert-proxmox-backup-discord.png)

**Gmail:**

![Proxmox Backup Success Gmail Alert Screenshot](/Career_Projects/assets/screenshots/alert-proxmox-backup-gmail.png)

#### Splunk Scheduled Weekly VPN Activity Log Notification

![Splunk VPN Activity Alert Screenshot](/Career_Projects/assets/screenshots/alert-splunk-vpn.png)

#### pfSense Firewall Event Alert

![pfSense Alert Screenshot](/Career_Projects/assets/screenshots/alert-pfsense.png)

#### Grafana pfSense Interface Status Alerts

![Grafana Interface Status Alert Screenshot](/Career_Projects/assets/screenshots/alert-grafana-interface.png)

![Grafana Alert Details Screenshot](/Career_Projects/assets/screenshots/alert-grafana-details.png)

#### Prometheus Blackbox Alerts

HTTP Get, TLS Cert expiry, Discord ping, local ICMP, TCP SSH and TCP HTTPS

**Alert Manager - Endpoint Reachability Alerts:**

![Prometheus Blackbox Alerts Screenshot](/Career_Projects/assets/screenshots/alert-prometheus-blackbox.png)

---

## 4. Security Controls Summary

### Visibility and Response Security Controls

**Control Framework:**

| Control Domain | Implementation | Coverage |
|----------------|----------------|----------|
| Log Aggregation | Splunk + Elastic centralized collection | All infrastructure |
| Endpoint Detection | Wazuh EDR on 12 hosts | Windows, Linux, MacOS |
| Network Monitoring | Suricata/Snort IDS on all interfaces | 100% traffic inspection |
| File Integrity Monitoring | Wazuh FIM on critical paths | System files, configs |
| Vulnerability Assessment | Wazuh + OpenVAS automated scanning | All hosts |
| Compliance Auditing | Wazuh SCA policies (CIS, PCI-DSS) | Continuous assessment |
| Alert Correlation | Splunk SPL queries, Elastic detection rules | Multi-source correlation |
| Incident Response | Automated containment, Discord alerting | Real-time response |
| Audit Logging | 90-day retention in SIEM | Full audit trail |
| Performance Monitoring | Prometheus + Grafana dashboards | All infrastructure |

**Security Event Pipeline:**

1. Collection: Agents/forwarders collect logs from sources
2. Transport: Encrypted TLS/SSL to SIEM platforms
3. Parsing: Field extraction and normalization
4. Enrichment: GeoIP, threat intel, asset context
5. Correlation: Multi-source event correlation
6. Detection: Rule-based and ML anomaly detection
7. Alerting: Discord webhooks + email notifications
8. Response: Automated containment actions
9. Investigation: Search and visualization tools
10. Retention: 90-day storage, then archive

**Data Classification:**

| Data Type | Sensitivity | Retention | Encryption |
|-----------|-------------|-----------|------------|
| Security Alerts | High | 90 days | At rest + in transit |
| System Logs | Medium | 90 days | At rest + in transit |
| Application Logs | Low | 30 days | In transit only |
| Performance Metrics | Low | 90 days | None |

**Access Control:**

- SIEM Platforms: Authentik SSO with MFA required
- API Access: API tokens with 90-day rotation
- Dashboard Access: Role-based permissions (admin, analyst, viewer)
- Alert Management: Admin-only response actions

**Encryption Standards:**

- Log Transport: TLS 1.3 for all forwarder connections
- At Rest: AES-256 for stored logs and backups
- Certificates: Step-CA issued, auto-renewed

**Detection Coverage:**

| MITRE ATT&CK Technique | Detection Method | Data Source |
|------------------------|------------------|-------------|
| Initial Access (T1078) | Failed login correlation | Wazuh, pfSense |
| Execution (T1059) | PowerShell command monitoring | Sysmon |
| Persistence (T1547) | Registry/startup monitoring | Wazuh FIM |
| Privilege Escalation (T1068) | Process creation anomalies | Sysmon, Wazuh |
| Defense Evasion (T1070) | Log clearing detection | Windows Event Log |
| Credential Access (T1003) | LSASS access monitoring | Sysmon Event ID 10 |
| Discovery (T1082) | System info enumeration | Wazuh, Sysmon |
| Lateral Movement (T1021) | RDP/SMB connection tracking | Suricata, Wazuh |
| Collection (T1005) | Unusual file access patterns | Wazuh FIM |
| Exfiltration (T1041) | Large outbound transfers | pfSense, Suricata |
| Command and Control (T1071) | Beacon detection | Suricata, pfSense |

---

## 5. Use Cases and Scenarios

### Practical Use Cases and Detection Scenarios

#### Scenario 1: Brute Force Attack Detection and Response

**Objective:** Detect and automatically block SSH brute force attempts

**Workflow:**

1. Attacker attempts SSH login to docker-vm-01 from 192.168.1.99
2. Failed attempts logged to /var/log/auth.log
3. Splunk Universal Forwarder forwards logs to Splunk indexer
4. Splunk correlation search detects >20 failed attempts in 5 minutes
5. Alert triggered: "SSH Brute Force from 192.168.1.99"
6. Discord webhook notification sent to #security channel
7. Wazuh active response triggers firewall-drop.sh script
8. iptables rule added: Block 192.168.1.99 for 10 minutes
9. Security analyst reviews alert in Splunk dashboard
10. Analyst extends block to permanent if deemed malicious

**SPL Query:**
```spl
index=auth sourcetype=syslog "Failed password"
| rex field=_raw "Failed password for (?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, dest_host
| where count > 20
| eval threat_level="High", action="Block IP"
```

#### Scenario 2: Malware Execution Detection

**Objective:** Detect execution of malicious file on Windows endpoint

**Workflow:**

1. User on Win11Pro opens malicious email attachment
2. Malware (ransomware.exe) executes
3. Sysmon Event ID 1 (Process Creation) logged
4. Wazuh agent forwards event to Wazuh manager
5. Wazuh rule matches suspicious process characteristics:
   - Unsigned executable
   - Launched from %TEMP% directory
   - Network connection to unknown IP
6. Wazuh generates Critical alert (level 15)
7. Alert forwarded to Splunk for correlation
8. Splunk enriches alert with threat intelligence lookup
9. MD5 hash matches known ransomware family
10. Discord notification: "CRITICAL: Ransomware detected on Win11Pro"
11. Wazuh active response kills process
12. File quarantined to secure location
13. Host isolated from network (manual step)
14. Incident response team engages

**Wazuh Rule:**
```xml
<rule id="100200" level="15">
  <if_sid>18106</if_sid>
  <field name="win.eventdata.image">\.exe$</field>
  <field name="win.eventdata.commandLine">\\Temp\\</field>
  <description>Suspicious executable launched from Temp directory</description>
  <mitre>
    <id>T1204.002</id>
  </mitre>
</rule>
```

#### Scenario 3: Lateral Movement Detection

**Objective:** Identify attacker moving between hosts after initial compromise

**Workflow:**

1. Attacker compromises Win11Pro via phishing
2. Attacker attempts RDP to DC01 using stolen credentials
3. Suricata IDS detects RDP connection: 192.168.1.200 → 192.168.1.152:3389
4. Windows Security Event 4624 (Successful Logon) on DC01
5. Wazuh agent on DC01 forwards event to manager
6. Splunk correlation search identifies:
   - User "jdoe" logged in from Win11Pro (unusual source)
   - Time: 2:30 AM (outside normal business hours)
   - Logon Type 10 (RemoteInteractive/RDP)
7. Alert generated: "Suspicious Lateral Movement Detected"
8. Discord notification with full context
9. Analyst reviews:
   - User's normal login pattern (9 AM - 5 PM from office PC)
   - No scheduled maintenance windows
   - Source host shows signs of compromise
10. Analyst disables user account in AD
11. Terminates RDP session on DC01
12. Initiates forensic investigation

**Splunk Correlation Query:**
```spl
(index=wazuh-alerts rule.id="60204") OR (index=suricata-lan dest_port=3389)
| eval time_hour=strftime(_time,"%H")
| where (time_hour < 6 OR time_hour > 22)
| stats values(src_ip) as source_ips, values(dest_ip) as dest_hosts by user
| where mvcount(dest_hosts) > 1
| eval threat="Lateral movement: user accessed multiple hosts outside business hours"
```

#### Scenario 4: Configuration Drift Detection

**Objective:** Detect unauthorized changes to critical system configurations

**Workflow:**

1. Attacker gains access to web server (Apache LXC)
2. Modifies /etc/ssh/sshd_config to enable PasswordAuthentication
3. Wazuh FIM detects file change within seconds
4. Wazuh generates alert with file diff:
   - Old value: PasswordAuthentication no
   - New value: PasswordAuthentication yes
5. Alert includes MD5/SHA256 hash of modified file
6. Alert forwarded to Splunk and displayed in dashboard
7. Discord notification: "File Integrity Violation on Apache LXC"
8. Analyst reviews change:
   - Change made by root user
   - No change ticket associated with modification
   - Unauthorized change confirmed
9. Wazuh active response:
   - Restores original sshd_config from backup
   - Restarts SSH service with secure config
10. Analyst investigates how attacker gained root access

**Wazuh FIM Alert:**
```
Event: Modified
File: /etc/ssh/sshd_config
Old MD5: a1b2c3d4e5f6...
New MD5: f6e5d4c3b2a1...
User: root
Time: 2024-11-06 14:23:45
Severity: High (level 10)
```

#### Scenario 5: Compliance Violation Detection

**Objective:** Identify hosts failing CIS benchmark requirements

**Workflow:**

1. Wazuh SCA scan runs every 12 hours
2. Scan detects violations on DC01:
   - Password minimum length: 8 (Required: 14)
   - Account lockout threshold: 5 (Required: 3)
   - Audit log retention: 30 days (Required: 90 days)
3. Wazuh generates compliance report
4. Report forwarded to Splunk
5. Compliance dashboard shows:
   - Overall score: 89.2% (below 95% target)
   - Critical failures: 3
   - Affected hosts: DC01
6. Weekly compliance report emailed to IT management
7. Security team creates remediation tickets:
   - GPO update for password policy
   - GPO update for lockout threshold
   - Increase audit log retention
8. Changes applied via Group Policy
9. Next scan confirms compliance: 96.5%

**Wazuh Compliance Query:**
```
Policy: CIS Windows Server 2022
Failed Checks: 3
Score: 89.2%
Risk Level: Medium
```
---

## 6. Standards Alignment

### Visibility and Response Standards

**Industry Framework Alignment:**

| Framework/Standard | Alignment | Implementation Evidence |
|-------------------|-----------|-------------------------|
| NIST Cybersecurity Framework | High | Full Detect, Respond, Recover implementation; Shuffle orchestrates automated response |
| NIST SP 800-53 (AU controls) | High | Comprehensive audit logging and monitoring |
| NIST SP 800-61 (Incident Response) | High | Full IR lifecycle automation via Shuffle playbooks; MTTR reduced by 85-97% |
| CIS Critical Security Controls | High | Controls 6, 7, 8, 13, 16 implemented |
| ISO 27001:2022 (Operations Security) | High | Logging, monitoring, incident management; automated playbooks for Controls 5.24-5.27 |
| PCI-DSS v4.0 (Requirement 10) | Moderate | Centralized logging, tamper protection |
| MITRE ATT&CK Framework | High | Detection coverage across 11 tactics; Shuffle correlates alerts to ATT&CK techniques |
| SANS Critical Controls | High | Continuous monitoring and alerting |
| Syslog Protocol (RFC 5424) | High | Standardized log format compliance |
| Elastic Common Schema (ECS) | High | Normalized field naming for cross-platform correlation |

### NIST Cybersecurity Framework (CSF) - Comprehensive Mapping

#### Detect Function

| Category | Subcategory | Implementation | Maturity Level |
|----------|-------------|----------------|----------------|
| DE.AE (Anomalies & Events) | DE.AE-1: Baseline established | Wazuh baseline monitoring; Prometheus metrics; behavioral analysis | **Advanced** |
| | DE.AE-2: Events analyzed | Cortex multi-engine analysis; MISP correlation; Splunk/Elastic analytics | **Advanced** |
| | DE.AE-3: Data aggregated | Splunk/Elastic centralized logging; Wazuh EDR; network flow data | **Advanced** |
| | DE.AE-4: Impact determined | TheHive case severity scoring; asset criticality assessment | **Advanced** |
| | DE.AE-5: Thresholds defined | Prometheus alerting rules; Splunk/Elastic correlation searches; Wazuh rules | **Advanced** |
| DE.CM (Continuous Monitoring) | DE.CM-1: Network monitored | Suricata/Snort IDS; pfSense flow logs; Safeline WAF; network observability | **Advanced** |
| | DE.CM-3: Personnel monitored | Active Directory audit logs; Authentik authentication; privileged access monitoring | **Advanced** |
| | DE.CM-4: Malicious code detected | Wazuh FIM; Yara rules; Cortex file analysis; WAF blocking | **Advanced** |
| | DE.CM-5: Unauthorized devices detected | Network device inventory; MAC address tracking; Wazuh agent monitoring | **Intermediate** |
| | DE.CM-6: External service activity | Cloudflare analytics; VPN logs; public service monitoring | **Advanced** |
| | DE.CM-7: Unauthorized activity monitored | Failed authentication tracking; privilege escalation detection; lateral movement monitoring | **Advanced** |
| | DE.CM-8: Vulnerability scans performed | OpenVAS/Nessus weekly scans; continuous assessment | **Advanced** |
| DE.DP (Detection Processes) | DE.DP-1: Roles defined | Documented SOC team structure; TheHive task assignments | **Advanced** |
| | DE.DP-2: Detection activities comply | CIS benchmarks; NIST 800-53 controls; vendor security baselines | **Advanced** |
| | DE.DP-4: Event detection communicated | Discord/email notifications; TheHive case updates | **Advanced** |
| | DE.DP-5: Detection improved | Post-incident reviews; MTTR tracking; workflow optimization | **Advanced** |

#### Respond Function

| Category | Subcategory | Implementation | Maturity Level |
|----------|-------------|----------------|----------------|
| RS.RP (Response Planning) | RS.RP-1: Plan executed | TheHive IR playbooks; documented procedures; runbooks | **Advanced** |
| RS.CO (Communications) | RS.CO-1: Personnel know roles | SOC team documentation; TheHive task assignments | **Advanced** |
| | RS.CO-2: Events reported | Internal: Discord, TheHive; External: ISAC sharing via MISP | **Advanced** |
| | RS.CO-3: Info shared | MISP threat intelligence sharing; CrowdSec community; vendor coordination | **Advanced** |
| | RS.CO-5: Voluntary info sharing | MISP events shared with trusted ISACs; CrowdSec community contributions | **Advanced** |
| RS.AN (Analysis) | RS.AN-1: Notifications investigated | Cortex automated analysis; MISP correlation; Splunk queries | **Advanced** |
| | RS.AN-2: Impact understood | Asset inventory correlation; data classification; business impact analysis | **Advanced** |
| | RS.AN-3: Forensics performed | Wazuh forensic data collection; memory dumps; network captures | **Advanced** |
| | RS.AN-4: Incidents categorized | TheHive taxonomy; MITRE ATT&CK mapping; severity scoring | **Advanced** |
| | RS.AN-5: Processes established | Documented analysis procedures; Cortex analyzer workflows; MISP playbooks | **Advanced** |
| RS.MI (Mitigation) | RS.MI-1: Incidents contained | Wazuh active response; firewall blocking; network isolation | **Advanced** |
| | RS.MI-2: Incidents mitigated | Malware removal; account lockouts; vulnerability patching | **Advanced** |
| | RS.MI-3: Vulnerabilities mitigated | Virtual patching (WAF); IDS signatures; emergency patching via Ansible | **Advanced** |
| RS.IM (Improvements) | RS.IM-1: Plans incorporate lessons learned | Post-incident reviews in TheHive; workflow optimization; playbook updates | **Advanced** |

#### Recover Function

| Category | Subcategory | Implementation | Maturity Level |
|----------|-------------|----------------|----------------|
| RC.RP (Recovery Planning) | RC.RP-1: Plan executed | Backup restoration procedures; system rebuild playbooks; service validation | **Advanced** |
| RC.IM (Improvements) | RC.IM-1: Lessons incorporated | TheHive post-incident documentation; workflow refinements; control updates | **Advanced** |
| | RC.IM-2: Strategies updated | Recovery time objectives reviewed; backup testing; disaster recovery exercises | **Intermediate** |

### NIST SP 800-53 Audit Controls

| Control | Requirement | Implementation |
|---------|-------------|----------------|
| AU-2 | Auditable Events | Comprehensive logging of all security events |
| AU-3 | Content of Audit Records | Timestamp, source, outcome, user recorded |
| AU-4 | Audit Storage Capacity | 90-day retention with capacity monitoring |
| AU-5 | Response to Audit Failures | Automated alerts on forwarder/indexer failures; failover mechanisms; disk full protection |
| AU-6 | Audit Review and Analysis | Daily dashboard review, correlation searches |
| AU-7 | Audit Reduction and Reports | Grafana/Splunk/Elastic dashboards; scheduled reports |
| AU-8 | Time Stamps | NTP synchronization across all systems |
| AU-9 | Protection of Audit Info | Write-once Elasticsearch indexes; TLS encryption in transit; RBAC access controls; tamper detection |
| AU-10 | Non-Repudiation | Digital signatures on critical logs; immutable audit trail; chain of custody for forensics; Shuffle maintains complete execution audit trail in OpenSearch |
| AU-11 | Audit Record Retention | 90-day hot storage, 1-year cold archive |
| AU-12 | Audit Generation | Agents deployed on all critical systems |
| AU-14 | Session Audit | User session logging; command-line auditing (Sysmon, auditd); privileged access tracking |

### NIST SP 800-61 Rev. 2 - Incident Response Lifecycle

| Phase | NIST 800-61 Requirement | Implementation |
|-------|------------------------|----------------|
| 1. Preparation | IR plan, tools, team training, communication procedures | TheHive playbooks, Cortex analyzers, MISP threat intel, documented procedures, SOC team structure, Shuffle playbooks (workflows) |
| 2. Detection & Analysis | Alert monitoring, triage, correlation, severity assessment, documentation | Wazuh/Splunk/Elastic alerting → Cortex enrichment → MISP correlation → TheHive case creation |
| 3. Containment, Eradication & Recovery | Short-term containment, evidence preservation, eradication, system restoration, vulnerability remediation | Wazuh active response, firewall blocking, network isolation, malware removal, patching, backup restoration, Shuffle workflow automation |
| 4. Post-Incident Activity | Lessons learned, metrics, process improvement, evidence retention | TheHive case documentation, MTTR tracking, workflow optimization, forensic archival, Shuffle reporting |

### CIS Controls v8 Implementation

| Control | Description | Implementation |
|---------|-------------|----------------|
| 6.2 | Activate audit logging | Syslog, Windows Event Log, application logs |
| 6.3 | Establish log management | Splunk + Elastic centralized aggregation |
| 6.4 | Ensure adequate log storage | 90-day hot retention, unlimited archive |
| 7.1 | Establish vulnerability management | OpenVAS/Nessus infrastructure scanning, patch tracking |
| 8.2 | Collect audit logs | Universal forwarders, Elastic agents |
| 8.5 | Centralize audit logs | Splunk indexers, Elasticsearch cluster |
| 8.6 | Collect DNS query logs | Pi-hole query logging, pfSense/OPNsense DNS logs to Splunk/Elastic |
| 8.8 | Collect command-line audit | Sysmon Event ID 1 (Windows), auditd execve logging (Linux), Wazuh command monitoring |
| 13.2 | Deploy host-based IDS | Wazuh agents on all endpoints |
| 13.3 | Deploy network IDS | Suricata/Snort on all network segments |
| 13.6 | Network boundary logging | pfSense/OPNsense logs to SIEM |
| 16.11 | Remediate penetration findings | OpenVAS/Nessus findings tracked in TheHive cases, SLA monitoring, validation scanning |

### MITRE ATT&CK Detection Coverage

| Tactic | Techniques Covered | Detection Data Sources |
|--------|-------------------|------------------------|
| Initial Access | 6 of 9 | Network traffic, authentication logs, email analysis |
| Execution | 8 of 12 | Process creation (Sysmon ID 1), command-line logging (auditd) |
| Persistence | 7 of 19 | Registry monitoring, file system (Wazuh FIM), scheduled tasks |
| Privilege Escalation | 5 of 13 | Process creation, UAC bypass detection, user activity monitoring |
| Defense Evasion | 9 of 42 | File integrity monitoring, log clearing detection (Wazuh), obfuscation |
| Credential Access | 4 of 15 | LSASS access monitoring, credential dumping detection, brute force |
| Discovery | 8 of 30 | Process creation, network connections, enumeration commands |
| Lateral Movement | 5 of 9 | Network traffic analysis, authentication logs (RDP/SMB/SSH) |
| Collection | 3 of 17 | File access monitoring, screen capture detection, clipboard monitoring |
| Exfiltration | 4 of 9 | Network traffic analysis, egress monitoring, unusual data transfers |
| Command and Control | 6 of 16 | Network connections, DNS queries, HTTP/HTTPS traffic analysis |
| Impact | 6 of 9 | Ransomware detection (Wazuh FIM), DoS detection, data destruction |

### Detailed Technique Mapping (High-Priority Techniques)

| ATT&CK ID | Technique | Detection Method |
|-----------|-----------|------------------|
| T1190 | Exploit Public-Facing Application | Safeline WAF alerts, vulnerability scanning (OpenVAS/Nessus) |
| T1566.001 | Phishing: Spearphishing Attachment | Email analysis (attachment scanning), Cortex malware analysis |
| T1566.002 | Phishing: Spearphishing Link | URL analysis (VirusTotal, URLhaus, PhishTank), Safeline WAF |
| T1059.001 | Command and Scripting: PowerShell | Sysmon ID 1 (process creation), command-line auditing, obfuscation detection |
| T1059.003 | Command and Scripting: Windows Command Shell | Command-line logging, Wazuh monitoring, parent-child process analysis |
| T1136.001 | Create Account: Local Account | Windows Security Event ID 4720, auditd user add, Active Directory logs |
| T1505.003 | Server Software Component: Web Shell | Wazuh FIM on web directories, Yara web shell signatures, Safeline WAF |
| T1027 | Obfuscated Files or Information | Yara rules, entropy analysis, Cortex file analysis (multiple engines) |
| T1070.004 | Indicator Removal: File Deletion | Wazuh FIM, mass deletion detection, suspicious file operations |
| T1110.001 | Brute Force: Password Guessing | Failed authentication tracking (Splunk correlation), CrowdSec detection |
| T1110.003 | Brute Force: Password Spraying | Multiple failed authentications across accounts, timeline analysis |
| T1555.003 | Credentials from Password Stores: Browser | Wazuh monitoring of browser credential file access, process monitoring |
| T1046 | Network Service Discovery | Port scan detection (Suricata), network reconnaissance patterns |
| T1021.001 | Remote Services: Remote Desktop Protocol | RDP authentication logs, unusual RDP connections, lateral movement patterns |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | SMB traffic analysis, authentication logs, file share access monitoring |
| T1005 | Data from Local System | Unusual file access patterns, data staging detection, large file operations |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS traffic analysis, MISP C2 infrastructure lookups, DNS queries |
| T1041 | Exfiltration Over C2 Channel | Egress traffic monitoring, MISP IOC matching, unusual data transfers |
| T1486 | Data Encrypted for Impact (Ransomware) | Wazuh FIM (>50 files modified <60 sec), file extension changes, ransom notes |
| T1499 | Endpoint Denial of Service | HTTP flood detection (Safeline WAF), connection rate monitoring, resource exhaustion |

### ISO 27001:2022 Controls Implementation

| Control | Title | Implementation |
|---------|-------|----------------|
| 5.24 | Information Security Incident Management Planning and Preparation | TheHive IR workflows, Cortex responders, documented playbooks, SOC team structure |
| 5.25 | Assessment and Decision on Information Security Events | Cortex analysis, MISP correlation, threat scoring, severity assessment |
| 5.26 | Response to Information Security Incidents | TheHive case management, automated containment, multi-party coordination |
| 5.27 | Learning from Information Security Incidents | Post-incident reviews, metrics tracking, process improvement, lessons learned |
| 8.7 | Protection Against Malware | Safeline WAF, Suricata/Snort IDS, Wazuh EDR, email security, ClamAV/Yara |
| 8.16 | Monitoring Activities | Prometheus, Grafana, Splunk SIEM, Wazuh EDR, Elastic Stack |
| A.12.4.1 | Event Logging | Comprehensive logging across endpoints, network, applications, cloud services |
| A.16.1.4 | Assessment of Security Events | Splunk/Elastic correlation, Cortex automated analysis, threat intelligence enrichment |
| A.16.1.5 | Response to Security Incidents | TheHive case workflows, automated containment, coordinated response |

### PCI-DSS v4.0 Requirement 10 (Logging and Monitoring)

| Requirement | Description | Implementation |
|-------------|-------------|----------------|
| 10.2.1 | All user access to cardholder data logged | Wazuh file access monitoring, database audit logs, application logging |
| 10.2.2 | All privileged actions logged | Active Directory privileged access tracking, sudo logging, admin portal access |
| 10.3.1 | User identity recorded | ECS normalized user fields, authentication logs, session tracking |
| 10.3.2 | Event type recorded | Standardized event taxonomy, ECS event.action field, categorization |
| 10.3.3 | Date and time recorded | NTP synchronization, UTC timestamps, millisecond precision |
| 10.3.4 | Success/failure indication | Event outcome field, authentication result, transaction status |
| 10.3.5 | Origination of event | Source IP, hostname, device ID, geographic location |
| 10.4.1 | Audit logs reviewed daily | Splunk/Elastic dashboards reviewed by SOC analysts, automated correlation searches |
| 10.5.1 | Audit logs protected from modification | Write-once Elasticsearch indexes, immutable S3 archival, tamper detection |
| 10.6.1 | Automated log review and anomaly detection | Prometheus alerting, Splunk correlation searches, Wazuh rules, ML anomaly detection |
| 10.7.1 | Audit log retention | 90 days hot, 1 year archive |

### GDPR (EU 2016/679) - Data Protection Requirements

| Article | Requirement | Implementation |
|---------|-------------|----------------|
| Article 25 | Data Protection by Design and by Default | Security controls at application layer (WAF, encryption), minimal data retention, access controls |
| Article 32 | Security of Processing | Technical security measures (encryption, pseudonymization, monitoring, incident response) |
| Article 33 | Notification of Personal Data Breach to Supervisory Authority (72 hours) | TheHive breach assessment workflow, timeline tracking, notification templates |
| Article 34 | Communication of Personal Data Breach to Data Subject | Affected user identification, breach impact assessment, notification procedures |

### HIPAA Security Rule (45 CFR Part 164) - Healthcare Compliance

| Rule | Requirement | Implementation |
|------|-------------|----------------|
| §164.308(a)(1) | Security Management Process | Risk analysis, risk management, sanction policy, information system activity review |
| §164.308(a)(6) | Security Incident Procedures | Incident response plan, reporting, mitigation |
| §164.312(a)(1) | Access Control | Unique user identification, emergency access, automatic logoff, encryption |
| §164.312(b) | Audit Controls | Logging and monitoring of PHI access |
| §164.312(e)(1) | Transmission Security | Encryption of PHI in transit, integrity controls |

### Syslog Compliance (RFC 5424)

| Component | Specification | Implementation |
|-----------|---------------|----------------|
| Facility | USER, LOCAL0-LOCAL7 | Properly categorized |
| Severity | 0 (Emergency) to 7 | Mapped correctly |
| Timestamp | ISO 8601 format | NTP synchronized |
| Hostname | FQDN or IP | FQDN preferred |
| Message Format | Structured data | JSON where possible |

### Elastic Common Schema (ECS) Compliance

**ECS Version:** 8.x

**Compliance:** 95%+ for integrated data sources

**Benefits:**

- Cross-source correlation without field mapping
- Pre-built Kibana dashboards work out-of-box
- Future integrations automatically compatible
- Machine learning models use standard fields

---

## 7. Security Homelab Section Links

- **[Executive Summary and Security Posture](/Career_Projects/projects/homelab/01-exec-summary/)**
- **[Infrastructure Platform, Virtualization Stack and Hardware](/Career_Projects/projects/homelab/02-platform/)**
- **[Network Security, Privacy and Remote Access](/Career_Projects/projects/homelab/03-network/)**
- **[Identity, Access, Secrets and Trust Management](/Career_Projects/projects/homelab/04-iam-secrets/)**
- **[Automation and IaC](/Career_Projects/projects/homelab/05-auto-iac/)**
- **[Applications and Services](/Career_Projects/projects/homelab/06-apps-service/)**
- **[Observability and Response, Part 1](/Career_Projects/projects/homelab/07-vis-response-pt1/)**
- **[Observability and Response, Part 2](/Career_Projects/projects/homelab/08-vis-response-pt2/)**

