## Comprehensive Framework Alignment Matrix

| Security Domain | NIST CSF 2.0 | CIS v8.1 | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | OWASP 2025 | MITRE ATT&CK v18.1 | CISA ZTMM v2.0 | NIST SP 800-207 |
|-----------------|--------------|----------|----------------|-------------------|--------------|------------|-------------------|----------------|-----------------|
| Asset Management | ID.AM-01 to ID.AM-08 | 1.1-1.5, 2.1-2.4 | A.5.9, A.8.1 | CM-8, CM-8(1)-(3), PM-5 | 2.4, 6.4.3 | N/A | T1018, T1046, T1135 | Devices: Advanced | Tenet 1: Resource Inventory |
| Network Segmentation | PR.AC, DE.CM | 12.1-12.4, 13.4 | A.8.20, A.8.22 | SC-7, SC-7(21) | 1.1.1, 1.3.1 | A01 (SSRF), A06 | N/A | Networks: Advanced | Tenet 2: Micro-segmentation |
| Firewall Management | PR.AC, SC-7 | 12.1-12.2 | A.8.20 | SC-7, SC-7(5) | 1.2.1, 1.4.2 | A02 | N/A | Networks: Advanced | Tenet 2: Boundary Protection |
| Firewall HA | PR.IR-01, RC.RP | 12.1, 12.2 | A.8.14, A.8.20 | CP-9, SC-7(20), SI-4(1) | 1.1.1, 1.3.7 | N/A | N/A | Networks: Advanced | Tenet 7: Resilience |
| DMZ Architecture | PR.IR, SC-7 | 12.2 | A.8.20, A.8.22 | SC-7(21) | 1.3.1 | A06 | N/A | Networks: Advanced | Tenet 2: Isolation |
| Network Monitoring | DE.CM | 13.1-13.6 | A.8.16, A.8.20 | SI-4, SI-4(1)(4) | 11.4.1, 11.4.2 | A09 | T1046, T1049, T1590 | Visibility: Advanced | Tenet 7: Comprehensive Telemetry |
| IDS/IPS | DE.CM-01, DE.AE-02 | 13.1-13.3, 13.6-13.8 | A.8.7, A.8.16, A.8.20 | SI-4, SI-4(1)(2)(5) | 11.4.1, 11.4.2 | N/A | T1046, T1595 | Visibility: Advanced | Tenet 7: Monitoring |
| WAF Protection | DE.CM, RS.MI | 13.10 | A.8.23, A.8.26 | SI-4(23), SI-10, SC-7(11) | 6.6 | A01, A05 (Injection) | T1190, T1659 | Apps: Advanced | Tenet 4: Policy Enforcement |
| VPN/Remote Access | PR.AC, PR.DS-02 | 12.3, 12.7, 13.10 | A.5.14, A.6.7, A.8.21 | AC-17, AC-17(1)(2)(4), SC-8, SC-13 | 4.1, 8.2.3, 12.3 | N/A | T1133 | Identity: Advanced | Tenet 2: Location Independence |
| Access Control & Authorization | PR.AA, PR.AC | 6.1-6.6 | A.5.15, A.5.18, A.8.3 | AC-2, AC-3, AC-6 | 7.1, 7.2, 8.1 | A01 (Broken Access Control) | T1078, T1098, T1087 | Identity: Advanced | Tenet 3: Least Privilege |
| RBAC Implementation | AC-3(7), PR.AA | 6.8 | A.5.18, A.8.3 | AC-2(7), AC-3(7) | 7.1.2 | A01 | T1078 | Identity: Advanced | Tenet 3: Role-Based Access |
| Least Privilege | AC-6, PR.AA | 5.4, 6.1-6.6 | A.5.18 | AC-6, AC-6(1)(2)(5) | 7.1.1 | A01, A06 | T1548 | Identity: Advanced | Tenet 3: Least Privilege |
| SSRF Prevention | PR.AC, DE.CM | 12.3, 13.10 | A.8.20, A.8.21 | SC-7, SI-10 | 6.6 | A01 | N/A | Networks: Advanced | Tenet 4: Policy Enforcement |
| SSO Implementation | IA-2(10), PR.AA | 6.6-6.7 | A.5.15, A.8.5 | IA-2(10) | 8.2.1 | A07 (Authentication) | T1078 | Identity: Advanced | Tenet 3: Centralized Identity |
| MFA Enforcement | IA-2(1), PR.AA-01 | 6.3-6.5 | A.5.17, A.8.5 | IA-2(1)(2) | 8.2.3, 8.3.1 | A07 | T1078, T1111 | Identity: Advanced | Tenet 6: Phishing-Resistant MFA |
| SSH Key Management | IA-5(2), PR.AA | 5.6, 6.7 | A.5.17, A.8.24 | IA-5(2), IA-5(14) | 8.3.2 | A07 | T1552, T1078 | Identity: Advanced | Tenet 6: Certificate-Based Auth |
| Account Lockout | AC-7, PR.AA | 6.3 | A.9.4.2 | AC-7 | 8.2.4, 8.2.5 | A07 | T1110 | Identity: Advanced | Tenet 6: Automated Protection |
| Session Management | AC-12, SC-23 | 6.3 | A.8.5 | AC-2(5), AC-11, AC-12, SC-23 | 8.1.8 | A07 | T1539, T1563 | Identity: Advanced | Tenet 3: Session-Based Access |
| Password Management | IA-5(1), PR.DS | 5.2, 6.2 | A.5.17 | IA-5(1), IA-5(18) | 8.2.2, 8.3.2 | A07 | T1555, T1552 | Identity: Advanced | Tenet 6: Strong Authentication |
| Credential Protection | IA-5(7), PR.DS | 3.11, 6.7 | A.5.17, A.8.24 | IA-5(7), IA-5(18), SC-28(3) | 3.5, 3.6, 8.3.2 | A07, A08 | T1003, T1555, T1552 | Data: Advanced | Tenet 6: Credential Encryption |
| Active Directory | PR.AA-01, AC-2 | 5.3, 5.6, 6.1, 6.8 | A.5.16, A.8.2 | AC-2, AC-3(7), IA-2, IA-4, IA-5 | 8.2, 8.3 | A07 | T1087, T1482 | Identity: Advanced | Tenet 3: Centralized Directory |
| Secrets Management | PR.DS-01, IA-5(7) | 3.11, 5.2, 6.7 | A.5.17, A.8.24 | IA-5(7), IA-5(18), SC-12, SC-28(3) | 3.5, 3.6, 8.2.1 | A07, A08 | T1552, T1555 | Data: Advanced | Tenet 6: Zero-Knowledge Vault |
| PKI/Certificate Management | PR.DS-10, SC-17 | 3.12, 16.14 | A.8.24 | SC-12, SC-13, SC-17, SC-17(1), IA-5(14) | 4.2.1 | A04 (Cryptography) | N/A | Identity: Advanced | Tenet 6: Automated PKI |
| TLS/Encryption (Transit) | PR.DS-02, SC-8 | 3.10, 12.6, 13.10 | A.8.24 | SC-8, SC-8(1), SC-13 | 4.2.1 | A04 | N/A | Data: Advanced | Tenet 2: Encrypt All Communications |
| Encryption at Rest | PR.DS-01, SC-28 | 3.11 | A.8.24 | SC-28, SC-28(1)(3) | 3.4, 4.2.1 | A04 | N/A | Data: Advanced | Tenet 2: Protect Data at Rest |
| Key Management | SC-12, PR.DS | 3.12, 6.7 | A.8.24 | SC-12, SC-13 | 4.2.1 | A04 | N/A | Data: Advanced | Tenet 6: Protected Key Storage |
| DNSSEC | SC-20, PR.DS | 9.2, 12.6 | A.8.21, A.8.23 | SC-20, SC-20(2), SC-21 | 2.2.5 | A04 | N/A | Networks: Advanced | Tenet 2: DNS Integrity |
| DNS Security | PR.DS, DE.CM | 9.2, 12.6 | A.8.21, A.8.23 | SC-20, SC-20(2), SC-21 | 2.2.5 | N/A | T1071.004, T1568 | Networks: Advanced | Tenet 7: DNS Monitoring |
| Configuration Management | PR.PS-01, CM-2 | 4.1-4.12, 16.7 | A.8.9, A.8.32 | CM-2, CM-3, CM-6, CM-6(1), CM-7 | 2.2.2, 2.2.4 | A02 (Misconfiguration) | T1547, T1112 | Devices: Advanced | Tenet 5: Asset Integrity |
| Baseline Hardening | CM-6, PR.IP | 4.1-4.7 | A.8.9 | CM-6, CM-6(1) | 2.2.2, 2.2.4 | A02 | N/A | Devices: Advanced | Tenet 5: Security Baselines |
| Configuration Drift Detection | CM-6(1), PR.PS | 4.1 | A.8.9 | CM-3, CM-6(1) | 2.2.4 | A02 | T1562.001 | Devices: Advanced | Tenet 5: Automated Monitoring |
| IaC/Automation | PR.PS-01, CM-2(2) | 4.1-4.2, 16.1, 16.7, 18.1 | A.5.8, A.5.37, A.8.9, A.8.32 | CM-2(2)(3), CM-3, CM-9 | 6.4.5, 11.6.1 | A02, A08 | N/A | Automation: Advanced | Tenet 5: Immutable Infrastructure |
| Default Credentials | IA-5(1), CM-6 | 4.7, 5.2 | A.5.17 | IA-5(1) | 2.2.3, 8.2.2 | A02, A07 | T1078 | Identity: Advanced | Tenet 6: No Default Credentials |
| Security Headers | SC-8, PR.DS | 9.2, 13.10 | A.8.21, A.8.26 | SC-8, SI-10 | 6.6 | A02, A05 | N/A | Apps: Advanced | Tenet 4: Defense in Depth |
| Vulnerability Management | ID.RA-01 to ID.RA-08, PR.IP, DE.CM-09 | 7.1-7.7 | A.8.8 | RA-3, RA-5, RA-5(2)(3)(5)(8)(10) | 6.3.1, 11.3.1 | N/A | T1190, T1210 | Devices: Advanced | Tenet 5: Continuous Assessment |
| Vulnerability Scanning | RA-5, DE.CM-09 | 7.5-7.6 | A.8.8, A.12.6.1 | RA-5, RA-5(2)(3)(5) | 11.3.1, 11.3.2 | N/A | N/A | Devices: Advanced | Tenet 5: Automated Scanning |
| Patch Management | SI-2, PR.PS-03 | 7.3-7.4, 12.1 | A.8.8, A.8.19 | SI-2, SI-2(2)(4)(6), CM-8 | 6.3.3 | N/A | T1068, T1210 | Devices: Advanced | Tenet 5: Rapid Remediation |
| SBOM/Supply Chain | GV.SC, ID.RA | 15.1-15.7, 16.4-16.5 | A.5.19-5.22 | SR-3, SR-11, SA-10 | 12.8.1-12.8.5 | A03 (Supply Chain) | T1195, T1199 | Governance: Developing | Tenet 5: Component Verification |
| Software Verification | CM-14, SI-7 | 2.3, 16.11 | A.8.32 | SI-7(6), CM-14, SR-11 | 6.3.2 | A03, A08 | T1195, T1553 | Devices: Advanced | Tenet 5: Signature Validation |
| Dependency Tracking | GV.SC-02, ID.RA | 16.4 | A.5.21 | SR-3, SA-10 | 12.8.5 | A03 | T1195 | Governance: Developing | Tenet 5: SBOM Management |
| Logging/Monitoring | DE.CM, DE.AE, AU-2 | 8.1-8.11, 13.1, 13.6 | A.8.15, A.8.16 | AU-2, AU-3, AU-6, AU-6(1)(3)(5), AU-12 | 10.2, 10.3, 10.6 | A09 (Logging & Alerting) | T1070, T1562.002 | Visibility: Advanced | Tenet 7: Comprehensive Telemetry |
| Log Protection | AU-9, DE.CM | 8.9, 8.10 | A.8.15 | AU-9, AU-11, SI-12 | 10.5.1 | A09 | T1070, T1562.002 | Visibility: Advanced | Tenet 7: Immutable Logs |
| Real-Time Alerting | DE.AE-06, RS.CO, SI-4(5) | 8.11, 13.1, 17.2, 17.6 | A.6.8, A.8.16 | AU-5(2), SI-4(5)(12), IR-6(1) | 10.6, 12.10 | A09 | N/A | Visibility: Advanced | Tenet 7: Automated Alerts |
| Alert Correlation | DE.AE, AU-6(3) | 8.11, 13.6 | A.8.16 | AU-6(1)(3)(5), SI-4(16) | 10.6 | A09 | N/A | Visibility: Advanced | Tenet 7: Cross-Pillar Correlation |
| Time Synchronization | DE.CM, AU-8 | 8.4 | A.8.17 | AU-8, SC-45, SC-45(1) | 10.4 | N/A | N/A | Visibility: Advanced | Tenet 7: Synchronized Timestamps |
| Malware Defenses | DE.CM-04, SI-3 | 10.1-10.7 | A.8.7 | SI-3, SI-3(4)(10), SI-7 | 5.1, 5.2 | N/A | T1204, T1566 | Devices: Advanced | Tenet 5: Threat Protection |
| Antivirus/EDR | SI-3, DE.CM | 10.1-10.2, 13.2 | A.8.7 | SI-3, SI-3(4), SI-4(23) | 5.1, 5.2 | N/A | T1562.001 | Devices: Advanced | Tenet 5: Endpoint Detection |
| File Integrity Monitoring | SI-7, SI-7(1) | 10.1, 13.2 | A.8.7, A.8.16 | SI-7(1)(6)(7), AU-9 | 11.5 | A08 (Data Integrity) | T1070, T1565 | Devices: Advanced | Tenet 5: Change Detection |
| Data Protection | PR.DS, ID.AM-07 | 3.1-3.14 | A.5.12, A.5.14, A.5.33, A.5.34, A.8.10 | SC-28, MP-6, MP-4 | 3.1-3.7, 4.1-4.2 | A04 | T1005, T1025 | Data: Advanced | Tenet 2: Encrypt Everything |
| Data Classification | PR.DS, GV.PO | 3.7, 3.12 | A.5.12 | MP-3, RA-2 | 3.1 | N/A | N/A | Data: Advanced | Tenet 4: Sensitivity-Based Controls |
| DLP | PR.DS, DE.CM | 3.13 | A.8.12 | SC-7, SI-4 | 3.4 | N/A | T1020, T1030, T1048 | Data: Developing | Tenet 4: Egress Monitoring |
| Backup/Recovery | RC.RP, RC.HL, CP-9 | 11.1-11.5 | A.5.29, A.5.30, A.8.13, A.8.14 | CP-9, CP-9(1)(3)(8), CP-10 | 12.10.1 | N/A | T1490, T1486 | Data: Advanced | Tenet 7: Resilience |
| Business Continuity | RC.RP, CP-2 | 11.1-11.5 | A.5.29, A.5.30, A.17.1 | CP-2, CP-6, CP-7 | 12.10 | N/A | N/A | Governance: Advanced | Tenet 7: Service Continuity |
| Incident Response | RS.AN, RS.CO, RS.MA, RS.MI | 17.1-17.9 | A.5.24-5.28, A.6.8 | IR-4, IR-4(1)(4), IR-5, IR-5(1), IR-6, IR-7, IR-8 | 12.10 | N/A | All Tactics | Automation: Advanced | Tenet 6: Automated Response |
| SOAR Platform | RS.AN, RS.MI, IR-4(1) | 17.1-17.9 | A.5.24, A.5.25, A.5.26 | IR-4(1), IR-5(1), IR-6(1), AU-6(1)(5) | 12.10 | N/A | All Tactics | Automation: Advanced | Tenet 6: Orchestrated Workflows |
| Threat Intelligence | ID.RA-02, DE.AE-07 | 7.1, 16.4 | A.5.7 | PM-16(1), RA-3(1), SI-4(18) | 11.3.1 | N/A | T1592-T1597 | Visibility: Advanced | Tenet 7: Contextual Enrichment |
| Threat Hunting | DE.CM, RA-10 | 13.6 | A.8.16 | RA-10, SI-4(16) | 11.4 | N/A | All Tactics | Visibility: Advanced | Tenet 7: Proactive Detection |
| Phishing Detection | ID.RA-02, DE.AE-02 | 9.2, 17.1 | A.5.7, A.5.24 | SI-3, SI-4, IR-4 | 11.4, 12.10 | N/A | T1566 | Apps: Advanced | Tenet 4: Email Security |
| Brute Force Detection | DE.CM, AC-7 | 6.3-6.5, 8.11 | A.5.17, A.8.5 | AC-7, SI-4(5) | 8.2.4, 8.2.5 | A07 | T1110 | Identity: Advanced | Tenet 6: Automated Lockout |
| Credential Dumping Detection | DE.CM, SI-4(23) | 10.1, 13.2 | A.8.7 | SI-4(23), AU-6 | 10.6, 11.4 | N/A | T1003 | Devices: Advanced | Tenet 5: LSASS Protection |
| Process Monitoring | DE.CM, AU-12 | 10.1, 13.2 | A.8.16 | SI-4(23), AU-12 | 10.2, 10.6 | N/A | T1059, T1106 | Devices: Advanced | Tenet 5: Execution Telemetry |
| PowerShell Logging | DE.CM, AU-12 | 8.8, 10.1 | A.8.15 | AU-3(1), SI-4 | 10.2.7 | N/A | T1059.001 | Devices: Advanced | Tenet 5: Script Auditing |
| Registry Monitoring | DE.CM, CM-6(1) | 4.1, 8.11 | A.8.9, A.8.16 | CM-6(1), SI-7(1) | 2.2.4, 10.6 | A02, A08 | T1112, T1547 | Devices: Advanced | Tenet 5: Persistence Detection |
| Service Creation Detection | DE.CM, CM-8(3) | 4.8, 10.1 | A.8.1, A.8.16 | SI-4, AU-12 | 10.2, 11.5 | N/A | T1543, T1569 | Devices: Advanced | Tenet 5: Service Monitoring |
| Scheduled Task Monitoring | DE.CM, AU-12 | 7.1, 8.11 | A.8.16 | SI-4, AU-12 | 10.2, 10.6 | N/A | T1053 | Devices: Advanced | Tenet 5: Task Auditing |
| Account Monitoring | AC-2(4), DE.CM | 5.1, 6.1, 8.11 | A.5.16, A.8.16 | AC-2(4)(12), AU-12 | 8.1.2, 10.2.5 | A01, A07 | T1136, T1098 | Identity: Advanced | Tenet 3: Lifecycle Tracking |
| Privilege Escalation Detection | AC-6(9), DE.CM | 5.4, 6.5, 8.11 | A.8.2, A.8.18 | AC-6(9), SI-4 | 7.1, 10.2 | A01 | T1548, T1134 | Identity: Advanced | Tenet 3: Anomaly Detection |
| LSASS Protection | IA-5, SI-3(10) | 5.2, 10.1 | A.5.17, A.8.7 | IA-5(7), SI-3(10) | 8.2.1 | A07 | T1003 | Identity: Advanced | Tenet 6: Memory Protection |
| Lateral Movement Detection | DE.CM, SI-4(16) | 12.3, 13.1-13.3 | A.8.16, A.8.20 | SI-4(1)(16), AU-6(3) | 10.6, 11.4 | N/A | T1021, T1080 | Visibility: Advanced | Tenet 7: Cross-Host Correlation |
| RDP/SMB/SSH Monitoring | AC-17(1), DE.CM | 12.3, 12.7, 13.6 | A.6.7, A.8.16 | AC-17(1), SI-4(4) | 8.3, 10.2 | N/A | T1021.001-.004 | Identity: Advanced | Tenet 2: Remote Session Tracking |
| Network Scanning Detection | DE.CM, SI-4(1) | 13.1-13.3, 18.1 | A.8.16, A.8.20 | SI-4(1)(4), CA-8 | 11.3, 11.4 | N/A | T1046, T1018 | Networks: Advanced | Tenet 7: Reconnaissance Detection |
| Port Scan Detection | DE.CM, SI-4(1) | 13.1, 13.3 | A.8.16, A.8.20 | SI-4(1)(4) | 11.4 | N/A | T1046 | Networks: Advanced | Tenet 7: Anomaly Detection |
| C2 Beacon Detection | DE.CM, SI-4(18) | 13.1, 13.6 | A.5.7, A.8.16 | SI-4(18), IR-4(4) | 10.6, 11.4 | N/A | T1071, T1095 | Visibility: Advanced | Tenet 7: Traffic Analysis |
| DNS Tunneling Detection | DE.CM, SI-4 | 8.6, 9.2, 13.6 | A.8.16, A.8.21 | SC-20, SC-21, SI-4 | 10.6 | N/A | T1071.004, T1048.003 | Networks: Advanced | Tenet 7: DNS Analysis |
| DGA Detection | DE.CM, SI-4 | 9.2, 13.6 | A.8.16, A.8.23 | SC-20(2), SI-4 | 10.6 | N/A | T1568 | Networks: Advanced | Tenet 7: Behavioral Analysis |
| Proxy Detection | DE.CM, SC-7 | 12.3, 13.10 | A.8.20, A.8.21 | SC-7(8), SI-4 | 1.3, 10.6 | N/A | T1090 | Networks: Advanced | Tenet 7: Proxy Monitoring |
| Ransomware Detection | DE.CM, IR-4(1) | 10.1, 11.1-11.5 | A.5.24, A.8.7 | IR-4(1), SI-3(10) | 12.10 | N/A | T1486 | Automation: Advanced | Tenet 6: Automated Containment |
| Cryptomining Detection | DE.CM, SI-4 | 10.1, 13.2 | A.8.7, A.8.16 | SI-4, AU-6 | 10.6, 11.4 | N/A | T1496 | Devices: Advanced | Tenet 5: Resource Monitoring |
| Data Exfiltration Detection | DE.CM, SI-4(4) | 13.6 | A.8.12, A.8.16 | SI-4(4), SC-7 | 10.6 | N/A | T1020, T1041 | Data: Developing | Tenet 4: Egress Detection |
| USB Device Monitoring | MP-7, DE.CM | 11.2.5 | A.7.10, A.8.16 | MP-2, MP-7, SI-4 | 9.6 | N/A | T1091, T1052 | Devices: Advanced | Tenet 5: Removable Media Control |
| Web Shell Detection | DE.CM, SI-3 | 13.10, 16.7 | A.8.7, A.8.26 | SI-3, SI-10 | 6.6, 11.4 | A05 | T1505 | Apps: Advanced | Tenet 4: Web Application Security |
| WMI Monitoring | DE.CM, AU-12 | 8.8, 10.1 | A.8.16 | SI-4, AU-12 | 10.2 | N/A | T1047, T1546.003 | Devices: Developing | Tenet 5: WMI Auditing |
| Container Security | SC-39, DE.CM | 16.1-16.14 | A.8.27 | SC-39, CM-7 | 6.4.3 | N/A | T1059.013, T1610, T1611 | Apps: Developing | Tenet 4: Workload Isolation |
| Log Tampering Detection | AU-9, SI-7 | 8.9, 8.10 | A.8.15 | AU-9, SI-7 | 10.5 | A09 | T1070, T1562.002 | Visibility: Advanced | Tenet 7: Immutable Audit |
| Obfuscation Detection | DE.CM, SI-3(10) | 10.1, 13.2 | A.8.7 | SI-3(10), SI-4(18) | 5.2, 11.4 | A05 | T1027, T1140 | Devices: Developing | Tenet 5: Entropy Analysis |
| Pass-the-Hash Detection | IA-2, DE.CM | 6.3, 8.11 | A.5.17, A.8.16 | IA-2(1), SI-4 | 8.3, 10.2 | A07 | T1550.002 | Identity: Developing | Tenet 6: Credential Replay Detection |
| Kerberos Monitoring | IA-2, DE.CM | 6.1, 8.11 | A.5.17, A.8.16 | IA-2, SI-4 | 8.2, 10.2 | A07 | T1558 | Identity: Developing | Tenet 6: Ticket Analysis |
| DLL Injection Detection | SI-3, DE.CM | 10.1, 13.2 | A.8.7 | SI-3, SI-7 | 5.2, 11.5 | N/A | T1055 | Devices: Developing | Tenet 5: Injection Detection |
| Browser Extension Monitoring | DE.CM, CM-8 | 9.4, 16.1 | A.8.1 | CM-8, SI-4 | 6.5.4 | N/A | T1176 | Apps: Developing | Tenet 4: Extension Inventory |
| Input Validation | SI-10, PR.DS | 13.10, 16.7 | A.8.26 | SI-10 | 6.5 | A05 (Injection Prevention) | T1659 | Apps: Advanced | Tenet 4: Boundary Checking |
| SQL Injection Prevention | SI-10, PR.PS | 16.7 | A.8.26, A.14.2 | SI-10, SA-11 | 6.5.1 | A05 | N/A | Apps: Advanced | Tenet 4: Parameterized Queries |
| XSS Prevention | SI-10, PR.DS | 9.2, 13.10 | A.8.23, A.8.26 | SI-10 | 6.5.7 | A05 | N/A | Apps: Advanced | Tenet 4: Output Encoding |
| Command Injection Prevention | SI-10, PR.PS | 16.7 | A.8.26 | SI-10 | 6.5 | A05 | T1059 | Apps: Advanced | Tenet 4: Input Sanitization |
| Secure Architecture | PL-8, RA-3 | 12.2, 16.1 | A.8.27, A.14.1 | SA-8, SA-17, PL-8 | 6.4 | A06 (Insecure Design) | N/A | Governance: Advanced | Tenet 4: Security by Design |
| Threat Modeling | RA-3, PL-8 | 16.14, 18.1 | A.14.1, A.14.2 | SA-8, RA-3 | 6.3.1 | A06 | N/A | Governance: Developing | Tenet 4: Risk-Based Design |
| Defense in Depth | PR.IR, PL-8(1) | 12.2, 13.4 | A.8.27, A.13.1 | SC-7, PL-8(1) | 1.2 | A06 | N/A | All Pillars: Advanced | Tenet 1-7: Layered Security |
| Change Control | CM-3, PR.IP | 4.1, 16.7, 18.1 | A.8.32 | CM-3, CM-3(2), CM-4, CM-5 | 6.4.5 | A08 | T1554 | Automation: Advanced | Tenet 5: Controlled Changes |
| Code Signing | SI-7, CM-14 | 2.3, 16.11 | A.8.32 | SI-7(6), CM-14 | 6.3.2 | A08 | T1553 | Devices: Developing | Tenet 5: Software Integrity |
| Boundary Protection | SC-7, PR.AC | 12.1-12.4, 13.3 | A.8.20, A.8.22 | SC-7, SC-7(3)(4)(5)(8)(21) | 1.2, 1.3 | A01 | N/A | Networks: Advanced | Tenet 2: Explicit Boundaries |
| Process Isolation | SC-39, PR.PS | 4.8, 16.7 | A.8.27 | SC-39 | 6.4.3 | N/A | T1055 | Apps: Advanced | Tenet 4: Workload Isolation |
| Capacity Management | PR.IR-04, AU-4 | 12.4 (via 4.1) | A.8.6 | AU-4, AU-5(1), CP-2 | 12.1.3 | N/A | N/A | Visibility: Advanced | Tenet 7: Resource Monitoring |
| Physical Security | PR.AA-06, PE-2 | 11.1.1-11.2.9 | A.7.1-A.7.14 | PE-2, PE-3, PE-6, PE-9 | 9.1-9.6 | N/A | N/A | N/A | N/A |
| Removable Media | MP-7, PR.DS | 11.2.5 | A.7.10 | MP-2, MP-4, MP-5, MP-7 | 9.6 | N/A | T1091, T1052 | Devices: Advanced | Tenet 5: Media Controls |
| Remote Maintenance | MA-4, AC-17 | 12.3 | A.6.7 | MA-4, MA-4(6), AC-17 | 8.3 | N/A | T1021 | Identity: Advanced | Tenet 2: Authenticated Maintenance |
| Cloud Security | PR.DS, DE.CM | 15.1 | A.5.23 | SC-7, SC-8, SC-13, AC-17 | 12.8.1-12.8.5 | N/A | T1537 | All Pillars: Advanced | Tenet 2: Cloud-Agnostic Security |
| Evidence Collection | RS.AN-03, AU-9 | 17.1 | A.5.28 | AU-9, IR-4(4), AU-11 | 10.5, 12.10.4 | N/A | N/A | Visibility: Advanced | Tenet 7: Forensic Readiness |
| Environment Separation | PR.IP, CM-2(6) | 16.8 | A.8.31 | CM-2(6), SC-7, CM-7 | 6.4.1 | N/A | N/A | Networks: Advanced | Tenet 2: Logical Isolation |
| Error Handling | SI-11, SC-24 | 16.7 | A.8.26 | SI-11, SC-24 | 6.5 | A10 (Exception Handling) | N/A | Apps: Advanced | Tenet 4: Fail Secure |
| Fail-Secure Design | SC-24, CP-10 | 12.1, 13.3 | A.8.27 | SC-24, CP-2 | 6.4 | A10 (Fail Closed) | N/A | All Pillars: Advanced | Tenet 4: Default Deny |
| Resource Limits | SC-5, SC-6 | 13.3 | A.8.6 | SC-5, SC-6 | 12.1.3 | A10 (DoS Prevention) | T1498, T1499 | Apps: Advanced | Tenet 4: Rate Limiting |
| Service Health Monitoring | SI-4, CP-10 | 8.6, 12.4 | A.8.6, A.8.16 | SI-4, AU-6, CP-10 | 10.6 | A10 (Availability) | T1489 | Visibility: Advanced | Tenet 7: Health Checks |
| Penetration Testing | CA-8, ID.RA-09 | 18.1-18.5 | A.8.29 | CA-8, RA-5(6) | 11.3, 11.4 | N/A | All Tactics | Governance: Developing | Tenet 7: Validation Testing |
| Secure Development | PR.PS-02, SA-8 | 16.1-16.14 | A.5.8, A.8.25-8.29 | SA-3, SA-8, SA-11, CM-3(2) | 6.5 | A06, A08 | N/A | Governance: Advanced | Tenet 4: SDLC Security |
| Source Code Security | CM-3, SA-10 | 16.11 | A.8.4 | CM-3, CM-5, SA-10 | 6.3.2 | A08 | N/A | Governance: Developing | Tenet 5: Code Integrity |
| Supplier Management | GV.SC-02 to GV.SC-05 | 15.1-15.7 | A.5.19-5.22 | SR-3, SR-6, SR-10, SR-11, SA-9 | 12.8 | A03 | T1195, T1199 | Governance: Developing | Tenet 5: Third-Party Risk |
| Zero Trust - Identity | PR.AA, IA-2 | 6.1-6.6 | A.5.15-5.18 | AC-2, AC-3, IA-2, IA-4 | 8.1, 8.2 | A01, A07 | T1078 | Identity: Advanced | Tenet 3: Identity as Perimeter |
| Zero Trust - Device | PR.AA, IA-3 | 1.1-1.5 | A.8.1 | IA-3, CM-8 | 2.4 | N/A | N/A | Devices: Advanced | Tenet 5: Device Trust |
| Zero Trust - Network | SC-7, PR.AC | 12.1-12.4, 13.4 | A.8.20, A.8.22 | SC-7, SC-7(4)(5)(21) | 1.1-1.4 | A01, A06 | N/A | Networks: Advanced | Tenet 2: Never Trust Location |
| Zero Trust - Application | PR.PS, SA-8 | 16.1-16.14 | A.8.25-8.27 | SA-8, SA-17, SC-39 | 6.4, 6.5 | A06 | N/A | Apps: Advanced | Tenet 4: Context-Aware Access |
| Zero Trust - Data | PR.DS, SC-28 | 3.1-3.14 | A.5.12, A.5.14, A.8.24 | SC-28, MP-3, MP-4 | 3.1-3.7 | A04 | N/A | Data: Advanced | Tenet 2: Data-Centric Security |
| Zero Trust - Visibility | DE.CM, AU-6 | 8.1-8.11, 13.6 | A.8.15, A.8.16 | AU-2, AU-6, SI-4 | 10.2-10.6 | A09 | All Tactics | Visibility: Advanced | Tenet 7: Full Observability |
| Zero Trust - Automation | RS.MA, IR-4(1) | 17.1-17.9 | A.5.24-5.27 | IR-4(1), IR-5(1) | 12.10 | N/A | All Tactics | Automation: Advanced | Tenet 6: Dynamic Policies |
| Privileged Access Management | AC-6, PR.AA | 5.4, 6.5 | A.8.2, A.8.18 | AC-2(7), AC-6, AC-6(1)(5)(9) | 7.1, 7.2 | A01 | T1078, T1134 | Identity: Advanced | Tenet 3: JIT/PIM |
| API Security | IA-5, SC-8 | 16.7 | A.8.26, A.14.1 | SC-8, SI-10, IA-5 | 6.5, 6.6 | A01, A05 | N/A | Apps: Advanced | Tenet 4: API Gateway |
| Database Security | SC-28, AC-3 | 3.11, 6.1 | A.8.24, A.9.2 | SC-28, AC-3 | 3.4, 8.2 | A05 | T1213.006 | Data: Advanced | Tenet 4: Query Monitoring |
| Wireless Security | SC-40, AC-18 | 12.6 | A.8.21 | AC-18, SC-40 | 4.1.1 | N/A | N/A | Networks: Advanced | Tenet 2: Wireless Segmentation |
| Email Security | SC-7, SI-8 | 9.1-9.7 | A.8.23 | SC-7, SI-8 | 12.3 | N/A | T1566 | Apps: Advanced | Tenet 4: Email Gateway |
| Mobile Device Security | AC-19, SC-7 | 4.10-4.12 | A.6.7, A.8.1 | AC-19, SC-43 | 8.2.3, 9.6 | N/A | N/A | Devices: Developing | Tenet 5: MDM/MAM |
| Endpoint Protection | SI-3, DE.CM | 10.1-10.7, 13.2 | A.8.7 | SI-3, SI-4(23) | 5.1, 5.2 | N/A | T1204, T1566 | Devices: Advanced | Tenet 5: EDR Coverage |
| Account Lifecycle | AC-2, PR.AA | 5.1-5.6 | A.5.16, A.9.2 | AC-2, AC-2(1)(3)(4) | 8.1.2-8.1.4 | A07 | T1136, T1098 | Identity: Advanced | Tenet 3: Automated Provisioning |
| Privileged Session Recording | AU-12, AC-6(9) | 8.11, 6.5 | A.8.18 | AU-12, AC-6(9) | 10.2.2 | N/A | T1078 | Identity: Advanced | Tenet 3: Session Audit |
| Security Awareness Training | AT-2, PR.AT | 14.1-14.9 | A.6.3 | AT-2, AT-3 | 12.6 | N/A | T1204, T1566 | N/A | N/A |
| Incident Classification | IR-4, RS.AN | 17.4 | A.5.25 | IR-4, IR-5 | 12.10.1 | N/A | All Tactics | Automation: Advanced | Tenet 6: Automated Triage |
| Forensic Analysis | IR-4(4), RS.AN | 17.1 | A.5.28 | IR-4(4), AU-9 | 12.10.4 | N/A | All Tactics | Visibility: Advanced | Tenet 7: Evidence Preservation |
| Communication Security | SC-8, PR.DS | 3.10, 13.10 | A.8.24 | SC-8, SC-13 | 4.2 | A04 | N/A | Data: Advanced | Tenet 2: Encrypted Channels |
| Third-Party Risk | GV.SC, SR-3 | 15.1-15.7 | A.5.19-5.22 | SR-3, SR-5, SR-6 | 12.8 | A03 | T1195, T1199 | Governance: Developing | Tenet 5: Vendor Assessment |
| Compliance Monitoring | CA-7, GV.PO | 18.1-18.5 | A.5.36 | CA-7, PM-9 | 12.11 | N/A | N/A | Governance: Advanced | Tenet 7: Continuous Compliance |
| Risk Assessment | RA-3, ID.RA | 7.1, 18.1 | A.5.7, A.8.8 | RA-3, RA-5 | 12.2 | N/A | N/A | Governance: Advanced | Tenet 4: Risk-Based Decisions |
| Security Metrics | GV.OV, PM-9 | 17.9, 18.1 | A.5.27 | PM-9, CA-7(3) | 12.11 | N/A | N/A | Governance: Advanced | Tenet 7: Performance Tracking |
| Policy Management | GV.PO, PL-1 | 4.1, 18.1 | A.5.1, A.5.36 | PL-1, PM-1 | 12.1 | N/A | N/A | Governance: Advanced | Tenet 4: Policy Automation |
| Disaster Recovery | RC.RP, CP-10 | 11.1-11.5 | A.5.29, A.5.30, A.17.1 | CP-10, CP-2 | 12.10.1 | N/A | N/A | Data: Advanced | Tenet 7: DR Testing |
| Service Continuity | RC.HL, CP-2 | 11.1-11.5 | A.5.29, A.17.1 | CP-2, CP-6, CP-7 | 12.10 | N/A | T1498, T1499 | Apps: Advanced | Tenet 7: HA Architecture |
| Data Retention | PR.DS, MP-6 | 3.4, 8.10 | A.5.33 | MP-6, SI-12 | 3.1, 10.7 | N/A | N/A | Data: Advanced | Tenet 4: Lifecycle Management |
| Secure Disposal | MP-6, PR.IR | 3.5, 11.2.7 | A.5.14, A.7.14 | MP-6, SR-12 | 9.8 | N/A | N/A | Data: Advanced | Tenet 4: Data Sanitization |
| Audit Trail Integrity | AU-9, SI-7 | 8.9, 10.1 | A.8.15 | AU-9, SI-7 | 10.5 | A09 | T1070 | Visibility: Advanced | Tenet 7: Tamper-Proof Logs |
| Non-Repudiation | AU-10, SI-7 | 8.5 | A.8.15 | AU-10, SC-17 | 10.3.4 | A08 | N/A | Visibility: Advanced | Tenet 7: Digital Signatures |
| Trusted Computing | SI-7, SC-34 | N/A | A.8.24 | SI-7, SC-34 | N/A | N/A | N/A | Devices: Developing | Tenet 5: Hardware Root of Trust |
| Virtualization Security | SC-44, CM-7 | N/A | A.8.27 | SC-44, SC-39 | 6.4.3 | N/A | T1611 | Apps: Advanced | Tenet 4: Hypervisor Isolation |
| Container Orchestration | CM-7, SC-39 | 16.1-16.14 | A.8.27 | SC-39, CM-7 | 6.4.3 | N/A | T1610, T1611 | Apps: Developing | Tenet 4: K8s Security |
| Microservices Security | SC-7, SA-8 | 16.1 | A.8.27 | SC-7(21), SA-8 | 6.4 | A06 | N/A | Apps: Advanced | Tenet 4: Service Mesh |
| DevSecOps | SA-10, PR.PS | 16.1-16.14, 18.1 | A.5.8, A.8.25 | SA-10, SA-11 | 6.5 | A08 | N/A | Governance: Developing | Tenet 4: Pipeline Security |
| Secrets Rotation | IA-5, SC-12 | 6.7 | A.8.24 | IA-5, SC-12 | 8.3.2 | A07 | T1552 | Identity: Advanced | Tenet 6: Automated Rotation |
| Certificate Lifecycle | SC-17, IA-5(14) | 3.12 | A.8.24 | SC-17, IA-5(14) | 4.2.1 | A04 | N/A | Identity: Advanced | Tenet 6: ACME Automation |
| Vulnerability Disclosure | RA-5, PM-16 | 7.1, 16.2 | A.5.7 | RA-5, PM-16 | 11.3.1 | A03 | N/A | Governance: Advanced | Tenet 7: Coordinated Disclosure |
| Security Orchestration | IR-4(1), RS.MA | 17.1-17.9 | A.5.24-5.27 | IR-4(1), IR-8 | 12.10 | N/A | All Tactics | Automation: Advanced | Tenet 6: SOAR Platform |
| Behavioral Analytics | AU-6, SI-4(18) | 8.11, 13.6 | A.8.16 | AU-6(5), SI-4(18) | 10.6 | A09 | All Tactics | Visibility: Developing | Tenet 7: UEBA/ML |
| Anomaly Detection | SI-4, DE.AE | 13.6 | A.8.16 | SI-4(2), SI-4(18) | 10.6, 11.4 | A09 | All Tactics | Visibility: Advanced | Tenet 7: Baseline Deviation |
| Deception Technology | SI-4, DE.CM | 13.1 | A.8.16 | SI-4 | 11.4 | N/A | All Tactics | Visibility: Developing | Tenet 7: Honeypots/Honeynets |
| Security Data Lake | AU-6, DE.CM | 8.9, 13.6 | A.8.15 | AU-6, AU-12 | 10.2 | A09 | N/A | Visibility: Advanced | Tenet 7: Centralized Repository |
| SIEM/SOAR Integration | AU-6(1), IR-4(1) | 8.11, 17.1 | A.8.16, A.5.24 | AU-6(1)(3), IR-4(1) | 10.6, 12.10 | A09 | All Tactics | Automation: Advanced | Tenet 6+7: Orchestrated Response |
| Threat Modeling Automation | RA-3, SA-8 | 16.14 | A.14.1 | RA-3, SA-8 | 6.3.1 | A06 | N/A | Governance: Developing | Tenet 4: Continuous Modeling |
| Security Posture Management | CA-7, GV.OV | 4.1, 18.1 | A.5.36, A.8.9 | CA-7, PM-9 | 12.11 | A02 | N/A | Governance: Advanced | Tenet 7: CSPM/CWPP |
| Attack Surface Management | RA-3, ID.AM | 1.1-1.5, 18.1 | A.5.9, A.8.8 | RA-3, RA-5 | 11.3.1 | N/A | T1595, T1596 | Devices: Advanced | Tenet 1: External Exposure |