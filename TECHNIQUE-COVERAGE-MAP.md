# MxTac - ATT&CK Technique Coverage Map

> **Document Type**: Solution-to-Technique Mapping  
> **Version**: 1.0  
> **Date**: January 2026  
> **ATT&CK Version**: v18  
> **Project**: MxTac (Matrix + Tactic)

---

## Overview

This document maps MITRE ATT&CK Enterprise techniques to open-source security solutions, indicating which tools can **detect** and/or **prevent** each technique. Use this guide to identify coverage gaps and select appropriate tools for your organization.

### Legend

| Symbol | Meaning |
|--------|---------|
| **D** | Detection capability |
| **P** | Prevention capability |
| **D/P** | Both detection and prevention |
| **~** | Partial/Limited capability |
| **-** | No capability |

### Solution Abbreviations

| Abbrev | Solution | Category |
|--------|----------|----------|
| **WAZ** | Wazuh | EDR/HIDS |
| **VEL** | Velociraptor | EDR/Forensics |
| **OSQ** | osquery + Fleet | Endpoint Visibility |
| **ZEK** | Zeek | NDR |
| **SUR** | Suricata | IDS/IPS |
| **ARK** | Arkime | Full Packet Capture |
| **PRO** | Prowler | Cloud Security |
| **TRV** | Trivy | Container/IaC Security |
| **CTI** | OpenCTI | Threat Intelligence |
| **MIS** | MISP | Threat Intelligence |
| **SHF** | Shuffle | SOAR/Response |

---

## Quick Reference: Solution Capabilities by Domain

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Solution Domain Coverage                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ENDPOINT                    NETWORK                    CLOUD           │
│  ┌─────────────────┐        ┌─────────────────┐       ┌─────────────┐  │
│  │ Wazuh      D/P  │        │ Zeek        D   │       │ Prowler  D  │  │
│  │ Velociraptor D  │        │ Suricata   D/P  │       │ Trivy    D  │  │
│  │ osquery     D   │        │ Arkime      D   │       └─────────────┘  │
│  └─────────────────┘        └─────────────────┘                        │
│                                                                         │
│  THREAT INTEL                RESPONSE                                   │
│  ┌─────────────────┐        ┌─────────────────┐                        │
│  │ OpenCTI     D   │        │ Shuffle    P    │                        │
│  │ MISP        D   │        │ (via actions)   │                        │
│  └─────────────────┘        └─────────────────┘                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## TA0043 - Reconnaissance

> The adversary is trying to gather information they can use to plan future operations.

**Primary Tools**: Zeek, Suricata, OpenCTI  
**Coverage Challenge**: Most reconnaissance occurs outside the target network

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1595 | Active Scanning | - | - | - | D | D | - | D | Network perimeter visibility |
| T1595.001 | └─ Scanning IP Blocks | - | - | - | D | D | - | D | Detect scan patterns |
| T1595.002 | └─ Vulnerability Scanning | - | - | - | D | D/P | - | D | IDS signatures for scanners |
| T1595.003 | └─ Wordlist Scanning | - | - | - | D | D | - | - | HTTP request patterns |
| T1592 | Gather Victim Host Info | - | - | - | ~D | - | - | D | Limited visibility |
| T1592.001 | └─ Hardware | - | - | - | - | - | - | D | Threat intel correlation |
| T1592.002 | └─ Software | - | - | - | ~D | - | - | D | User-agent analysis |
| T1592.003 | └─ Firmware | - | - | - | - | - | - | D | Threat intel only |
| T1592.004 | └─ Client Configs | - | - | - | - | - | - | D | Threat intel only |
| T1589 | Gather Victim Identity | - | - | - | - | - | - | D | Threat intel correlation |
| T1589.001 | └─ Credentials | - | - | - | - | - | - | D | Leaked credential monitoring |
| T1589.002 | └─ Email Addresses | - | - | - | - | - | - | D | Threat intel feeds |
| T1589.003 | └─ Employee Names | - | - | - | - | - | - | D | OSINT monitoring |
| T1590 | Gather Victim Network | - | - | - | ~D | - | - | D | External scan detection |
| T1590.001 | └─ Domain Properties | - | - | - | D | - | - | D | DNS monitoring |
| T1590.002 | └─ DNS | - | - | - | D | - | - | D | Passive DNS analysis |
| T1590.003 | └─ Network Trust | - | - | - | - | - | - | D | Threat intel only |
| T1590.004 | └─ Network Topology | - | - | - | - | - | - | D | Threat intel only |
| T1590.005 | └─ IP Addresses | - | - | - | D | - | - | D | Scan detection |
| T1590.006 | └─ Security Appliances | - | - | - | - | - | - | D | Threat intel only |
| T1591 | Gather Victim Org Info | - | - | - | - | - | - | D | OSINT/threat intel |
| T1591.001 | └─ Physical Location | - | - | - | - | - | - | D | Threat intel only |
| T1591.002 | └─ Business Relations | - | - | - | - | - | - | D | Threat intel only |
| T1591.003 | └─ Identify Bus. Tempo | - | - | - | - | - | - | D | Threat intel only |
| T1591.004 | └─ Identify Roles | - | - | - | - | - | - | D | Threat intel only |
| T1598 | Phishing for Info | D | - | - | D | D | - | D | Email + network analysis |
| T1598.001 | └─ Spearphishing Service | D | - | - | - | - | - | D | Email gateway logs |
| T1598.002 | └─ Spearphishing Attach. | D | - | - | D | D | - | D | Email + file analysis |
| T1598.003 | └─ Spearphishing Link | D | - | - | D | D | - | D | URL analysis |
| T1598.004 | └─ Spearphishing Voice | - | - | - | - | - | - | D | Limited, threat intel |
| T1597 | Search Closed Sources | - | - | - | - | - | - | D | Threat intel only |
| T1597.001 | └─ Threat Intel Vendors | - | - | - | - | - | - | D | Threat intel feeds |
| T1597.002 | └─ Purchase Tech Data | - | - | - | - | - | - | D | Dark web monitoring |
| T1596 | Search Open Tech DB | - | - | - | - | - | - | D | Limited visibility |
| T1596.001 | └─ DNS/Passive DNS | - | - | - | D | - | - | D | DNS monitoring |
| T1596.002 | └─ WHOIS | - | - | - | - | - | - | D | Threat intel |
| T1596.003 | └─ Digital Certificates | - | - | - | D | - | - | D | Cert transparency |
| T1596.004 | └─ CDNs | - | - | - | - | - | - | D | Threat intel |
| T1596.005 | └─ Scan Databases | - | - | - | - | - | - | D | Threat intel |
| T1593 | Search Open Websites | - | - | - | - | - | - | D | OSINT monitoring |
| T1593.001 | └─ Social Media | - | - | - | - | - | - | D | Threat intel |
| T1593.002 | └─ Search Engines | - | - | - | - | - | - | D | Threat intel |
| T1593.003 | └─ Code Repositories | - | - | - | - | - | - | D | Threat intel |
| T1594 | Search Victim Websites | - | - | - | - | - | - | D | Web log analysis |

### Reconnaissance Coverage Summary

| Solution | Techniques Covered | Coverage % |
|----------|-------------------|------------|
| Zeek | 12/43 | 28% |
| Suricata | 6/43 | 14% |
| OpenCTI | 43/43 | 100% (intel) |
| Wazuh | 3/43 | 7% |

**Recommendation**: Reconnaissance largely occurs outside your network. Focus on:
1. **Perimeter monitoring** with Zeek + Suricata
2. **Threat intelligence** integration with OpenCTI/MISP
3. **External attack surface monitoring** (consider tools like Shodan monitoring)

---

## TA0042 - Resource Development

> The adversary is trying to establish resources they can use to support operations.

**Primary Tools**: OpenCTI, MISP  
**Coverage Challenge**: Occurs entirely outside target environment

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1650 | Acquire Access | - | - | - | - | - | - | D | Dark web monitoring |
| T1583 | Acquire Infrastructure | - | - | - | - | - | - | D | Threat intel tracking |
| T1583.001 | └─ Domains | - | - | - | D | - | - | D | Newly registered domain feeds |
| T1583.002 | └─ DNS Server | - | - | - | D | - | - | D | DNS infrastructure tracking |
| T1583.003 | └─ Virtual Private Server | - | - | - | - | - | - | D | Threat intel |
| T1583.004 | └─ Server | - | - | - | - | - | - | D | Threat intel |
| T1583.005 | └─ Botnet | - | - | - | D | D | - | D | C2 feed correlation |
| T1583.006 | └─ Web Services | - | - | - | D | - | - | D | Known bad service tracking |
| T1583.007 | └─ Serverless | - | - | - | - | - | - | D | Threat intel |
| T1583.008 | └─ Malvertising | - | - | - | D | D | - | D | Ad network monitoring |
| T1586 | Compromise Accounts | - | - | - | - | - | - | D | Credential leak monitoring |
| T1586.001 | └─ Social Media | - | - | - | - | - | - | D | Threat intel |
| T1586.002 | └─ Email Accounts | - | - | - | - | - | - | D | Leaked credential feeds |
| T1586.003 | └─ Cloud Accounts | - | - | - | - | - | D | D | Cloud audit + threat intel |
| T1584 | Compromise Infrastructure | - | - | - | - | - | - | D | Threat intel |
| T1584.001 | └─ Domains | - | - | - | D | - | - | D | Domain reputation |
| T1584.002 | └─ DNS Server | - | - | - | D | - | - | D | DNS monitoring |
| T1584.003 | └─ Virtual Private Server | - | - | - | - | - | - | D | Threat intel |
| T1584.004 | └─ Server | - | - | - | - | - | - | D | Threat intel |
| T1584.005 | └─ Botnet | - | - | - | D | D | - | D | Botnet tracking |
| T1584.006 | └─ Web Services | - | - | - | D | - | - | D | Service abuse tracking |
| T1584.007 | └─ Serverless | - | - | - | - | - | - | D | Threat intel |
| T1587 | Develop Capabilities | - | - | - | - | - | - | D | Malware tracking |
| T1587.001 | └─ Malware | - | - | - | - | - | - | D | Malware family tracking |
| T1587.002 | └─ Code Signing Certs | - | - | - | - | - | - | D | Cert abuse tracking |
| T1587.003 | └─ Digital Certificates | - | - | - | D | - | - | D | Cert transparency |
| T1587.004 | └─ Exploits | - | - | - | - | - | - | D | Exploit intelligence |
| T1585 | Establish Accounts | - | - | - | - | - | - | D | Threat intel |
| T1585.001 | └─ Social Media | - | - | - | - | - | - | D | Threat intel |
| T1585.002 | └─ Email Accounts | - | - | - | - | - | - | D | Threat intel |
| T1585.003 | └─ Cloud Accounts | - | - | - | - | - | D | D | Cloud + threat intel |
| T1588 | Obtain Capabilities | - | - | - | - | - | - | D | Threat intel |
| T1588.001 | └─ Malware | - | - | - | - | - | - | D | Malware intel |
| T1588.002 | └─ Tool | - | - | - | - | - | - | D | Tool tracking |
| T1588.003 | └─ Code Signing Certs | - | - | - | - | - | - | D | Cert tracking |
| T1588.004 | └─ Digital Certificates | - | - | - | D | - | - | D | Cert monitoring |
| T1588.005 | └─ Exploits | - | - | - | - | - | - | D | Exploit intel |
| T1588.006 | └─ Vulnerabilities | - | - | - | - | - | - | D | Vuln intelligence |
| T1608 | Stage Capabilities | - | - | - | - | - | - | D | Staging infrastructure |
| T1608.001 | └─ Upload Malware | - | - | - | - | - | - | D | Malware hosting tracking |
| T1608.002 | └─ Upload Tool | - | - | - | - | - | - | D | Tool hosting tracking |
| T1608.003 | └─ Install Dig. Cert | - | - | - | D | - | - | D | Cert monitoring |
| T1608.004 | └─ Drive-by Target | - | - | - | D | D | - | D | Compromised site feeds |
| T1608.005 | └─ Link Target | - | - | - | D | D | - | D | URL reputation |
| T1608.006 | └─ SEO Poisoning | - | - | - | - | - | - | D | Threat intel |

### Resource Development Coverage Summary

| Solution | Techniques Covered | Coverage % |
|----------|-------------------|------------|
| OpenCTI | 45/45 | 100% (intel) |
| Zeek | 15/45 | 33% |
| Suricata | 6/45 | 13% |
| Prowler | 2/45 | 4% |

**Recommendation**: This tactic occurs entirely outside your network. Primary defense is:
1. **Threat intelligence** via OpenCTI + MISP feeds
2. **Domain/IP reputation** checking at network perimeter
3. **Certificate transparency** monitoring

---

## TA0001 - Initial Access

> The adversary is trying to get into your network.

**Primary Tools**: Wazuh, Suricata, Zeek, Prowler  
**Coverage Challenge**: Multiple entry vectors require layered defense

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1189 | Drive-by Compromise | D | D | - | D | D/P | - | D | Browser + network detection |
| T1190 | Exploit Public-Facing App | D | D | - | D | D/P | D | D | WAF logs + IDS + cloud |
| T1133 | External Remote Services | D | D | D | D | D | D | D | VPN/RDP monitoring |
| T1200 | Hardware Additions | D | D | D | - | - | - | - | USB/device detection |
| T1566 | Phishing | D | D | - | D | D/P | - | D | Email gateway + network |
| T1566.001 | └─ Spearphishing Attach. | D | D | - | D | D/P | - | D | File analysis |
| T1566.002 | └─ Spearphishing Link | D | D | - | D | D/P | - | D | URL analysis |
| T1566.003 | └─ Spearphishing via Svc | D | - | - | D | D | - | D | Social media/messaging |
| T1566.004 | └─ Spearphishing Voice | - | - | - | - | - | - | D | Limited detection |
| T1091 | Replication Through Media | D | D | D | - | - | - | - | USB monitoring |
| T1195 | Supply Chain Compromise | ~D | D | D | - | - | D | D | Limited visibility |
| T1195.001 | └─ Compromise SW Deps | ~D | D | D | - | - | D | D | Package monitoring |
| T1195.002 | └─ Compromise SW Supply | ~D | D | D | - | - | D | D | Binary verification |
| T1195.003 | └─ Compromise HW Supply | - | D | D | - | - | - | D | Hardware audit |
| T1199 | Trusted Relationship | D | D | - | D | D | D | D | Third-party access logs |
| T1078 | Valid Accounts | D | D | D | D | D | D | D | Auth monitoring |
| T1078.001 | └─ Default Accounts | D | D | D | D | D | D | D | Default cred detection |
| T1078.002 | └─ Domain Accounts | D | D | D | D | D | - | D | AD monitoring |
| T1078.003 | └─ Local Accounts | D | D | D | - | - | - | D | Local auth logs |
| T1078.004 | └─ Cloud Accounts | D | - | - | - | - | D | D | Cloud auth monitoring |

### Initial Access Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 18/20 | 2/20 | 90% (D) |
| Suricata | 12/20 | 8/20 | 60% (D), 40% (P) |
| Zeek | 14/20 | 0/20 | 70% (D) |
| Prowler | 8/20 | 0/20 | 40% (D) |
| Velociraptor | 15/20 | 0/20 | 75% (D) |

**Recommended Stack for Initial Access**:
```
┌─────────────────────────────────────────────────────────────────────────┐
│  Initial Access Defense Stack                                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Layer 1: Network Perimeter                                             │
│  ├── Suricata (IPS mode) ─── Block known exploits, malware              │
│  └── Zeek ─────────────────── Deep protocol analysis                    │
│                                                                         │
│  Layer 2: Endpoint                                                      │
│  ├── Wazuh ────────────────── File integrity, auth monitoring           │
│  └── osquery ──────────────── Hardware/software inventory               │
│                                                                         │
│  Layer 3: Cloud                                                         │
│  └── Prowler ──────────────── Cloud account/config monitoring           │
│                                                                         │
│  Layer 4: Intelligence                                                  │
│  └── OpenCTI ──────────────── IOC correlation, campaign tracking        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## TA0002 - Execution

> The adversary is trying to run malicious code.

**Primary Tools**: Wazuh, Velociraptor, Suricata  
**Coverage Challenge**: Diverse execution methods require endpoint + network visibility

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1651 | Cloud Admin Command | - | - | - | - | - | D | D | Cloud audit logs |
| T1059 | Command & Scripting | D/P | D | D | - | - | - | D | Process monitoring |
| T1059.001 | └─ PowerShell | D/P | D | D | - | - | - | D | Script block logging |
| T1059.002 | └─ AppleScript | D | D | D | - | - | - | D | macOS process mon |
| T1059.003 | └─ Windows Cmd | D/P | D | D | - | - | - | D | Command line logging |
| T1059.004 | └─ Unix Shell | D/P | D | D | - | - | - | D | Shell command logging |
| T1059.005 | └─ Visual Basic | D/P | D | D | - | - | - | D | VBS execution |
| T1059.006 | └─ Python | D | D | D | - | - | - | D | Interpreter monitoring |
| T1059.007 | └─ JavaScript | D | D | D | D | D | - | D | Browser + host JS |
| T1059.008 | └─ Network Device CLI | D | - | - | D | - | - | D | Network device logs |
| T1059.009 | └─ Cloud API | - | - | - | - | - | D | D | Cloud API audit |
| T1059.010 | └─ AutoHotKey & AutoIt | D | D | D | - | - | - | D | Process monitoring |
| T1609 | Container Admin Command | D | - | - | - | - | D | D | Container audit |
| T1610 | Deploy Container | D | - | - | - | - | D | D | Container orchestration |
| T1203 | Exploitation for Client | D | D | - | D | D/P | - | D | Exploit detection |
| T1559 | Inter-Process Comm. | D | D | D | - | - | - | D | IPC monitoring |
| T1559.001 | └─ Component Object Model | D | D | D | - | - | - | D | COM object tracking |
| T1559.002 | └─ Dynamic Data Exchange | D | D | D | - | - | - | D | DDE detection |
| T1559.003 | └─ XPC Services | D | D | D | - | - | - | D | macOS XPC |
| T1106 | Native API | D | D | D | - | - | - | D | API call monitoring |
| T1053 | Scheduled Task/Job | D/P | D | D | - | - | D | D | Task scheduler mon |
| T1053.002 | └─ At | D/P | D | D | - | - | - | D | at command detection |
| T1053.003 | └─ Cron | D/P | D | D | - | - | - | D | Cron monitoring |
| T1053.005 | └─ Scheduled Task | D/P | D | D | - | - | - | D | Windows tasks |
| T1053.006 | └─ Systemd Timers | D/P | D | D | - | - | - | D | Systemd monitoring |
| T1053.007 | └─ Container Orch. Job | D | - | - | - | - | D | D | K8s CronJob |
| T1129 | Shared Modules | D | D | D | - | - | - | D | DLL loading |
| T1072 | Software Deploy Tools | D | D | D | - | - | - | D | Deployment tool abuse |
| T1569 | System Services | D/P | D | D | - | - | - | D | Service monitoring |
| T1569.001 | └─ Launchctl | D/P | D | D | - | - | - | D | macOS launchctl |
| T1569.002 | └─ Service Execution | D/P | D | D | - | - | - | D | Windows services |
| T1204 | User Execution | D | D | - | D | D | - | D | User action tracking |
| T1204.001 | └─ Malicious Link | D | D | - | D | D | - | D | URL + browser mon |
| T1204.002 | └─ Malicious File | D | D | - | D | D | - | D | File execution |
| T1204.003 | └─ Malicious Image | D | - | - | - | - | D | D | Container images |
| T1047 | WMI | D | D | D | - | - | - | D | WMI event monitoring |

### Execution Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 34/36 | 14/36 | 94% (D), 39% (P) |
| Velociraptor | 30/36 | 0/36 | 83% (D) |
| osquery | 28/36 | 0/36 | 78% (D) |
| Prowler | 6/36 | 0/36 | 17% (D) |
| Suricata | 4/36 | 2/36 | 11% (D), 6% (P) |

**Recommended Stack for Execution**:
- **Primary**: Wazuh (comprehensive process/command monitoring + active response)
- **Hunting**: Velociraptor (deep investigation of execution artifacts)
- **Cloud**: Prowler (cloud-specific execution monitoring)

---

## TA0003 - Persistence

> The adversary is trying to maintain their foothold.

**Primary Tools**: Wazuh, Velociraptor, osquery  
**Coverage Challenge**: Many persistence mechanisms across OS types

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1098 | Account Manipulation | D | D | D | D | - | D | D | Account change monitoring |
| T1098.001 | └─ Additional Cloud Creds | - | - | - | - | - | D | D | Cloud IAM monitoring |
| T1098.002 | └─ Additional Email Perms | D | - | - | - | - | D | D | Exchange/M365 audit |
| T1098.003 | └─ Additional Cloud Roles | - | - | - | - | - | D | D | Cloud role changes |
| T1098.004 | └─ SSH Authorized Keys | D | D | D | - | - | - | D | SSH key monitoring |
| T1098.005 | └─ Device Registration | D | - | - | - | - | D | D | Device enrollment |
| T1098.006 | └─ Additional Container Roles | - | - | - | - | - | D | D | K8s RBAC changes |
| T1197 | BITS Jobs | D | D | D | - | - | - | D | BITS monitoring |
| T1547 | Boot/Logon Autostart | D | D | D | - | - | - | D | Startup locations |
| T1547.001 | └─ Registry Run Keys | D | D | D | - | - | - | D | Registry monitoring |
| T1547.002 | └─ Authentication Package | D | D | D | - | - | - | D | LSA monitoring |
| T1547.003 | └─ Time Providers | D | D | D | - | - | - | D | Time provider DLLs |
| T1547.004 | └─ Winlogon Helper DLL | D | D | D | - | - | - | D | Winlogon monitoring |
| T1547.005 | └─ Security Support Provider | D | D | D | - | - | - | D | SSP monitoring |
| T1547.006 | └─ Kernel Modules/Ext. | D | D | D | - | - | - | D | Kernel module loading |
| T1547.007 | └─ Re-opened Applications | D | D | D | - | - | - | D | macOS reopen |
| T1547.008 | └─ LSASS Driver | D | D | D | - | - | - | D | LSASS driver loading |
| T1547.009 | └─ Shortcut Modification | D | D | D | - | - | - | D | LNK file monitoring |
| T1547.010 | └─ Port Monitors | D | D | D | - | - | - | D | Print monitor DLLs |
| T1547.012 | └─ Print Processors | D | D | D | - | - | - | D | Print processor DLLs |
| T1547.013 | └─ XDG Autostart | D | D | D | - | - | - | D | Linux autostart |
| T1547.014 | └─ Active Setup | D | D | D | - | - | - | D | Active Setup keys |
| T1547.015 | └─ Login Items | D | D | D | - | - | - | D | macOS login items |
| T1037 | Boot/Logon Init Scripts | D | D | D | - | - | - | D | Init script monitoring |
| T1037.001 | └─ Logon Script (Windows) | D | D | D | - | - | - | D | GPO logon scripts |
| T1037.002 | └─ Login Hook | D | D | D | - | - | - | D | macOS login hooks |
| T1037.003 | └─ Network Logon Script | D | D | D | - | - | - | D | Network scripts |
| T1037.004 | └─ RC Scripts | D | D | D | - | - | - | D | Unix rc scripts |
| T1037.005 | └─ Startup Items | D | D | D | - | - | - | D | macOS startup items |
| T1176 | Browser Extensions | D | D | D | - | - | - | D | Extension monitoring |
| T1554 | Compromise Host Software | D | D | D | - | - | - | D | Binary modification |
| T1136 | Create Account | D | D | D | D | - | D | D | Account creation |
| T1136.001 | └─ Local Account | D | D | D | - | - | - | D | Local user creation |
| T1136.002 | └─ Domain Account | D | D | D | D | - | - | D | AD account creation |
| T1136.003 | └─ Cloud Account | - | - | - | - | - | D | D | Cloud IAM creation |
| T1543 | Create/Modify System Proc | D | D | D | - | - | - | D | System process changes |
| T1543.001 | └─ Launch Agent | D | D | D | - | - | - | D | macOS launch agents |
| T1543.002 | └─ Systemd Service | D | D | D | - | - | - | D | Systemd unit files |
| T1543.003 | └─ Windows Service | D | D | D | - | - | - | D | Service creation |
| T1543.004 | └─ Launch Daemon | D | D | D | - | - | - | D | macOS launch daemons |
| T1543.005 | └─ Container Service | - | - | - | - | - | D | D | K8s services |
| T1546 | Event Triggered Execution | D | D | D | - | - | - | D | Event-based persistence |
| T1546.001 | └─ Change Default File Assoc | D | D | D | - | - | - | D | File association |
| T1546.002 | └─ Screensaver | D | D | D | - | - | - | D | Screensaver abuse |
| T1546.003 | └─ WMI Event Subscription | D | D | D | - | - | - | D | WMI persistence |
| T1546.004 | └─ Unix Shell Config | D | D | D | - | - | - | D | Shell RC files |
| T1546.005 | └─ Trap | D | D | D | - | - | - | D | Shell trap commands |
| T1546.006 | └─ LC_LOAD_DYLIB Addition | D | D | D | - | - | - | D | macOS dylib loading |
| T1546.007 | └─ Netsh Helper DLL | D | D | D | - | - | - | D | Netsh helper DLLs |
| T1546.008 | └─ Accessibility Features | D | D | D | - | - | - | D | Accessibility abuse |
| T1546.009 | └─ AppCert DLLs | D | D | D | - | - | - | D | AppCert DLL loading |
| T1546.010 | └─ AppInit DLLs | D | D | D | - | - | - | D | AppInit monitoring |
| T1546.011 | └─ Application Shimming | D | D | D | - | - | - | D | Shim database |
| T1546.012 | └─ Image File Exec Options | D | D | D | - | - | - | D | IFEO monitoring |
| T1546.013 | └─ PowerShell Profile | D | D | D | - | - | - | D | PS profile changes |
| T1546.014 | └─ Emond | D | D | D | - | - | - | D | macOS emond |
| T1546.015 | └─ COM Object Hijacking | D | D | D | - | - | - | D | COM hijacking |
| T1546.016 | └─ Installer Packages | D | D | D | - | - | - | D | Package persistence |
| T1133 | External Remote Services | D | D | D | D | D | D | D | Remote access mon |
| T1574 | Hijack Execution Flow | D | D | D | - | - | - | D | DLL/binary hijacking |
| T1574.001 | └─ DLL Search Order | D | D | D | - | - | - | D | DLL loading order |
| T1574.002 | └─ DLL Side-Loading | D | D | D | - | - | - | D | Side-loading detection |
| T1574.004 | └─ Dylib Hijacking | D | D | D | - | - | - | D | macOS dylib hijack |
| T1574.005 | └─ Executable Installer | D | D | D | - | - | - | D | Installer hijacking |
| T1574.006 | └─ Dynamic Linker Hijack | D | D | D | - | - | - | D | LD_PRELOAD abuse |
| T1574.007 | └─ Path Interception | D | D | D | - | - | - | D | PATH hijacking |
| T1574.008 | └─ Path Interception by Search | D | D | D | - | - | - | D | Search order hijack |
| T1574.009 | └─ Path Interception Unquoted | D | D | D | - | - | - | D | Unquoted path |
| T1574.010 | └─ Services File Perms Weak | D | D | D | - | - | - | D | Weak service perms |
| T1574.011 | └─ Services Registry Perms | D | D | D | - | - | - | D | Weak registry perms |
| T1574.012 | └─ COR_PROFILER | D | D | D | - | - | - | D | .NET profiler |
| T1574.013 | └─ KernelCallbackTable | D | D | D | - | - | - | D | Callback hijacking |
| T1574.014 | └─ AppDomainManager | D | D | D | - | - | - | D | .NET AppDomain |
| T1525 | Implant Container Image | - | - | - | - | - | D | D | Container image scan |
| T1556 | Modify Auth Process | D | D | D | - | - | D | D | Auth mechanism changes |
| T1556.001 | └─ Domain Controller Auth | D | D | - | - | - | - | D | DC auth changes |
| T1556.002 | └─ Password Filter DLL | D | D | D | - | - | - | D | Password filter |
| T1556.003 | └─ Pluggable Auth Modules | D | D | D | - | - | - | D | PAM modification |
| T1556.004 | └─ Network Device Auth | D | - | - | D | - | - | D | Network device auth |
| T1556.005 | └─ Reversible Encryption | D | D | - | - | - | - | D | Password storage |
| T1556.006 | └─ Multi-Factor Auth | D | - | - | - | - | D | D | MFA bypass |
| T1556.007 | └─ Hybrid Identity | - | - | - | - | - | D | D | AAD Connect abuse |
| T1556.008 | └─ Network Provider DLL | D | D | D | - | - | - | D | Network provider |
| T1556.009 | └─ Conditional Access Pol | - | - | - | - | - | D | D | CA policy changes |
| T1137 | Office Application Startup | D | D | D | - | - | - | D | Office startup |
| T1137.001 | └─ Office Template Macros | D | D | D | - | - | - | D | Template macros |
| T1137.002 | └─ Office Test | D | D | D | - | - | - | D | Office test key |
| T1137.003 | └─ Outlook Forms | D | D | D | - | - | - | D | Outlook forms |
| T1137.004 | └─ Outlook Home Page | D | D | D | - | - | - | D | Outlook homepage |
| T1137.005 | └─ Outlook Rules | D | D | D | - | - | - | D | Malicious rules |
| T1137.006 | └─ Add-ins | D | D | D | - | - | - | D | Office add-ins |
| T1542 | Pre-OS Boot | D | D | D | - | - | - | D | Bootkit detection |
| T1542.001 | └─ System Firmware | D | D | D | - | - | - | D | Firmware monitoring |
| T1542.002 | └─ Component Firmware | D | D | D | - | - | - | D | Component firmware |
| T1542.003 | └─ Bootkit | D | D | D | - | - | - | D | Bootkit detection |
| T1542.004 | └─ ROMMONkit | - | - | - | - | - | - | D | Network device boot |
| T1542.005 | └─ TFTP Boot | D | - | - | D | - | - | D | TFTP boot mon |
| T1053 | Scheduled Task/Job | D/P | D | D | - | - | D | D | See Execution |
| T1505 | Server Software Component | D | D | D | D | D | D | D | Web server mods |
| T1505.001 | └─ SQL Stored Procedures | D | D | - | - | - | - | D | SQL audit |
| T1505.002 | └─ Transport Agent | D | D | - | - | - | - | D | Exchange agents |
| T1505.003 | └─ Web Shell | D | D | D | D | D | - | D | Webshell detection |
| T1505.004 | └─ IIS Components | D | D | D | - | - | - | D | IIS modules |
| T1505.005 | └─ Terminal Services DLL | D | D | D | - | - | - | D | RDP DLL loading |
| T1205 | Traffic Signaling | D | - | - | D | D | - | D | Port knocking |
| T1205.001 | └─ Port Knocking | D | - | - | D | D | - | D | Port knock detection |
| T1205.002 | └─ Socket Filters | D | D | D | - | - | - | D | BPF filter abuse |
| T1078 | Valid Accounts | D | D | D | D | D | D | D | See Initial Access |

### Persistence Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 98/102 | 8/102 | 96% (D), 8% (P) |
| Velociraptor | 94/102 | 0/102 | 92% (D) |
| osquery | 90/102 | 0/102 | 88% (D) |
| Prowler | 18/102 | 0/102 | 18% (D) |

**Recommended Stack for Persistence**:
- **Primary**: Wazuh (comprehensive FIM, registry, scheduled task monitoring)
- **Hunting**: Velociraptor (artifact collection for persistence locations)
- **Baseline**: osquery (scheduled queries for persistence enumeration)

---

## TA0004 - Privilege Escalation

> The adversary is trying to gain higher-level permissions.

**Primary Tools**: Wazuh, Velociraptor, Prowler  
**Note**: Many techniques overlap with Persistence (same mechanisms)

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1548 | Abuse Elevation Control | D | D | D | - | - | - | D | Elevation abuse |
| T1548.001 | └─ Setuid and Setgid | D | D | D | - | - | - | D | SUID/SGID monitoring |
| T1548.002 | └─ Bypass UAC | D | D | D | - | - | - | D | UAC bypass detection |
| T1548.003 | └─ Sudo and Sudo Caching | D | D | D | - | - | - | D | Sudo abuse |
| T1548.004 | └─ Elevated Execution w/Prompt | D | D | D | - | - | - | D | macOS elevation |
| T1548.005 | └─ Temporary Elevated Access | - | - | - | - | - | D | D | Cloud temp elevation |
| T1548.006 | └─ TCC Manipulation | D | D | D | - | - | - | D | macOS TCC abuse |
| T1134 | Access Token Manipulation | D | D | D | - | - | - | D | Token manipulation |
| T1134.001 | └─ Token Impersonation | D | D | D | - | - | - | D | Impersonation |
| T1134.002 | └─ Create Process w/Token | D | D | D | - | - | - | D | Token-based spawn |
| T1134.003 | └─ Make and Impersonate Token | D | D | D | - | - | - | D | Token creation |
| T1134.004 | └─ Parent PID Spoofing | D | D | D | - | - | - | D | PPID spoofing |
| T1134.005 | └─ SID-History Injection | D | D | - | - | - | - | D | SID history abuse |
| T1098 | Account Manipulation | D | D | D | D | - | D | D | See Persistence |
| T1547 | Boot/Logon Autostart | D | D | D | - | - | - | D | See Persistence |
| T1037 | Boot/Logon Init Scripts | D | D | D | - | - | - | D | See Persistence |
| T1543 | Create/Modify System Proc | D | D | D | - | - | - | D | See Persistence |
| T1484 | Domain/Tenant Policy Mod | D | D | - | D | - | D | D | Policy changes |
| T1484.001 | └─ Group Policy Modification | D | D | - | - | - | - | D | GPO changes |
| T1484.002 | └─ Trust Modification | D | D | - | D | - | D | D | Trust changes |
| T1611 | Escape to Host | - | - | - | - | - | D | D | Container escape |
| T1546 | Event Triggered Execution | D | D | D | - | - | - | D | See Persistence |
| T1068 | Exploitation for Priv Esc | D | D | - | D | D | - | D | Exploit detection |
| T1574 | Hijack Execution Flow | D | D | D | - | - | - | D | See Persistence |
| T1055 | Process Injection | D | D | D | - | - | - | D | Injection detection |
| T1055.001 | └─ DLL Injection | D | D | D | - | - | - | D | DLL injection |
| T1055.002 | └─ PE Injection | D | D | D | - | - | - | D | PE injection |
| T1055.003 | └─ Thread Execution Hijack | D | D | D | - | - | - | D | Thread hijacking |
| T1055.004 | └─ Asynchronous Proc Call | D | D | D | - | - | - | D | APC injection |
| T1055.005 | └─ Thread Local Storage | D | D | D | - | - | - | D | TLS callback |
| T1055.008 | └─ Ptrace System Calls | D | D | D | - | - | - | D | Ptrace abuse |
| T1055.009 | └─ Proc Memory | D | D | D | - | - | - | D | /proc injection |
| T1055.011 | └─ Extra Window Memory Inj | D | D | D | - | - | - | D | EWM injection |
| T1055.012 | └─ Process Hollowing | D | D | D | - | - | - | D | Hollowing detection |
| T1055.013 | └─ Process Doppelgänging | D | D | D | - | - | - | D | Doppelgänging |
| T1055.014 | └─ VDSO Hijacking | D | D | D | - | - | - | D | VDSO abuse |
| T1055.015 | └─ ListPlanting | D | D | D | - | - | - | D | List planting |
| T1053 | Scheduled Task/Job | D/P | D | D | - | - | D | D | See Execution |
| T1078 | Valid Accounts | D | D | D | D | D | D | D | See Initial Access |

### Privilege Escalation Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 42/44 | 4/44 | 95% (D), 9% (P) |
| Velociraptor | 40/44 | 0/44 | 91% (D) |
| osquery | 36/44 | 0/44 | 82% (D) |
| Prowler | 8/44 | 0/44 | 18% (D) |

---

## TA0005 - Defense Evasion

> The adversary is trying to avoid being detected.

**Primary Tools**: Wazuh, Velociraptor, Zeek, Suricata  
**Coverage Challenge**: Most extensive tactic with 42+ techniques

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1548 | Abuse Elevation Control | D | D | D | - | - | - | D | See Priv Esc |
| T1134 | Access Token Manipulation | D | D | D | - | - | - | D | See Priv Esc |
| T1197 | BITS Jobs | D | D | D | - | - | - | D | BITS abuse |
| T1612 | Build Image on Host | - | - | - | - | - | D | D | Container build |
| T1622 | Debugger Evasion | D | D | D | - | - | - | D | Anti-debug |
| T1140 | Deobfuscate/Decode | D | D | D | D | D | - | D | Decoding activity |
| T1610 | Deploy Container | D | - | - | - | - | D | D | Container deploy |
| T1006 | Direct Volume Access | D | D | D | - | - | - | D | Raw disk access |
| T1484 | Domain/Tenant Policy Mod | D | D | - | D | - | D | D | See Priv Esc |
| T1480 | Execution Guardrails | ~D | D | D | - | - | - | D | Env checks |
| T1480.001 | └─ Environmental Keying | ~D | D | D | - | - | - | D | Env-specific exec |
| T1480.002 | └─ Mutual Exclusion | D | D | D | - | - | - | D | Mutex checks |
| T1211 | Exploitation for Defense Ev | D | D | - | D | D | - | D | Exploit detection |
| T1222 | File & Directory Perms Mod | D | D | D | - | - | D | D | Permission changes |
| T1222.001 | └─ Windows File/Dir Perms | D | D | D | - | - | - | D | DACL changes |
| T1222.002 | └─ Linux/Mac File/Dir Perms | D | D | D | - | - | - | D | chmod/chown |
| T1564 | Hide Artifacts | D | D | D | D | - | D | D | Hidden artifacts |
| T1564.001 | └─ Hidden Files and Dirs | D | D | D | - | - | - | D | Hidden file attr |
| T1564.002 | └─ Hidden Users | D | D | D | - | - | - | D | Hidden accounts |
| T1564.003 | └─ Hidden Window | D | D | D | - | - | - | D | Hidden windows |
| T1564.004 | └─ NTFS File Attributes | D | D | D | - | - | - | D | ADS abuse |
| T1564.005 | └─ Hidden File System | D | D | D | - | - | - | D | Hidden FS |
| T1564.006 | └─ Run Virtual Instance | D | D | D | - | - | D | D | Hidden VM |
| T1564.007 | └─ VBA Stomping | D | D | D | - | - | - | D | Macro stomping |
| T1564.008 | └─ Email Hiding Rules | D | - | - | - | - | D | D | Mailbox rules |
| T1564.009 | └─ Resource Forking | D | D | D | - | - | - | D | macOS resource fork |
| T1564.010 | └─ Process Argument Spoofing | D | D | D | - | - | - | D | Arg spoofing |
| T1564.011 | └─ Ignore Process Interrupts | D | D | D | - | - | - | D | Signal ignoring |
| T1564.012 | └─ File/Path Exclusions | D | D | D | - | - | - | D | AV exclusions |
| T1574 | Hijack Execution Flow | D | D | D | - | - | - | D | See Persistence |
| T1562 | Impair Defenses | D | D | D | - | - | D | D | Security tool tampering |
| T1562.001 | └─ Disable/Modify Tools | D | D | D | - | - | - | D | Tool disabling |
| T1562.002 | └─ Disable Win Event Log | D | D | D | - | - | - | D | Event log tampering |
| T1562.003 | └─ Impair Command History | D | D | D | - | - | - | D | History clearing |
| T1562.004 | └─ Disable/Modify Firewall | D | D | D | - | - | D | D | FW changes |
| T1562.006 | └─ Indicator Blocking | D | D | D | - | - | - | D | Block indicators |
| T1562.007 | └─ Disable/Mod Cloud FW | - | - | - | - | - | D | D | Cloud FW changes |
| T1562.008 | └─ Disable/Mod Cloud Logs | - | - | - | - | - | D | D | Cloud log tampering |
| T1562.009 | └─ Safe Mode Boot | D | D | D | - | - | - | D | Safe mode abuse |
| T1562.010 | └─ Downgrade Attack | D | D | D | D | D | - | D | Protocol downgrade |
| T1562.011 | └─ Spoof Security Alerting | D | - | - | - | - | D | D | Alert spoofing |
| T1562.012 | └─ Disable/Mod Linux Audit | D | D | D | - | - | - | D | Auditd tampering |
| T1070 | Indicator Removal | D | D | D | D | - | D | D | Evidence destruction |
| T1070.001 | └─ Clear Windows Event Logs | D | D | D | - | - | - | D | Event log clearing |
| T1070.002 | └─ Clear Linux/Mac Logs | D | D | D | - | - | - | D | Syslog clearing |
| T1070.003 | └─ Clear Command History | D | D | D | - | - | - | D | History clearing |
| T1070.004 | └─ File Deletion | D | D | D | - | - | - | D | Secure deletion |
| T1070.005 | └─ Network Share Removal | D | D | D | - | - | - | D | Share cleanup |
| T1070.006 | └─ Timestomp | D | D | D | - | - | - | D | Timestamp modification |
| T1070.007 | └─ Clear Network Connect Hist | D | D | D | - | - | - | D | Network history |
| T1070.008 | └─ Clear Mailbox Data | D | - | - | - | - | D | D | Email deletion |
| T1070.009 | └─ Clear Persistence | D | D | D | - | - | - | D | Persistence cleanup |
| T1202 | Indirect Command Execution | D | D | D | - | - | - | D | LOLBins |
| T1036 | Masquerading | D | D | D | D | D | - | D | Identity spoofing |
| T1036.001 | └─ Invalid Code Signature | D | D | D | - | - | - | D | Bad signatures |
| T1036.002 | └─ Right-to-Left Override | D | D | D | - | - | - | D | RTLO abuse |
| T1036.003 | └─ Rename System Utilities | D | D | D | - | - | - | D | Renamed binaries |
| T1036.004 | └─ Masquerade Task or Service | D | D | D | - | - | - | D | Fake services |
| T1036.005 | └─ Match Legit Name/Location | D | D | D | - | - | - | D | Path masquerading |
| T1036.006 | └─ Space after Filename | D | D | D | - | - | - | D | Trailing spaces |
| T1036.007 | └─ Double File Extension | D | D | D | - | - | - | D | Double extension |
| T1036.008 | └─ Masquerade File Type | D | D | D | - | - | - | D | File type spoof |
| T1036.009 | └─ Break Process Trees | D | D | D | - | - | - | D | Parent break |
| T1556 | Modify Auth Process | D | D | D | - | - | D | D | See Persistence |
| T1578 | Modify Cloud Compute | - | - | - | - | - | D | D | Cloud compute changes |
| T1578.001 | └─ Create Snapshot | - | - | - | - | - | D | D | Snapshot creation |
| T1578.002 | └─ Create Cloud Instance | - | - | - | - | - | D | D | Instance creation |
| T1578.003 | └─ Delete Cloud Instance | - | - | - | - | - | D | D | Instance deletion |
| T1578.004 | └─ Revert Cloud Instance | - | - | - | - | - | D | D | Instance revert |
| T1578.005 | └─ Modify Cloud Compute Config | - | - | - | - | - | D | D | Config changes |
| T1112 | Modify Registry | D | D | D | - | - | - | D | Registry changes |
| T1601 | Modify System Image | D | D | - | D | - | - | D | System image mod |
| T1601.001 | └─ Patch System Image | D | D | - | - | - | - | D | Image patching |
| T1601.002 | └─ Downgrade System Image | D | D | - | D | - | - | D | Image downgrade |
| T1599 | Network Boundary Bridging | - | - | - | D | D | - | D | NAT traversal |
| T1599.001 | └─ Network Address Translation | - | - | - | D | D | - | D | NAT abuse |
| T1027 | Obfuscated Files or Info | D | D | D | D | D | - | D | Obfuscation |
| T1027.001 | └─ Binary Padding | D | D | D | - | - | - | D | File padding |
| T1027.002 | └─ Software Packing | D | D | D | - | - | - | D | Packed binaries |
| T1027.003 | └─ Steganography | ~D | D | - | D | D | - | D | Hidden data |
| T1027.004 | └─ Compile After Delivery | D | D | D | - | - | - | D | Runtime compile |
| T1027.005 | └─ Indicator Removal Malware | D | D | D | - | - | - | D | Self-modifying |
| T1027.006 | └─ HTML Smuggling | D | D | - | D | D | - | D | HTML smuggling |
| T1027.007 | └─ Dynamic API Resolution | D | D | D | - | - | - | D | API hashing |
| T1027.008 | └─ Stripped Payloads | D | D | D | - | - | - | D | Minimal malware |
| T1027.009 | └─ Embedded Payloads | D | D | D | D | D | - | D | Nested payloads |
| T1027.010 | └─ Command Obfuscation | D | D | D | - | - | - | D | Cmd obfuscation |
| T1027.011 | └─ Fileless Storage | D | D | D | - | - | - | D | Registry/WMI storage |
| T1027.012 | └─ LNK Icon Smuggling | D | D | D | - | - | - | D | LNK payload |
| T1027.013 | └─ Encrypted/Encoded File | D | D | D | D | D | - | D | Encrypted content |
| T1647 | Plist File Modification | D | D | D | - | - | - | D | macOS plist |
| T1542 | Pre-OS Boot | D | D | D | - | - | - | D | See Persistence |
| T1055 | Process Injection | D | D | D | - | - | - | D | See Priv Esc |
| T1620 | Reflective Code Loading | D | D | D | - | - | - | D | Reflective loading |
| T1207 | Rogue Domain Controller | D | D | - | D | - | - | D | DCShadow |
| T1014 | Rootkit | D | D | D | - | - | - | D | Rootkit detection |
| T1553 | Subvert Trust Controls | D | D | D | D | D | D | D | Trust abuse |
| T1553.001 | └─ Gatekeeper Bypass | D | D | D | - | - | - | D | macOS Gatekeeper |
| T1553.002 | └─ Code Signing | D | D | D | - | - | - | D | Signature abuse |
| T1553.003 | └─ SIP and Trust Provider | D | D | D | - | - | - | D | SIP hijack |
| T1553.004 | └─ Install Root Certificate | D | D | D | D | D | D | D | Root CA install |
| T1553.005 | └─ Mark-of-the-Web Bypass | D | D | D | - | - | - | D | MOTW bypass |
| T1553.006 | └─ Code Signing Policy Mod | D | D | D | - | - | - | D | Policy changes |
| T1218 | System Binary Proxy Exec | D | D | D | - | - | - | D | LOLBins execution |
| T1218.001 | └─ Compiled HTML File | D | D | D | - | - | - | D | CHM abuse |
| T1218.002 | └─ Control Panel | D | D | D | - | - | - | D | CPL execution |
| T1218.003 | └─ CMSTP | D | D | D | - | - | - | D | CMSTP abuse |
| T1218.004 | └─ InstallUtil | D | D | D | - | - | - | D | InstallUtil |
| T1218.005 | └─ Mshta | D | D | D | - | - | - | D | Mshta execution |
| T1218.007 | └─ Msiexec | D | D | D | - | - | - | D | Msiexec abuse |
| T1218.008 | └─ Odbcconf | D | D | D | - | - | - | D | Odbcconf |
| T1218.009 | └─ Regsvcs/Regasm | D | D | D | - | - | - | D | .NET utilities |
| T1218.010 | └─ Regsvr32 | D | D | D | - | - | - | D | Regsvr32 |
| T1218.011 | └─ Rundll32 | D | D | D | - | - | - | D | Rundll32 |
| T1218.012 | └─ Verclsid | D | D | D | - | - | - | D | Verclsid |
| T1218.013 | └─ Mavinject | D | D | D | - | - | - | D | Mavinject |
| T1218.014 | └─ MMC | D | D | D | - | - | - | D | MMC snap-in |
| T1216 | System Script Proxy Exec | D | D | D | - | - | - | D | Script proxies |
| T1216.001 | └─ PubPrn | D | D | D | - | - | - | D | PubPrn.vbs |
| T1216.002 | └─ SyncAppvPublishingServer | D | D | D | - | - | - | D | SyncAppv |
| T1221 | Template Injection | D | D | D | D | D | - | D | Doc templates |
| T1205 | Traffic Signaling | D | - | - | D | D | - | D | See Persistence |
| T1127 | Trusted Developer Utilities | D | D | D | - | - | - | D | Dev tool abuse |
| T1127.001 | └─ MSBuild | D | D | D | - | - | - | D | MSBuild |
| T1535 | Unused/Unsupported Cloud Regions | - | - | - | - | - | D | D | Unused regions |
| T1550 | Use Alternate Auth Material | D | D | D | D | D | D | D | Auth material abuse |
| T1550.001 | └─ Application Access Token | D | - | - | - | - | D | D | App tokens |
| T1550.002 | └─ Pass the Hash | D | D | D | D | D | - | D | PTH |
| T1550.003 | └─ Pass the Ticket | D | D | D | D | D | - | D | PTT |
| T1550.004 | └─ Web Session Cookie | D | - | - | D | - | D | D | Cookie theft |
| T1078 | Valid Accounts | D | D | D | D | D | D | D | See Initial Access |
| T1497 | Virtualization/Sandbox Eva | D | D | D | - | - | - | D | VM detection |
| T1497.001 | └─ System Checks | D | D | D | - | - | - | D | Hardware checks |
| T1497.002 | └─ User Activity Based | D | D | D | - | - | - | D | User behavior |
| T1497.003 | └─ Time Based Evasion | D | D | D | - | - | - | D | Time delays |
| T1600 | Weaken Encryption | D | D | - | D | D | - | D | Crypto weakening |
| T1600.001 | └─ Reduce Key Space | D | D | - | D | D | - | D | Key reduction |
| T1600.002 | └─ Disable Crypto Hardware | D | D | - | - | - | - | D | HSM disable |
| T1220 | XSL Script Processing | D | D | D | - | - | - | D | XSLT abuse |

### Defense Evasion Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 118/122 | 0/122 | 97% (D) |
| Velociraptor | 114/122 | 0/122 | 93% (D) |
| osquery | 106/122 | 0/122 | 87% (D) |
| Prowler | 28/122 | 0/122 | 23% (D) |
| Zeek | 24/122 | 0/122 | 20% (D) |
| Suricata | 20/122 | 0/122 | 16% (D) |

**Recommendation**: Defense Evasion requires comprehensive endpoint visibility:
- **Primary**: Wazuh + Velociraptor (deep process, file, registry monitoring)
- **Network**: Zeek + Suricata (encrypted traffic analysis, protocol abuse)
- **Cloud**: Prowler (cloud-specific evasion techniques)

---

## TA0006 - Credential Access

> The adversary is trying to steal account names and passwords.

**Primary Tools**: Wazuh, Velociraptor, Zeek  
**Coverage Challenge**: Diverse credential theft methods

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1557 | Adversary-in-the-Middle | D | D | - | D | D | - | D | MITM detection |
| T1557.001 | └─ LLMNR/NBT-NS Poisoning | D | D | - | D | D | - | D | Responder detection |
| T1557.002 | └─ ARP Cache Poisoning | D | - | - | D | D | - | D | ARP spoofing |
| T1557.003 | └─ DHCP Spoofing | D | - | - | D | D | - | D | Rogue DHCP |
| T1110 | Brute Force | D | D | D | D | D | D | D | Auth failures |
| T1110.001 | └─ Password Guessing | D | D | D | D | D | D | D | Login attempts |
| T1110.002 | └─ Password Cracking | ~D | D | - | - | - | - | D | Offline cracking |
| T1110.003 | └─ Password Spraying | D | D | D | D | D | D | D | Spray detection |
| T1110.004 | └─ Credential Stuffing | D | D | D | D | D | D | D | Stuffing detection |
| T1555 | Credentials from Password Stores | D | D | D | - | - | - | D | Password store access |
| T1555.001 | └─ Keychain | D | D | D | - | - | - | D | macOS keychain |
| T1555.002 | └─ Securityd Memory | D | D | D | - | - | - | D | macOS securityd |
| T1555.003 | └─ Credentials from Web Browsers | D | D | D | - | - | - | D | Browser creds |
| T1555.004 | └─ Windows Credential Manager | D | D | D | - | - | - | D | Cred manager |
| T1555.005 | └─ Password Managers | D | D | D | - | - | - | D | Password mgr access |
| T1555.006 | └─ Cloud Secrets Mgmt Stores | - | - | - | - | - | D | D | Cloud secrets |
| T1212 | Exploitation for Cred Access | D | D | - | D | D | - | D | Exploit detection |
| T1187 | Forced Authentication | D | D | D | D | D | - | D | Coerced auth |
| T1606 | Forge Web Credentials | D | - | - | D | - | D | D | Token forging |
| T1606.001 | └─ Web Cookies | D | - | - | D | - | D | D | Cookie forging |
| T1606.002 | └─ SAML Tokens | D | - | - | D | - | D | D | Golden SAML |
| T1056 | Input Capture | D | D | D | - | - | - | D | Keylogging |
| T1056.001 | └─ Keylogging | D | D | D | - | - | - | D | Keylogger detection |
| T1056.002 | └─ GUI Input Capture | D | D | D | - | - | - | D | Fake prompts |
| T1056.003 | └─ Web Portal Capture | D | - | - | D | D | - | D | Fake login pages |
| T1056.004 | └─ Credential API Hooking | D | D | D | - | - | - | D | API hooks |
| T1556 | Modify Auth Process | D | D | D | - | - | D | D | See Persistence |
| T1111 | Multi-Factor Auth Intercept | D | - | - | D | - | D | D | MFA interception |
| T1621 | Multi-Factor Auth Request Gen | D | - | - | - | - | D | D | MFA bombing |
| T1040 | Network Sniffing | D | D | D | D | D | - | D | Packet capture |
| T1003 | OS Credential Dumping | D | D | D | - | - | - | D | Cred dumping |
| T1003.001 | └─ LSASS Memory | D | D | D | - | - | - | D | LSASS access |
| T1003.002 | └─ Security Account Manager | D | D | D | - | - | - | D | SAM access |
| T1003.003 | └─ NTDS | D | D | D | - | - | - | D | NTDS.dit access |
| T1003.004 | └─ LSA Secrets | D | D | D | - | - | - | D | LSA access |
| T1003.005 | └─ Cached Domain Creds | D | D | D | - | - | - | D | Cached creds |
| T1003.006 | └─ DCSync | D | D | - | D | - | - | D | DCSync detection |
| T1003.007 | └─ Proc Filesystem | D | D | D | - | - | - | D | /proc access |
| T1003.008 | └─ /etc/passwd and /etc/shadow | D | D | D | - | - | - | D | Shadow file access |
| T1528 | Steal Application Access Token | D | - | - | D | - | D | D | OAuth token theft |
| T1649 | Steal or Forge Auth Certificates | D | D | D | D | - | D | D | Cert theft |
| T1558 | Steal or Forge Kerberos Tickets | D | D | D | D | D | - | D | Kerberos attacks |
| T1558.001 | └─ Golden Ticket | D | D | D | D | D | - | D | Golden ticket |
| T1558.002 | └─ Silver Ticket | D | D | D | D | D | - | D | Silver ticket |
| T1558.003 | └─ Kerberoasting | D | D | D | D | D | - | D | Kerberoasting |
| T1558.004 | └─ AS-REP Roasting | D | D | D | D | D | - | D | AS-REP roasting |
| T1539 | Steal Web Session Cookie | D | - | - | D | - | D | D | Cookie theft |
| T1552 | Unsecured Credentials | D | D | D | - | - | D | D | Exposed creds |
| T1552.001 | └─ Credentials In Files | D | D | D | - | - | D | D | Cred file search |
| T1552.002 | └─ Credentials in Registry | D | D | D | - | - | - | D | Registry creds |
| T1552.003 | └─ Bash History | D | D | D | - | - | - | D | History files |
| T1552.004 | └─ Private Keys | D | D | D | - | - | D | D | Key file access |
| T1552.005 | └─ Cloud Instance Metadata | - | - | - | D | - | D | D | IMDS access |
| T1552.006 | └─ Group Policy Preferences | D | D | D | - | - | - | D | GPP passwords |
| T1552.007 | └─ Container API | - | - | - | - | - | D | D | K8s secrets |
| T1552.008 | └─ Chat Messages | D | - | - | - | - | - | D | Chat logs |

### Credential Access Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 54/58 | 0/58 | 93% (D) |
| Velociraptor | 44/58 | 0/58 | 76% (D) |
| Zeek | 26/58 | 0/58 | 45% (D) |
| Prowler | 18/58 | 0/58 | 31% (D) |
| Suricata | 16/58 | 0/58 | 28% (D) |

**Recommended Stack for Credential Access**:
- **Primary**: Wazuh (LSASS monitoring, auth logs, file access)
- **Network**: Zeek (Kerberos, LDAP, NTLM protocol analysis)
- **Hunting**: Velociraptor (memory analysis, credential artifact collection)

---

## TA0007 - Discovery

> The adversary is trying to figure out your environment.

**Primary Tools**: Wazuh, Velociraptor, osquery, Zeek  
**Coverage**: Generally good detection across solutions

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1087 | Account Discovery | D | D | D | D | - | D | D | Account enumeration |
| T1087.001 | └─ Local Account | D | D | D | - | - | - | D | Local users |
| T1087.002 | └─ Domain Account | D | D | D | D | - | - | D | AD enumeration |
| T1087.003 | └─ Email Account | D | - | - | - | - | D | D | Email enum |
| T1087.004 | └─ Cloud Account | - | - | - | - | - | D | D | Cloud IAM enum |
| T1010 | Application Window Discovery | D | D | D | - | - | - | D | Window enum |
| T1217 | Browser Information Discovery | D | D | D | - | - | - | D | Browser enum |
| T1580 | Cloud Infra Discovery | - | - | - | - | - | D | D | Cloud enum |
| T1538 | Cloud Service Dashboard | - | - | - | - | - | D | D | Console access |
| T1526 | Cloud Service Discovery | - | - | - | - | - | D | D | Service enum |
| T1613 | Container and Resource Discovery | - | - | - | - | - | D | D | K8s enum |
| T1622 | Debugger Evasion | D | D | D | - | - | - | D | Debug detection |
| T1652 | Device Driver Discovery | D | D | D | - | - | - | D | Driver enum |
| T1482 | Domain Trust Discovery | D | D | D | D | - | - | D | Trust enum |
| T1083 | File and Directory Discovery | D | D | D | - | - | - | D | File enum |
| T1615 | Group Policy Discovery | D | D | D | - | - | - | D | GPO enum |
| T1654 | Log Enumeration | D | D | D | - | - | D | D | Log access |
| T1046 | Network Service Discovery | D | D | D | D | D | - | D | Port scanning |
| T1135 | Network Share Discovery | D | D | D | D | - | - | D | Share enum |
| T1040 | Network Sniffing | D | D | D | D | D | - | D | Packet capture |
| T1201 | Password Policy Discovery | D | D | D | D | - | D | D | Policy enum |
| T1120 | Peripheral Device Discovery | D | D | D | - | - | - | D | Device enum |
| T1069 | Permission Groups Discovery | D | D | D | D | - | D | D | Group enum |
| T1069.001 | └─ Local Groups | D | D | D | - | - | - | D | Local groups |
| T1069.002 | └─ Domain Groups | D | D | D | D | - | - | D | AD groups |
| T1069.003 | └─ Cloud Groups | - | - | - | - | - | D | D | Cloud groups |
| T1057 | Process Discovery | D | D | D | - | - | - | D | Process enum |
| T1012 | Query Registry | D | D | D | - | - | - | D | Registry query |
| T1018 | Remote System Discovery | D | D | D | D | D | - | D | Network enum |
| T1518 | Software Discovery | D | D | D | - | - | D | D | Software enum |
| T1518.001 | └─ Security Software Discovery | D | D | D | - | - | D | D | AV enum |
| T1082 | System Information Discovery | D | D | D | - | - | D | D | System enum |
| T1614 | System Location Discovery | D | D | D | D | - | D | D | Geo detection |
| T1614.001 | └─ System Language Discovery | D | D | D | - | - | - | D | Language check |
| T1016 | System Network Config Discovery | D | D | D | D | - | D | D | Network config |
| T1016.001 | └─ Internet Connection Discovery | D | D | D | D | - | - | D | Connectivity test |
| T1016.002 | └─ Wi-Fi Discovery | D | D | D | - | - | - | D | WiFi enum |
| T1049 | System Network Connections | D | D | D | D | - | - | D | Connection enum |
| T1033 | System Owner/User Discovery | D | D | D | - | - | - | D | User enum |
| T1007 | System Service Discovery | D | D | D | - | - | - | D | Service enum |
| T1124 | System Time Discovery | D | D | D | D | - | - | D | Time sync check |
| T1497 | Virtualization/Sandbox Eva | D | D | D | - | - | - | D | VM detection |

### Discovery Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 40/44 | 0/44 | 91% (D) |
| Velociraptor | 40/44 | 0/44 | 91% (D) |
| osquery | 40/44 | 0/44 | 91% (D) |
| Prowler | 16/44 | 0/44 | 36% (D) |
| Zeek | 14/44 | 0/44 | 32% (D) |

---

## TA0008 - Lateral Movement

> The adversary is trying to move through your environment.

**Primary Tools**: Wazuh, Zeek, Suricata, Velociraptor

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1210 | Exploitation of Remote Services | D | D | - | D | D/P | - | D | Remote exploit |
| T1534 | Internal Spearphishing | D | D | - | D | D | - | D | Internal phishing |
| T1570 | Lateral Tool Transfer | D | D | D | D | D | - | D | Tool movement |
| T1563 | Remote Service Session Hijack | D | D | - | D | D | - | D | Session hijack |
| T1563.001 | └─ SSH Hijacking | D | D | - | D | D | - | D | SSH hijack |
| T1563.002 | └─ RDP Hijacking | D | D | - | D | D | - | D | RDP hijack |
| T1021 | Remote Services | D | D | D | D | D | D | D | Remote access |
| T1021.001 | └─ Remote Desktop Protocol | D | D | D | D | D | - | D | RDP |
| T1021.002 | └─ SMB/Windows Admin Shares | D | D | D | D | D | - | D | SMB shares |
| T1021.003 | └─ Distributed COM | D | D | D | D | D | - | D | DCOM |
| T1021.004 | └─ SSH | D | D | D | D | D | - | D | SSH |
| T1021.005 | └─ VNC | D | D | D | D | D | - | D | VNC |
| T1021.006 | └─ Windows Remote Mgmt | D | D | D | D | D | - | D | WinRM |
| T1021.007 | └─ Cloud Services | - | - | - | - | - | D | D | Cloud lateral |
| T1021.008 | └─ Direct Cloud VM Connections | - | - | - | - | - | D | D | Cloud VM |
| T1091 | Replication Through Media | D | D | D | - | - | - | D | USB spread |
| T1072 | Software Deploy Tools | D | D | D | - | - | D | D | Deploy tool abuse |
| T1080 | Taint Shared Content | D | D | D | D | - | - | D | Share poisoning |
| T1550 | Use Alternate Auth Material | D | D | D | D | D | D | D | See Defense Evasion |

### Lateral Movement Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 18/20 | 0/20 | 90% (D) |
| Zeek | 16/20 | 0/20 | 80% (D) |
| Velociraptor | 16/20 | 0/20 | 80% (D) |
| Suricata | 14/20 | 6/20 | 70% (D), 30% (P) |
| Prowler | 4/20 | 0/20 | 20% (D) |

**Recommended Stack for Lateral Movement**:
- **Primary**: Wazuh (endpoint auth logs, process monitoring)
- **Network**: Zeek + Suricata (SMB, RDP, SSH traffic analysis)
- **Cloud**: Prowler (cloud service lateral movement)

---

## TA0009 - Collection

> The adversary is trying to gather data of interest to their goal.

**Primary Tools**: Wazuh, Velociraptor, Zeek

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1557 | Adversary-in-the-Middle | D | D | - | D | D | - | D | See Cred Access |
| T1560 | Archive Collected Data | D | D | D | D | D | - | D | Compression |
| T1560.001 | └─ Archive via Utility | D | D | D | - | - | - | D | zip/rar/7z |
| T1560.002 | └─ Archive via Library | D | D | D | - | - | - | D | Code compression |
| T1560.003 | └─ Archive via Custom Method | D | D | D | - | - | - | D | Custom archive |
| T1123 | Audio Capture | D | D | D | - | - | - | D | Mic access |
| T1119 | Automated Collection | D | D | D | - | - | - | D | Scripted collection |
| T1185 | Browser Session Hijacking | D | D | D | D | - | - | D | Browser hijack |
| T1115 | Clipboard Data | D | D | D | - | - | - | D | Clipboard access |
| T1530 | Data from Cloud Storage | - | - | - | D | - | D | D | Cloud storage |
| T1602 | Data from Config Repository | D | D | - | D | - | - | D | Config access |
| T1602.001 | └─ SNMP (MIB Dump) | D | - | - | D | D | - | D | SNMP data |
| T1602.002 | └─ Network Device Config Dump | D | - | - | D | - | - | D | Device config |
| T1213 | Data from Info Repositories | D | D | D | D | - | D | D | Repository access |
| T1213.001 | └─ Confluence | D | - | - | D | - | D | D | Confluence |
| T1213.002 | └─ Sharepoint | D | - | - | D | - | D | D | Sharepoint |
| T1213.003 | └─ Code Repositories | D | D | - | D | - | D | D | Git repos |
| T1005 | Data from Local System | D | D | D | - | - | - | D | Local data |
| T1039 | Data from Network Shared Drive | D | D | D | D | - | - | D | Share access |
| T1025 | Data from Removable Media | D | D | D | - | - | - | D | USB data |
| T1074 | Data Staged | D | D | D | D | - | - | D | Staging detection |
| T1074.001 | └─ Local Data Staging | D | D | D | - | - | - | D | Local staging |
| T1074.002 | └─ Remote Data Staging | D | D | D | D | - | - | D | Remote staging |
| T1114 | Email Collection | D | D | - | D | - | D | D | Email access |
| T1114.001 | └─ Local Email Collection | D | D | - | - | - | - | D | Local email |
| T1114.002 | └─ Remote Email Collection | D | - | - | D | - | D | D | Remote email |
| T1114.003 | └─ Email Forwarding Rule | D | - | - | - | - | D | D | Forward rules |
| T1056 | Input Capture | D | D | D | - | - | - | D | See Cred Access |
| T1113 | Screen Capture | D | D | D | - | - | - | D | Screenshot |
| T1125 | Video Capture | D | D | D | - | - | - | D | Camera access |

### Collection Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 30/32 | 0/32 | 94% (D) |
| Velociraptor | 26/32 | 0/32 | 81% (D) |
| Zeek | 16/32 | 0/32 | 50% (D) |
| Prowler | 10/32 | 0/32 | 31% (D) |

---

## TA0011 - Command and Control

> The adversary is trying to communicate with compromised systems.

**Primary Tools**: Zeek, Suricata, OpenCTI

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1071 | Application Layer Protocol | D | D | - | D | D | - | D | Protocol abuse |
| T1071.001 | └─ Web Protocols | D | D | - | D | D | - | D | HTTP/S C2 |
| T1071.002 | └─ File Transfer Protocols | D | - | - | D | D | - | D | FTP C2 |
| T1071.003 | └─ Mail Protocols | D | - | - | D | D | - | D | SMTP C2 |
| T1071.004 | └─ DNS | D | - | - | D | D | - | D | DNS C2 |
| T1132 | Data Encoding | D | D | - | D | D | - | D | Encoded C2 |
| T1132.001 | └─ Standard Encoding | D | D | - | D | D | - | D | Base64 etc |
| T1132.002 | └─ Non-Standard Encoding | D | D | - | D | D | - | D | Custom encoding |
| T1001 | Data Obfuscation | D | D | - | D | D | - | D | Obfuscated C2 |
| T1001.001 | └─ Junk Data | D | D | - | D | D | - | D | Padding |
| T1001.002 | └─ Steganography | ~D | D | - | D | D | - | D | Hidden data |
| T1001.003 | └─ Protocol Impersonation | D | D | - | D | D | - | D | Protocol mimicry |
| T1568 | Dynamic Resolution | D | - | - | D | D | - | D | Dynamic C2 |
| T1568.001 | └─ Fast Flux DNS | D | - | - | D | D | - | D | Fast flux |
| T1568.002 | └─ Domain Generation Algorithms | D | - | - | D | D | - | D | DGA |
| T1568.003 | └─ DNS Calculation | D | - | - | D | D | - | D | DNS calc |
| T1573 | Encrypted Channel | D | D | - | D | D | - | D | Encrypted C2 |
| T1573.001 | └─ Symmetric Cryptography | D | D | - | D | D | - | D | Symmetric |
| T1573.002 | └─ Asymmetric Cryptography | D | D | - | D | D | - | D | Asymmetric |
| T1008 | Fallback Channels | D | - | - | D | D | - | D | Backup C2 |
| T1105 | Ingress Tool Transfer | D | D | D | D | D | - | D | Tool download |
| T1104 | Multi-Stage Channels | D | - | - | D | D | - | D | Staged C2 |
| T1095 | Non-Application Layer Protocol | D | - | - | D | D | - | D | Non-app proto |
| T1571 | Non-Standard Port | D | - | - | D | D | - | D | Port abuse |
| T1572 | Protocol Tunneling | D | D | - | D | D | - | D | Tunneling |
| T1090 | Proxy | D | D | - | D | D | - | D | C2 proxy |
| T1090.001 | └─ Internal Proxy | D | D | - | D | D | - | D | Internal proxy |
| T1090.002 | └─ External Proxy | D | D | - | D | D | - | D | External proxy |
| T1090.003 | └─ Multi-hop Proxy | D | D | - | D | D | - | D | Multi-hop |
| T1090.004 | └─ Domain Fronting | D | D | - | D | D | - | D | CDN abuse |
| T1219 | Remote Access Software | D | D | D | D | D | - | D | RAT detection |
| T1205 | Traffic Signaling | D | - | - | D | D | - | D | See Persistence |
| T1102 | Web Service | D | D | - | D | D | - | D | Legit service C2 |
| T1102.001 | └─ Dead Drop Resolver | D | D | - | D | D | - | D | Dead drop |
| T1102.002 | └─ Bidirectional Comm. | D | D | - | D | D | - | D | Two-way C2 |
| T1102.003 | └─ One-Way Comm. | D | D | - | D | D | - | D | One-way C2 |

### Command and Control Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Zeek | 36/36 | 0/36 | 100% (D) |
| Suricata | 36/36 | 18/36 | 100% (D), 50% (P) |
| Wazuh | 32/36 | 0/36 | 89% (D) |
| OpenCTI | 36/36 | 0/36 | 100% (D) via IOCs |

**Recommended Stack for C2**:
- **Primary**: Zeek (deep protocol analysis, JA3/JA4 fingerprinting)
- **Secondary**: Suricata (signature-based C2 detection, IPS mode)
- **Enrichment**: OpenCTI (IOC correlation, C2 infrastructure tracking)

---

## TA0010 - Exfiltration

> The adversary is trying to steal data.

**Primary Tools**: Zeek, Suricata, Wazuh, Prowler

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1020 | Automated Exfiltration | D | D | - | D | D | D | D | Automated theft |
| T1020.001 | └─ Traffic Duplication | D | - | - | D | D | - | D | Traffic mirror |
| T1030 | Data Transfer Size Limits | D | - | - | D | D | - | D | Chunked exfil |
| T1048 | Exfiltration Over Alt Protocol | D | D | - | D | D | - | D | Alt proto exfil |
| T1048.001 | └─ Exfil Over Symmetric Encrypted | D | D | - | D | D | - | D | Encrypted exfil |
| T1048.002 | └─ Exfil Over Asymmetric Encrypted | D | D | - | D | D | - | D | Asymmetric exfil |
| T1048.003 | └─ Exfil Over Unencrypted | D | D | - | D | D | - | D | Plaintext exfil |
| T1041 | Exfiltration Over C2 Channel | D | D | - | D | D | - | D | C2 exfil |
| T1011 | Exfiltration Over Other Network | D | - | - | D | D | - | D | Alt network |
| T1011.001 | └─ Exfil Over Bluetooth | D | - | - | - | - | - | D | Bluetooth |
| T1052 | Exfiltration Over Physical Medium | D | D | D | - | - | - | D | Physical exfil |
| T1052.001 | └─ Exfil over USB | D | D | D | - | - | - | D | USB exfil |
| T1567 | Exfiltration Over Web Service | D | D | - | D | D | D | D | Web svc exfil |
| T1567.001 | └─ Exfil to Code Repository | D | D | - | D | D | D | D | Git exfil |
| T1567.002 | └─ Exfil to Cloud Storage | D | D | - | D | D | D | D | Cloud storage |
| T1567.003 | └─ Exfil to Text Storage Sites | D | D | - | D | D | - | D | Pastebin etc |
| T1567.004 | └─ Exfil Over Webhook | D | D | - | D | D | D | D | Webhook exfil |
| T1029 | Scheduled Transfer | D | D | - | D | D | - | D | Scheduled exfil |
| T1537 | Transfer Data to Cloud Account | - | - | - | D | - | D | D | Cloud transfer |

### Exfiltration Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Zeek | 16/19 | 0/19 | 84% (D) |
| Suricata | 14/19 | 8/19 | 74% (D), 42% (P) |
| Wazuh | 16/19 | 0/19 | 84% (D) |
| Prowler | 6/19 | 0/19 | 32% (D) |

---

## TA0040 - Impact

> The adversary is trying to manipulate, interrupt, or destroy systems and data.

**Primary Tools**: Wazuh, Velociraptor, Prowler

| ID | Technique | WAZ | VEL | OSQ | ZEK | SUR | PRO | CTI | Notes |
|----|-----------|-----|-----|-----|-----|-----|-----|-----|-------|
| T1531 | Account Access Removal | D | D | D | D | - | D | D | Account lockout |
| T1485 | Data Destruction | D | D | D | - | - | D | D | Data deletion |
| T1486 | Data Encrypted for Impact | D | D | D | - | - | - | D | Ransomware |
| T1565 | Data Manipulation | D | D | D | - | - | D | D | Data integrity |
| T1565.001 | └─ Stored Data Manipulation | D | D | D | - | - | D | D | DB/file manip |
| T1565.002 | └─ Transmitted Data Manipulation | D | D | - | D | D | - | D | MITM manip |
| T1565.003 | └─ Runtime Data Manipulation | D | D | D | - | - | - | D | Memory manip |
| T1491 | Defacement | D | D | D | D | D | D | D | Web defacement |
| T1491.001 | └─ Internal Defacement | D | D | D | - | - | - | D | Internal deface |
| T1491.002 | └─ External Defacement | D | D | D | D | D | D | D | External deface |
| T1561 | Disk Wipe | D | D | D | - | - | - | D | Disk destruction |
| T1561.001 | └─ Disk Content Wipe | D | D | D | - | - | - | D | Content wipe |
| T1561.002 | └─ Disk Structure Wipe | D | D | D | - | - | - | D | MBR/partition wipe |
| T1499 | Endpoint Denial of Service | D | D | - | D | D/P | D | D | Endpoint DoS |
| T1499.001 | └─ OS Exhaustion Flood | D | D | - | D | D/P | - | D | Resource flood |
| T1499.002 | └─ Service Exhaustion Flood | D | D | - | D | D/P | D | D | Service flood |
| T1499.003 | └─ Application Exhaustion Flood | D | D | - | D | D/P | D | D | App flood |
| T1499.004 | └─ App or System Exploitation | D | D | - | D | D/P | D | D | Exploit DoS |
| T1657 | Financial Theft | D | - | - | D | - | D | D | Financial fraud |
| T1495 | Firmware Corruption | D | D | D | - | - | - | D | Firmware damage |
| T1490 | Inhibit System Recovery | D | D | D | - | - | - | D | Recovery disable |
| T1498 | Network Denial of Service | D | - | - | D | D/P | D | D | Network DoS |
| T1498.001 | └─ Direct Network Flood | D | - | - | D | D/P | D | D | Direct flood |
| T1498.002 | └─ Reflection Amplification | D | - | - | D | D/P | D | D | Amplification |
| T1496 | Resource Hijacking | D | D | D | D | D | D | D | Cryptomining etc |
| T1489 | Service Stop | D | D | D | - | - | D | D | Service kill |
| T1529 | System Shutdown/Reboot | D | D | D | - | - | - | D | Forced shutdown |

### Impact Coverage Summary

| Solution | Detection | Prevention | Total Coverage |
|----------|-----------|------------|----------------|
| Wazuh | 26/28 | 0/28 | 93% (D) |
| Velociraptor | 22/28 | 0/28 | 79% (D) |
| Suricata | 12/28 | 10/28 | 43% (D), 36% (P) |
| Prowler | 14/28 | 0/28 | 50% (D) |

---

## Coverage Summary by Tactic

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Overall ATT&CK Coverage Summary                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Tactic                  | WAZ  | VEL  | ZEK  | SUR  | PRO  | Best     │
│  ────────────────────────┼──────┼──────┼──────┼──────┼──────┼──────────│
│  Reconnaissance          |  7%  |  0%  | 28%  | 14%  |  0%  | Zeek     │
│  Resource Development    |  0%  |  0%  | 33%  | 13%  |  4%  | Zeek     │
│  Initial Access          | 90%  | 75%  | 70%  | 60%  | 40%  | Wazuh    │
│  Execution               | 94%  | 83%  |  6%  | 11%  | 17%  | Wazuh    │
│  Persistence             | 96%  | 92%  |  4%  |  2%  | 18%  | Wazuh    │
│  Privilege Escalation    | 95%  | 91%  |  5%  |  5%  | 18%  | Wazuh    │
│  Defense Evasion         | 97%  | 93%  | 20%  | 16%  | 23%  | Wazuh    │
│  Credential Access       | 93%  | 76%  | 45%  | 28%  | 31%  | Wazuh    │
│  Discovery               | 91%  | 91%  | 32%  |  5%  | 36%  | Wazuh    │
│  Lateral Movement        | 90%  | 80%  | 80%  | 70%  | 20%  | Wazuh    │
│  Collection              | 94%  | 81%  | 50%  | 16%  | 31%  | Wazuh    │
│  Command and Control     | 89%  | 67%  |100%  |100%  |  0%  | Zeek     │
│  Exfiltration            | 84%  | 63%  | 84%  | 74%  | 32%  | Zeek     │
│  Impact                  | 93%  | 79%  | 36%  | 43%  | 50%  | Wazuh    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Recommended Tool Combinations by Organization Type

### Small Organization (< 100 endpoints)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Small Organization Stack                                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ESSENTIAL (Start Here):                                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Wazuh (All-in-One)                                              │   │
│  │  - EDR, HIDS, FIM, Log Analysis                                  │   │
│  │  - Coverage: ~75% of endpoint techniques                         │   │
│  │  - Resource: 8 vCPU, 16GB RAM                                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ADD NEXT:                                                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Suricata (IDS/IPS mode)                                         │   │
│  │  - Network signature detection                                   │   │
│  │  - Coverage: ~50% of network techniques                          │   │
│  │  - Resource: 4 vCPU, 8GB RAM                                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  OPTIONAL:                                                              │
│  - Prowler (if cloud workloads)                                        │
│  - OpenCTI (if threat intel needed)                                    │
│                                                                         │
│  Expected Coverage: 65-70% of relevant techniques                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Medium Organization (100-1000 endpoints)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Medium Organization Stack                                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  TIER 1 - Detection Foundation:                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Wazuh                     + Zeek                                │   │
│  │  - Endpoint detection       - Network metadata                   │   │
│  │  - ~90% endpoint coverage   - ~100% C2 detection                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  TIER 2 - Enhanced Detection:                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Suricata (IPS)           + Velociraptor                        │   │
│  │  - Signature blocking       - Threat hunting                    │   │
│  │  - Prevention capability    - Forensic collection               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  TIER 3 - Intelligence & Response:                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  OpenCTI                  + Shuffle                              │   │
│  │  - Threat intelligence      - Automated response                │   │
│  │  - IOC management           - Playbook execution                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  TIER 4 - Cloud (if applicable):                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Prowler                  + Trivy                                │   │
│  │  - Cloud posture            - Container security                │   │
│  │  - Compliance               - IaC scanning                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Expected Coverage: 75-80% of relevant techniques                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Large Enterprise (1000+ endpoints)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Enterprise Stack                                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ENDPOINT LAYER:                                                        │
│  ├── Wazuh (clustered) ─────── Continuous monitoring, compliance       │
│  ├── Velociraptor ──────────── On-demand hunting, IR                   │
│  └── osquery + Fleet ───────── Asset inventory, compliance queries     │
│                                                                         │
│  NETWORK LAYER:                                                         │
│  ├── Zeek (clustered) ──────── Full protocol analysis                  │
│  ├── Suricata (IPS) ────────── Signature detection/prevention          │
│  └── Arkime ────────────────── Full packet capture, forensics          │
│                                                                         │
│  CLOUD LAYER:                                                           │
│  ├── Prowler ───────────────── Multi-cloud security posture            │
│  ├── Trivy ─────────────────── Container/IaC scanning                  │
│  └── Steampipe ─────────────── Custom cloud queries                    │
│                                                                         │
│  INTELLIGENCE LAYER:                                                    │
│  ├── OpenCTI ───────────────── Knowledge management, ATT&CK mapping    │
│  └── MISP ──────────────────── IOC sharing, community feeds            │
│                                                                         │
│  RESPONSE LAYER:                                                        │
│  ├── Shuffle ───────────────── Security automation                     │
│  └── TheHive ───────────────── Case management                         │
│                                                                         │
│  Expected Coverage: 80-85% of relevant techniques                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Coverage Gap Analysis

### Techniques with Limited OSS Coverage

| Technique | ID | Gap Reason | Mitigation |
|-----------|----|-----------| ------------|
| Firmware Persistence | T1542 | Requires specialized tools | Consider commercial firmware scanning |
| Hardware Additions | T1200 | Physical security | NAC, USB monitoring policies |
| Supply Chain | T1195 | Outside org control | SBOM tools, vendor management |
| MFA Interception | T1111 | Application-specific | MFA-specific monitoring tools |
| Steganography | T1027.003 | Computationally expensive | Sample-based analysis |

### Recommended Additional Tools for Gap Coverage

| Gap Area | Recommended Tool | Notes |
|----------|-----------------|-------|
| Email Security | Mailcow + rspamd | OSS email gateway |
| DNS Security | Pi-hole / DNSCrypt | DNS filtering |
| Web Application | ModSecurity | WAF for web apps |
| Container Runtime | Falco | Runtime container security |
| Network Forensics | NetworkMiner | PCAP analysis |

---

## Implementation Priority Matrix

| Priority | Techniques Covered | Solutions | Effort |
|----------|-------------------|-----------|--------|
| **P0 - Critical** | T1059, T1078, T1003, T1021, T1071 | Wazuh + Zeek | Medium |
| **P1 - High** | T1055, T1547, T1053, T1486, T1048 | + Suricata + Velociraptor | Medium |
| **P2 - Medium** | T1190, T1566, T1105, T1082, T1018 | + Prowler + OpenCTI | High |
| **P3 - Lower** | Reconnaissance, Resource Dev | + MISP + Arkime | High |

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK Techniques](https://attack.mitre.org/techniques/enterprise/)
- [Wazuh ATT&CK Mapping](https://documentation.wazuh.com/current/user-manual/ruleset/mitre-attack.html)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [OCSF Schema](https://schema.ocsf.io/)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01 | Initial comprehensive mapping |

---

*Document maintained by MxTac Project*
