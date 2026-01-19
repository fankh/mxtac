# MxTac - Requirements Specification

> **Version**: 1.0  
> **Last Updated**: 2026-01-12  
> **Status**: Draft

---

## Table of Contents

1. [Introduction](#introduction)
2. [Scope](#scope)
3. [User Personas](#user-personas)
4. [Functional Requirements](#functional-requirements)
5. [Non-Functional Requirements](#non-functional-requirements)
6. [Integration Requirements](#integration-requirements)
7. [Security Requirements](#security-requirements)
8. [Compliance Requirements](#compliance-requirements)
9. [Acceptance Criteria](#acceptance-criteria)

---

## Introduction

### Purpose

This document defines the comprehensive requirements for **MxTac (Matrix + Tactic)**, an open-source security integration platform that provides unified ATT&CK-based threat detection and response by orchestrating best-of-breed open-source security tools.

### Problem Statement

Organizations using open-source security tools face:

| Problem | Impact | Business Cost |
|---------|--------|---------------|
| Fragmented visibility | No unified security posture view | Missed threats |
| No ATT&CK mapping | Cannot measure detection coverage | Unknown gaps |
| Data silos | Each tool has different formats | Manual correlation |
| Rule conversion | Sigma rules need conversion per tool | Engineering time |
| Limited response | No unified orchestration | Slow remediation |

### Solution Overview

MxTac addresses these challenges by providing:

1. **Unified ATT&CK Dashboard** - Single view across all tools
2. **OCSF Data Normalization** - Common schema for all sources
3. **Native Sigma Engine** - Direct rule execution without conversion
4. **Cross-Tool Correlation** - Multi-stage attack detection
5. **Integrated Response** - Orchestrated playbooks

---

## Scope

### In Scope

| Area | Included |
|------|----------|
| Data Sources | Wazuh, Zeek, Suricata, Prowler, OpenCTI, Velociraptor |
| Detection | Sigma rules, correlation rules, ATT&CK mapping |
| Response | Manual actions, automated playbooks, integration triggers |
| Visualization | Dashboards, ATT&CK Navigator, reports |
| Management | Users, roles, connectors, rules, settings |

### Out of Scope

| Area | Excluded | Rationale |
|------|----------|-----------|
| Agent Development | Not building new agents | Use existing (Wazuh, osquery) |
| Network Sensors | Not building sensors | Use existing (Zeek, Suricata) |
| Cloud Scanners | Not building scanners | Use existing (Prowler) |
| SIEM Replacement | Not replacing SIEM | Integration layer on top |

---

## User Personas

### Primary Personas

#### P1: SOC Analyst (Tier 1-2)

| Attribute | Description |
|-----------|-------------|
| **Role** | Alert triage, initial investigation |
| **Goals** | Fast alert processing, reduce noise |
| **Pain Points** | Tool switching, alert fatigue, missing context |
| **Key Features** | Unified queue, enrichment, quick actions |

#### P2: Detection Engineer

| Attribute | Description |
|-----------|-------------|
| **Role** | Create and tune detection rules |
| **Goals** | Coverage improvement, reduce false positives |
| **Pain Points** | Rule conversion, testing difficulty |
| **Key Features** | Native Sigma, rule testing, ATT&CK mapping |

#### P3: Threat Hunter

| Attribute | Description |
|-----------|-------------|
| **Role** | Proactive threat discovery |
| **Goals** | Find unknown threats, validate controls |
| **Pain Points** | Data silos, query limitations |
| **Key Features** | Cross-tool search, entity timeline, ATT&CK hunting |

#### P4: Security Architect

| Attribute | Description |
|-----------|-------------|
| **Role** | Security strategy and coverage planning |
| **Goals** | Identify gaps, optimize tool deployment |
| **Pain Points** | Coverage visibility, tool sprawl |
| **Key Features** | Coverage dashboard, gap analysis, reports |

#### P5: CISO / Security Manager

| Attribute | Description |
|-----------|-------------|
| **Role** | Security program leadership |
| **Goals** | Risk visibility, metrics, compliance |
| **Pain Points** | Reporting burden, ROI justification |
| **Key Features** | Executive dashboards, trend reports |

---

## Functional Requirements

### FR-1: ATT&CK Coverage Dashboard

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-1.1 | Display ATT&CK Navigator heatmap | P0 | Heatmap renders all 14 tactics |
| FR-1.2 | Calculate coverage per tactic/technique | P0 | Accurate percentage calculation |
| FR-1.3 | Show coverage by data source | P0 | Breakdown by tool (Wazuh, Zeek, etc.) |
| FR-1.4 | Drill-down to detection rules | P1 | Click technique → see rules |
| FR-1.5 | Compare coverage over time | P2 | Trend graph available |
| FR-1.6 | Export reports (PDF, JSON, Navigator) | P1 | All formats downloadable |
| FR-1.7 | Set coverage targets | P2 | Target vs actual display |

### FR-2: Data Normalization (OCSF)

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-2.1 | Normalize Wazuh alerts to OCSF | P0 | All Wazuh fields mapped |
| FR-2.2 | Normalize Zeek logs to OCSF | P0 | All Zeek log types mapped |
| FR-2.3 | Normalize Suricata EVE to OCSF | P0 | All EVE event types mapped |
| FR-2.4 | Normalize Prowler findings to OCSF | P1 | Cloud findings normalized |
| FR-2.5 | Normalize osquery results to OCSF | P1 | Query results normalized |
| FR-2.6 | Support custom field mappings | P1 | User-defined mappings work |
| FR-2.7 | Validate against OCSF schema | P2 | Validation errors logged |
| FR-2.8 | Handle schema version upgrades | P2 | Migration path documented |

### FR-3: Sigma Rule Engine

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-3.1 | Execute Sigma rules natively | P0 | No conversion to other formats |
| FR-3.2 | Import from SigmaHQ repository | P0 | Automated sync works |
| FR-3.3 | Support all Sigma modifiers | P0 | contains, startswith, re, etc. |
| FR-3.4 | Support Sigma correlations | P1 | Count, temporal correlations |
| FR-3.5 | Provide rule editor with validation | P1 | Syntax errors highlighted |
| FR-3.6 | Test rules against historical data | P1 | Retroactive testing works |
| FR-3.7 | Track rule performance metrics | P2 | Hit count, FP rate visible |
| FR-3.8 | Auto-map rules to ATT&CK | P1 | Tags parsed correctly |

### FR-4: Integration Connectors

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-4.1 | Wazuh integration | P0 | Alerts, agent data ingested |
| FR-4.2 | Zeek integration | P0 | All log types ingested |
| FR-4.3 | Suricata integration | P0 | EVE JSON ingested |
| FR-4.4 | Prowler integration | P1 | Cloud findings ingested |
| FR-4.5 | OpenCTI integration | P1 | Threat intel available |
| FR-4.6 | Velociraptor integration | P2 | Forensic data available |
| FR-4.7 | Shuffle integration | P2 | Playbooks executable |
| FR-4.8 | Generic webhook/syslog | P1 | Custom sources work |

### FR-5: Correlation Engine

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-5.1 | Correlate by entity (IP, host, user) | P0 | Entity linking works |
| FR-5.2 | Support multiple correlation keys | P0 | Hash, domain, etc. |
| FR-5.3 | Define correlation rules | P1 | Rule builder available |
| FR-5.4 | Detect ATT&CK attack chains | P1 | Technique sequences detected |
| FR-5.5 | Time-window based correlation | P1 | Configurable windows |
| FR-5.6 | Statistical anomaly detection | P2 | Baseline deviation alerts |

### FR-6: Alert Management

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-6.1 | Unified alert queue | P0 | All sources in one view |
| FR-6.2 | Alert enrichment | P1 | Threat intel, context added |
| FR-6.3 | Alert grouping/deduplication | P1 | Similar alerts grouped |
| FR-6.4 | Risk-based scoring | P1 | Score visible, sortable |
| FR-6.5 | Assignment and workflow | P2 | Assign to analyst works |
| FR-6.6 | SLA tracking | P2 | Response time tracked |
| FR-6.7 | Suppression rules | P1 | Known FPs suppressible |

### FR-7: Investigation & Hunting

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-7.1 | Unified search across sources | P0 | Single query, all data |
| FR-7.2 | Entity timeline | P1 | All events for entity |
| FR-7.3 | Pivot from any field | P1 | Click field → related events |
| FR-7.4 | Save and share queries | P1 | Saved queries accessible |
| FR-7.5 | ATT&CK-guided hunting | P2 | Technique-based hunt guides |
| FR-7.6 | Notebook-style investigation | P2 | Markdown + queries |

### FR-8: Response & Automation

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-8.1 | Manual response actions | P1 | Block, isolate, etc. work |
| FR-8.2 | Playbook templates | P1 | Pre-built templates available |
| FR-8.3 | Automated response triggers | P2 | Rule-based automation |
| FR-8.4 | Shuffle SOAR integration | P2 | Playbooks executable |
| FR-8.5 | Response audit logging | P1 | All actions logged |
| FR-8.6 | Approval workflows | P2 | High-impact needs approval |

### FR-9: Reporting & Analytics

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-9.1 | ATT&CK coverage reports | P1 | PDF/JSON export |
| FR-9.2 | Alert volume trends | P1 | Time-series graphs |
| FR-9.3 | MTTR/MTTD metrics | P2 | Metrics calculated |
| FR-9.4 | Analyst productivity | P2 | Per-analyst metrics |
| FR-9.5 | Scheduled delivery | P2 | Email/webhook delivery |
| FR-9.6 | Custom report builder | P3 | Drag-and-drop builder |

---

## Non-Functional Requirements

### NFR-1: Performance

| ID | Requirement | Target | Measurement |
|----|-------------|--------|-------------|
| NFR-1.1 | Event ingestion rate | 50,000 EPS | Sustained 1-hour test |
| NFR-1.2 | Search query response | < 5 seconds | 7-day range, complex query |
| NFR-1.3 | Dashboard load time | < 3 seconds | Cold cache load |
| NFR-1.4 | Alert processing latency | < 30 seconds | Event to UI |
| NFR-1.5 | Sigma rule evaluation | < 100ms/event | 10,000 rules active |
| NFR-1.6 | API response time | < 200ms P95 | Under load |

### NFR-2: Scalability

| ID | Requirement | Target | Notes |
|----|-------------|--------|-------|
| NFR-2.1 | Horizontal scaling | Add nodes without downtime | Zero-downtime scaling |
| NFR-2.2 | Data retention | Configurable (90+ days) | Hot/warm/cold tiers |
| NFR-2.3 | Concurrent users | 100+ analysts | Simultaneous sessions |
| NFR-2.4 | Endpoint scale | 10,000+ endpoints | Per deployment |
| NFR-2.5 | Rule capacity | 10,000+ active rules | Sigma + correlation |

### NFR-3: Availability

| ID | Requirement | Target | Notes |
|----|-------------|--------|-------|
| NFR-3.1 | Uptime | 99.9% | Planned maintenance excluded |
| NFR-3.2 | Failover time | < 60 seconds | Automatic failover |
| NFR-3.3 | Data durability | No data loss | On single node failure |
| NFR-3.4 | Backup restore | < 4 hours | Full system restore |
| NFR-3.5 | Disaster recovery | < 24 hours RTO | Cross-region recovery |

### NFR-4: Usability

| ID | Requirement | Target | Notes |
|----|-------------|--------|-------|
| NFR-4.1 | Initial setup | < 1 hour | Basic deployment |
| NFR-4.2 | Learning curve | Productive in 1 day | With documentation |
| NFR-4.3 | Documentation | Complete coverage | User, admin, API docs |
| NFR-4.4 | Accessibility | WCAG 2.1 AA | Web accessibility |
| NFR-4.5 | Internationalization | i18n ready | Translation framework |

### NFR-5: Maintainability

| ID | Requirement | Target | Notes |
|----|-------------|--------|-------|
| NFR-5.1 | Code coverage | > 80% | Unit + integration tests |
| NFR-5.2 | Documentation | Inline + external | API docs auto-generated |
| NFR-5.3 | Modularity | Pluggable connectors | Easy to add integrations |
| NFR-5.4 | Upgrade path | Non-breaking updates | Semantic versioning |

---

## Integration Requirements

### IR-1: Wazuh Integration

| ID | Requirement | Method | Data |
|----|-------------|--------|------|
| IR-1.1 | Alert ingestion | API pull / Filebeat | Real-time alerts |
| IR-1.2 | Agent inventory | API pull | Agent list, status |
| IR-1.3 | FIM events | API / Filebeat | File integrity data |
| IR-1.4 | SCA results | API pull | Compliance data |
| IR-1.5 | Active response | API push | Block, isolate commands |

### IR-2: Zeek Integration

| ID | Requirement | Method | Data |
|----|-------------|--------|------|
| IR-2.1 | Connection logs | File / Kafka | conn.log |
| IR-2.2 | DNS logs | File / Kafka | dns.log |
| IR-2.3 | HTTP logs | File / Kafka | http.log |
| IR-2.4 | SSL/TLS logs | File / Kafka | ssl.log |
| IR-2.5 | File logs | File / Kafka | files.log |
| IR-2.6 | Notice logs | File / Kafka | notice.log |

### IR-3: Suricata Integration

| ID | Requirement | Method | Data |
|----|-------------|--------|------|
| IR-3.1 | Alert events | EVE JSON / Kafka | IDS alerts |
| IR-3.2 | Flow events | EVE JSON / Kafka | Network flows |
| IR-3.3 | DNS events | EVE JSON / Kafka | DNS queries |
| IR-3.4 | HTTP events | EVE JSON / Kafka | HTTP requests |
| IR-3.5 | TLS events | EVE JSON / Kafka | TLS handshakes |

### IR-4: Prowler Integration

| ID | Requirement | Method | Data |
|----|-------------|--------|------|
| IR-4.1 | AWS findings | Scheduled pull | Security findings |
| IR-4.2 | Azure findings | Scheduled pull | Security findings |
| IR-4.3 | GCP findings | Scheduled pull | Security findings |
| IR-4.4 | K8s findings | Scheduled pull | Security findings |

### IR-5: OpenCTI Integration

| ID | Requirement | Method | Data |
|----|-------------|--------|------|
| IR-5.1 | Indicator feed | GraphQL / TAXII | IOCs |
| IR-5.2 | Threat actors | GraphQL | Actor profiles |
| IR-5.3 | Malware profiles | GraphQL | Malware data |
| IR-5.4 | ATT&CK mappings | GraphQL | Technique data |
| IR-5.5 | Alert enrichment | Real-time lookup | Context addition |

---

## Security Requirements

### SR-1: Authentication

| ID | Requirement | Implementation | Enterprise Compliance |
|----|-------------|----------------|----------------------|
| SR-1.1 | Local authentication | bcrypt password hashing (12 rounds) | ✅ bcrypt > SHA-256 |
| SR-1.2 | SSO - OIDC | Keycloak, Okta, Azure AD | ✅ Enterprise SSO |
| SR-1.3 | SSO - SAML 2.0 | Enterprise IdP support | ✅ Enterprise SSO |
| SR-1.4 | Multi-factor authentication | TOTP, WebAuthn | Future phase |
| SR-1.5 | Session management | JWT with refresh tokens | ✅ 30 min timeout |
| SR-1.6 | Session timeout | **30 minutes** (enterprise requirement) | ✅ Compliant |
| SR-1.7 | **Account lockout** | **5 failed attempts → 30 min lock** | ✅ **NEW** |
| SR-1.8 | **Concurrent session control** | **Single session per user** | ✅ **NEW** |
| SR-1.9 | **Inactive account locking** | **Auto-lock after 90 days** | ✅ **NEW** |

### SR-2: Password Policy

| ID | Requirement | Implementation | Enterprise Compliance |
|----|-------------|----------------|----------------------|
| SR-2.1 | **Password complexity** | **3 char types + 8 chars OR 2 types + 10 chars** | ✅ **NEW** |
| SR-2.2 | **No consecutive chars** | **Max 3 identical consecutive characters** | ✅ **NEW** |
| SR-2.3 | **Password expiration** | **90 days, forced change** | ✅ **NEW** |
| SR-2.4 | **Password history** | **Cannot reuse last 2 passwords** | ✅ **NEW** |
| SR-2.5 | **Initial password change** | **Force change on first login** | ✅ **NEW** |
| SR-2.6 | Password masking | Masked input (type=password) | ✅ Standard |
| SR-2.7 | No default accounts | Prevent admin/root/test usernames | ✅ Validated |

### SR-3: Authorization

| ID | Requirement | Implementation | Enterprise Compliance |
|----|-------------|----------------|----------------------|
| SR-3.1 | Role-based access control | Predefined + custom roles | ✅ Enhanced |
| SR-3.2 | **Granular permissions** | **Per-resource:action permissions** | ✅ **NEW** |
| SR-3.3 | Data-level access control | Team/tenant isolation | ✅ Standard |
| SR-3.4 | API key management | Scoped API keys | ✅ Standard |
| SR-3.5 | **IP whitelisting** | **Admin access from allowed IPs only** | ✅ **NEW** |
| SR-3.6 | **Admin panel isolation** | **Internal network only or 2FA** | ✅ **NEW** |
| SR-3.7 | Least privilege | Role-appropriate permissions only | ✅ RBAC |

### SR-4: Data Protection

| ID | Requirement | Implementation | Enterprise Compliance |
|----|-------------|----------------|----------------------|
| SR-4.1 | Encryption at rest | AES-256 | ✅ Standard |
| SR-4.2 | **Encryption in transit** | **TLS 1.2+ only (disable 1.0/1.1)** | ✅ **UPDATED** |
| SR-4.3 | Secret management | Vault / K8s Secrets | ✅ Standard |
| SR-4.4 | Data masking | PII/sensitive field masking | ✅ Standard |
| SR-4.5 | Secure deletion | Crypto-shred on delete | ✅ Standard |

### SR-5: Audit & Logging

| ID | Requirement | Implementation | Enterprise Compliance |
|----|-------------|----------------|----------------------|
| SR-5.1 | **Authentication logging** | **All login attempts (success/fail)** | ✅ **ENHANCED** |
| SR-5.2 | **User activity logging** | **All user actions logged** | ✅ **NEW** |
| SR-5.3 | **Permission change logging** | **RBAC changes with 3-year retention** | ✅ **NEW** |
| SR-5.4 | Administrative actions | Full admin audit trail | ✅ Standard |
| SR-5.5 | Data access logging | Query audit (optional) | ✅ Standard |
| SR-5.6 | Response action logging | All response actions logged | ✅ Standard |
| SR-5.7 | Log integrity | Tamper-evident logging | ✅ Standard |
| SR-5.8 | **Log retention** | **3 years for compliance logs** | ✅ **NEW** |

### SR-6: Secure Development

| ID | Requirement | Implementation | Enterprise Compliance |
|----|-------------|----------------|----------------------|
| SR-6.1 | Generic login errors | "Invalid credentials" (no user enumeration) | ✅ Implemented |
| SR-6.2 | Input validation | All inputs validated/sanitized | ✅ Standard |
| SR-6.3 | SQL injection prevention | Parameterized queries (SQLAlchemy) | ✅ ORM |
| SR-6.4 | XSS prevention | Content Security Policy + sanitization | ✅ React |
| SR-6.5 | CSRF protection | CSRF tokens on state-changing ops | ✅ FastAPI |

---

## Compliance Requirements

### CR-1: Standards Support

| Standard | Requirement | Implementation |
|----------|-------------|----------------|
| SOC 2 Type II | Audit trail, access control | Built-in capabilities |
| GDPR | Data privacy, right to delete | Data lifecycle management |
| HIPAA | PHI protection | Encryption, access control |
| PCI DSS | Cardholder data protection | Network segmentation support |
| FedRAMP | Government compliance | Hardening guides |

### CR-2: Reporting

| ID | Requirement | Output |
|----|-------------|--------|
| CR-2.1 | Access reports | User access audit |
| CR-2.2 | Configuration reports | System configuration |
| CR-2.3 | Incident reports | Detection/response summary |
| CR-2.4 | Compliance dashboards | Control status |

---

## Acceptance Criteria

### Phase 1: MVP (P0 Requirements)

| Criteria | Metric | Target |
|----------|--------|--------|
| Wazuh integration | Data ingestion | 100% alert coverage |
| Zeek integration | Log types | conn, dns, http, ssl |
| Suricata integration | EVE events | Alerts, flows |
| OCSF normalization | Field mapping | > 90% coverage |
| Sigma engine | Rule execution | 1,000+ rules |
| ATT&CK dashboard | Technique display | All 14 tactics |
| Unified search | Query capability | Cross-source search |
| Alert queue | Alert display | All sources unified |

### Phase 2: Detection Enhancement (P1 Requirements)

| Criteria | Metric | Target |
|----------|--------|--------|
| Prowler integration | Cloud coverage | AWS, Azure, GCP |
| OpenCTI integration | Intel enrichment | IOC matching |
| Correlation engine | Chain detection | 5+ attack patterns |
| Rule testing | Historical search | 7-day retroactive |
| Response actions | Manual actions | 5+ action types |

### Phase 3: Production Ready (P2 Requirements)

| Criteria | Metric | Target |
|----------|--------|--------|
| Velociraptor integration | Forensic capability | Live response |
| Shuffle integration | Playbook execution | 10+ playbooks |
| Statistical anomaly | ML detection | Baseline alerts |
| RBAC | Role management | 5+ roles |
| Reporting | Scheduled reports | Daily/weekly |

---

## Appendix

### A. Glossary

| Term | Definition |
|------|------------|
| ATT&CK | MITRE ATT&CK framework for adversary tactics and techniques |
| OCSF | Open Cybersecurity Schema Framework for data normalization |
| Sigma | Generic signature format for SIEM systems |
| STIX | Structured Threat Information Expression |
| SOAR | Security Orchestration, Automation, and Response |
| EPS | Events Per Second |
| IOC | Indicator of Compromise |

### B. References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [OCSF Schema](https://schema.ocsf.io/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)

---

*Document maintained by MxTac Project*
