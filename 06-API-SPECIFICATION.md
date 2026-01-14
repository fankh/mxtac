# MxTac - API Specification

> **Version**: 1.0  
> **Last Updated**: 2026-01-12  
> **Status**: Draft  
> **OpenAPI**: 3.1.0

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Common Patterns](#common-patterns)
4. [API Endpoints](#api-endpoints)
5. [WebSocket API](#websocket-api)
6. [Error Handling](#error-handling)
7. [Rate Limiting](#rate-limiting)
8. [SDKs & Examples](#sdks--examples)

---

## Overview

### Base URL

```
Production: https://api.mxtac.example.com/api/v1
Development: http://localhost:8080/api/v1
```

### API Versioning

| Version | Status | Sunset Date |
|---------|--------|-------------|
| v1 | Current | - |
| v2 | Planned | - |

### Content Types

| Content-Type | Usage |
|--------------|-------|
| `application/json` | Default for all requests/responses |
| `text/event-stream` | Server-Sent Events (real-time) |
| `application/octet-stream` | File downloads |

### Common Headers

```http
# Request Headers
Authorization: Bearer <jwt_token>
Content-Type: application/json
Accept: application/json
X-Request-ID: <uuid>  # Optional, for tracing

# Response Headers
X-Request-ID: <uuid>
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1704067200
```

---

## Authentication

### Authentication Methods

| Method | Use Case | Header |
|--------|----------|--------|
| JWT Bearer | Web application | `Authorization: Bearer <token>` |
| API Key | Automation, scripts | `X-API-Key: <key>` |

### JWT Authentication

#### Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "analyst@example.com",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

#### Refresh Token

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

#### SSO (OIDC)

```http
GET /api/v1/auth/sso/oidc?provider=keycloak
# Redirects to IdP
# Callback: /api/v1/auth/sso/callback
```

### API Key Authentication

```http
GET /api/v1/alerts
X-API-Key: mxtac_ak_1234567890abcdef
```

#### Create API Key

```http
POST /api/v1/auth/api-keys
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "name": "CI/CD Integration",
  "scopes": ["alerts:read", "events:read"],
  "expires_at": "2027-01-01T00:00:00Z"
}
```

**Response:**
```json
{
  "id": "ak_123456",
  "key": "mxtac_ak_1234567890abcdef",
  "name": "CI/CD Integration",
  "scopes": ["alerts:read", "events:read"],
  "created_at": "2026-01-12T10:00:00Z",
  "expires_at": "2027-01-01T00:00:00Z"
}
```

---

## Common Patterns

### Pagination

All list endpoints support cursor-based pagination:

```http
GET /api/v1/alerts?limit=50&cursor=eyJpZCI6MTIzfQ
```

**Response:**
```json
{
  "data": [...],
  "pagination": {
    "limit": 50,
    "has_more": true,
    "next_cursor": "eyJpZCI6MTczfQ",
    "prev_cursor": "eyJpZCI6MTIzfQ"
  }
}
```

### Filtering

Common filter parameters:

| Parameter | Type | Example |
|-----------|------|---------|
| `filter[field]` | String | `filter[severity]=high` |
| `filter[field][op]` | String | `filter[created_at][gte]=2026-01-01` |

**Operators:**
- `eq` - Equal (default)
- `neq` - Not equal
- `gt`, `gte` - Greater than (or equal)
- `lt`, `lte` - Less than (or equal)
- `in` - In array
- `contains` - String contains

### Sorting

```http
GET /api/v1/alerts?sort=-created_at,severity
```

- Prefix `-` for descending order
- Comma-separated for multiple fields

### Field Selection

```http
GET /api/v1/alerts?fields=id,title,severity,created_at
```

### Time Ranges

```http
GET /api/v1/events?time_range=last_24h
GET /api/v1/events?start_time=2026-01-11T00:00:00Z&end_time=2026-01-12T00:00:00Z
```

**Preset ranges:**
- `last_15m`, `last_1h`, `last_4h`, `last_24h`
- `last_7d`, `last_30d`, `last_90d`
- `today`, `yesterday`, `this_week`, `this_month`

---

## API Endpoints

### Alerts API

#### List Alerts

```http
GET /api/v1/alerts
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | `new`, `acknowledged`, `in_progress`, `resolved`, `closed` |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `technique` | string | ATT&CK technique ID (e.g., `T1059.001`) |
| `source` | string | Data source (`wazuh`, `zeek`, `suricata`) |
| `assignee` | string | User ID or `unassigned` |
| `time_range` | string | Time range preset |

**Response:**
```json
{
  "data": [
    {
      "id": "alert_abc123",
      "title": "Mimikatz Detection - Credential Dumping",
      "description": "Potential credential dumping activity detected",
      "severity": "critical",
      "severity_id": 5,
      "status": "new",
      "source": "wazuh",
      "technique": {
        "id": "T1003.001",
        "name": "LSASS Memory",
        "tactic": "Credential Access"
      },
      "entities": {
        "host": "workstation-01",
        "user": "admin",
        "ip": "192.168.1.50"
      },
      "risk_score": 95,
      "created_at": "2026-01-12T10:30:00Z",
      "updated_at": "2026-01-12T10:30:00Z"
    }
  ],
  "pagination": {
    "limit": 50,
    "has_more": true,
    "next_cursor": "eyJpZCI6ImFsZXJ0X2RlZjQ1NiJ9"
  }
}
```

#### Get Alert Details

```http
GET /api/v1/alerts/{alert_id}
```

**Response:**
```json
{
  "id": "alert_abc123",
  "title": "Mimikatz Detection - Credential Dumping",
  "description": "Potential credential dumping activity detected",
  "severity": "critical",
  "status": "new",
  "source": "wazuh",
  "rule": {
    "id": "rule_xyz789",
    "name": "Mimikatz Credential Dumping",
    "type": "sigma"
  },
  "technique": {
    "id": "T1003.001",
    "name": "LSASS Memory",
    "tactic": "Credential Access",
    "url": "https://attack.mitre.org/techniques/T1003/001/"
  },
  "entities": {
    "host": "workstation-01",
    "user": "admin",
    "ip": "192.168.1.50",
    "process": "powershell.exe"
  },
  "raw_event": {
    "class_uid": 1007,
    "class_name": "Process Activity",
    "process": {
      "cmd_line": "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('...')\"",
      "file": {
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      }
    }
  },
  "enrichment": {
    "threat_intel": {
      "matched_iocs": ["hash:abc123"],
      "threat_actor": "APT29"
    },
    "asset": {
      "criticality": "high",
      "owner": "IT Department"
    }
  },
  "timeline": [
    {
      "action": "created",
      "timestamp": "2026-01-12T10:30:00Z"
    }
  ],
  "related_alerts": ["alert_def456", "alert_ghi789"],
  "created_at": "2026-01-12T10:30:00Z"
}
```

#### Update Alert

```http
PATCH /api/v1/alerts/{alert_id}
Content-Type: application/json

{
  "status": "in_progress",
  "assignee_id": "user_123",
  "notes": "Investigating, appears to be legitimate admin activity"
}
```

#### Bulk Update Alerts

```http
POST /api/v1/alerts/bulk
Content-Type: application/json

{
  "alert_ids": ["alert_abc123", "alert_def456"],
  "action": "acknowledge",
  "assignee_id": "user_123"
}
```

---

### Events API

#### Search Events

```http
POST /api/v1/events/search
Content-Type: application/json

{
  "query": "process.cmd_line:*mimikatz* OR process.cmd_line:*sekurlsa*",
  "time_range": {
    "start": "2026-01-11T00:00:00Z",
    "end": "2026-01-12T00:00:00Z"
  },
  "filters": [
    {
      "field": "class_uid",
      "operator": "eq",
      "value": 1007
    }
  ],
  "sort": [
    {"field": "time", "order": "desc"}
  ],
  "limit": 100
}
```

**Response:**
```json
{
  "data": [
    {
      "id": "event_xyz123",
      "time": "2026-01-12T10:29:55Z",
      "class_uid": 1007,
      "class_name": "Process Activity",
      "severity_id": 3,
      "src_endpoint": {
        "hostname": "workstation-01",
        "ip": "192.168.1.50"
      },
      "process": {
        "pid": 1234,
        "cmd_line": "powershell.exe -ep bypass ...",
        "file": {
          "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "hashes": {
            "sha256": "abc123..."
          }
        }
      },
      "actor": {
        "user": {
          "name": "admin"
        }
      }
    }
  ],
  "aggregations": {},
  "total": 1,
  "took_ms": 45
}
```

#### Get Event by ID

```http
GET /api/v1/events/{event_id}
```

#### Aggregate Events

```http
POST /api/v1/events/aggregate
Content-Type: application/json

{
  "time_range": "last_24h",
  "aggregations": [
    {
      "name": "by_severity",
      "type": "terms",
      "field": "severity_id"
    },
    {
      "name": "over_time",
      "type": "date_histogram",
      "field": "time",
      "interval": "1h"
    }
  ]
}
```

---

### Rules API

#### List Rules

```http
GET /api/v1/rules
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | `sigma`, `correlation` |
| `enabled` | boolean | Filter by enabled status |
| `technique` | string | ATT&CK technique ID |
| `source` | string | `sigmahq`, `custom`, `imported` |

**Response:**
```json
{
  "data": [
    {
      "id": "rule_xyz789",
      "name": "Mimikatz Credential Dumping",
      "type": "sigma",
      "description": "Detects Mimikatz credential dumping activity",
      "severity": "critical",
      "enabled": true,
      "source": "sigmahq",
      "techniques": ["T1003.001"],
      "tags": ["attack.credential_access", "attack.t1003.001"],
      "hit_count": 5,
      "last_hit": "2026-01-12T10:30:00Z",
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "pagination": {...}
}
```

#### Get Rule Details

```http
GET /api/v1/rules/{rule_id}
```

**Response:**
```json
{
  "id": "rule_xyz789",
  "name": "Mimikatz Credential Dumping",
  "type": "sigma",
  "content": "title: Mimikatz Credential Dumping\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - 'sekurlsa'\n      - 'lsadump'\n  condition: selection",
  "parsed": {
    "title": "Mimikatz Credential Dumping",
    "logsource": {
      "category": "process_creation",
      "product": "windows"
    },
    "detection": {...}
  },
  "ocsf_mapping": {
    "class_uid": 1007,
    "field_mappings": {
      "CommandLine": "process.cmd_line"
    }
  },
  "techniques": [
    {
      "id": "T1003.001",
      "name": "LSASS Memory",
      "tactic": "Credential Access"
    }
  ],
  "performance": {
    "hit_count": 5,
    "false_positive_rate": 0.02,
    "avg_evaluation_ms": 2.5
  },
  "enabled": true,
  "created_at": "2026-01-01T00:00:00Z"
}
```

#### Create Rule

```http
POST /api/v1/rules
Content-Type: application/json

{
  "name": "Custom PowerShell Detection",
  "type": "sigma",
  "content": "title: Custom PowerShell Detection\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains: '-enc'\n  condition: selection",
  "enabled": false,
  "tags": ["custom", "powershell"]
}
```

#### Test Rule

```http
POST /api/v1/rules/{rule_id}/test
Content-Type: application/json

{
  "time_range": "last_7d",
  "limit": 100
}
```

**Response:**
```json
{
  "matches": [
    {
      "event_id": "event_abc123",
      "time": "2026-01-10T15:30:00Z",
      "matched_fields": {
        "process.cmd_line": "powershell.exe -enc JABjAGwAaQBl..."
      }
    }
  ],
  "total_matches": 3,
  "scanned_events": 150000,
  "took_ms": 2500
}
```

#### Sync SigmaHQ Rules

```http
POST /api/v1/rules/sync
Content-Type: application/json

{
  "source": "sigmahq",
  "categories": ["process_creation", "network_connection"],
  "products": ["windows", "linux"]
}
```

---

### Coverage API

#### Get ATT&CK Coverage

```http
GET /api/v1/coverage
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `version` | string | ATT&CK version (default: latest) |
| `source` | string | Filter by data source |

**Response:**
```json
{
  "version": "14.1",
  "overall_coverage": 0.72,
  "by_tactic": [
    {
      "tactic_id": "TA0001",
      "tactic_name": "Initial Access",
      "coverage": 0.85,
      "techniques_covered": 8,
      "techniques_total": 10
    },
    {
      "tactic_id": "TA0002",
      "tactic_name": "Execution",
      "coverage": 0.90,
      "techniques_covered": 12,
      "techniques_total": 14
    }
  ],
  "by_source": {
    "wazuh": 0.45,
    "zeek": 0.15,
    "suricata": 0.12
  },
  "gaps": [
    {
      "technique_id": "T1055",
      "technique_name": "Process Injection",
      "tactic": "Defense Evasion",
      "coverage": 0,
      "recommendation": "Enable Sysmon or EDR for process injection detection"
    }
  ]
}
```

#### Get Coverage Gaps

```http
GET /api/v1/coverage/gaps
```

**Response:**
```json
{
  "gaps": [
    {
      "technique_id": "T1055",
      "technique_name": "Process Injection",
      "tactic": "Defense Evasion",
      "priority": "high",
      "data_sources_needed": ["Process: OS API Execution"],
      "recommendations": [
        "Enable Sysmon EventID 8 (CreateRemoteThread)",
        "Deploy EDR with process hollowing detection"
      ]
    }
  ],
  "total_gaps": 45
}
```

#### Export Navigator Layer

```http
GET /api/v1/coverage/navigator
Accept: application/json
```

**Response:** ATT&CK Navigator layer JSON

---

### Connectors API

#### List Connectors

```http
GET /api/v1/connectors
```

**Response:**
```json
{
  "data": [
    {
      "id": "conn_wazuh_01",
      "name": "Production Wazuh",
      "type": "wazuh",
      "status": "connected",
      "last_sync": "2026-01-12T10:00:00Z",
      "events_ingested": 1500000,
      "health": {
        "status": "healthy",
        "latency_ms": 45
      }
    }
  ]
}
```

#### Create Connector

```http
POST /api/v1/connectors
Content-Type: application/json

{
  "name": "Production Wazuh",
  "type": "wazuh",
  "config": {
    "host": "wazuh.example.com",
    "port": 55000,
    "username": "api_user",
    "password": "secure_password",
    "verify_ssl": true
  }
}
```

#### Test Connector

```http
POST /api/v1/connectors/{connector_id}/test
```

**Response:**
```json
{
  "success": true,
  "latency_ms": 45,
  "version": "4.7.0",
  "agents_count": 500,
  "message": "Connection successful"
}
```

---

### Response API

#### List Available Actions

```http
GET /api/v1/response/actions
```

**Response:**
```json
{
  "data": [
    {
      "id": "action_block_ip",
      "name": "Block IP Address",
      "type": "network",
      "targets": ["firewall", "wazuh"],
      "parameters": [
        {
          "name": "ip_address",
          "type": "string",
          "required": true
        },
        {
          "name": "duration",
          "type": "integer",
          "required": false,
          "default": 3600
        }
      ],
      "requires_approval": false
    },
    {
      "id": "action_isolate_host",
      "name": "Isolate Host",
      "type": "endpoint",
      "targets": ["wazuh"],
      "parameters": [
        {
          "name": "agent_id",
          "type": "string",
          "required": true
        }
      ],
      "requires_approval": true
    }
  ]
}
```

#### Execute Action

```http
POST /api/v1/response/execute
Content-Type: application/json

{
  "action_id": "action_block_ip",
  "target": "firewall",
  "parameters": {
    "ip_address": "203.0.113.50",
    "duration": 7200
  },
  "alert_id": "alert_abc123",
  "reason": "Blocking C2 IP from alert investigation"
}
```

**Response:**
```json
{
  "execution_id": "exec_xyz789",
  "status": "completed",
  "action": "block_ip",
  "target": "firewall",
  "result": {
    "success": true,
    "message": "IP 203.0.113.50 blocked for 7200 seconds"
  },
  "executed_by": "user_123",
  "executed_at": "2026-01-12T10:35:00Z"
}
```

---

### Users API

#### List Users

```http
GET /api/v1/users
```

#### Create User

```http
POST /api/v1/users
Content-Type: application/json

{
  "email": "newuser@example.com",
  "name": "New User",
  "role_id": "role_analyst",
  "send_invite": true
}
```

#### Update User

```http
PATCH /api/v1/users/{user_id}
Content-Type: application/json

{
  "role_id": "role_hunter",
  "enabled": true
}
```

---

## WebSocket API

### Real-Time Alerts

```javascript
// Connect to WebSocket
const ws = new WebSocket('wss://api.mxtac.example.com/ws/v1/alerts');

// Authenticate
ws.send(JSON.stringify({
  type: 'auth',
  token: 'eyJhbGciOiJSUzI1NiIs...'
}));

// Subscribe to alerts
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'alerts',
  filters: {
    severity: ['critical', 'high']
  }
}));

// Receive alerts
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('New alert:', data);
};
```

### Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `auth` | Client → Server | Authentication |
| `subscribe` | Client → Server | Subscribe to channel |
| `unsubscribe` | Client → Server | Unsubscribe from channel |
| `alert` | Server → Client | New alert notification |
| `alert_update` | Server → Client | Alert status change |
| `ping` | Both | Keepalive |

---

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": [
      {
        "field": "severity",
        "message": "Must be one of: critical, high, medium, low, info"
      }
    ],
    "request_id": "req_abc123"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Invalid request parameters |
| `CONFLICT` | 409 | Resource conflict |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Rate Limiting

### Limits

| Tier | Requests/Minute | Burst |
|------|-----------------|-------|
| Default | 60 | 100 |
| Authenticated | 1000 | 2000 |
| API Key | 5000 | 10000 |

### Rate Limit Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1704067200
```

### Rate Limit Response

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60

{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded. Retry after 60 seconds."
  }
}
```

---

## SDKs & Examples

### Python SDK

```python
from mxtac import MxTacClient

# Initialize client
client = MxTacClient(
    base_url="https://api.mxtac.example.com",
    api_key="mxtac_ak_1234567890"
)

# List alerts
alerts = client.alerts.list(
    severity="critical",
    status="new",
    time_range="last_24h"
)

for alert in alerts:
    print(f"{alert.title} - {alert.severity}")

# Search events
events = client.events.search(
    query="process.cmd_line:*mimikatz*",
    time_range="last_7d"
)

# Get coverage
coverage = client.coverage.get()
print(f"Overall coverage: {coverage.overall_coverage * 100}%")
```

### JavaScript/TypeScript SDK

```typescript
import { MxTacClient } from '@mxtac/sdk';

const client = new MxTacClient({
  baseUrl: 'https://api.mxtac.example.com',
  apiKey: 'mxtac_ak_1234567890'
});

// List alerts
const alerts = await client.alerts.list({
  severity: 'critical',
  status: 'new',
  timeRange: 'last_24h'
});

// Subscribe to real-time alerts
client.alerts.subscribe({
  severity: ['critical', 'high'],
  onAlert: (alert) => {
    console.log('New alert:', alert.title);
  }
});
```

### cURL Examples

```bash
# List alerts
curl -X GET "https://api.mxtac.example.com/api/v1/alerts?severity=critical" \
  -H "Authorization: Bearer $TOKEN"

# Search events
curl -X POST "https://api.mxtac.example.com/api/v1/events/search" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "process.cmd_line:*mimikatz*",
    "time_range": "last_7d"
  }'

# Execute response action
curl -X POST "https://api.mxtac.example.com/api/v1/response/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action_id": "action_block_ip",
    "target": "firewall",
    "parameters": {"ip_address": "203.0.113.50"}
  }'
```

---

## Appendix

### A. OCSF Event Classes

| Class UID | Class Name | Description |
|-----------|------------|-------------|
| 1001 | File Activity | File operations |
| 1007 | Process Activity | Process events |
| 2001 | Security Finding | Detection alerts |
| 3002 | Authentication | Auth events |
| 4001 | Network Activity | Network connections |

### B. Webhook Payloads

```json
{
  "event_type": "alert.created",
  "timestamp": "2026-01-12T10:30:00Z",
  "data": {
    "alert": {
      "id": "alert_abc123",
      "title": "Mimikatz Detection",
      "severity": "critical"
    }
  }
}
```

---

*Document maintained by MxTac Project*
