# MxTac — Data Source Integration Guide

## Overview

MxTac ingests security events from NDR, EDR, SIEM, and cloud sources. This guide covers how to connect each source type.

---

## NDR Sources

### Suricata

Suricata IDS/IPS generates EVE JSON logs. MxTac supports two input modes:

#### Option A: Local File (Suricata on same host)

```
Input Mode: Local File
EVE JSON Path: /var/log/suricata/eve.json
Poll Interval: 10 seconds
```

MxTac reads the EVE JSON file directly and parses alerts, flows, DNS, HTTP, TLS events.

#### Option B: Remote ELK (Suricata logs in Elasticsearch/OpenSearch)

If Suricata logs are already collected by your ELK stack (Filebeat → Logstash → Elasticsearch), MxTac can pull them directly:

```
Input Mode: Remote ELK
Elasticsearch URL: https://elk.company.com:9200
Index Pattern: filebeat-suricata-*
Username: mxtac-reader
Password: ********
```

**Setup on your ELK side:**

1. Create a read-only user for MxTac:
   ```
   POST /_security/user/mxtac-reader
   {
     "password": "secure-password",
     "roles": ["mxtac_reader"]
   }
   
   POST /_security/role/mxtac_reader
   {
     "indices": [
       { "names": ["filebeat-suricata-*"], "privileges": ["read"] }
     ]
   }
   ```

2. Ensure the index pattern matches where Filebeat stores Suricata logs.

3. In MxTac Sources page, select Suricata → Configure → enter your ELK URL, index pattern, and credentials.

MxTac polls the remote index every 60 seconds for new events matching `event.module: suricata`.

---

### Zeek

Zeek produces structured log files (conn.log, dns.log, http.log, etc.).

```
Input Mode: Local Directory
Log Directory: /opt/zeek/logs/current
Poll Interval: 10 seconds
```

MxTac watches the directory for new/rotated log files and parses all standard Zeek log types: conn, dns, http, ssl, ssh, smb, rdp, files.

**For remote Zeek logs via ELK:**

Same as Suricata Option B — point MxTac to your Elasticsearch index where Filebeat stores Zeek logs:

```
Elasticsearch URL: https://elk.company.com:9200
Index Pattern: filebeat-zeek-*
```

---

### MxWatch (Built-in NDR Agent)

MxWatch is MxTac's built-in NDR agent. Deploy it on network tap points:

```bash
# Install
curl -L https://github.com/fankh/mxtac/releases/latest/download/mxwatch -o /usr/local/bin/mxwatch
chmod +x /usr/local/bin/mxwatch

# Configure
cat > /etc/mxwatch/mxwatch.toml << EOF
[agent]
api_endpoint = "https://mxtac.company.com/api/v1/events/ingest"
api_key = "your-api-key"

[capture]
interface = "eth0"
bpf_filter = "not port 22"
EOF

# Run
mxwatch --config /etc/mxwatch/mxwatch.toml
```

MxWatch auto-registers with MxTac and appears on the Sources page as "Connected."

---

## EDR Sources

### Wazuh

```
Wazuh Manager URL: https://wazuh-manager:55000
Username: wazuh-wui
Password: ********
```

MxTac polls the Wazuh API for alerts and agent status.

### Velociraptor

```
Server URL: https://velociraptor:8889
API Key: vr-api-...
```

MxTac connects to Velociraptor's API for artifact results and endpoint data.

### MxGuard (Built-in EDR Agent)

```bash
curl -L https://github.com/fankh/mxtac/releases/latest/download/mxguard -o /usr/local/bin/mxguard
chmod +x /usr/local/bin/mxguard

cat > /etc/mxguard/mxguard.toml << EOF
[agent]
api_endpoint = "https://mxtac.company.com/api/v1/events/ingest"
api_key = "your-api-key"

[collectors.process]
enabled = true

[collectors.file]
enabled = true
watch_paths = ["/etc", "/usr/bin"]

[collectors.auth]
enabled = true
EOF

mxguard --config /etc/mxguard/mxguard.toml
```

---

## SIEM Sources

### Elastic SIEM / OpenSearch

Forward events from an existing Elasticsearch or OpenSearch cluster:

```
Cluster URL: https://elasticsearch:9200
Username: elastic
Password: ********
Index Pattern: .siem-signals-*
```

MxTac reads alerts/signals from the specified index and maps them to MITRE ATT&CK techniques.

---

## Cloud Sources

### AWS CloudTrail

```
S3 Bucket: my-cloudtrail-logs
AWS Region: ap-northeast-2
Access Key ID: AKIA...
Secret Access Key: ********
```

### Prowler (Cloud Security)

```
AWS Region: ap-northeast-2
AWS Profile: default
Scan Interval: 24 hours
```

---

## Generic Webhook Ingest

Any system can send events to MxTac via webhook:

```bash
curl -X POST https://mxtac.company.com/ingest \
  -H "X-MxTac-Source: custom-siem" \
  -H "X-MxTac-Token: webhook-secret" \
  -H "Content-Type: application/json" \
  -d '[{"timestamp": "2026-04-06T12:00:00Z", "alert": "Suspicious login", "src_ip": "1.2.3.4"}]'
```

Events are normalized to OCSF format and processed through the detection pipeline.

---

## API Key Management

Generate API keys for agents and integrations:

```bash
# Via API
curl -X POST https://mxtac.company.com/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label": "mxwatch-prod", "scopes": ["events:write"]}'
```

Or via Settings → Users → API Keys in the MxTac UI.

---

## Port Reference

| Service | Port | Description |
|---------|------|-------------|
| Backend API | 15000 | REST API + event ingest |
| Frontend | 15001 | Web UI |
| PostgreSQL | 15002 | Primary database |
| Valkey (Redis) | 15003 | Cache & queue |
| OpenSearch | 15004 | Log search & analytics |
| Syslog (UDP) | 514 | Syslog receiver (optional) |
