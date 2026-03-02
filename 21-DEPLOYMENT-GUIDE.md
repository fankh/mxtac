# MxTac - Deployment Guide

> **Document Type**: Operations Guide
> **Version**: 2.0
> **Last Updated**: 2026-03-01
> **Status**: Active

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Deployment Options](#deployment-options)
4. [Option A: Automated Ubuntu Setup (Recommended)](#option-a-automated-ubuntu-setup-recommended)
5. [Option B: Docker Compose (Single Host)](#option-b-docker-compose-single-host)
6. [Option C: Docker Swarm (Multi-Host HA)](#option-c-docker-swarm-multi-host-ha)
7. [Option D: Kubernetes / K3s](#option-d-kubernetes--k3s)
8. [Option E: Systemd (Bare Metal)](#option-e-systemd-bare-metal)
9. [TLS / HTTPS Setup](#tls--https-setup)
10. [Database Operations](#database-operations)
11. [Upgrading](#upgrading)
12. [Monitoring](#monitoring)
13. [Security Hardening](#security-hardening)
14. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 20 GB SSD | 50+ GB SSD |
| Network | 10 Mbps | 100 Mbps |

### Software Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| Ubuntu | 22.04 / 24.04 LTS | Host OS (other Linux distros work with manual setup) |
| Docker Engine | 24.x+ | Container runtime |
| Docker Compose | V2 (plugin) | Service orchestration |
| Git | 2.x+ | Source management |
| OpenSSL | 3.x+ | Secret generation, TLS certificates |

### Required Secrets

Generate before deployment:

```bash
# JWT signing key (required)
openssl rand -hex 32

# PostgreSQL password (required)
openssl rand -base64 32 | tr -d '=+/' | head -c 32
```

---

## Architecture Overview

```
                  ┌──────────────┐
                  │   Clients    │
                  └──────┬───────┘
                         │ :443 (HTTPS)
                  ┌──────▼───────┐
                  │    Nginx     │  SSL termination, rate limiting
                  └──┬───────┬──┘
                     │       │
          ┌──────────▼──┐ ┌──▼──────────┐
          │  Frontend   │ │   Backend   │  FastAPI (Python 3.12)
          │  (React)    │ │   :8080     │
          └─────────────┘ └──┬──┬──┬────┘
                             │  │  │
              ┌──────────────┘  │  └──────────────┐
              │                 │                  │
       ┌──────▼──────┐  ┌──────▼──────┐  ┌────────▼────────┐
       │ PostgreSQL  │  │   Valkey    │  │   OpenSearch    │
       │   :5432     │  │   :6379    │  │     :9200       │
       └─────────────┘  └────────────┘  └─────────────────┘
       Metadata + Auth   Cache + Queue   Search + Analytics
```

### Service Dependencies

| Service | Required | Depends On |
|---------|----------|------------|
| PostgreSQL 16 | Yes | - |
| Valkey 8 (Redis-compatible) | Yes | - |
| OpenSearch 2.17 | Optional | - |
| Redpanda (Kafka-compatible) | Optional | - |
| Backend (FastAPI) | Yes | PostgreSQL, Valkey |
| Frontend (React) | Yes | - |
| Nginx | Yes | Backend, Frontend |

### Port Map

| Port | Service | Binding | Notes |
|------|---------|---------|-------|
| 80 | Nginx | `0.0.0.0` | HTTP (redirects to HTTPS) |
| 443 | Nginx | `0.0.0.0` | HTTPS (public) |
| 8080 | Backend | `127.0.0.1` | Internal only |
| 3000 | Frontend | `127.0.0.1` | Internal only |
| 5432 | PostgreSQL | `127.0.0.1` | Internal only |
| 6379 | Valkey | `127.0.0.1` | Internal only |
| 9200 | OpenSearch | `127.0.0.1` | Internal only |

---

## Deployment Options

| Option | Best For | Scaling | Complexity |
|--------|----------|---------|------------|
| **A. Automated Setup** | First-time deployment on Ubuntu | Single host | Low |
| **B. Docker Compose** | Small teams, single server | Single host | Low |
| **C. Docker Swarm** | Multi-node HA, rolling updates | Horizontal | Medium |
| **D. Kubernetes / K3s** | Enterprise, auto-scaling | Horizontal | High |
| **E. Systemd** | Bare metal, no containers | Single host | Medium |

---

## Option A: Automated Ubuntu Setup (Recommended)

The fastest path to a production deployment on Ubuntu.

### What It Does

1. Installs system packages and configures UFW firewall
2. Installs Docker Engine + Compose V2
3. Tunes kernel parameters (OpenSearch mmap requirement)
4. Generates secrets and writes `.env`
5. Deploys all services via Docker Compose
6. Waits for health checks to pass
7. Runs Alembic database migrations
8. Prints access URLs

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/fankh/mxtac.git
cd mxtac

# 2. Run the setup script
sudo bash app/setup.sh
```

The script is **idempotent** — safe to re-run on failures.

### What Gets Created

| Path | Contents |
|------|----------|
| `/opt/mxtac/` | Deployed application |
| `/opt/mxtac/.env` | Generated secrets (chmod 600) |
| `/opt/mxtac/docker-compose.yml` | Production compose file |
| `/opt/mxtac/nginx/` | Nginx config + SSL certificates |

### Post-Install

```bash
# Verify all services are healthy
cd /opt/mxtac && docker compose ps

# Enable HTTPS with Let's Encrypt (requires domain pointing to server)
sudo bash /opt/mxtac/enable-https.sh your-domain.com

# View logs
docker compose -f /opt/mxtac/docker-compose.yml logs -f
```

---

## Option B: Docker Compose (Single Host)

Manual deployment using `docker-compose.prod.yml`.

### 1. Configure Environment

```bash
cd mxtac/app

# Create .env file
cat > .env <<EOF
SECRET_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d '=+/' | head -c 32)
DOMAIN=mxtac.example.com
EOF

chmod 600 .env
```

### 2. Prepare SSL Certificates

```bash
mkdir -p nginx/ssl

# Self-signed (for testing)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/CN=mxtac.example.com"

# Or use Let's Encrypt (see TLS section below)
```

### 3. Build and Start

```bash
# Build images and start services
docker compose -f docker-compose.prod.yml up -d --build

# Wait for services to be healthy
docker compose -f docker-compose.prod.yml ps

# Run database migrations
docker compose -f docker-compose.prod.yml exec backend \
  sh -c "cd /app && alembic upgrade head"
```

### 4. Verify

```bash
# Health check
curl -sf http://localhost:8080/ready

# Service status
docker compose -f docker-compose.prod.yml ps
```

### Resource Limits (docker-compose.prod.yml)

| Service | CPU Limit | Memory Limit |
|---------|-----------|-------------|
| Backend | 2.0 | 1 GB |
| Frontend | 0.5 | 256 MB |
| Nginx | 0.5 | 128 MB |
| PostgreSQL | 2.0 | 2 GB |
| Valkey | 0.5 | 512 MB |

---

## Option C: Docker Swarm (Multi-Host HA)

High availability with rolling updates and horizontal scaling.

### 1. Initialize Swarm

```bash
# On the manager node
docker swarm init --advertise-addr <MANAGER_IP>

# Join worker nodes (use the token from swarm init output)
docker swarm join --token <TOKEN> <MANAGER_IP>:2377
```

### 2. Label Nodes

Stateful services are pinned to specific nodes:

```bash
# Identify node IDs
docker node ls

# Assign roles
docker node update --label-add mxtac.db=true    <db-node-id>
docker node update --label-add mxtac.redis=true  <redis-node-id>
docker node update --label-add mxtac.proxy=true  <proxy-node-id>
```

### 3. Create Secrets and Configs

```bash
# Secrets (stored encrypted in Raft log)
echo "$(openssl rand -hex 32)" | docker secret create mxtac_secret_key -
echo "$(openssl rand -base64 32 | tr -d '=+/')" | docker secret create mxtac_postgres_password -

# Nginx config
docker config create nginx_swarm_conf ./app/nginx/nginx.swarm.conf
```

### 4. Prepare SSL Certificates

Place certificates on the proxy node:

```bash
# On the node labeled mxtac.proxy=true
sudo mkdir -p /etc/mxtac/ssl
sudo cp fullchain.pem /etc/mxtac/ssl/cert.pem
sudo cp privkey.pem   /etc/mxtac/ssl/key.pem
sudo chmod 600 /etc/mxtac/ssl/key.pem
```

### 5. Build and Push Images

```bash
# Build
docker build -t mxtac/backend:latest  ./app/backend/
docker build -t mxtac/frontend:latest ./app/frontend/ -f ./app/frontend/Dockerfile.prod

# Push to your registry
docker tag mxtac/backend:latest  registry.example.com/mxtac/backend:latest
docker push registry.example.com/mxtac/backend:latest
docker tag mxtac/frontend:latest registry.example.com/mxtac/frontend:latest
docker push registry.example.com/mxtac/frontend:latest
```

### 6. Deploy Stack

```bash
# Set environment variables
export DOMAIN=mxtac.example.com
export IMAGE_PREFIX=registry.example.com/mxtac
export VERSION=latest

# Deploy
docker stack deploy -c app/docker-stack.yml --with-registry-auth mxtac
```

### 7. Verify

```bash
# Service status
docker stack services mxtac

# Service logs
docker service logs mxtac_backend --follow

# Scale stateless services
docker service scale mxtac_backend=4 mxtac_frontend=3
```

### Swarm Architecture

| Service | Replicas | Scaling | Update Strategy |
|---------|----------|---------|-----------------|
| Backend | 2 | Horizontal | start-first (zero-downtime) |
| Frontend | 2 | Horizontal | start-first (zero-downtime) |
| Proxy | 1 | Fixed | stop-first |
| PostgreSQL | 1 | Fixed (pinned) | stop-first |
| Valkey | 1 | Fixed (pinned) | stop-first |

---

## Option D: Kubernetes / K3s

Full Kubernetes deployment with autoscaling, network policies, and pod disruption budgets.

### 1. Install K3s

```bash
curl -sfL https://get.k3s.io | sh -
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

### 2. Deploy Manifests

```bash
cd app/deploy/k3s

# Create namespace
kubectl apply -f namespace.yaml

# Create secrets (edit secrets.yaml with base64-encoded values first)
kubectl apply -f secrets.yaml

# Deploy all resources via Kustomize
kubectl apply -k .

# Or apply individually
kubectl apply -f configmap.yaml
kubectl apply -f serviceaccount.yaml
kubectl apply -f postgres-statefulset.yaml
kubectl apply -f valkey-statefulset.yaml
kubectl apply -f opensearch-statefulset.yaml
kubectl apply -f backend-deployment.yaml
kubectl apply -f backend-service.yaml
kubectl apply -f frontend-deployment.yaml
kubectl apply -f ingress.yaml
kubectl apply -f networkpolicy.yaml
kubectl apply -f pdb.yaml
kubectl apply -f hpa.yaml
```

### 3. Verify

```bash
kubectl get pods -n mxtac
kubectl get services -n mxtac
kubectl get ingress -n mxtac
```

### K3s Features

- **HPA**: Horizontal Pod Autoscaler for backend/frontend
- **PDB**: Pod Disruption Budgets for availability during maintenance
- **NetworkPolicy**: Restrict pod-to-pod communication
- **SecurityContext**: Non-root containers, read-only filesystem, dropped capabilities
- **InitContainer**: Runs Alembic migrations before backend starts

---

## Option E: Systemd (Bare Metal)

Run MxTac directly on a Linux host without containers.

### 1. Install Dependencies

```bash
# Python 3.12+
sudo apt install python3.12 python3.12-venv

# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install nodejs

# PostgreSQL 16
sudo apt install postgresql-16

# Valkey
sudo apt install valkey-server
```

### 2. Set Up Backend

```bash
cd app/backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with production values
```

### 3. Build Frontend

```bash
cd app/frontend
npm ci
npm run build
# Static files in dist/
```

### 4. Install Systemd Service

```bash
# Copy service file
sudo cp app/deploy/systemd/mxtac.service /etc/systemd/system/

# Copy environment file
sudo cp app/deploy/systemd/mxtac.env.example /etc/mxtac/mxtac.env
# Edit /etc/mxtac/mxtac.env with production values

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now mxtac
sudo systemctl status mxtac
```

### Systemd Security Hardening

The service unit file includes:

- `ProtectSystem=strict` — Read-only `/usr`, `/boot`, `/etc`
- `ProtectHome=true` — No access to home directories
- `PrivateTmp=true` — Isolated `/tmp`
- `NoNewPrivileges=true` — Prevents privilege escalation
- `SystemCallFilter=@system-service` — Restricted syscalls

---

## TLS / HTTPS Setup

### Let's Encrypt (Production)

Requires a domain name pointing to the server (A record).

```bash
# Using the provided script
sudo bash app/enable-https.sh your-domain.com
```

This script:
1. Installs certbot
2. Obtains a certificate via HTTP-01 challenge
3. Copies certificates to `nginx/ssl/`
4. Updates `nginx.conf` with the domain
5. Sets up a cron job for auto-renewal (daily at 03:00)

### Manual Certificate Installation

```bash
# Copy your certificates
cp fullchain.pem /opt/mxtac/nginx/ssl/server.crt
cp privkey.pem   /opt/mxtac/nginx/ssl/server.key
chmod 600 /opt/mxtac/nginx/ssl/server.key

# Reload Nginx
docker compose exec nginx nginx -s reload
```

### Certificate Renewal (Cron)

The auto-renewal cron entry installed by `enable-https.sh`:

```
0 3 * * * root certbot renew --quiet --deploy-hook "..."
```

---

## Database Operations

### Backup

```bash
# Manual backup
./scripts/backup-db.sh

# With custom options
./scripts/backup-db.sh --dir /var/backups/mxtac --host db.example.com

# Inside Docker
docker compose exec backend sh -c "cd /app && alembic current"
```

**Retention policy** (applied automatically after each backup):

| Window | Kept |
|--------|------|
| Daily | 7 most recent |
| Weekly | 1 per week, 4 weeks |
| Monthly | 1 per month, 3 months |

**Automated backups** (cron):

```bash
# Add to /etc/cron.d/mxtac-backup
0 2 * * * mxtac /opt/mxtac/scripts/backup-db.sh >> /var/log/mxtac-backup.log 2>&1
```

### Restore

```bash
# Restore from backup (DESTRUCTIVE — drops and recreates the database)
./scripts/restore-db.sh backups/mxtac_backup_2026-03-01_02-00.sql.gz

# Non-interactive (skip confirmation)
./scripts/restore-db.sh --yes backups/mxtac_backup_2026-03-01_02-00.sql.gz
```

### Migrations

```bash
# Run pending migrations
docker compose exec backend sh -c "cd /app && alembic upgrade head"

# Check current migration version
docker compose exec backend sh -c "cd /app && alembic current"

# View migration history
docker compose exec backend sh -c "cd /app && alembic history --verbose"
```

---

## Upgrading

### Single Host (Docker Compose)

```bash
# Using the update script
sudo bash /opt/mxtac/update.sh
```

The `update.sh` script performs:
1. Syncs updated source files (preserves `.env`)
2. Rebuilds Docker images
3. Rolling restart: backend, then frontend
4. Runs Alembic migrations
5. Reloads Nginx

### Manual Upgrade

```bash
cd /opt/mxtac

# Pull latest code
git pull origin main

# Rebuild and restart
docker compose build --quiet
docker compose up -d --no-deps --build backend
docker compose up -d --no-deps --build frontend

# Run migrations
docker compose exec backend sh -c "cd /app && alembic upgrade head"

# Reload Nginx config
docker compose exec nginx nginx -s reload
```

### Docker Swarm Rolling Update

```bash
# Update images
docker service update --image mxtac/backend:2.0.1 mxtac_backend
docker service update --image mxtac/frontend:2.0.1 mxtac_frontend

# Monitor rollout
docker service ps mxtac_backend
```

Swarm uses `start-first` update order for backend/frontend — the new replica starts and passes health checks before the old one is removed (zero downtime).

---

## Monitoring

### Health Endpoints

| Endpoint | Purpose | Expected |
|----------|---------|----------|
| `GET /health` | Basic liveness | `200 OK` |
| `GET /ready` | Readiness (DB + cache connected) | `200 OK` |

### Prometheus + Grafana (Optional)

Enable the monitoring profile in development:

```bash
docker compose --profile monitoring up -d
```

Or deploy from the monitoring configs:

```bash
# Prometheus config
app/deploy/monitoring/prometheus.yml

# Grafana dashboards
app/deploy/monitoring/grafana/
```

| Service | URL | Default Port |
|---------|-----|------|
| Prometheus | `http://localhost:9090` | 9090 |
| Grafana | `http://localhost:3001` | 3001 |

The backend automatically exposes Prometheus metrics via `prometheus-fastapi-instrumentator`.

### Log Inspection

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f backend

# Last 100 lines
docker compose logs --tail 100 backend

# Nginx access logs (inside container)
docker compose exec nginx tail -f /var/log/nginx/access.log
```

---

## Security Hardening

### Pre-Deployment Checklist

- [ ] Generate a unique `SECRET_KEY` (not the development default)
- [ ] Set `DEBUG=false`
- [ ] Use a strong `POSTGRES_PASSWORD`
- [ ] Configure `CORS_ORIGINS` for your domain only
- [ ] Set up TLS certificates (not self-signed in production)
- [ ] Configure UFW firewall (ports 22, 80, 443 only)

### Network Security

All internal services bind to `127.0.0.1` — not accessible from external networks:

```yaml
ports:
  - "127.0.0.1:5432:5432"   # PostgreSQL
  - "127.0.0.1:6379:6379"   # Valkey
  - "127.0.0.1:9200:9200"   # OpenSearch
  - "127.0.0.1:8080:8080"   # Backend API
```

Only Nginx exposes ports publicly (`0.0.0.0:80`, `0.0.0.0:443`).

### Nginx Security Headers

Applied automatically by the Nginx config:

| Header | Value |
|--------|-------|
| X-Frame-Options | SAMEORIGIN |
| X-Content-Type-Options | nosniff |
| X-XSS-Protection | 1; mode=block |
| Strict-Transport-Security | max-age=31536000; includeSubDomains |
| Referrer-Policy | strict-origin-when-cross-origin |

### Rate Limiting

| Zone | Limit | Burst |
|------|-------|-------|
| API (`/api/`) | 30 req/min per IP | 50 |
| Login (`/api/v1/auth/login`) | 5 req/min per IP | 10 |

### Startup Security Checks

The backend performs automatic security warnings at startup:

- `DEBUG=true` in production
- Default database credentials (`mxtac:mxtac`)
- Empty OpenSearch password with a remote host

---

## Troubleshooting

### Service Won't Start

```bash
# Check service logs
docker compose logs <service-name>

# Check health status
docker compose ps

# Restart a specific service
docker compose restart <service-name>
```

### OpenSearch Fails to Start

OpenSearch requires a higher `vm.max_map_count`:

```bash
# Check current value
sysctl vm.max_map_count

# Set it (temporary)
sudo sysctl -w vm.max_map_count=262144

# Set it (permanent)
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-mxtac.conf
sudo sysctl --system
```

### Database Connection Refused

```bash
# Verify PostgreSQL is running and healthy
docker compose ps postgres
docker compose logs postgres

# Test connectivity from backend container
docker compose exec backend sh -c "python -c \"import asyncpg; print('asyncpg OK')\""

# Check if migrations are current
docker compose exec backend sh -c "cd /app && alembic current"
```

### Backend Returns 500 Errors

```bash
# Check backend logs for tracebacks
docker compose logs --tail 200 backend | grep -A 5 "ERROR\|Traceback"

# Verify environment
docker compose exec backend env | grep -E "SECRET_KEY|DATABASE_URL|VALKEY_URL"

# Test health endpoint
curl -v http://localhost:8080/health
```

### Port Already in Use

```bash
# Find what's using the port
ss -tlnp sport = :8080

# Kill the process or change the port in docker-compose.yml
```

### Disk Space Issues

```bash
# Check Docker disk usage
docker system df

# Clean up unused images and volumes
docker system prune --volumes
```

---

## Environment Variable Reference

See [ENV-REFERENCE.md](ENV-REFERENCE.md) for the complete list of all environment variables across components.

### Key Production Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | JWT signing key — `openssl rand -hex 32` |
| `DATABASE_URL` | Yes | PostgreSQL async DSN |
| `VALKEY_URL` | Yes | Valkey/Redis connection URL |
| `QUEUE_BACKEND` | No | `memory` (dev), `redis` (prod), `kafka` (advanced) |
| `CORS_ORIGINS` | No | JSON array of allowed origins |
| `DEBUG` | No | Must be `false` in production |
| `DOMAIN` | No | Used for CORS and SSL configuration |

---

## Quick Reference

### File Locations

| File | Purpose |
|------|---------|
| `app/setup.sh` | Automated Ubuntu deployment |
| `app/update.sh` | Zero-downtime upgrade script |
| `app/enable-https.sh` | Let's Encrypt certificate setup |
| `app/docker-compose.yml` | Development compose |
| `app/docker-compose.prod.yml` | Single-host production compose |
| `app/docker-stack.yml` | Docker Swarm stack manifest |
| `app/nginx/nginx.conf` | Nginx reverse proxy config |
| `app/deploy/k3s/` | Kubernetes manifests |
| `app/deploy/systemd/` | Systemd service unit |
| `app/deploy/monitoring/` | Prometheus + Grafana configs |
| `scripts/backup-db.sh` | PostgreSQL backup with retention |
| `scripts/restore-db.sh` | PostgreSQL restore |
| `ENV-REFERENCE.md` | All environment variables |

### Common Commands

```bash
# Start (development)
cd app && docker compose up -d

# Start (production)
cd app && docker compose -f docker-compose.prod.yml up -d

# Stop
docker compose down

# View logs
docker compose logs -f

# Run migrations
docker compose exec backend sh -c "cd /app && alembic upgrade head"

# Backup database
./scripts/backup-db.sh

# Restore database
./scripts/restore-db.sh backups/<file>.sql.gz

# Check service health
curl http://localhost:8080/ready
```
