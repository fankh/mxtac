#!/usr/bin/env bash
# =============================================================================
# MxTac — Automated Server Setup
# Target: Ubuntu 22.04 / 24.04 LTS
# Usage:  sudo bash setup.sh
#
# What this script does (idempotent — safe to re-run):
#   1. System prerequisites + UFW firewall
#   2. Docker Engine + Compose V2
#   3. sysctl tuning (OpenSearch requirement)
#   4. Generate secrets (.env)
#   5. Deploy full stack via docker compose
#   6. Wait for health checks
#   7. Run Alembic migrations
#   8. Print access URLs
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[MxTac]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN] ${NC} $*"; }
err()  { echo -e "${RED}[ERR]  ${NC} $*" >&2; }
step() { echo -e "\n${BOLD}${BLUE}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "Run as root:  sudo bash setup.sh"
  exit 1
fi

# ── Config ────────────────────────────────────────────────────────────────────
DEPLOY_DIR="/opt/mxtac"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"   # directory where setup.sh lives
ENV_FILE="${DEPLOY_DIR}/.env"
COMPOSE_FILE="${DEPLOY_DIR}/docker-compose.yml"

# ── Detect OS ─────────────────────────────────────────────────────────────────
if [[ ! -f /etc/os-release ]]; then
  err "Cannot detect OS. Ubuntu 22.04 or 24.04 required."
  exit 1
fi
. /etc/os-release
log "Detected OS: ${NAME} ${VERSION_ID} (${VERSION_CODENAME})"
if [[ "$ID" != "ubuntu" ]]; then
  warn "This script is tested on Ubuntu. Proceeding anyway..."
fi

# =============================================================================
# STEP 1 — System prerequisites + UFW
# =============================================================================
step "Step 1 — System packages + Firewall"

apt-get update -qq
apt-get install -y -qq \
  curl ca-certificates gnupg lsb-release \
  openssl ufw git jq

# UFW — only SSH, HTTP, HTTPS publicly exposed
log "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment 'SSH'
ufw allow 80/tcp   comment 'HTTP  (Nginx)'
ufw allow 443/tcp  comment 'HTTPS (Nginx)'
ufw --force enable
log "UFW enabled. Open ports: 22, 80, 443"

# Prevent Docker from bypassing UFW (critical for public IPs)
# Docker adds iptables rules that bypass UFW by default.
# We bind all internal service ports to 127.0.0.1 in docker-compose.yml
# to mitigate this — no extra config needed beyond correct port binding.

# =============================================================================
# STEP 2 — Docker Engine + Compose V2
# =============================================================================
step "Step 2 — Docker Engine + Compose V2"

if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
  log "Docker already installed: $(docker --version)"
  log "Compose: $(docker compose version)"
else
  log "Installing Docker Engine..."

  # Remove legacy packages
  apt-get remove -y -qq docker.io docker-compose containerd runc 2>/dev/null || true

  # Add Docker official repo
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    ${VERSION_CODENAME} stable" \
    | tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt-get update -qq
  apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

  systemctl enable --now docker
  log "Docker installed: $(docker --version)"
  log "Compose: $(docker compose version)"
fi

# =============================================================================
# STEP 3 — Kernel tuning (required for OpenSearch)
# =============================================================================
step "Step 3 — Kernel / sysctl tuning"

# OpenSearch uses mmap extensively — will refuse to start without this
if ! grep -q "vm.max_map_count=262144" /etc/sysctl.d/99-mxtac.conf 2>/dev/null; then
  log "Setting vm.max_map_count=262144..."
  cat > /etc/sysctl.d/99-mxtac.conf <<'EOF'
# Required by OpenSearch (Lucene mmap)
vm.max_map_count=262144
# Improve network throughput
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
EOF
  sysctl --system -q
  log "Kernel parameters applied"
else
  log "sysctl already configured"
fi

# =============================================================================
# STEP 4 — Generate secrets + write .env
# =============================================================================
step "Step 4 — Secrets + configuration"

mkdir -p "${DEPLOY_DIR}"
chmod 750 "${DEPLOY_DIR}"

if [[ -f "${ENV_FILE}" ]]; then
  log ".env already exists — loading existing secrets"
  set -a; source "${ENV_FILE}"; set +a
else
  log "Generating secrets..."

  DB_PASSWORD=$(openssl rand -base64 32 | tr -d '=+/' | head -c 32)
  SECRET_KEY=$(openssl rand -base64 64 | tr -d '=+/' | head -c 64)
  OPENSEARCH_ADMIN_PASSWORD="Admin@$(openssl rand -hex 6)1Aa!"

  cat > "${ENV_FILE}" <<EOF
# MxTac environment — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# DO NOT commit this file to version control

# ── Application ───────────────────────────────────────────────────────────────
APP_ENV=production
SECRET_KEY=${SECRET_KEY}
DEBUG=false

# ── Database ──────────────────────────────────────────────────────────────────
POSTGRES_USER=mxtac
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=mxtac
DATABASE_URL=postgresql+asyncpg://mxtac:${DB_PASSWORD}@postgres:5432/mxtac

# ── Valkey (Redis-compatible, BSD license) ────────────────────────────────────
VALKEY_URL=redis://valkey:6379/0

# ── Queue ─────────────────────────────────────────────────────────────────────
QUEUE_BACKEND=redis
KAFKA_BOOTSTRAP_SERVERS=redpanda:9092

# ── OpenSearch ────────────────────────────────────────────────────────────────
OPENSEARCH_HOST=opensearch
OPENSEARCH_PORT=9200
OPENSEARCH_INITIAL_ADMIN_PASSWORD=${OPENSEARCH_ADMIN_PASSWORD}

# ── CORS ─────────────────────────────────────────────────────────────────────
CORS_ORIGINS=["http://localhost","http://115.90.24.199"]
EOF

  chmod 600 "${ENV_FILE}"
  log ".env written to ${ENV_FILE}"
  set -a; source "${ENV_FILE}"; set +a
fi

# =============================================================================
# STEP 5 — Copy project files + write docker-compose.yml
# =============================================================================
step "Step 5 — Deploy project files"

# Copy app source to deploy dir
log "Syncing project to ${DEPLOY_DIR}..."
rsync -a --exclude='.venv' --exclude='node_modules' --exclude='__pycache__' \
  --exclude='.git' --exclude='*.pyc' \
  "${REPO_DIR}/" "${DEPLOY_DIR}/"

# Write the production docker-compose.yml
cat > "${DEPLOY_DIR}/docker-compose.yml" <<'COMPOSE'
version: '3.9'

# ── Internal network (no external exposure) ───────────────────────────────────
networks:
  mxtac_net:
    driver: bridge

services:

  # ── PostgreSQL 16 ────────────────────────────────────────────────────────────
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "127.0.0.1:5432:5432"   # localhost only — not exposed to Internet
    networks: [mxtac_net]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s

  # ── Valkey 8 (Redis-compatible, BSD license) ──────────────────────────────────
  valkey:
    image: valkey/valkey:8-alpine
    restart: unless-stopped
    command: >
      valkey-server
      --save 60 1
      --loglevel notice
      --maxmemory 512mb
      --maxmemory-policy allkeys-lru
    volumes:
      - valkey_data:/data
    ports:
      - "127.0.0.1:6379:6379"   # localhost only
    networks: [mxtac_net]
    healthcheck:
      test: ["CMD", "valkey-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  # ── OpenSearch 2 (single-node, security disabled) ────────────────────────────
  opensearch:
    image: opensearchproject/opensearch:2.17.0
    restart: unless-stopped
    environment:
      - cluster.name=mxtac-cluster
      - node.name=mxtac-node-1
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx1g
      - DISABLE_SECURITY_PLUGIN=true
      - DISABLE_INSTALL_DEMO_CONFIG=true
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - opensearch_data:/usr/share/opensearch/data
    ports:
      - "127.0.0.1:9200:9200"   # localhost only
    networks: [mxtac_net]
    healthcheck:
      test: >
        ["CMD-SHELL",
         "curl -sf http://localhost:9200/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"]
      interval: 15s
      timeout: 10s
      retries: 12
      start_period: 60s

  # ── Redpanda (Kafka-compatible, single broker) ────────────────────────────────
  redpanda:
    image: redpandadata/redpanda:v24.3.1
    restart: unless-stopped
    command:
      - redpanda
      - start
      - --overprovisioned
      - --smp=1
      - --memory=512M
      - --reserve-memory=0M
      - --node-id=0
      - --check=false
      - --kafka-addr=INTERNAL://0.0.0.0:9092,EXTERNAL://0.0.0.0:19092
      - --advertise-kafka-addr=INTERNAL://redpanda:9092,EXTERNAL://127.0.0.1:19092
    volumes:
      - redpanda_data:/var/lib/redpanda/data
    ports:
      - "127.0.0.1:9092:9092"    # Kafka API — localhost only
      - "127.0.0.1:19092:19092"  # External Kafka — localhost only
      - "127.0.0.1:9644:9644"    # Admin HTTP — localhost only
    networks: [mxtac_net]
    healthcheck:
      test: ["CMD-SHELL", "rpk cluster health | grep -q 'Healthy: true' || exit 1"]
      interval: 15s
      timeout: 10s
      retries: 10
      start_period: 30s

  # ── FastAPI Backend ───────────────────────────────────────────────────────────
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    restart: unless-stopped
    env_file: .env
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - VALKEY_URL=${VALKEY_URL}
      - QUEUE_BACKEND=${QUEUE_BACKEND}
      - SECRET_KEY=${SECRET_KEY}
      - DEBUG=false
    ports:
      - "127.0.0.1:8080:8080"   # Only Nginx reaches this
    networks: [mxtac_net]
    depends_on:
      postgres:
        condition: service_healthy
      valkey:
        condition: service_healthy
      opensearch:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 20s

  # ── React Frontend (Nginx serves static files) ────────────────────────────────
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.prod
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:80"     # Only Nginx proxies here
    networks: [mxtac_net]
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:80/"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ── Nginx Reverse Proxy (public-facing) ──────────────────────────────────────
  nginx:
    image: nginx:1.27-alpine
    restart: unless-stopped
    ports:
      - "0.0.0.0:80:80"         # Public HTTP
      - "0.0.0.0:443:443"       # Public HTTPS (TLS termination)
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - nginx_logs:/var/log/nginx
    networks: [mxtac_net]
    depends_on:
      backend:
        condition: service_healthy
      frontend:
        condition: service_healthy

volumes:
  postgres_data:
  valkey_data:
  opensearch_data:
  redpanda_data:
  nginx_logs:
COMPOSE

log "docker-compose.yml written"

# =============================================================================
# STEP 6 — Nginx config
# =============================================================================
step "Step 6 — Nginx configuration"

mkdir -p "${DEPLOY_DIR}/nginx/ssl"

cat > "${DEPLOY_DIR}/nginx/nginx.conf" <<'NGINX'
worker_processes auto;
error_log /var/log/nginx/error.log warn;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # ── Logging ──────────────────────────────────────────────────────────────
    log_format main '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
    access_log /var/log/nginx/access.log main;

    # ── Performance ──────────────────────────────────────────────────────────
    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout 65;
    gzip on;
    gzip_types text/plain text/css application/json application/javascript
               text/xml application/xml text/javascript;

    # ── Rate limiting ─────────────────────────────────────────────────────────
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # ── Security headers ──────────────────────────────────────────────────────
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # ── HTTP → HTTPS redirect ─────────────────────────────────────────────────
    server {
        listen 80;
        server_name _;

        # ACME challenge passthrough (for Let's Encrypt)
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }

        # All other traffic: redirect to HTTPS
        location / {
            return 301 https://$host$request_uri;
        }
    }

    # ── Main HTTPS server ─────────────────────────────────────────────────────
    server {
        listen 443 ssl;
        server_name _;

        # SSL — self-signed for initial deploy; replace with Let's Encrypt
        ssl_certificate     /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # ── API proxy ─────────────────────────────────────────────────────────
        location /api/ {
            limit_req zone=api burst=50 nodelay;
            proxy_pass         http://backend:8080;
            proxy_http_version 1.1;
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
            proxy_read_timeout 60s;
        }

        # ── WebSocket proxy ───────────────────────────────────────────────────
        location /api/v1/ws/ {
            proxy_pass         http://backend:8080;
            proxy_http_version 1.1;
            proxy_set_header   Upgrade    $http_upgrade;
            proxy_set_header   Connection "upgrade";
            proxy_set_header   Host       $host;
            proxy_read_timeout 3600s;
        }

        # ── Auth rate limit ───────────────────────────────────────────────────
        location /api/v1/auth/login {
            limit_req zone=login burst=10 nodelay;
            proxy_pass http://backend:8080;
        }

        # ── Frontend SPA ──────────────────────────────────────────────────────
        location / {
            proxy_pass         http://frontend:80;
            proxy_set_header   Host $host;
            # SPA fallback handled by frontend Nginx
        }
    }
}
NGINX

# Generate self-signed certificate (replace with Let's Encrypt in production)
SSL_DIR="${DEPLOY_DIR}/nginx/ssl"
if [[ ! -f "${SSL_DIR}/server.crt" ]]; then
  log "Generating self-signed TLS certificate..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${SSL_DIR}/server.key" \
    -out    "${SSL_DIR}/server.crt" \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=MxTac/CN=115.90.24.199" \
    -addext "subjectAltName=IP:115.90.24.199" \
    2>/dev/null
  chmod 600 "${SSL_DIR}/server.key"
  log "Self-signed certificate created. Replace with Let's Encrypt for production."
else
  log "TLS certificate already exists"
fi

# =============================================================================
# STEP 7 — Build + start all services
# =============================================================================
step "Step 7 — Docker Compose up"

cd "${DEPLOY_DIR}"

log "Pulling base images..."
docker compose pull --quiet postgres valkey opensearch redpanda nginx 2>/dev/null || true

log "Building application images..."
docker compose build --quiet

log "Starting all services..."
docker compose up -d

# =============================================================================
# STEP 8 — Wait for health checks
# =============================================================================
step "Step 8 — Waiting for services to be healthy"

wait_healthy() {
  local service="$1"
  local max_wait="${2:-120}"
  local elapsed=0
  local interval=5

  printf "  Waiting for %-20s " "${service}..."
  while [[ $elapsed -lt $max_wait ]]; do
    status=$(docker compose ps --format json "${service}" 2>/dev/null \
      | jq -r '.Health // .Status' 2>/dev/null || echo "")
    if [[ "$status" == "healthy" ]]; then
      echo -e "${GREEN}healthy${NC} (${elapsed}s)"
      return 0
    fi
    sleep $interval
    elapsed=$((elapsed + interval))
    printf "."
  done
  echo -e "${YELLOW}timeout${NC} (${elapsed}s) — check: docker compose logs ${service}"
  return 1
}

wait_healthy "postgres"    60
wait_healthy "valkey"      30
wait_healthy "opensearch"  180   # JVM startup takes time
wait_healthy "redpanda"    90
wait_healthy "backend"     60
wait_healthy "frontend"    30

# =============================================================================
# STEP 9 — Run database migrations
# =============================================================================
step "Step 9 — Database migrations (Alembic)"

log "Running Alembic migrations..."
docker compose exec -T backend \
  sh -c "cd /app && alembic upgrade head" \
  && log "Migrations complete" \
  || warn "Migration failed — check: docker compose logs backend"

# =============================================================================
# STEP 10 — Health verification
# =============================================================================
step "Step 10 — Final health check"

echo ""
echo -e "${BOLD}Service Status:${NC}"
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo -e "${BOLD}Endpoint Checks:${NC}"

check_url() {
  local label="$1"
  local url="$2"
  if curl -sf --max-time 5 "${url}" >/dev/null 2>&1; then
    echo -e "  ${GREEN}[OK]${NC}   ${label}"
  else
    echo -e "  ${YELLOW}[WARN]${NC} ${label} — ${url}"
  fi
}

check_url "Backend /health"      "http://localhost:8080/health"
check_url "OpenSearch cluster"   "http://localhost:9200/_cluster/health"
check_url "Nginx HTTP"           "http://localhost:80/"
check_url "Nginx HTTPS"          "https://localhost:443/" --insecure 2>/dev/null || \
  check_url "Nginx HTTPS"        "https://115.90.24.199/" --insecure 2>/dev/null

# Port binding check — internal services must NOT be on 0.0.0.0
echo ""
echo -e "${BOLD}Port Security Check (internal services must bind to 127.0.0.1):${NC}"
for port in 5432 6379 9200 9092; do
  binding=$(ss -tlnp "sport = :${port}" 2>/dev/null | awk 'NR>1{print $4}' | head -1)
  if [[ "$binding" == "127.0.0.1:${port}" ]]; then
    echo -e "  ${GREEN}[OK]${NC}   :${port} → 127.0.0.1 only"
  elif [[ -n "$binding" ]]; then
    echo -e "  ${RED}[RISK]${NC} :${port} → ${binding} (check docker-compose ports)"
  else
    echo -e "  ${YELLOW}[-]${NC}   :${port} not listening yet"
  fi
done

# =============================================================================
# Done!
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}  MxTac deployed successfully!${NC}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}  https://115.90.24.199/"
echo -e "  ${BOLD}API docs:${NC}   https://115.90.24.199/api/docs"
echo -e "  ${BOLD}Health:${NC}     https://115.90.24.199/api/health"
echo ""
echo -e "  ${BOLD}Secrets:${NC}    ${ENV_FILE}"
echo -e "  ${BOLD}Logs:${NC}       docker compose -f ${COMPOSE_FILE} logs -f"
echo -e "  ${BOLD}Restart:${NC}    docker compose -f ${COMPOSE_FILE} restart"
echo -e "  ${BOLD}Update:${NC}     bash ${DEPLOY_DIR}/update.sh"
echo ""
echo -e "  ${YELLOW}Note:${NC} TLS uses a self-signed certificate."
echo -e "        Run ${BOLD}bash ${DEPLOY_DIR}/enable-https.sh${NC} to get a Let's Encrypt cert."
echo ""
