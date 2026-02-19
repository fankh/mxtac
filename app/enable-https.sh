#!/usr/bin/env bash
# =============================================================================
# MxTac — Enable HTTPS with Let's Encrypt (Certbot)
# Usage: sudo bash enable-https.sh <your-domain.com>
#
# Prerequisites:
#   - Domain must point to 115.90.24.199
#   - Port 80 must be open (used for ACME challenge)
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${GREEN}[https]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

DOMAIN="${1:-}"
DEPLOY_DIR="/opt/mxtac"

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash enable-https.sh <domain>"
[[ -z "$DOMAIN" ]] && err "Usage: sudo bash enable-https.sh <your-domain.com>"

# Install certbot
if ! command -v certbot &>/dev/null; then
  log "Installing certbot..."
  apt-get install -y -qq certbot
fi

# Get certificate (standalone mode — temporarily stops nginx)
log "Obtaining Let's Encrypt certificate for ${DOMAIN}..."
cd "${DEPLOY_DIR}"

docker compose stop nginx

certbot certonly --standalone \
  --non-interactive \
  --agree-tos \
  --register-unsafely-without-email \
  -d "${DOMAIN}" \
  --preferred-challenges http

# Update Nginx config to use real cert
SSL_DIR="${DEPLOY_DIR}/nginx/ssl"
cp /etc/letsencrypt/live/"${DOMAIN}"/fullchain.pem "${SSL_DIR}/server.crt"
cp /etc/letsencrypt/live/"${DOMAIN}"/privkey.pem   "${SSL_DIR}/server.key"
chmod 600 "${SSL_DIR}/server.key"

# Update nginx.conf server_name
sed -i "s/server_name _;/server_name ${DOMAIN};/" \
  "${DEPLOY_DIR}/nginx/nginx.conf"

# Add Strict-Transport-Security (already in template)
docker compose start nginx
docker compose exec -T nginx nginx -s reload

# Auto-renewal via cron
log "Setting up auto-renewal..."
cat > /etc/cron.d/mxtac-certbot <<CRON
0 3 * * * root certbot renew --quiet --deploy-hook \
  "cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${SSL_DIR}/server.crt && \
   cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${SSL_DIR}/server.key && \
   docker compose -f ${DEPLOY_DIR}/docker-compose.yml exec -T nginx nginx -s reload"
CRON

log "HTTPS enabled for https://${DOMAIN}/"
log "Certificate auto-renews daily at 03:00."
