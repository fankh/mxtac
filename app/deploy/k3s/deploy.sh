#!/usr/bin/env bash
# deploy.sh — MxTac k3s deployment helper
#
# Usage:
#   ./deploy.sh bootstrap   — first-time: create secrets + apply all manifests
#   ./deploy.sh apply        — apply / update all manifests (idempotent)
#   ./deploy.sh status       — show rollout status for all workloads
#   ./deploy.sh rollback     — roll back backend and frontend deployments
#   ./deploy.sh destroy      — delete all MxTac resources (preserves PVCs by default)
#   ./deploy.sh images       — build and load images into k3s containerd
#
# Requirements:
#   k3s or kubectl configured with a valid kubeconfig
#   docker (for building images)
#   openssl (for secret generation)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="mxtac"
DOMAIN="${MXTAC_DOMAIN:-mxtac.local}"
KUBE="${KUBECTL:-kubectl}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*" >&2; }
die()     { echo "[ERROR] $*" >&2; exit 1; }

require_cmd() { command -v "$1" &>/dev/null || die "'$1' is required but not found in PATH"; }

wait_for_rollout() {
  local resource="$1"
  info "Waiting for rollout: $resource ..."
  $KUBE rollout status "$resource" -n "$NAMESPACE" --timeout=300s
}

# ---------------------------------------------------------------------------
# bootstrap — create namespace, secrets, then apply manifests
# ---------------------------------------------------------------------------
cmd_bootstrap() {
  require_cmd openssl

  info "Creating namespace $NAMESPACE (if not exists) ..."
  $KUBE apply -f "$SCRIPT_DIR/namespace.yaml"

  # ---- Secrets -----------------------------------------------------------
  if $KUBE get secret mxtac-secrets -n "$NAMESPACE" &>/dev/null; then
    warn "Secret 'mxtac-secrets' already exists — skipping generation."
    warn "To regenerate, run: kubectl delete secret mxtac-secrets -n $NAMESPACE"
  else
    info "Generating mxtac-secrets ..."
    local postgres_pass secret_key db_url
    postgres_pass="$(openssl rand -hex 32)"
    secret_key="$(openssl rand -hex 64)"
    db_url="postgresql+asyncpg://mxtac:${postgres_pass}@mxtac-postgres-0.mxtac-postgres.${NAMESPACE}.svc.cluster.local:5432/mxtac"

    $KUBE create secret generic mxtac-secrets \
      --namespace "$NAMESPACE" \
      --from-literal="postgres-password=${postgres_pass}" \
      --from-literal="secret-key=${secret_key}" \
      --from-literal="database-url=${db_url}"

    success "Secret 'mxtac-secrets' created."
    info  "Postgres password: ${postgres_pass}"
    info  "(Store these values securely — they will not be shown again)"
  fi

  # ---- TLS secret --------------------------------------------------------
  if $KUBE get secret mxtac-tls -n "$NAMESPACE" &>/dev/null; then
    warn "Secret 'mxtac-tls' already exists — skipping certificate generation."
  else
    info "Generating self-signed TLS certificate for ${DOMAIN} ..."
    local tls_dir
    tls_dir="$(mktemp -d)"
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
      -keyout "${tls_dir}/tls.key" \
      -out    "${tls_dir}/tls.crt" \
      -subj   "/CN=${DOMAIN}/O=MxTac" \
      -addext "subjectAltName=DNS:${DOMAIN}" \
      2>/dev/null

    $KUBE create secret tls mxtac-tls \
      --namespace "$NAMESPACE" \
      --cert="${tls_dir}/tls.crt" \
      --key="${tls_dir}/tls.key"
    rm -rf "${tls_dir}"
    success "TLS secret 'mxtac-tls' created (self-signed, valid 365 days)."
    warn "For production, replace with a cert-manager Certificate or valid cert."
  fi

  # ---- Apply manifests ---------------------------------------------------
  cmd_apply

  info "Running Alembic migrations ..."
  # Wait for at least one backend pod to be ready before migrating
  $KUBE wait pod \
    -l "app.kubernetes.io/name=backend" \
    -n "$NAMESPACE" \
    --for=condition=Ready \
    --timeout=120s
  $KUBE exec -n "$NAMESPACE" \
    "$(${KUBE} get pod -n ${NAMESPACE} -l app.kubernetes.io/name=backend -o name | head -1)" \
    -- alembic upgrade head

  success "Bootstrap complete. Access MxTac at https://${DOMAIN}"
}

# ---------------------------------------------------------------------------
# apply — idempotent apply of all manifests (secrets excluded)
# ---------------------------------------------------------------------------
cmd_apply() {
  info "Applying MxTac k3s manifests ..."

  # Apply via kustomize if available, otherwise plain kubectl apply
  if command -v kustomize &>/dev/null; then
    kustomize build "$SCRIPT_DIR" | $KUBE apply -f -
  else
    $KUBE apply -f "$SCRIPT_DIR/namespace.yaml"
    $KUBE apply -f "$SCRIPT_DIR/serviceaccount.yaml"
    $KUBE apply -f "$SCRIPT_DIR/configmap.yaml"
    $KUBE apply -f "$SCRIPT_DIR/postgres-statefulset.yaml"
    $KUBE apply -f "$SCRIPT_DIR/valkey-statefulset.yaml"
    $KUBE apply -f "$SCRIPT_DIR/opensearch-statefulset.yaml"
    $KUBE apply -f "$SCRIPT_DIR/backend-deployment.yaml"
    $KUBE apply -f "$SCRIPT_DIR/backend-service.yaml"
    $KUBE apply -f "$SCRIPT_DIR/frontend-deployment.yaml"
    $KUBE apply -f "$SCRIPT_DIR/ingress.yaml"
    $KUBE apply -f "$SCRIPT_DIR/hpa.yaml"
    $KUBE apply -f "$SCRIPT_DIR/pdb.yaml"
    $KUBE apply -f "$SCRIPT_DIR/networkpolicy.yaml"
  fi

  success "Manifests applied."
}

# ---------------------------------------------------------------------------
# status — show rollout status for all workloads
# ---------------------------------------------------------------------------
cmd_status() {
  info "=== Pods ==="
  $KUBE get pods -n "$NAMESPACE" -o wide

  info "=== Deployments ==="
  $KUBE get deployments -n "$NAMESPACE"

  info "=== StatefulSets ==="
  $KUBE get statefulsets -n "$NAMESPACE"

  info "=== HPA ==="
  $KUBE get hpa -n "$NAMESPACE"

  info "=== Ingress ==="
  $KUBE get ingress -n "$NAMESPACE"

  info "=== PVCs ==="
  $KUBE get pvc -n "$NAMESPACE"
}

# ---------------------------------------------------------------------------
# rollback — undo the last rollout for backend and frontend
# ---------------------------------------------------------------------------
cmd_rollback() {
  warn "Rolling back backend ..."
  $KUBE rollout undo deployment/mxtac-backend -n "$NAMESPACE"
  warn "Rolling back frontend ..."
  $KUBE rollout undo deployment/mxtac-frontend -n "$NAMESPACE"
  wait_for_rollout deployment/mxtac-backend
  wait_for_rollout deployment/mxtac-frontend
  success "Rollback complete."
}

# ---------------------------------------------------------------------------
# destroy — remove all MxTac resources (PVCs preserved by default)
# ---------------------------------------------------------------------------
cmd_destroy() {
  local delete_pvcs="${1:-no}"
  warn "Destroying all MxTac resources in namespace $NAMESPACE ..."
  read -r -p "Type 'yes' to confirm: " confirm
  [[ "$confirm" == "yes" ]] || { info "Aborted."; exit 0; }

  $KUBE delete namespace "$NAMESPACE" --ignore-not-found

  if [[ "$delete_pvcs" == "--with-pvcs" ]]; then
    warn "Deleting PVCs ..."
    $KUBE delete pvc -l "app.kubernetes.io/part-of=mxtac" --all-namespaces --ignore-not-found
  else
    info "PVCs preserved. To delete them: kubectl delete pvc -n $NAMESPACE --all"
  fi

  success "MxTac resources removed."
}

# ---------------------------------------------------------------------------
# images — build Docker images and import into k3s containerd
# ---------------------------------------------------------------------------
cmd_images() {
  require_cmd docker

  local root_dir
  root_dir="$(dirname "$(dirname "$SCRIPT_DIR")")/app"

  info "Building mxtac/backend:latest ..."
  docker build -t mxtac/backend:latest "${root_dir}/backend"

  info "Building mxtac/frontend:latest ..."
  docker build -f "${root_dir}/frontend/Dockerfile.prod" -t mxtac/frontend:latest "${root_dir}/frontend"

  # Import into k3s containerd (only needed when not using a registry)
  if command -v k3s &>/dev/null; then
    info "Importing images into k3s containerd ..."
    docker save mxtac/backend:latest  | sudo k3s ctr images import -
    docker save mxtac/frontend:latest | sudo k3s ctr images import -
    success "Images imported into k3s."
  else
    info "k3s not found locally — push images to a registry accessible by your cluster nodes."
    info "  docker tag mxtac/backend:latest  <registry>/mxtac/backend:latest"
    info "  docker push <registry>/mxtac/backend:latest"
  fi
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "${1:-help}" in
  bootstrap) cmd_bootstrap ;;
  apply)     cmd_apply ;;
  status)    cmd_status ;;
  rollback)  cmd_rollback ;;
  destroy)   cmd_destroy "${2:-}" ;;
  images)    cmd_images ;;
  *)
    echo "Usage: $0 {bootstrap|apply|status|rollback|destroy|images}"
    echo ""
    echo "  bootstrap   First-time setup: generate secrets and deploy everything"
    echo "  apply       Apply/update manifests (idempotent)"
    echo "  status      Show pod/deployment/HPA/ingress status"
    echo "  rollback    Undo last backend and frontend rollout"
    echo "  destroy     Remove all MxTac resources (add --with-pvcs to also delete PVCs)"
    echo "  images      Build Docker images and import into k3s containerd"
    echo ""
    echo "Environment variables:"
    echo "  MXTAC_DOMAIN   Ingress hostname (default: mxtac.local)"
    echo "  KUBECTL        kubectl binary to use (default: kubectl)"
    exit 1
    ;;
esac
