#!/usr/bin/env bash
# scan-images.sh — Container image vulnerability scan for MxTac
#
# Scans built Docker images using Grype (primary) or Trivy (fallback).
#
# Usage:
#   ./scripts/scan-images.sh                    # scan all MxTac images
#   ./scripts/scan-images.sh --image backend    # scan specific image
#   ./scripts/scan-images.sh --ci               # exit non-zero on HIGH/CRITICAL
#   ./scripts/scan-images.sh --build            # build images before scanning
#
# Install scanners:
#   Grype:  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
#   Trivy:  https://aquasecurity.github.io/trivy/latest/getting-started/installation/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
APP_DIR="$PROJECT_ROOT/app"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

CI_MODE=false
BUILD_FIRST=false
SPECIFIC_IMAGE=""
OVERALL_EXIT=0

for arg in "$@"; do
  case $arg in
    --ci)        CI_MODE=true ;;
    --build)     BUILD_FIRST=true ;;
    --image)     shift; SPECIFIC_IMAGE="$1" ;;
    --image=*)   SPECIFIC_IMAGE="${arg#*=}" ;;
  esac
done

# ─── Images to scan ──────────────────────────────────────────────────────────
declare -A IMAGES=(
  [backend]="mxtac-backend:latest"
  [frontend]="mxtac-frontend:latest"
)

if [ -n "$SPECIFIC_IMAGE" ]; then
  if [ -z "${IMAGES[$SPECIFIC_IMAGE]+_}" ]; then
    echo -e "${RED}Unknown image: $SPECIFIC_IMAGE${NC}"
    echo "Available: ${!IMAGES[*]}"
    exit 1
  fi
  IMAGES=( [$SPECIFIC_IMAGE]="${IMAGES[$SPECIFIC_IMAGE]}" )
fi

# ─── Detect scanner ──────────────────────────────────────────────────────────
detect_scanner() {
  if command -v grype &>/dev/null; then
    echo "grype"
  elif command -v trivy &>/dev/null; then
    echo "trivy"
  else
    echo "none"
  fi
}

print_header() {
  echo ""
  echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
}

SCANNER=$(detect_scanner)

if [ "$SCANNER" = "none" ]; then
  echo -e "${RED}No image scanner found. Install Grype or Trivy:${NC}"
  echo ""
  echo "  Grype (recommended):"
  echo "    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
  echo ""
  echo "  Trivy:"
  echo "    # Debian/Ubuntu:"
  echo "    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -"
  echo "    echo 'deb https://aquasecurity.github.io/trivy-repo/deb generic main' | sudo tee /etc/apt/sources.list.d/trivy.list"
  echo "    sudo apt-get update && sudo apt-get install trivy"
  exit 1
fi

echo -e "${GREEN}Using scanner: $SCANNER${NC}"

# ─── Build images if requested ───────────────────────────────────────────────
if $BUILD_FIRST; then
  print_header "Building Docker Images"
  docker compose -f "$APP_DIR/docker-compose.yml" build backend frontend
fi

# ─── Scan each image ─────────────────────────────────────────────────────────
scan_with_grype() {
  local image="$1"
  local fail_on_severity="${2:-high}"

  if $CI_MODE; then
    grype "$image" --fail-on "$fail_on_severity" --output table
  else
    grype "$image" --output table
  fi
}

scan_with_trivy() {
  local image="$1"
  local severity="${2:-HIGH,CRITICAL}"

  if $CI_MODE; then
    trivy image --exit-code 1 --severity "$severity" "$image"
  else
    trivy image --severity "CRITICAL,HIGH,MEDIUM,LOW" "$image"
  fi
}

REPORT_DIR="$PROJECT_ROOT/security-reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

for name in "${!IMAGES[@]}"; do
  image="${IMAGES[$name]}"
  print_header "Scanning: $image ($name)"

  # Check image exists
  if ! docker image inspect "$image" &>/dev/null; then
    echo -e "${YELLOW}Image '$image' not found locally.${NC}"
    echo "Build it first with: docker compose -f app/docker-compose.yml build $name"
    echo "Or run: ./scripts/scan-images.sh --build"
    OVERALL_EXIT=1
    continue
  fi

  REPORT_FILE="$REPORT_DIR/${name}-${TIMESTAMP}.txt"
  echo "Report will be saved to: $REPORT_FILE"
  echo ""

  EXIT_CODE=0
  if [ "$SCANNER" = "grype" ]; then
    scan_with_grype "$image" "high" 2>&1 | tee "$REPORT_FILE" || EXIT_CODE=$?
  else
    scan_with_trivy "$image" "HIGH,CRITICAL" 2>&1 | tee "$REPORT_FILE" || EXIT_CODE=$?
  fi

  if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    if $CI_MODE; then
      echo -e "${RED}HIGH/CRITICAL vulnerabilities found in $image. Build failed.${NC}"
      OVERALL_EXIT=1
    else
      echo -e "${YELLOW}Vulnerabilities found in $image. Review report: $REPORT_FILE${NC}"
    fi
  else
    echo -e "${GREEN}No HIGH/CRITICAL vulnerabilities in $image.${NC}"
  fi
done

# ─── Summary ─────────────────────────────────────────────────────────────────
print_header "Scan Complete"
echo "Reports saved to: $REPORT_DIR/"
echo ""
if [ $OVERALL_EXIT -eq 0 ]; then
  echo -e "${GREEN}All images passed security scan.${NC}"
else
  echo -e "${RED}One or more images have vulnerabilities or could not be scanned.${NC}"
fi
echo ""

if $CI_MODE && [ $OVERALL_EXIT -ne 0 ]; then
  exit 1
fi
