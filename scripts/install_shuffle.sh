#!/bin/bash
# =============================================================================
# Shuffle SOAR Installation Script for Ubuntu
# Installs Shuffle using Docker Compose
# Compatible with Ubuntu 20.04 / 22.04
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "This script must be run as root."

SHUFFLE_VERSION="1.4.0"
SHUFFLE_DIR="/opt/shuffle"
SHUFFLE_PORT=3001
SHUFFLE_BACKEND_PORT=5001
HOST_IP=$(hostname -I | awk '{print $1}')

# ─── 1. Install Docker & Docker Compose ──────────────────────────────────────
install_docker() {
    if command -v docker &>/dev/null; then
        info "Docker already installed: $(docker --version)"
        return
    fi
    info "Installing Docker..."
    apt-get update -qq
    apt-get install -y ca-certificates curl gnupg lsb-release
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) \
signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        | tee /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    info "Docker installed: $(docker --version)"
}

install_docker

# ─── 2. Set kernel parameter required by OpenSearch ──────────────────────────
sysctl -w vm.max_map_count=262144
grep -q 'vm.max_map_count' /etc/sysctl.conf \
    && sed -i 's/^vm.max_map_count=.*/vm.max_map_count=262144/' /etc/sysctl.conf \
    || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf

# ─── 3. Clone / download Shuffle ─────────────────────────────────────────────
info "Setting up Shuffle ${SHUFFLE_VERSION} in ${SHUFFLE_DIR}..."
mkdir -p "${SHUFFLE_DIR}"

cat > "${SHUFFLE_DIR}/docker-compose.yml" <<COMPOSE
version: "3"
services:

  frontend:
    image: ghcr.io/shuffle/shuffle-frontend:${SHUFFLE_VERSION}
    container_name: shuffle-frontend
    hostname: shuffle-frontend
    ports:
      - "${SHUFFLE_PORT}:80"
      - "3002:443"
    environment:
      - BACKEND_HOSTNAME=shuffle-backend
    restart: unless-stopped
    depends_on:
      - backend

  backend:
    image: ghcr.io/shuffle/shuffle-backend:${SHUFFLE_VERSION}
    container_name: shuffle-backend
    hostname: shuffle-backend
    ports:
      - "${SHUFFLE_BACKEND_PORT}:5001"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - shuffle-apps:/shuffle-apps
      - shuffle-files:/shuffle-files
    environment:
      - DATASTORE_EMULATOR_HOST=shuffle-database:8000
      - SHUFFLE_APP_HOTLOAD_FOLDER=/shuffle-apps
      - SHUFFLE_FILE_LOCATION=/shuffle-files
      - SHUFFLE_OPENSEARCH_URL=http://shuffle-opensearch:9200
      - SHUFFLE_OPENSEARCH_USERNAME=admin
      - SHUFFLE_OPENSEARCH_PASSWORD=admin
      - BASE_URL=http://${HOST_IP}:${SHUFFLE_BACKEND_PORT}
    restart: unless-stopped
    depends_on:
      - shuffle-opensearch

  shuffle-opensearch:
    image: opensearchproject/opensearch:2.11.1
    container_name: shuffle-opensearch
    hostname: shuffle-opensearch
    environment:
      - cluster.name=shuffle-cluster
      - node.name=shuffle-opensearch
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m
      - OPENSEARCH_INITIAL_ADMIN_PASSWORD=admin
      - plugins.security.disabled=true
    volumes:
      - shuffle-opensearch-data:/usr/share/opensearch/data
    ulimits:
      memlock:
        soft: -1
        hard: -1
    restart: unless-stopped

  shuffle-database:
    image: ghcr.io/shuffle/shuffle-database:${SHUFFLE_VERSION}
    container_name: shuffle-database
    hostname: shuffle-database
    volumes:
      - shuffle-database:/etc/shuffle
    restart: unless-stopped

volumes:
  shuffle-apps:
  shuffle-files:
  shuffle-opensearch-data:
  shuffle-database:
COMPOSE

# ─── 4. Start Shuffle ─────────────────────────────────────────────────────────
info "Starting Shuffle containers..."
cd "${SHUFFLE_DIR}"
docker compose pull --quiet
docker compose up -d

# ─── 5. Wait for backend to be ready ─────────────────────────────────────────
info "Waiting for Shuffle backend to become ready (up to 120 s)..."
TIMEOUT=120; ELAPSED=0
until curl -sf "http://localhost:${SHUFFLE_BACKEND_PORT}/api/v1/health" &>/dev/null; do
    sleep 5; ELAPSED=$((ELAPSED+5))
    [[ ${ELAPSED} -ge ${TIMEOUT} ]] && warn "Shuffle backend not ready yet – check 'docker compose logs'" && break
done

# ─── 6. Configure Wazuh → Shuffle webhook integration ────────────────────────
configure_wazuh_integration() {
    local OSSEC_CONF="/var/ossec/etc/ossec.conf"
    [[ ! -f "${OSSEC_CONF}" ]] && warn "ossec.conf not found; skipping Wazuh integration." && return

    # Check if integration block already exists
    grep -q '<integration>' "${OSSEC_CONF}" && \
        warn "Wazuh integration already configured in ossec.conf." && return

    SHUFFLE_WEBHOOK_URL="http://${HOST_IP}:${SHUFFLE_BACKEND_PORT}/api/v1/hooks/webhook_soc_triage"

    python3 - <<PYEOF
import xml.etree.ElementTree as ET

tree = ET.parse("${OSSEC_CONF}")
root = tree.getroot()
ossec = root

integ = ET.SubElement(ossec, 'integration')
name_el = ET.SubElement(integ, 'name'); name_el.text = 'shuffle'
hook_el  = ET.SubElement(integ, 'hook_url'); hook_el.text = '${SHUFFLE_WEBHOOK_URL}'
level_el = ET.SubElement(integ, 'level'); level_el.text = '7'
alert_fmt = ET.SubElement(integ, 'alert_format'); alert_fmt.text = 'json'

ET.indent(tree, space='  ')
tree.write("${OSSEC_CONF}", xml_declaration=True, encoding='utf-8')
print("Integration block added to ossec.conf")
PYEOF

    systemctl restart wazuh-manager 2>/dev/null || true
    info "Wazuh–Shuffle integration configured."
}

configure_wazuh_integration

# ─── Summary ─────────────────────────────────────────────────────────────────
info "══════════════════════════════════════════════════"
info " Shuffle SOAR ${SHUFFLE_VERSION} installation complete!"
info " UI         : http://${HOST_IP}:${SHUFFLE_PORT}"
info " Backend API: http://${HOST_IP}:${SHUFFLE_BACKEND_PORT}"
info " Default credentials: admin / password  (change on first login)"
info "══════════════════════════════════════════════════"
