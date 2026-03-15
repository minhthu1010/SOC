#!/bin/bash
# =============================================================================
# Wazuh SIEM Installation Script for Ubuntu
# Installs Wazuh Manager, Wazuh Indexer (OpenSearch), and Wazuh Dashboard
# Compatible with Ubuntu 20.04 / 22.04
# =============================================================================

set -euo pipefail

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ─── Configuration ────────────────────────────────────────────────────────────
WAZUH_VERSION="4.7.3"
WAZUH_MANAGER_IP=$(hostname -I | awk '{print $1}')
WAZUH_ADMIN_PASSWORD="WazuhAdmin@SOC2024"
WAZUH_DASHBOARD_PORT=443

# ─── Pre-flight checks ────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "This script must be run as root."
command -v curl  &>/dev/null || apt-get install -y curl  &>/dev/null
command -v gpg   &>/dev/null || apt-get install -y gpg   &>/dev/null

info "Starting Wazuh ${WAZUH_VERSION} installation on ${WAZUH_MANAGER_IP}"

# ─── 1. Add Wazuh GPG key and repository ─────────────────────────────────────
info "Adding Wazuh repository..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring \
          --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
          --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" \
    | tee /etc/apt/sources.list.d/wazuh.list

apt-get update -qq

# ─── 2. Install Wazuh Indexer ────────────────────────────────────────────────
info "Installing Wazuh Indexer..."
apt-get install -y wazuh-indexer

# Generate certificates
cat > /tmp/indexer_certs.yml <<EOF
nodes:
  indexer:
    - name: node-1
      ip: "${WAZUH_MANAGER_IP}"
EOF

/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-certs-tool.sh \
    -A -c /tmp/indexer_certs.yml 2>/dev/null || true

mkdir -p /etc/wazuh-indexer/certs
cp -p /tmp/wazuh-certificates/node-1.pem     /etc/wazuh-indexer/certs/indexer.pem
cp -p /tmp/wazuh-certificates/node-1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
cp -p /tmp/wazuh-certificates/root-ca.pem    /etc/wazuh-indexer/certs/root-ca.pem
cp -p /tmp/wazuh-certificates/admin.pem      /etc/wazuh-indexer/certs/admin.pem
cp -p /tmp/wazuh-certificates/admin-key.pem  /etc/wazuh-indexer/certs/admin-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*

# Configure Wazuh Indexer
sed -i "s/^network.host:.*/network.host: \"${WAZUH_MANAGER_IP}\"/" \
    /etc/wazuh-indexer/opensearch.yml

systemctl daemon-reload
systemctl enable --now wazuh-indexer
info "Wazuh Indexer started."

# Initialise security plugin
JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /etc/wazuh-indexer/opensearch-security \
    -nhnv \
    -cacert /etc/wazuh-indexer/certs/root-ca.pem \
    -cert   /etc/wazuh-indexer/certs/admin.pem \
    -key    /etc/wazuh-indexer/certs/admin-key.pem \
    -p 9200 -icl || true

# ─── 3. Install Wazuh Manager ────────────────────────────────────────────────
info "Installing Wazuh Manager..."
apt-get install -y wazuh-manager

# Copy SOC custom rules
RULES_DIR=/var/ossec/etc/rules
mkdir -p "${RULES_DIR}"
cp "$(dirname "$0")/../wazuh_config/soc_custom_rules.xml" \
    "${RULES_DIR}/soc_custom_rules.xml" 2>/dev/null || true

# Copy main ossec.conf if present
OSSEC_CONF="$(dirname "$0")/../wazuh_config/ossec.conf"
[[ -f "${OSSEC_CONF}" ]] && cp "${OSSEC_CONF}" /var/ossec/etc/ossec.conf

systemctl daemon-reload
systemctl enable --now wazuh-manager
info "Wazuh Manager started."

# ─── 4. Install Wazuh Dashboard ──────────────────────────────────────────────
info "Installing Wazuh Dashboard..."
apt-get install -y wazuh-dashboard

mkdir -p /etc/wazuh-dashboard/certs
cp -p /tmp/wazuh-certificates/dashboard.pem     \
      /etc/wazuh-dashboard/certs/dashboard.pem     2>/dev/null || \
cp -p /tmp/wazuh-certificates/node-1.pem         \
      /etc/wazuh-dashboard/certs/dashboard.pem
cp -p /tmp/wazuh-certificates/dashboard-key.pem  \
      /etc/wazuh-dashboard/certs/dashboard-key.pem 2>/dev/null || \
cp -p /tmp/wazuh-certificates/node-1-key.pem     \
      /etc/wazuh-dashboard/certs/dashboard-key.pem
cp -p /tmp/wazuh-certificates/root-ca.pem        \
      /etc/wazuh-dashboard/certs/root-ca.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*

# Update dashboard config
sed -i "s|^opensearch.hosts:.*|opensearch.hosts: [\"https://${WAZUH_MANAGER_IP}:9200\"]|" \
    /etc/wazuh-dashboard/opensearch_dashboards.yml
sed -i "s|^server.host:.*|server.host: \"${WAZUH_MANAGER_IP}\"|" \
    /etc/wazuh-dashboard/opensearch_dashboards.yml

systemctl daemon-reload
systemctl enable --now wazuh-dashboard
info "Wazuh Dashboard started."

# ─── 5. API user password ────────────────────────────────────────────────────
info "Setting Wazuh API admin password..."
/var/ossec/framework/python/bin/python3 \
    /var/ossec/api/scripts/configure_api.py \
    --set-user admin --password "${WAZUH_ADMIN_PASSWORD}" 2>/dev/null || true

# ─── Summary ─────────────────────────────────────────────────────────────────
info "══════════════════════════════════════════════════"
info " Wazuh ${WAZUH_VERSION} installation complete!"
info " Dashboard : https://${WAZUH_MANAGER_IP}:${WAZUH_DASHBOARD_PORT}"
info " API       : https://${WAZUH_MANAGER_IP}:55000"
info " Username  : admin"
info " Password  : ${WAZUH_ADMIN_PASSWORD}"
info "══════════════════════════════════════════════════"
