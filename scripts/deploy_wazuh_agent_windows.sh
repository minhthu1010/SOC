#!/bin/bash
# =============================================================================
# Wazuh Agent Deployment Script for Windows (run from Ubuntu manager)
# Generates a pre-configured MSI installer command and PowerShell onboarding
# script that operators execute on each Windows target.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

WAZUH_VERSION="4.7.3"
WAZUH_MANAGER_IP="${1:-$(hostname -I | awk '{print $1}')}"
WAZUH_AGENT_GROUP="windows-endpoints"
OUTPUT_DIR="$(dirname "$0")/../agent_config"
mkdir -p "${OUTPUT_DIR}"

info "Manager IP : ${WAZUH_MANAGER_IP}"
info "Agent group: ${WAZUH_AGENT_GROUP}"

# ─── 1. Create agent group on the manager ────────────────────────────────────
if command -v /var/ossec/bin/agent_groups &>/dev/null; then
    /var/ossec/bin/agent_groups -a -g "${WAZUH_AGENT_GROUP}" 2>/dev/null || \
        warn "Group '${WAZUH_AGENT_GROUP}' may already exist."
    info "Agent group '${WAZUH_AGENT_GROUP}' ensured."
fi

# ─── 2. Push agent group configuration ───────────────────────────────────────
GROUP_CONF="/var/ossec/etc/shared/${WAZUH_AGENT_GROUP}/agent.conf"
mkdir -p "$(dirname "${GROUP_CONF}")"
cat > "${GROUP_CONF}" <<'XML'
<agent_config>
  <!-- Windows-specific log collection for SOC use-case -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>
      <![CDATA[
        Event/System[EventID=4624 or
                     EventID=4625 or
                     EventID=4634 or
                     EventID=4648 or
                     EventID=4670 or
                     EventID=4698 or
                     EventID=4720 or
                     EventID=4728 or
                     EventID=4732 or
                     EventID=4756 or
                     EventID=5140 or
                     EventID=5145]
      ]]>
    </query>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Sysmon if deployed -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- File integrity monitoring for sensitive paths -->
  <syscheck>
    <frequency>300</frequency>
    <directories check_all="yes">%WINDIR%\System32\drivers\etc</directories>
    <directories check_all="yes" realtime="yes">C:\Users</directories>
    <ignore>%WINDIR%\SoftwareDistribution</ignore>
  </syscheck>

  <!-- Active response – block IP via Windows Firewall -->
  <active-response>
    <disabled>no</disabled>
    <command>netsh-block-ip</command>
    <location>local</location>
    <level>10</level>
    <timeout>600</timeout>
  </active-response>
</agent_config>
XML
info "Group configuration written to ${GROUP_CONF}"

# ─── 3. Generate PowerShell onboarding script ────────────────────────────────
PS_SCRIPT="${OUTPUT_DIR}/Install-WazuhAgent.ps1"
cat > "${PS_SCRIPT}" <<PSEOF
#Requires -RunAsAdministrator
# ============================================================
# Wazuh ${WAZUH_VERSION} Agent – Silent install for Windows
# Run from an elevated PowerShell session on the Windows host.
# ============================================================

\$WazuhVersion   = "${WAZUH_VERSION}"
\$ManagerIP      = "${WAZUH_MANAGER_IP}"
\$AgentGroup     = "${WAZUH_AGENT_GROUP}"
\$AgentName      = \$env:COMPUTERNAME
\$InstallerUrl   = "https://packages.wazuh.com/4.x/windows/wazuh-agent-\${WazuhVersion}-1.msi"
\$InstallerPath  = "\$env:TEMP\wazuh-agent.msi"
\$LogPath        = "\$env:TEMP\wazuh-install.log"

Write-Host "[INFO] Downloading Wazuh agent \${WazuhVersion}..."
Invoke-WebRequest -Uri \$InstallerUrl -OutFile \$InstallerPath -UseBasicParsing

Write-Host "[INFO] Installing Wazuh agent..."
\$Arguments = @(
    "/i", \$InstallerPath,
    "/quiet",
    "/l*v", \$LogPath,
    "WAZUH_MANAGER=\${ManagerIP}",
    "WAZUH_MANAGER_PORT=1514",
    "WAZUH_PROTOCOL=tcp",
    "WAZUH_AGENT_NAME=\${AgentName}",
    "WAZUH_AGENT_GROUP=\${AgentGroup}",
    "WAZUH_REGISTRATION_SERVER=\${ManagerIP}",
    "WAZUH_REGISTRATION_PORT=1515"
)
Start-Process msiexec.exe -ArgumentList \$Arguments -Wait -NoNewWindow

Write-Host "[INFO] Starting Wazuh agent service..."
Start-Service -Name WazuhSvc -ErrorAction SilentlyContinue
Set-Service  -Name WazuhSvc -StartupType Automatic

\$Svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if (\$Svc -and \$Svc.Status -eq 'Running') {
    Write-Host "[OK]   Wazuh agent is running."
} else {
    Write-Warning "Wazuh agent service not running – check \${LogPath}"
}

# Enable Windows Audit Policies required for Event ID 4624/4625 etc.
Write-Host "[INFO] Configuring Windows audit policies..."
\$AuditCategories = @(
    "Logon/Logoff,Logon,Success and Failure",
    "Logon/Logoff,Logoff,Success",
    "Logon/Logoff,Account Lockout,Success and Failure",
    "Object Access,File System,Success and Failure",
    "Object Access,File Share,Success and Failure",
    "Account Management,User Account Management,Success and Failure",
    "Detailed Tracking,Process Creation,Success"
)
foreach (\$cat in \$AuditCategories) {
    \$parts = \$cat -split ","
    auditpol /set /subcategory:"\$(\$parts[1].Trim())" /success:enable /failure:enable 2>\$null
}

Write-Host "[INFO] Wazuh agent deployment complete."
PSEOF
info "PowerShell onboarding script: ${PS_SCRIPT}"

# ─── 4. Display usage instructions ───────────────────────────────────────────
info "══════════════════════════════════════════════════════════"
info " To deploy the agent on a Windows machine:"
info "   1. Copy ${PS_SCRIPT} to the Windows host."
info "   2. Open PowerShell as Administrator and run:"
info "        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
info "        .\\Install-WazuhAgent.ps1"
info "══════════════════════════════════════════════════════════"
