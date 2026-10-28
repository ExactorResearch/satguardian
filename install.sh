#!/usr/bin/env bash
# ==============================================================================
# SATGuardian Edge WAF - Automated Server Installation Script
# Operating Systems: Ubuntu, Debian, RHEL, CentOS, Rocky Linux, Alpine
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}🛡️  Installing SATGuardian Edge WAF Server Component${NC}"
echo -e "${BLUE}   Deterministic SAT Cyber-Defense & Reverse Proxy (100% Free Edge)${NC}"
echo -e "${BLUE}   Cloud Boolean Optimization: https://satguardian.tech${NC}"
echo -e "${BLUE}============================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root (use sudo).${NC}" 
   exit 1
fi

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/satguardian"
SERVICE_FILE="/etc/systemd/system/satguardian-waf.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Locate Bundled Binary or Download Standalone Release
echo -e "${YELLOW}[1/5] Preparing binary (Zero-Dependency Mode)...${NC}"
BINARY_PATH=""
RELEASE_TAG="v0.2.0"
BUILD_SOURCE=false

for arg in "$@"; do
    if [[ "$arg" == "--source" ]] || [[ "$arg" == "--build-from-source" ]]; then
        BUILD_SOURCE=true
    fi
done

if [[ -f "${SCRIPT_DIR}/satguardian-waf" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/satguardian-waf"
    echo -e "${GREEN}✓ Found bundled standalone binary in package.${NC}"
elif [[ -f "${SCRIPT_DIR}/exactor-waf-guardian" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/exactor-waf-guardian"
    echo -e "${GREEN}✓ Found bundled binary in package.${NC}"
elif [[ -f "${SCRIPT_DIR}/bin/satguardian-waf" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/bin/satguardian-waf"
    echo -e "${GREEN}✓ Found bundled binary in bin/ directory.${NC}"
elif [[ -f "${SCRIPT_DIR}/bin/exactor-waf-guardian" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/bin/exactor-waf-guardian"
    echo -e "${GREEN}✓ Found bundled binary in bin/ directory.${NC}"
elif [[ -f "${SCRIPT_DIR}/target/release/satguardian-waf" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/target/release/satguardian-waf"
    echo -e "${GREEN}✓ Found local release target binary.${NC}"
elif [[ -f "${SCRIPT_DIR}/target/release/exactor-waf-guardian" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/target/release/exactor-waf-guardian"
    echo -e "${GREEN}✓ Found local release target binary.${NC}"
elif [[ "$BUILD_SOURCE" == "true" ]]; then
    echo -e "Compiling release binary from source using cargo..."
    if command -v cargo &> /dev/null; then
        (cd "${SCRIPT_DIR}" && cargo build --release)
        BINARY_PATH="${SCRIPT_DIR}/target/release/satguardian-waf"
    else
        echo -e "${RED}Error: Cargo not found for source build.${NC}"
        exit 1
    fi
else
    # Zero-Install: Download pre-compiled standalone binary matching architecture
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64|amd64) TARGET_ARCH="x86_64-unknown-linux-musl" ;;
        aarch64|arm64) TARGET_ARCH="aarch64-unknown-linux-musl" ;;
        *) echo -e "${RED}Unsupported CPU architecture: ${ARCH}${NC}"; exit 1 ;;
    esac

    DOWNLOAD_URL="https://github.com/SATGuardian/satguardian-waf/releases/download/${RELEASE_TAG}/satguardian-waf-${TARGET_ARCH}"
    TEMP_BIN="/tmp/satguardian-waf"
    echo -e "Downloading pre-compiled standalone binary (${TARGET_ARCH})..."
    
    if command -v curl &> /dev/null; then
        curl -sSL -f "${DOWNLOAD_URL}" -o "${TEMP_BIN}" || true
    elif command -v wget &> /dev/null; then
        wget -qO "${TEMP_BIN}" "${DOWNLOAD_URL}" || true
    fi

    if [[ -f "${TEMP_BIN}" ]] && [[ -s "${TEMP_BIN}" ]]; then
        chmod +x "${TEMP_BIN}"
        BINARY_PATH="${TEMP_BIN}"
        echo -e "${GREEN}✓ Pre-compiled standalone binary downloaded successfully.${NC}"
    else
        # If offline or download fails, check if cargo is available as ultimate fallback
        if command -v cargo &> /dev/null; then
            echo -e "${YELLOW}Download unavailable. Building from source via cargo...${NC}"
            (cd "${SCRIPT_DIR}" && cargo build --release)
            BINARY_PATH="${SCRIPT_DIR}/target/release/satguardian-waf"
        else
            echo -e "${RED}Error: Could not retrieve precompiled binary and Cargo is not installed.${NC}"
            echo -e "Provide the precompiled 'satguardian-waf' binary in the installer folder."
            exit 1
        fi
    fi
fi

# 2. Install Binary & CLI Suite
echo -e "${YELLOW}[2/5] Installing binary and management tools to ${INSTALL_DIR}...${NC}"
install -m 755 "${BINARY_PATH}" "${INSTALL_DIR}/satguardian-waf"
ln -sf "${INSTALL_DIR}/satguardian-waf" "${INSTALL_DIR}/exactor-waf-guardian"
echo -e "${GREEN}✓ Binary installed at ${INSTALL_DIR}/satguardian-waf (alias: exactor-waf-guardian)${NC}"

for tool in satguardian-top satguardian-advisor satguardian-rules; do
    if [[ -f "${SCRIPT_DIR}/${tool}.py" ]]; then
        install -m 755 "${SCRIPT_DIR}/${tool}.py" "${INSTALL_DIR}/${tool}"
        echo -e "${GREEN}✓ ${tool} installed at ${INSTALL_DIR}/${tool}${NC}"
    fi
done
# Legacy compatibility links
[[ -f "${INSTALL_DIR}/satguardian-top" ]] && ln -sf "${INSTALL_DIR}/satguardian-top" "${INSTALL_DIR}/exactor-top"
[[ -f "${INSTALL_DIR}/satguardian-advisor" ]] && ln -sf "${INSTALL_DIR}/satguardian-advisor" "${INSTALL_DIR}/exactor-advisor"
[[ -f "${INSTALL_DIR}/satguardian-rules" ]] && ln -sf "${INSTALL_DIR}/satguardian-rules" "${INSTALL_DIR}/exactor-rules"

# 3. Create Configuration
echo -e "${YELLOW}[3/5] Setting up configuration directory ${CONFIG_DIR}...${NC}"
mkdir -p "${CONFIG_DIR}"

if [[ ! -f "${CONFIG_DIR}/waf_config.toml" ]]; then
    if [[ -f "${SCRIPT_DIR}/waf_config.toml" ]]; then
        cp "${SCRIPT_DIR}/waf_config.toml" "${CONFIG_DIR}/waf_config.toml"
    else
        cat << 'EOF' > "${CONFIG_DIR}/waf_config.toml"
listen_addr = "0.0.0.0:8080"
upstream_url = "http://127.0.0.1:3000"
mode = "block"
satguardian_api_url = "https://satguardian.tech/api/simplify"
database_path = "/etc/satguardian/waf_ledger.db"
autonomous_sync_interval_secs = 300
auto_sync_enabled = true
EOF
    fi
    chmod 644 "${CONFIG_DIR}/waf_config.toml"
    echo -e "${GREEN}✓ Created default config at ${CONFIG_DIR}/waf_config.toml${NC}"
else
    echo -e "${BLUE}ℹ️  Existing configuration preserved at ${CONFIG_DIR}/waf_config.toml${NC}"
fi

# 4. Install Systemd Service
echo -e "${YELLOW}[4/5] Installing systemd service...${NC}"
if [[ -d "/etc/systemd/system" ]]; then
    cat << 'EOF' > "${SERVICE_FILE}"
[Unit]
Description=SATGuardian Edge WAF - Deterministic SAT Cyber-Defense Proxy
Documentation=https://satguardian.tech
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/etc/satguardian
ExecStart=/usr/local/bin/satguardian-waf proxy --config /etc/satguardian/waf_config.toml
Restart=always
RestartSec=3s

# Performance and File Descriptor Limits
LimitNOFILE=1048576
LimitNPROC=512000

# Security Hardening
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=satguardian-waf

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "${SERVICE_FILE}"
    systemctl daemon-reload
    systemctl enable satguardian-waf.service
    echo -e "${GREEN}✓ Systemd service registered and enabled.${NC}"
else
    echo -e "${YELLOW}Warning: systemd not detected. You can run the server with:${NC}"
    echo -e "${GREEN}satguardian-waf proxy --config ${CONFIG_DIR}/waf_config.toml${NC}"
fi

# 5. Start Service
echo -e "${YELLOW}[5/5] Starting service...${NC}"
if command -v systemctl &> /dev/null && systemctl is-system-running &> /dev/null; then
    systemctl restart satguardian-waf.service
    sleep 1
    if systemctl is-active --quiet satguardian-waf.service; then
        echo -e "${GREEN}✅ SATGuardian Edge WAF is ACTIVE and protecting your server!${NC}"
    else
        echo -e "${RED}⚠️  Service failed to start. Check logs with: journalctl -u satguardian-waf -e${NC}"
    fi
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}🎉 Installation successfully completed!${NC}"
echo -e "   Status command   : systemctl status satguardian-waf"
echo -e "   Logs command     : journalctl -u satguardian-waf -f"
echo -e "   Config file      : /etc/satguardian/waf_config.toml"
echo -e "   Entitlement check: satguardian-waf entitlement"
echo -e "   CLI inspection   : satguardian-waf inspect --query \"id=1' OR 1=1--\""
echo -e "   Benchmark        : satguardian-waf benchmark"
echo -e "${GREEN}============================================================${NC}"
