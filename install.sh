#!/usr/bin/env bash
# ==============================================================================
# Guardian WAF - Automated Server Installation Script
# Operating Systems: Ubuntu, Debian, RHEL, CentOS, Rocky Linux, Alpine
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}🛡️  Installing Guardian WAF Server Component${NC}"
echo -e "${BLUE}   Deterministic SAT Cyber-Defense & Reverse Proxy${NC}"
echo -e "${BLUE}   Engine: EXACTOR Core & https://exactor.tech${NC}"
echo -e "${BLUE}============================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root (use sudo).${NC}" 
   exit 1
fi

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/exactor"
SERVICE_FILE="/etc/systemd/system/exactor-waf.service"
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

if [[ -f "${SCRIPT_DIR}/exactor-waf-guardian" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/exactor-waf-guardian"
    echo -e "${GREEN}✓ Found bundled standalone binary in package.${NC}"
elif [[ -f "${SCRIPT_DIR}/bin/exactor-waf-guardian" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/bin/exactor-waf-guardian"
    echo -e "${GREEN}✓ Found bundled binary in bin/ directory.${NC}"
elif [[ -f "${SCRIPT_DIR}/target/release/exactor-waf-guardian" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/target/release/exactor-waf-guardian"
    echo -e "${GREEN}✓ Found local release target binary.${NC}"
elif [[ "$BUILD_SOURCE" == "true" ]]; then
    echo -e "Compiling release binary from source using cargo..."
    if command -v cargo &> /dev/null; then
        (cd "${SCRIPT_DIR}" && cargo build --release)
        BINARY_PATH="${SCRIPT_DIR}/target/release/exactor-waf-guardian"
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

    DOWNLOAD_URL="https://github.com/ExactorResearch/exactor-waf-guardian/releases/download/${RELEASE_TAG}/exactor-waf-guardian-${TARGET_ARCH}"
    echo $DOWNLOAD_URL
    DOWNLOAD_URL="https://github.com/ExactorResearch/exactor-waf-guardian/blob/main/releases/download/v0.2.0/exactor-waf-guardian-x86_64-unknown-linux-musl"
    TEMP_BIN="/tmp/exactor-waf-guardian"
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
            BINARY_PATH="${SCRIPT_DIR}/target/release/exactor-waf-guardian"
        else
            echo -e "${RED}Error: Could not retrieve precompiled binary and Cargo is not installed.${NC}"
            echo -e "Provide the precompiled 'exactor-waf-guardian' binary in the installer folder."
            exit 1
        fi
    fi
fi

# 2. Install Binary & CLI Suite
echo -e "${YELLOW}[2/5] Installing binary and management tools to ${INSTALL_DIR}...${NC}"
install -m 755 "${BINARY_PATH}" "${INSTALL_DIR}/exactor-waf-guardian"
echo -e "${GREEN}✓ Binary installed at ${INSTALL_DIR}/exactor-waf-guardian${NC}"

if [[ -f "${SCRIPT_DIR}/exactor-top.py" ]]; then
    install -m 755 "${SCRIPT_DIR}/exactor-top.py" "${INSTALL_DIR}/exactor-top"
    echo -e "${GREEN}✓ exactor-top installed at ${INSTALL_DIR}/exactor-top${NC}"
fi

if [[ -f "${SCRIPT_DIR}/exactor-advisor.py" ]]; then
    install -m 755 "${SCRIPT_DIR}/exactor-advisor.py" "${INSTALL_DIR}/exactor-advisor"
    echo -e "${GREEN}✓ exactor-advisor installed at ${INSTALL_DIR}/exactor-advisor${NC}"
fi

if [[ -f "${SCRIPT_DIR}/exactor-rules.py" ]]; then
    install -m 755 "${SCRIPT_DIR}/exactor-rules.py" "${INSTALL_DIR}/exactor-rules"
    echo -e "${GREEN}✓ exactor-rules installed at ${INSTALL_DIR}/exactor-rules${NC}"
fi

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
exactor_api_url = "https://exactor.tech/api/simplify"
database_path = "/etc/exactor/waf_ledger.db"
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
    if [[ -f "${SCRIPT_DIR}/exactor-waf.service" ]]; then
        cp "${SCRIPT_DIR}/exactor-waf.service" "${SERVICE_FILE}"
    else
        cat << 'EOF' > "${SERVICE_FILE}"
[Unit]
Description=Guardian WAF - Deterministic SAT Cyber-Defense Proxy
Documentation=https://github.com/ExactorResearch/exactor-waf-guardian
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/etc/exactor
ExecStart=/usr/local/bin/exactor-waf-guardian proxy --config /etc/exactor/waf_config.toml
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
SyslogIdentifier=exactor-waf

[Install]
WantedBy=multi-user.target
EOF
    fi
    chmod 644 "${SERVICE_FILE}"
    systemctl daemon-reload
    systemctl enable exactor-waf.service
    echo -e "${GREEN}✓ Systemd service registered and enabled.${NC}"
else
    echo -e "${YELLOW}Warning: systemd not detected. You can run the server with:${NC}"
    echo -e "${GREEN}exactor-waf-guardian proxy --config ${CONFIG_DIR}/waf_config.toml${NC}"
fi

# 5. Start Service
echo -e "${YELLOW}[5/5] Starting service...${NC}"
if command -v systemctl &> /dev/null && systemctl is-system-running &> /dev/null; then
    systemctl restart exactor-waf.service
    sleep 1
    if systemctl is-active --quiet exactor-waf.service; then
        echo -e "${GREEN}✅ Guardian WAF is ACTIVE and protecting your server!${NC}"
    else
        echo -e "${RED}⚠️  Service failed to start. Check logs with: journalctl -u exactor-waf -e${NC}"
    fi
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}🎉 Installation successfully completed!${NC}"
echo -e "   Status command   : systemctl status exactor-waf"
echo -e "   Logs command     : journalctl -u exactor-waf -f"
echo -e "   Config file      : /etc/exactor/waf_config.toml"
echo -e "   CLI inspection   : exactor-waf-guardian inspect --query \"id=1' OR 1=1--\""
echo -e "   Benchmark        : exactor-waf-guardian benchmark"
echo -e "${GREEN}============================================================${NC}"
