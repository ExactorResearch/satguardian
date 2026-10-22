#!/usr/bin/env bash
# ==============================================================================
# Guardian WAF - Linux Server Uninstaller
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}============================================================${NC}"
echo -e "${RED}🛡️  Uninstalling Guardian WAF${NC}"
echo -e "${RED}============================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root (use sudo).${NC}" 
   exit 1
fi

PURGE_DATA=false
for arg in "$@"; do
    if [[ "$arg" == "--purge" ]]; then
        PURGE_DATA=true
    fi
done

# 1. Stop and disable systemd service
if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet exactor-waf.service 2>/dev/null; then
        echo -e "${YELLOW}Stopping exactor-waf.service...${NC}"
        systemctl stop exactor-waf.service || true
    fi
    if systemctl is-enabled --quiet exactor-waf.service 2>/dev/null; then
        echo -e "${YELLOW}Disabling exactor-waf.service...${NC}"
        systemctl disable exactor-waf.service || true
    fi
    if [[ -f "/etc/systemd/system/exactor-waf.service" ]]; then
        rm -f "/etc/systemd/system/exactor-waf.service"
        systemctl daemon-reload || true
        echo -e "${GREEN}✓ Removed systemd service definition.${NC}"
    fi
fi

# 2. Remove Binary & CLI Tools
for tool in exactor-waf-guardian exactor-top exactor-advisor exactor-rules; do
    if [[ -f "/usr/local/bin/${tool}" ]]; then
        rm -f "/usr/local/bin/${tool}"
        echo -e "${GREEN}✓ Removed /usr/local/bin/${tool}.${NC}"
    fi
done

# 3. Handle Configuration and Database
if [[ "$PURGE_DATA" == "true" ]]; then
    if [[ -d "/etc/exactor" ]]; then
        rm -rf "/etc/exactor"
        echo -e "${GREEN}✓ Purged configuration and SQLite ledger at /etc/exactor.${NC}"
    fi
else
    echo -e "${BLUE}ℹ️  Preserved configuration and ledger database at /etc/exactor.${NC}"
    echo -e "   (To remove completely, delete /etc/exactor or run ./uninstall.sh --purge)"
fi

echo -e "\n${GREEN}✅ Guardian WAF uninstalled successfully.${NC}"
