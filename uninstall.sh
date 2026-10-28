#!/usr/bin/env bash
# ==============================================================================
# SATGuardian Edge WAF - Linux Server Uninstaller
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}============================================================${NC}"
echo -e "${RED}🛡️  Uninstalling SATGuardian Edge WAF${NC}"
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
    for svc in satguardian-waf.service exactor-waf.service; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "${YELLOW}Stopping ${svc}...${NC}"
            systemctl stop "$svc" || true
        fi
        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            echo -e "${YELLOW}Disabling ${svc}...${NC}"
            systemctl disable "$svc" || true
        fi
        if [[ -f "/etc/systemd/system/${svc}" ]]; then
            rm -f "/etc/systemd/system/${svc}"
            systemctl daemon-reload || true
            echo -e "${GREEN}✓ Removed /etc/systemd/system/${svc}.${NC}"
        fi
    done
fi

# 2. Remove Binary & CLI Tools
for tool in satguardian-waf exactor-waf-guardian satguardian-top exactor-top satguardian-advisor exactor-advisor satguardian-rules exactor-rules; do
    if [[ -f "/usr/local/bin/${tool}" ]]; then
        rm -f "/usr/local/bin/${tool}"
        echo -e "${GREEN}✓ Removed /usr/local/bin/${tool}.${NC}"
    fi
done

# 3. Handle Configuration and Database
if [[ "$PURGE_DATA" == "true" ]]; then
    for dir in "/etc/satguardian" "/etc/exactor"; do
        if [[ -d "$dir" ]]; then
            rm -rf "$dir"
            echo -e "${GREEN}✓ Purged configuration and SQLite ledger at ${dir}.${NC}"
        fi
    done
else
    echo -e "${BLUE}ℹ️  Preserved configuration and ledger database at /etc/satguardian.${NC}"
    echo -e "   (To remove completely, delete /etc/satguardian or run ./uninstall.sh --purge)"
fi

echo -e "\n${GREEN}✅ SATGuardian Edge WAF uninstalled successfully.${NC}"
