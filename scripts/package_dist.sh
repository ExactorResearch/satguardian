#!/usr/bin/env bash
# ==============================================================================
# SATGuardian Edge WAF - Linux Distribution Packager
# Generates a standalone, zero-dependency tar.gz bundle for client distribution.
# ==============================================================================

set -euo pipefail

VERSION="v0.3.0"
NO_REBUILD=false

for arg in "$@"; do
    if [[ "$arg" == "--no-rebuild" ]]; then
        NO_REBUILD=true
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64|amd64) TARGET_NAME="linux-x86_64" ;;
    aarch64|arm64) TARGET_NAME="linux-aarch64" ;;
    *) TARGET_NAME="linux-${ARCH}" ;;
esac

STAGING_DIR="${DIST_DIR}/satguardian-waf-${VERSION}-${TARGET_NAME}"
TAR_FILE="${DIST_DIR}/satguardian-waf-${VERSION}-${TARGET_NAME}.tar.gz"

echo "============================================================"
echo "📦 Packaging SATGuardian Edge WAF for Linux (${TARGET_NAME})"
echo "============================================================"

# 1. Build or Locate Release Binary
RELEASE_BIN=""
if [[ -f "${PROJECT_ROOT}/target/release/satguardian-waf" ]]; then
    RELEASE_BIN="${PROJECT_ROOT}/target/release/satguardian-waf"
elif [[ -f "${PROJECT_ROOT}/../target/release/satguardian-waf" ]]; then
    RELEASE_BIN="${PROJECT_ROOT}/../target/release/satguardian-waf"
elif [[ -f "${PROJECT_ROOT}/target/release/exactor-waf-guardian" ]]; then
    RELEASE_BIN="${PROJECT_ROOT}/target/release/exactor-waf-guardian"
fi

if [[ -z "${RELEASE_BIN}" ]] || [[ "$NO_REBUILD" == "false" ]]; then
    echo "Building release binary..."
    (cd "${PROJECT_ROOT}" && cargo build --release -p satguardian-waf)
    if [[ -f "${PROJECT_ROOT}/target/release/satguardian-waf" ]]; then
        RELEASE_BIN="${PROJECT_ROOT}/target/release/satguardian-waf"
    elif [[ -f "${PROJECT_ROOT}/../target/release/satguardian-waf" ]]; then
        RELEASE_BIN="${PROJECT_ROOT}/../target/release/satguardian-waf"
    fi
fi

if [[ -z "${RELEASE_BIN}" ]] || [[ ! -f "${RELEASE_BIN}" ]]; then
    echo "Error: Release binary not found in target directories."
    exit 1
fi

# 2. Prepare Dist & Staging Directory
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/bin"

# 3. Copy Assets
cp "${RELEASE_BIN}" "${STAGING_DIR}/satguardian-waf"
cp "${RELEASE_BIN}" "${STAGING_DIR}/bin/satguardian-waf"
chmod +x "${STAGING_DIR}/satguardian-waf"
chmod +x "${STAGING_DIR}/bin/satguardian-waf"
# Legacy symlink for compatibility
ln -sf "satguardian-waf" "${STAGING_DIR}/exactor-waf-guardian"

cp "${PROJECT_ROOT}/waf_config.toml" "${STAGING_DIR}/waf_config.toml"
cp "${PROJECT_ROOT}/install.sh" "${STAGING_DIR}/install.sh"
chmod +x "${STAGING_DIR}/install.sh"
cp "${PROJECT_ROOT}/uninstall.sh" "${STAGING_DIR}/uninstall.sh"
chmod +x "${STAGING_DIR}/uninstall.sh"

if [[ -f "${PROJECT_ROOT}/satguardian-waf.service" ]]; then
    cp "${PROJECT_ROOT}/satguardian-waf.service" "${STAGING_DIR}/satguardian-waf.service"
fi

for tool in satguardian-top satguardian-advisor satguardian-rules; do
    if [[ -f "${PROJECT_ROOT}/${tool}.py" ]]; then
        cp "${PROJECT_ROOT}/${tool}.py" "${STAGING_DIR}/${tool}.py"
        chmod +x "${STAGING_DIR}/${tool}.py"
    fi
done

# 4. Generate README_INSTALL.txt
cat << EOF > "${STAGING_DIR}/README_INSTALL.txt"
================================================================================
  SATGUARDIAN EDGE WAF - ZERO-DEPENDENCY CLIENT INSTALLATION PACKAGE
  Deterministic SAT Cyber-Defense & Sub-millisecond Reverse Proxy
  100% Free Edge Traffic | Cloud Synthesis at https://satguardian.tech
================================================================================

This package is 100% self-contained. The client does NOT need Rust,
Cargo, Python, GCC, Make, or any other dependency installed on their Linux server.

OPTION A: AUTOMATIC INSTALLATION WITH SYSTEMD (RECOMMENDED)
--------------------------------------------------------------------------------
1. Extract the compressed archive and enter the folder:
     tar -xzf satguardian-waf-${VERSION}-${TARGET_NAME}.tar.gz
     cd satguardian-waf-${VERSION}-${TARGET_NAME}
2. Run the installer as root:
     sudo ./install.sh

   The installer will automatically:
   - Install the precompiled binary to /usr/local/bin/satguardian-waf
   - Create configuration at /etc/satguardian/waf_config.toml
   - Register and start the systemd service "satguardian-waf.service"

OPTION B: PORTABLE EXECUTION (WITHOUT INSTALLING)
--------------------------------------------------------------------------------
If you only wish to test the firewall without modifying system paths:
1. Run the binary directly:
     ./satguardian-waf proxy --config ./waf_config.toml
2. Test formal payload inspection:
     ./satguardian-waf inspect --query "id=1' OR 1=1--"

CLEAN UNINSTALLATION:
--------------------------------------------------------------------------------
To completely remove the service and binary:
   sudo ./uninstall.sh
================================================================================
EOF

# 5. Compress into tar.gz
rm -f "${TAR_FILE}"
(cd "${DIST_DIR}" && tar -czf "${TAR_FILE}" "$(basename "${STAGING_DIR}")")

# 6. Checksum
SHA=$(sha256sum "${TAR_FILE}" | awk '{print $1}')
echo ""
echo "============================================================"
echo "✅ Linux Client Distribution Package ready!"
echo "   Archive  : ${TAR_FILE}"
echo "   SHA256   : ${SHA}"
echo "============================================================"
