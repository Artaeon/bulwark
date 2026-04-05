#!/usr/bin/env bash
# bulwark uninstallation script

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bulwark}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
DOC_DIR="${DOC_DIR:-/usr/local/share/doc/bulwark}"

info()    { echo -e "${BLUE}==>${RESET} ${BOLD}$*${RESET}"; }
success() { echo -e "${GREEN}==>${RESET} ${BOLD}$*${RESET}"; }
warn()    { echo -e "${YELLOW}==>${RESET} ${BOLD}$*${RESET}"; }
error()   { echo -e "${RED}==> error:${RESET} ${BOLD}$*${RESET}" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    error "this script must be run as root (try: sudo ./uninstall.sh)"
fi

cat <<'EOF'

  ┌──────────────────────────────────────────┐
  │           bulwark uninstaller            │
  └──────────────────────────────────────────┘

EOF

# Stop and disable service
if systemctl is-active --quiet bulwark.service 2>/dev/null; then
    info "stopping bulwark service"
    systemctl stop bulwark.service
fi

if systemctl is-enabled --quiet bulwark.service 2>/dev/null; then
    info "disabling bulwark service"
    systemctl disable bulwark.service
fi

# Remove systemd unit
if [ -f "${SYSTEMD_DIR}/bulwark.service" ]; then
    info "removing ${SYSTEMD_DIR}/bulwark.service"
    rm -f "${SYSTEMD_DIR}/bulwark.service"
    systemctl daemon-reload
fi

# Remove binary
if [ -f "${BIN_DIR}/bulwark" ]; then
    info "removing ${BIN_DIR}/bulwark"
    rm -f "${BIN_DIR}/bulwark"
fi

# Remove docs
if [ -d "${DOC_DIR}" ]; then
    info "removing ${DOC_DIR}"
    rm -rf "${DOC_DIR}"
fi

# Keep config unless asked to remove
if [ -d "${CONFIG_DIR}" ]; then
    if [ "${1:-}" = "--purge" ]; then
        info "removing ${CONFIG_DIR} (--purge)"
        rm -rf "${CONFIG_DIR}"
    else
        warn "keeping ${CONFIG_DIR} (use --purge to remove)"
    fi
fi

echo
success "bulwark uninstalled"
echo
