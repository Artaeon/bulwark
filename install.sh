#!/usr/bin/env bash
# bulwark installation script
# Builds from source and installs binary, config, and systemd unit.

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# Paths
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bulwark}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
DOC_DIR="${DOC_DIR:-/usr/local/share/doc/bulwark}"

info()    { echo -e "${BLUE}==>${RESET} ${BOLD}$*${RESET}"; }
success() { echo -e "${GREEN}==>${RESET} ${BOLD}$*${RESET}"; }
warn()    { echo -e "${YELLOW}==>${RESET} ${BOLD}$*${RESET}"; }
error()   { echo -e "${RED}==> error:${RESET} ${BOLD}$*${RESET}" >&2; exit 1; }

# Pretty header
cat <<'EOF'

  ┌──────────────────────────────────────────┐
  │            bulwark installer             │
  │   network security for open WiFi         │
  └──────────────────────────────────────────┘

EOF

# Root check
if [ "$(id -u)" -ne 0 ]; then
    error "this installer must be run as root (try: sudo ./install.sh)"
fi

# Check dependencies
info "checking dependencies"

if ! command -v cargo >/dev/null 2>&1; then
    error "cargo is required but not installed (install rustup: https://rustup.rs)"
fi

if ! command -v nft >/dev/null 2>&1; then
    warn "nftables (nft) not found — firewall hardener and some protections will be disabled"
fi

if ! command -v ip >/dev/null 2>&1; then
    warn "iproute2 (ip) not found — ARP pinning and MAC randomization will not work"
fi

if ! command -v iw >/dev/null 2>&1; then
    warn "iw not found — BSSID/evil twin detector will not work"
fi

if ! command -v notify-send >/dev/null 2>&1; then
    warn "libnotify (notify-send) not found — desktop notifications will be disabled"
fi

# Build
info "building bulwark (release profile)"
cargo build --release --quiet || error "cargo build failed"
success "build complete: $(du -h target/release/bulwark | cut -f1)"

# Install binary
info "installing binary to ${BIN_DIR}/bulwark"
install -m 755 -D target/release/bulwark "${BIN_DIR}/bulwark"

# Install config
if [ -f "${CONFIG_DIR}/bulwark.toml" ]; then
    warn "config already exists at ${CONFIG_DIR}/bulwark.toml — not overwriting"
    info "new example available at ${CONFIG_DIR}/bulwark.toml.example"
    install -m 644 -D bulwark.toml "${CONFIG_DIR}/bulwark.toml.example"
else
    info "installing default config to ${CONFIG_DIR}/bulwark.toml"
    install -m 644 -D bulwark.toml "${CONFIG_DIR}/bulwark.toml"
fi

# Install systemd unit
if [ -d "${SYSTEMD_DIR}" ]; then
    info "installing systemd unit to ${SYSTEMD_DIR}/bulwark.service"
    install -m 644 -D bulwark.service "${SYSTEMD_DIR}/bulwark.service"
    systemctl daemon-reload
fi

# Install docs
info "installing documentation to ${DOC_DIR}"
install -m 644 -D README.md "${DOC_DIR}/README.md"
install -m 644 -D SECURITY.md "${DOC_DIR}/SECURITY.md"
[ -f EXAMPLES.md ] && install -m 644 -D EXAMPLES.md "${DOC_DIR}/EXAMPLES.md"
install -m 644 -D LICENSE "${DOC_DIR}/LICENSE"

# Done
echo
success "bulwark installed successfully"
echo
cat <<EOF
  ${BOLD}Quick start:${RESET}
    bulwark --check-config              # validate configuration
    sudo bulwark --foreground           # run in foreground
    sudo systemctl enable --now bulwark # enable as service

  ${BOLD}Configuration:${RESET}
    ${CONFIG_DIR}/bulwark.toml

  ${BOLD}Documentation:${RESET}
    ${DOC_DIR}/README.md

  ${BOLD}Uninstall:${RESET}
    sudo ./uninstall.sh

EOF
