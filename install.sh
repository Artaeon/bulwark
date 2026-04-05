#!/usr/bin/env bash
# bulwark installation script
# Builds from source and installs binary, config, and systemd unit.

set -euo pipefail

# Colors (using $'...' so escape sequences are interpreted at assignment).
# This means ${BOLD} etc. work correctly in both echo and heredocs.
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

# Paths
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bulwark}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
DOC_DIR="${DOC_DIR:-/usr/local/share/doc/bulwark}"

info()    { printf '%s==>%s %s%s%s\n' "$BLUE" "$RESET" "$BOLD" "$*" "$RESET"; }
success() { printf '%s==>%s %s%s%s\n' "$GREEN" "$RESET" "$BOLD" "$*" "$RESET"; }
warn()    { printf '%s==>%s %s%s%s\n' "$YELLOW" "$RESET" "$BOLD" "$*" "$RESET"; }
error()   { printf '%s==> error:%s %s%s%s\n' "$RED" "$RESET" "$BOLD" "$*" "$RESET" >&2; exit 1; }

# Pretty header
cat <<'EOF'

  ┌──────────────────────────────────────────┐
  │            bulwark installer             │
  │   network security for open WiFi         │
  └──────────────────────────────────────────┘

EOF

# Run from script directory so relative paths work even with `sudo` from elsewhere
cd "$(dirname "$(readlink -f "$0")")"

# Figure out which mode we're running in:
#   - release archive: pre-built ./bulwark sits next to this script
#   - source tree: Cargo.toml present, need to build
if [ -f ./bulwark ] && [ -x ./bulwark ]; then
    MODE="binary"
    BULWARK_BIN="./bulwark"
elif [ -f Cargo.toml ] && [ -f bulwark.toml ] && [ -f bulwark.service ]; then
    MODE="source"
    BULWARK_BIN="target/release/bulwark"
else
    error "could not find source files or pre-built binary (run this from the bulwark source dir or release archive)"
fi

# Required config files (present in both modes)
if [ ! -f bulwark.toml ] || [ ! -f bulwark.service ]; then
    error "missing bulwark.toml or bulwark.service"
fi

# Root check
if [ "$(id -u)" -ne 0 ]; then
    error "this installer must be run as root (try: sudo ./install.sh)"
fi

# Check runtime dependencies
info "checking runtime dependencies"

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

# Build if installing from source
if [ "$MODE" = "source" ]; then
    if ! command -v cargo >/dev/null 2>&1; then
        error "cargo is required to build from source (install rustup: https://rustup.rs)"
    fi
    info "building bulwark (release profile)"
    cargo build --release --quiet || error "cargo build failed"
    success "build complete: $(du -h "$BULWARK_BIN" | cut -f1)"
else
    info "using pre-built binary ($(du -h "$BULWARK_BIN" | cut -f1))"
fi

# Install binary
info "installing binary to ${BIN_DIR}/bulwark"
install -m 755 -D "$BULWARK_BIN" "${BIN_DIR}/bulwark"

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
