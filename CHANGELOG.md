# Changelog

All notable changes to bulwark will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — Initial release

### Detection (6 detectors)

- **ARP spoof detector** — Monitors `/proc/net/arp` for MAC-IP binding changes
  that indicate ARP cache poisoning (Critical).
- **ARP flood detector** — Detects rapid new ARP entries in a sliding window
  indicating network scanning (High).
- **Gateway change detector** — Tracks the default gateway IP and MAC via
  `/proc/net/route` and `/proc/net/arp`. Reports IP changes (High) and MAC
  changes on same IP (Critical).
- **DNS poisoning detector** — Cross-validates DNS responses from the system
  resolver against trusted resolvers (Cloudflare, Google) with zero-overlap
  detection logic to avoid CDN false positives (High).
- **Rogue DHCP detector** — Monitors DHCP OFFER packets on a bound UDP socket
  with `SO_BINDTODEVICE`. Falls back to dhclient lease file parsing when raw
  sockets are unavailable (Critical).
- **BSSID change detector** — Monitors the access point BSSID via
  `iw dev link`. BSSID change on the same SSID indicates an evil twin
  attack (High).

### Active protections (4 measures)

- **ARP gateway pinning** — Installs the gateway's MAC as a `PERMANENT` ARP
  entry via `ip neigh replace`, preventing ARP cache poisoning at the kernel
  level.
- **Client isolation** — nftables rules that block all LAN traffic except
  to/from the default gateway, preventing lateral attacks from other WiFi
  clients.
- **DNS-over-TLS proxy** — Local DNS proxy on `127.0.0.1:5353` that forwards
  queries over TLS (port 853) to trusted resolvers. An nftables DNAT rule
  redirects all host DNS traffic through the proxy.
- **MAC address randomization** — Generates a random locally-administered MAC
  address on startup to prevent cross-network tracking. Restores the original
  MAC on shutdown.

### Response

- **Firewall auto-hardening** — Optional nftables ruleset under a dedicated
  `inet bulwark` table that drops all traffic except established connections,
  loopback, DHCP, DNS, essential ICMP, and configured outbound ports.
  Auto-activates on High+ severity threats.
- **Desktop notifications** — Fires `notify-send` for High+ severity threats
  via libnotify. Fire-and-forget, never blocks the daemon.
- **Threat deduplication** — Suppresses repeated identical alerts within a
  60-second window. Bounded memory (max 1024 tracked keys with auto-eviction).
- **Captive portal grace period** — Configurable startup window during which
  alerts are suppressed, avoiding false positives on hotel/airport networks
  with captive portal redirects.

### Quality

- **190 unit tests** across 13 modules, including adversarial input tests for
  every parser (malformed packets, binary garbage, overflow attempts).
- **4 libFuzzer targets** for DNS, DHCP, ARP table, and DNS query parsers.
- **Strict lints** enforced in production code:
  `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]`.
- **Hardened parsers** — bounds checking, loop limits, `checked_add` on all
  offset arithmetic, graceful rejection of malformed input.
- **Minimal unsafe** — Two `unsafe` blocks (`geteuid`, `setsockopt`), each
  with documented `SAFETY` comments.
- **Compile-time panic prevention** via clippy lints.
- **Reproducible builds** — committed `Cargo.lock`, release builds use
  `--locked`.

### Tooling

- GitHub Actions CI — test matrix (stable + nightly), clippy with
  `--all-targets -D warnings`, rustfmt check, strict rustdoc, release build.
- GitHub Actions release workflow — triggered on `v*` tags, builds
  `x86_64-gnu`, `x86_64-musl`, and `aarch64-gnu` archives with SHA-256
  checksums, auto-generates release notes.
- `install.sh` / `uninstall.sh` scripts with dependency checks and support
  for both source tree and release archive modes.
- `Makefile` with 16 targets for common development tasks.
- Arch Linux `PKGBUILD` in `packaging/arch/`.

### Documentation

- Comprehensive `README.md` with threat model, use cases, install methods,
  configuration reference, architecture, and FAQ.
- `EXAMPLES.md` with 8 detailed real-world scenarios and expected output.
- `SECURITY.md` vulnerability disclosure policy.
- `CONTRIBUTING.md` development setup, coding standards, PR process.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- Module-level rustdoc on every source file.
- SVG banner.

[Unreleased]: https://github.com/Artaeon/bulwark/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Artaeon/bulwark/releases/tag/v0.1.0
