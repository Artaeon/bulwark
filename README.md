# bulwark

**Network security daemon for open/untrusted wireless networks.**

bulwark is a lightweight Linux daemon written in Rust that continuously monitors your network environment and alerts you to active attacks commonly found on open WiFi networks — coffee shops, airports, hotels, conferences.

It detects ARP spoofing, gateway hijacking, DNS poisoning, and rogue DHCP servers in real-time, and can optionally auto-harden your firewall when threats are detected.

## Why

Open WiFi is hostile territory. Anyone on the same network can:

- **ARP spoof** your gateway and silently intercept all your traffic (Man-in-the-Middle)
- **Run a rogue DHCP server** to redirect your DNS and gateway to attacker-controlled infrastructure
- **Poison your DNS** responses to redirect you to phishing sites
- **Hijack your gateway** by swapping the default route mid-session

Most people have no idea when this is happening. bulwark watches for it and tells you immediately.

## Features

### Detection

| Detector | What it catches | How it works | Severity |
|---|---|---|---|
| **ARP Spoof** | Man-in-the-Middle via ARP poisoning | Tracks MAC-IP bindings from `/proc/net/arp`, alerts on changes | Critical |
| **ARP Flood** | Network scanning, ARP poisoning prep | Detects rapid new ARP entries in a time window | High |
| **Gateway Hijack** | Evil twin AP, rogue gateway | Monitors default gateway IP + MAC via `/proc/net/route` | Critical |
| **DNS Poisoning** | Phishing via DNS manipulation | Compares system resolver vs trusted resolvers (1.1.1.1, 8.8.8.8) | High |
| **Rogue DHCP** | Rogue AP, evil twin infrastructure | Monitors DHCP offers, flags multiple DHCP servers | Critical |

### Response

- **Firewall auto-hardening** (nftables) — when a high-severity threat is detected, bulwark can automatically:
  - Drop all inbound traffic except established connections
  - Restrict outbound to essential ports only (DNS, HTTP/S, etc.)
  - Allow only DHCP and ICMP for basic connectivity
  - Clean rollback on shutdown

## Installation

### From source

```bash
# Clone and build
git clone https://github.com/yourusername/bulwark.git
cd bulwark
cargo build --release

# Install binary
sudo cp target/release/bulwark /usr/local/bin/

# Install config
sudo mkdir -p /etc/bulwark
sudo cp bulwark.toml /etc/bulwark/

# Install systemd service (optional)
sudo cp bulwark.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bulwark
```

### Requirements

- Linux (uses `/proc/net/arp`, `/proc/net/route`, nftables)
- Root or `CAP_NET_RAW` + `CAP_NET_ADMIN` capabilities
- nftables (for firewall hardening feature)

## Usage

### Quick start

```bash
# Run in foreground with default settings (auto-detects wireless interface)
sudo bulwark --foreground

# Run with custom config
sudo bulwark --foreground --config /path/to/bulwark.toml

# Increase verbosity
sudo bulwark --foreground --log-level debug
```

### Validate configuration

```bash
bulwark --check-config
# Configuration OK
#   Interface: (auto-detect)
#   ARP detector: enabled
#   Gateway detector: enabled
#   DNS detector: enabled
#   DHCP detector: enabled
#   Hardener: disabled
```

### Preview firewall rules

```bash
bulwark --print-rules
```

### Run as systemd service

```bash
sudo systemctl start bulwark
sudo journalctl -u bulwark -f   # follow logs
```

## Configuration

bulwark uses a TOML configuration file. All settings have sensible defaults — you can run it with no config at all.

```toml
# Wireless interface to monitor (empty = auto-detect)
interface = ""
log_level = "info"

# ARP spoof detection — polls /proc/net/arp
[arp]
enabled = true
poll_interval_secs = 5

# Gateway change detection — watches default route
[gateway]
enabled = true
poll_interval_secs = 10

# DNS poisoning detection — cross-validates resolvers
[dns]
enabled = true
poll_interval_secs = 30
trusted_resolvers = ["1.1.1.1", "8.8.8.8"]
test_domains = ["example.com", "cloudflare.com", "google.com"]

# Rogue DHCP server detection
[dhcp]
enabled = true
listen_timeout_secs = 10

# Firewall hardening via nftables
[hardener]
enabled = false          # must opt-in
auto_harden = false      # auto-activate on threat detection
allowed_outbound_ports = [53, 80, 443, 853, 993, 587]
```

## Architecture

```
bulwark
├── main.rs          CLI entry point, signal handling, daemon lifecycle
├── error.rs         Central error types
├── config.rs        TOML configuration with serde
├── daemon.rs        Orchestrator: spawns detectors, processes threats
├── alert.rs         Threat types, severity levels
├── net_util.rs      MAC address type, /proc parsers, DNS packet builder
├── hardener.rs      nftables rule generation and management
└── detectors/
    ├── arp.rs       ARP spoof + flood detection
    ├── gateway.rs   Default gateway monitoring
    ├── dns.rs       DNS cross-validation
    └── dhcp.rs      Rogue DHCP server detection
```

Each detector runs as an independent async task, sending `Threat` events through a tokio channel to the central daemon loop. The daemon logs threats and optionally triggers the firewall hardener.

### Design principles

- **Minimal dependencies** — small attack surface for a security tool
- **No external C libraries** — pure Rust with `libc` for syscalls
- **Zero configuration required** — sane defaults, auto-detects wireless interface
- **Graceful lifecycle** — clean startup, SIGINT/SIGTERM handling, firewall rollback on shutdown
- **Testable core logic** — detection algorithms are pure functions with comprehensive unit tests

## What it doesn't do

bulwark is a **detection and hardening** tool, not a full network security suite:

- It won't encrypt your traffic — use a VPN or WireGuard for that
- It won't prevent passive sniffing — open WiFi is unencrypted at L2
- It won't detect attacks on other devices — it protects the machine it runs on
- It won't replace a proper firewall — it adds temporary hardening rules on top of your existing setup

**Best used alongside**: VPN/WireGuard, HTTPS-only browsing, DNS-over-TLS/HTTPS.

## Testing

```bash
cargo test
# running 53 tests ... test result: ok. 53 passed
```

All detection logic is unit-tested with synthetic network data — ARP tables, route tables, DHCP packets, DNS responses.

## License

MIT — see [LICENSE](LICENSE).
