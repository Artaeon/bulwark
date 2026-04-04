<p align="center">
  <img src="assets/banner.svg" alt="bulwark" width="100%"/>
</p>

<p align="center">
  <strong>Real-time threat detection and firewall hardening for open wireless networks.</strong>
</p>

<p align="center">
  <a href="#installation">Install</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#configuration">Configure</a> &middot;
  <a href="#threat-model">Threat Model</a> &middot;
  <a href="#architecture">Architecture</a>
</p>

<p align="center">
  <img alt="Language" src="https://img.shields.io/badge/language-Rust-orange?style=flat-square"/>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square"/>
  <img alt="Tests" src="https://img.shields.io/badge/tests-177%20passing-brightgreen?style=flat-square"/>
</p>

---

## Overview

**bulwark** is a lightweight Linux daemon that monitors your network for active attacks commonly found on open WiFi — coffee shops, airports, hotels, conferences — and optionally locks down your firewall the moment a threat is detected.

It watches for **ARP spoofing**, **gateway hijacking**, **DNS poisoning**, and **rogue DHCP servers** in real-time. Everything runs as async tasks with zero external dependencies beyond the kernel's `/proc` filesystem and `nftables`.

```
$ sudo bulwark --foreground

2026-04-04T14:23:01 INFO  bulwark starting                    version=0.1.0
2026-04-04T14:23:01 INFO  monitoring interface                 interface=wlan0
2026-04-04T14:23:01 INFO  established ARP baseline             entries=4
2026-04-04T14:23:01 INFO  established gateway baseline         gateway_ip=192.168.1.1 gateway_mac=aa:bb:cc:dd:ee:ff
2026-04-04T14:23:01 INFO  bulwark daemon running               detectors=4 hardener=false

2026-04-04T14:23:06 ERROR THREAT: ARP spoof: 192.168.1.1 changed from aa:bb:cc:dd:ee:ff to de:ad:be:ef:00:01
                          severity=CRITICAL detector=arp
2026-04-04T14:23:06 WARN  high-severity threat detected, auto-activating firewall hardening
2026-04-04T14:23:06 INFO  firewall hardening activated
```

---

## Threat Model

Open WiFi is hostile territory. Anyone on the same network can execute these attacks with off-the-shelf tools:

### What bulwark detects

| Attack | Technique | Real-world tool | bulwark detector | Severity |
|:---|:---|:---|:---|:---:|
| **Man-in-the-Middle** | ARP cache poisoning swaps the gateway's MAC in your ARP table, routing all traffic through the attacker | `arpspoof`, `ettercap`, `bettercap` | ARP Spoof | Critical |
| **Network reconnaissance** | Rapid ARP scanning to map all hosts on the network before launching targeted attacks | `arp-scan`, `nmap -sn` | ARP Flood | High |
| **Evil twin / rogue AP** | Attacker sets up a fake access point; your machine's default gateway changes to attacker infrastructure | `hostapd`, `wifiphisher` | Gateway Hijack | Critical |
| **DNS hijacking** | Poisoned DNS responses redirect domains to attacker-controlled IPs for credential phishing | `dnsspoof`, `bettercap` | DNS Poisoning | High |
| **Rogue DHCP** | Unauthorized DHCP server assigns attacker-controlled DNS/gateway to new clients | `dnsmasq`, `yersinia` | Rogue DHCP | Critical |

### What bulwark does NOT protect against

| Threat | Why | Mitigation |
|:---|:---|:---|
| Passive sniffing | Open WiFi is unencrypted at L2; bulwark can't change physics | VPN / WireGuard |
| SSL stripping | Application-layer attack | HSTS preload, HTTPS-only mode |
| Attacks on other devices | bulwark protects the machine it runs on | Deploy per-device |
| Kernel exploits | Requires host-level compromise first | Keep kernel patched |

**Best combined with:** VPN or WireGuard, DNS-over-HTTPS/TLS, browser HTTPS-only mode.

---

## Detection & Response

### Detectors

Each detector runs as an independent async task, polling at configurable intervals:

**ARP Spoof Detector** — Polls `/proc/net/arp`, maintains a baseline of MAC-IP bindings, and fires a **Critical** alert when a known IP's MAC address changes. This is the primary indicator of ARP cache poisoning.

**ARP Flood Detector** — Tracks the rate of new ARP entries within a sliding window. A burst of 10+ new entries in 5 seconds indicates active network scanning or ARP poisoning preparation (**High**).

**Gateway Change Detector** — Monitors the default route via `/proc/net/route` and cross-references the gateway's MAC from the ARP table. Detects both gateway IP changes (**High** — possible evil twin) and gateway MAC changes on the same IP (**Critical** — active ARP poisoning of the gateway itself).

**DNS Poisoning Detector** — Periodically resolves configured test domains through both the system resolver (from `/etc/resolv.conf`) and trusted resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8 by default). Uses set intersection to compare results — only alerts when there is **zero overlap**, avoiding false positives from CDN IP variation.

**Rogue DHCP Detector** — Listens for DHCP OFFER packets on the monitored interface using `SO_BINDTODEVICE`. The first DHCP server seen becomes the baseline; any subsequent different server triggers a **Critical** alert. Falls back to parsing dhclient lease files when raw sockets are unavailable.

### Firewall Hardener

When enabled, bulwark can auto-activate an nftables ruleset in response to high-severity threats:

```
table inet bulwark {
    chain bulwark_input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        udp sport 67 udp dport 68 accept          # DHCP
        ip protocol icmp icmp type { echo-reply, destination-unreachable, time-exceeded } accept
        counter log prefix "bulwark_drop_in: " drop
    }
    chain bulwark_output {
        type filter hook output priority 0; policy drop;
        oif lo accept
        ct state established,related accept
        udp sport 68 udp dport 67 accept           # DHCP
        udp dport 53 accept                         # DNS
        tcp dport 53 accept
        tcp dport { 80, 443, 853, 993, 587 } accept # Configured ports
        ip protocol icmp icmp type echo-request accept
        counter log prefix "bulwark_drop_out: " drop
    }
}
```

Rules are applied via `nft -f -` (stdin) and managed under a dedicated `inet bulwark` table for clean activation and rollback. On shutdown, bulwark deletes the table entirely — no residual rules.

### Threat Deduplication

bulwark deduplicates repeated identical alerts within a 60-second window to prevent log flooding. A persistent ARP spoof fires once, not every 5-second poll cycle. Counters are logged at shutdown so you know exactly how many events were suppressed.

---

## Active Protections

Beyond detection, bulwark can **actively harden** your network stack. All protections are opt-in and require root.

### ARP Gateway Pinning

Sets the gateway's ARP entry to `PERMANENT` state, making the kernel ignore ARP replies that try to change the gateway's MAC. This is the single most effective countermeasure against ARP cache poisoning — it prevents the attack entirely, not just detects it.

```toml
[protect]
arp_pin = true
```

### Client Isolation

Adds nftables rules that block all LAN subnet traffic **except** to/from the default gateway. Prevents port scanning, service exploitation, LLMNR poisoning, and all lateral movement from other clients on the same network.

```toml
[protect]
client_isolation = true
```

### DNS-over-TLS Encryption

Runs a lightweight local DNS proxy that encrypts all queries via TLS (port 853) to trusted resolvers. An nftables DNAT rule transparently redirects all outgoing DNS to the local proxy, making DNS poisoning impossible at the network level.

```toml
[protect]
dns_encrypt = true
dns_resolvers = ["1.1.1.1:853", "8.8.8.8:853"]
```

### MAC Address Randomization

Generates a random locally-administered MAC address on startup. Prevents tracking across networks and sessions. The original MAC is saved and restored on shutdown.

```toml
[protect]
mac_randomize = true
```

### Full protection mode

Enable everything for maximum security on untrusted networks:

```toml
[protect]
arp_pin = true
client_isolation = true
dns_encrypt = true
mac_randomize = true

[hardener]
enabled = true
auto_harden = true
```

---

## Installation

### From source

```bash
git clone https://github.com/Artaeon/bulwark.git
cd bulwark
cargo build --release

# Install
sudo install -m 755 target/release/bulwark /usr/local/bin/
sudo install -d /etc/bulwark
sudo install -m 644 bulwark.toml /etc/bulwark/

# Optional: systemd service
sudo install -m 644 bulwark.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bulwark
```

### Requirements

| Requirement | Notes |
|:---|:---|
| **Linux** | Uses `/proc/net/arp`, `/proc/net/route`, `/sys/class/net/` |
| **Root** or capabilities | `CAP_NET_RAW` for DHCP listener, `CAP_NET_ADMIN` for nftables |
| **nftables** | Only required if firewall hardener is enabled |
| **Rust 1.70+** | For building from source |

---

## Quick Start

```bash
# Run in foreground with all defaults (auto-detects wireless interface)
sudo bulwark --foreground

# Custom config file
sudo bulwark --foreground --config ./bulwark.toml

# Debug verbosity
sudo bulwark --foreground --log-level debug

# Validate config without running
bulwark --check-config --config ./bulwark.toml

# Preview the nftables ruleset that would be applied
bulwark --print-rules
```

### As a systemd service

```bash
sudo systemctl start bulwark
sudo journalctl -u bulwark -f    # follow live output
```

The service runs with systemd hardening: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`.

---

## Configuration

All settings have sensible defaults. bulwark runs out of the box with zero configuration.

```toml
# /etc/bulwark/bulwark.toml

# Wireless interface to monitor (empty = auto-detect via /sys/class/net/*/wireless)
interface = ""

# Log level: trace, debug, info, warn, error
log_level = "info"

# ── ARP spoof & flood detection ────────────────────────────
[arp]
enabled = true
poll_interval_secs = 5         # How often to read /proc/net/arp

# ── Default gateway monitoring ─────────────────────────────
[gateway]
enabled = true
poll_interval_secs = 10        # How often to check /proc/net/route

# ── DNS poisoning detection ────────────────────────────────
[dns]
enabled = true
poll_interval_secs = 30        # How often to cross-validate DNS
trusted_resolvers = [          # Resolvers to compare against
    "1.1.1.1",                 #   Cloudflare
    "8.8.8.8",                 #   Google
]
test_domains = [               # Domains to resolve
    "example.com",
    "cloudflare.com",
    "google.com",
]

# ── Rogue DHCP server detection ────────────────────────────
[dhcp]
enabled = true
listen_timeout_secs = 10       # Socket recv timeout per cycle

# ── Firewall hardening (nftables) ──────────────────────────
[hardener]
enabled = false                # Must opt-in explicitly
auto_harden = false            # Auto-activate on High+ threats
allowed_outbound_ports = [     # Ports allowed when hardened
    53,                        #   DNS
    80,                        #   HTTP
    443,                       #   HTTPS
    853,                       #   DNS-over-TLS
    993,                       #   IMAPS
    587,                       #   SMTP submission
]

# ── Active protections ─────────────────────────────────────
[protect]
arp_pin = false                # Pin gateway MAC as static ARP entry
client_isolation = false       # Block LAN traffic except gateway
dns_encrypt = false            # Encrypt DNS via TLS (port 853)
dns_resolvers = [              # DoT resolvers
    "1.1.1.1:853",
    "8.8.8.8:853",
]
mac_randomize = false          # Randomize MAC on startup
```

### Validation

All config values are validated at load time:

- Poll intervals must be > 0 (prevents busy-loop DoS)
- DNS resolvers must be valid IPv4 or IPv6 addresses
- Test domains must be non-empty and within RFC 1035 limits (253 chars, 63 per label)
- Port numbers must not be 0
- Interface name must be <= 15 characters (Linux `IFNAMSIZ`)

---

## Architecture

```
src/
  main.rs              CLI (clap), logging (tracing), signal handling, daemon lifecycle
  error.rs             Central Error enum with thiserror
  config.rs            TOML config with serde, validation at load time
  daemon.rs            Async orchestrator: spawns detectors, threat dedup, hardener dispatch
  alert.rs             Severity, ThreatKind, Threat types
  net_util.rs          MacAddr, /proc parsers, DNS packet codec
  hardener.rs          nftables rule generation, activation, rollback
  detectors/
    mod.rs             Module structure, ThreatSender type alias
    arp.rs             ARP spoof + flood detection
    gateway.rs         Default gateway IP + MAC monitoring
    dns.rs             Cross-resolver DNS validation
    dhcp.rs            DHCP OFFER parsing, rogue server detection
  protect/
    mod.rs             Active protection module structure
    arp_pin.rs         Static ARP gateway pinning (prevents ARP spoof)
    dns_crypt.rs       DNS-over-TLS proxy (encrypts DNS queries)
    isolation.rs       Client isolation via nftables (blocks LAN traffic)
    mac_rand.rs        MAC address randomization (prevents tracking)
```

### Data flow

```
  ┌─────────────────────── DETECTION ───────────────────────┐
  │                                                         │
  │ /proc/net/arp ──> [ARP Detector]  ──┐                   │
  │ /proc/net/route ─> [GW Detector]  ──┤                   │
  │ /etc/resolv.conf ─> [DNS Detector] ─┤── mpsc ──> [Daemon] ──> [Hardener] ──> nft
  │ UDP :68 ─────────> [DHCP Detector] ─┘      │     │     │
  │                                         [Dedup]   │     │
  │                                             │     │     │
  │                                       tracing     │     │
  └───────────────────────────────────────────────────┘     │
                                                            │
  ┌─────────────────── PROTECTION ─────────────────────┐    │
  │                                                    │    │
  │ [ARP Pin] ──────> ip neigh permanent               │    │
  │ [Client Isolation] ──> nft (block LAN)             │    │
  │ [DNS Encrypt] ──> TLS proxy + nft DNAT             │    │
  │ [MAC Randomize] ──> ip link set address            │    │
  └────────────────────────────────────────────────────┘
```

### Design principles

- **Minimal attack surface** — A security tool with a sprawling dependency tree is a liability. bulwark uses only essential, well-audited crates.
- **No panics in production** — `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` is enforced at compile time. All error paths return `Result`.
- **Hardened parsers** — DNS, DHCP, ARP, and route parsers validate every byte: bounds checking, loop limits, checked arithmetic, and adversarial input rejection.
- **Testable core logic** — Detection algorithms are pure functions that accept string/byte input and return threats. No filesystem or network access in test paths.
- **Graceful lifecycle** — Clean startup, SIGINT/SIGTERM handling, firewall rollback on shutdown, threat summary on exit.
- **Deduplication** — Identical threats are suppressed within a 60-second window to prevent log flooding.

---

## Testing

```
$ cargo test

running 177 tests
...
test result: ok. 155 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Test coverage by module

| Module | Tests | What's covered |
|:---|:---:|:---|
| `net_util` | 44 | MAC parsing, ARP table parsing, route parsing, DNS codec, adversarial packets, bounds overflow, label limits |
| `config` | 22 | Defaults, TOML parsing, all validation rules, edge cases (zero intervals, invalid IPs, long names) |
| `detectors/arp` | 12 | Baseline, spoof detection, flood detection, interface filtering, multi-spoof, revert, empty tables |
| `detectors/dhcp` | 16 | DHCP OFFER parsing, truncated/malformed packets, padding, rogue detection, lease file parsing |
| `detectors/dns` | 12 | resolv.conf parsing, query construction, poisoning logic, CDN overlap, IPv6, malformed domains |
| `detectors/gateway` | 9 | Baseline, IP change, MAC change, simultaneous changes, route disappearance, empty tables |
| `daemon` | 9 | Threat dedup (first emit, suppression, window expiry, eviction), wireless detection, no-detector mode |
| `hardener` | 12 | Rule generation (ports, DHCP, loopback, ICMPv6, logging), auto-harden thresholds, deactivation |
| `alert` | 7 | Display for all severity/threat variants, ordering, timestamps, equality |
| `protect/arp_pin` | 3 | Initial state, deactivation, gateway discovery |
| `protect/dns_crypt` | 6 | TLS config, redirect rules, loopback exception, initial state |
| `protect/isolation` | 8 | Rule generation, gateway/subnet, DHCP broadcast, various subnets |
| `protect/mac_rand` | 5 | MAC format, locally-administered bit, uniqueness, lifecycle |

All detection logic is tested with **synthetic adversarial data** — crafted ARP tables, malformed DNS packets with overflow attempts, truncated DHCP packets, and garbage binary input.

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

### Hardening measures in the codebase

- **Compile-time lint enforcement** — `deny(clippy::unwrap_used)`, `deny(clippy::expect_used)`, `deny(clippy::panic)` prevent any production code path from panicking.
- **Checked arithmetic** — All DNS parser offset calculations use `checked_add()` to prevent integer overflow.
- **Loop limits** — DNS name traversal is limited to 128 labels; section counts capped at 64. Prevents DoS from crafted packets.
- **Input validation** — Config validated at load. Parsers reject malformed data gracefully (return `None`/`Err`, never panic).
- **Minimal unsafe** — Only two `unsafe` blocks, both documented with `SAFETY` comments: `geteuid()` (trivial syscall) and `setsockopt()` (socket binding with validated buffer).
- **Threat deduplication** — Bounded memory (max 1024 tracked keys with auto-eviction) prevents memory exhaustion from sustained attacks.

---

## License

[MIT](LICENSE) &copy; Raphael Lugmayr

---

<p align="center">
  <sub>Built with Rust. Designed for hostile networks.</sub>
</p>
