<p align="center">
  <img src="assets/banner.svg" alt="bulwark" width="100%"/>
</p>

<p align="center">
  <strong>Real-time threat detection and firewall hardening for open wireless networks.</strong>
</p>

<p align="center">
  <a href="#installation">Install</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#use-cases">Use Cases</a> &middot;
  <a href="#configuration">Configure</a> &middot;
  <a href="#threat-model">Threat Model</a> &middot;
  <a href="EXAMPLES.md">Examples</a>
</p>

<p align="center">
  <img alt="Language" src="https://img.shields.io/badge/language-Rust-orange?style=flat-square"/>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square"/>
  <img alt="Tests" src="https://img.shields.io/badge/tests-190%20passing-brightgreen?style=flat-square"/>
  <img alt="CI" src="https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=flat-square"/>
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

## At a Glance

**bulwark does two things:**

### 1. Detect attacks (6 detectors)

| Detector | Catches | Severity |
|:---|:---|:---:|
| ARP Spoof | Man-in-the-Middle via ARP poisoning | Critical |
| ARP Flood | Network scanning, attack prep | High |
| Gateway Hijack | Evil twin, rogue gateway, MITM | Critical |
| DNS Poisoning | DNS manipulation for phishing | High |
| Rogue DHCP | Rogue AP, DHCP-based MITM | Critical |
| BSSID Change | Evil twin with same SSID | High |

### 2. Actively prevent attacks (4 protections)

| Protection | What it does |
|:---|:---|
| ARP Gateway Pinning | Locks the gateway's MAC at the kernel level — ARP spoofing becomes impossible |
| Client Isolation | Blocks all LAN traffic except the gateway — other clients can't touch you |
| DNS-over-TLS Proxy | Encrypts all DNS queries via TLS to Cloudflare/Google — DNS poisoning becomes impossible |
| MAC Randomization | Randomizes your MAC — prevents cross-network tracking |

**Plus:** Firewall auto-hardening (nftables), desktop notifications, threat deduplication, captive portal grace period, graceful rollback on shutdown.

---

## Use Cases

### ☕ Coffee Shop / Public WiFi

Enable all protections. Your machine becomes a ghost on the network — you're unspoofable, uninterceptable, and invisible to other clients.

```bash
sudo bulwark --foreground
```

### 🏨 Hotel WiFi (with captive portal)

Set a 90-second grace period so portal authentication doesn't fire false positives:

```toml
startup_grace_secs = 90
```

### ✈️ Airport Lounge

Prime location for evil twin attacks. Enable BSSID monitoring with aggressive polling (5s) to catch AP swaps fast.

### 🎤 Security Conferences (DEF CON, Black Hat)

Maximum paranoia mode. Combine bulwark with a VPN, disable all non-essential services, and run in a disposable VM if possible.

### 🏠 Home Network Monitoring

Detect-only mode catches misbehaving IoT devices, compromised clients, or malware on your router.

### 🖥️ Server / Infrastructure

Run bulwark on Linux servers to catch lateral movement attempts and rogue DHCP on your LAN. Alerts feed into journald for SIEM integration.

**📖 See [EXAMPLES.md](EXAMPLES.md) for detailed configurations and real output for every scenario.**

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

### One-liner (install script)

```bash
git clone https://github.com/Artaeon/bulwark.git
cd bulwark
sudo ./install.sh
```

The installer builds from source, installs the binary, config, systemd unit, and documentation, and verifies all dependencies. Uninstall with `sudo ./uninstall.sh`.

### Using Make

```bash
git clone https://github.com/Artaeon/bulwark.git
cd bulwark
make release
sudo make install
```

Available targets: `build`, `release`, `install`, `uninstall`, `test`, `fuzz`, `fmt`, `clippy`, `doc`, `check`, `run`, `clean`, `service-enable`, `service-disable`, `service-status`. Run `make help` for the full list.

### From GitHub releases (binary)

Download a prebuilt binary from the [releases page](https://github.com/Artaeon/bulwark/releases):

```bash
VERSION="v0.1.0"
curl -LO "https://github.com/Artaeon/bulwark/releases/download/${VERSION}/bulwark-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
tar xzf "bulwark-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
cd "bulwark-${VERSION}-x86_64-unknown-linux-gnu"
sudo ./install.sh
```

Every release provides `x86_64-gnu`, `x86_64-musl` (static), and `aarch64-gnu` archives, each with SHA-256 checksums.

### Arch Linux (AUR)

```bash
# Using the bundled PKGBUILD
cd packaging/arch
makepkg -si
```

### Manual from source

```bash
git clone https://github.com/Artaeon/bulwark.git
cd bulwark
cargo build --release
sudo install -Dm755 target/release/bulwark /usr/local/bin/bulwark
sudo install -Dm644 bulwark.toml /etc/bulwark/bulwark.toml
sudo install -Dm644 bulwark.service /etc/systemd/system/bulwark.service
sudo systemctl daemon-reload
```

### Requirements

| Requirement | Purpose | Required? |
|:---|:---|:---|
| **Linux** | Kernel interfaces (`/proc/net/*`, `/sys/class/net/`) | Yes |
| **Rust 1.70+** | Building from source | Only for source install |
| **Root** or capabilities | `CAP_NET_RAW` (DHCP), `CAP_NET_ADMIN` (nftables, ARP, MAC) | Yes for most features |
| **nftables** (`nft`) | Firewall hardener, client isolation, DNS redirect | For active protections |
| **iproute2** (`ip`) | ARP pinning, MAC randomization | For those protections |
| **iw** | BSSID/evil-twin detection | For BSSID detector |
| **libnotify** (`notify-send`) | Desktop notifications | Optional, best-effort |

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
- **No panics in production** — `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]` enforced at compile time, checked in CI via `cargo clippy --all-targets -- -D warnings`. All error paths return `Result`.
- **Hardened parsers** — DNS, DHCP, ARP, and route parsers validate every byte: bounds checking, loop limits, checked arithmetic, and adversarial input rejection.
- **Testable core logic** — Detection algorithms are pure functions that accept string/byte input and return threats. No filesystem or network access in test paths.
- **Graceful lifecycle** — Clean startup, SIGINT/SIGTERM handling, firewall rollback on shutdown, threat summary on exit.
- **Deduplication** — Identical threats are suppressed within a 60-second window to prevent log flooding.

---

## Testing

```
$ cargo test

running 190 tests
...
test result: ok. 190 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
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

## FAQ

**Q: Will bulwark break my normal network usage?**
A: No. In default (detect-only) mode it makes zero changes to your system — it only reads `/proc` files. Active protections are all opt-in and cleanly reversible.

**Q: Does it work on home WiFi (WPA2/WPA3)?**
A: Yes. It's designed for open networks but works anywhere. On a trusted home network you probably want detect-only mode to catch compromised devices or misbehaving IoT.

**Q: Does it replace a VPN?**
A: No — it complements one. A VPN encrypts all your traffic end-to-end; bulwark protects your local network stack against LAN-layer attacks. Use both for maximum security on hostile networks.

**Q: What about captive portals (hotels, airports)?**
A: Set `startup_grace_secs = 90` to suppress alerts during portal authentication. After the grace period, alerts resume normally.

**Q: Can I use it without root?**
A: You can run `--check-config` and `--print-rules` as any user. Full operation needs root or `CAP_NET_RAW` + `CAP_NET_ADMIN` for raw sockets and nftables.

**Q: Does MAC randomization break my network connection?**
A: Yes, briefly — the interface is brought down and up to apply the new MAC. Most systems will auto-reconnect within a few seconds. If you need zero interruption, disable this one protection.

**Q: How much does it cost in resources?**
A: Minimal. The release binary is ~4 MB with LTO+strip, idle CPU use is effectively zero, and memory usage is under 20 MB. All detectors poll with configurable intervals — the default settings won't noticeably impact your battery.

**Q: Does it work on NixOS / Debian / Ubuntu / Fedora?**
A: Yes. The install script is distro-agnostic. An AUR PKGBUILD is provided for Arch; other package formats are welcome contributions.

**Q: How do I know it's actually detecting things?**
A: Run `sudo bulwark --foreground --log-level debug` and in another terminal run `arping` or `arp` commands — you'll see the detector track changes in real-time. See [EXAMPLES.md](EXAMPLES.md) for more test scenarios.

**Q: Can I integrate alerts with my SIEM / Slack / email?**
A: Today, alerts go to stderr (and journald when run as a service). You can pipe journald output to anything — Promtail, Vector, Fluent Bit, or a simple `grep | mail` script. Native webhook/SIEM support is a planned feature.

**Q: What's the deal with the 190 tests?**
A: Every parser has adversarial input tests (malformed packets, binary garbage, overflow attempts). Every detector has edge-case tests (empty tables, disappearing routes, simultaneous changes). Every protection has lifecycle tests. See the test coverage table above.

---

## Contributing

Contributions welcome! Please:

1. Run `cargo test` and `cargo clippy -- -D warnings` before submitting
2. Add tests for new functionality (adversarial input tests for parsers are especially valued)
3. Keep dependencies minimal — this is a security tool
4. Follow the existing code style (`cargo fmt`)

For security-related issues, please see [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## License

[MIT](LICENSE) &copy; Raphael Lugmayr

---

<p align="center">
  <sub>Built with Rust. Designed for hostile networks.</sub>
</p>
