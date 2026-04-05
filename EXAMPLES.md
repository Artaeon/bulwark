# bulwark Examples

Real-world usage scenarios with expected output.

---

## Table of Contents

- [Scenario 1: Coffee Shop WiFi](#scenario-1-coffee-shop-wifi)
- [Scenario 2: Hotel with Captive Portal](#scenario-2-hotel-with-captive-portal)
- [Scenario 3: Airport Lounge](#scenario-3-airport-lounge)
- [Scenario 4: Security Conference](#scenario-4-security-conference)
- [Scenario 5: Home Network Monitoring](#scenario-5-home-network-monitoring)
- [Scenario 6: Detecting an Active Attack](#scenario-6-detecting-an-active-attack)
- [Scenario 7: Validating Configuration](#scenario-7-validating-configuration)
- [Scenario 8: Previewing Firewall Rules](#scenario-8-previewing-firewall-rules)

---

## Scenario 1: Coffee Shop WiFi

You're working from a cafe. You want **maximum protection** with minimal effort.

### Configuration

```toml
# /etc/bulwark/bulwark.toml

[arp]
enabled = true

[gateway]
enabled = true

[dns]
enabled = true

[dhcp]
enabled = true

[bssid]
enabled = true

# Turn on all active protections
[protect]
arp_pin = true
client_isolation = true
dns_encrypt = true
mac_randomize = true

# Auto-lock down firewall on any High+ threat
[hardener]
enabled = true
auto_harden = true
```

### Run it

```bash
sudo bulwark --foreground
```

### Expected output

```
2026-04-04T10:15:00Z INFO bulwark starting                                   version=0.1.0
2026-04-04T10:15:00Z INFO monitoring interface                               interface=wlan0
2026-04-04T10:15:00Z INFO randomizing MAC address                            original=aa:bb:cc:dd:ee:ff randomized=02:7f:3a:9c:d1:4e
2026-04-04T10:15:01Z INFO MAC address randomized                             interface=wlan0 mac=02:7f:3a:9c:d1:4e
2026-04-04T10:15:02Z INFO gateway ARP entry pinned as permanent              gateway_ip=192.168.1.1 gateway_mac=de:ad:be:ef:00:01
2026-04-04T10:15:02Z INFO client isolation activated                         interface=wlan0 gateway=192.168.1.1 subnet=192.168.1.0/24
2026-04-04T10:15:02Z INFO DNS-over-TLS redirection activated (port 53 -> 127.0.0.1:5353)
2026-04-04T10:15:02Z INFO DNS-over-TLS proxy started                         listen=127.0.0.1:5353
2026-04-04T10:15:03Z INFO starting ARP spoof detector                        interval_secs=5
2026-04-04T10:15:03Z INFO starting gateway change detector                   interval_secs=10
2026-04-04T10:15:03Z INFO starting DNS poisoning detector                    interval_secs=30 domains=["example.com", "cloudflare.com", "google.com"]
2026-04-04T10:15:03Z INFO starting rogue DHCP detector                       interface=wlan0
2026-04-04T10:15:03Z INFO starting BSSID change detector                     interface=wlan0 interval_secs=10
2026-04-04T10:15:03Z INFO established ARP baseline                           entries=3
2026-04-04T10:15:03Z INFO established gateway baseline                       gateway_ip=192.168.1.1 gateway_mac=de:ad:be:ef:00:01
2026-04-04T10:15:03Z INFO established BSSID baseline                         bssid=c8:d7:19:ac:4f:21 ssid=CoffeeShopWiFi
2026-04-04T10:15:03Z INFO bulwark daemon running                             detectors=5 hardener=true arp_pin=true client_isolation=true dns_encrypt=true mac_randomize=true
```

You're now protected. Keep it running in a terminal tab, or enable it as a systemd service (see [Systemd service](#systemd-service)).

### What you're protected against

| Attack an attacker tries | What happens |
|:---|:---|
| `arpspoof` to MITM your traffic | Kernel ignores forged ARP replies (pinned). ARP detector fires Critical. |
| `nmap -sn` to scan your machine | Their packets are dropped by client isolation. You're invisible. |
| `dnsspoof` to redirect your DNS | Your DNS is TLS-encrypted to Cloudflare. They can't intercept. |
| Rogue DHCP to inject fake gateway | DHCP detector fires Critical, firewall auto-hardens. |
| Cross-network MAC tracking | Random MAC — they can't correlate you across visits. |
| Passive sniffing | They see only TLS traffic (HTTPS + encrypted DNS). Useless. |

### On shutdown

```
^C
2026-04-04T10:45:12Z INFO received SIGINT
2026-04-04T10:45:12Z INFO shutdown signal received
2026-04-04T10:45:12Z INFO threat summary                                     total=0 suppressed=0
2026-04-04T10:45:12Z INFO firewall hardening deactivated
2026-04-04T10:45:12Z INFO DNS-over-TLS redirection deactivated
2026-04-04T10:45:12Z INFO client isolation deactivated
2026-04-04T10:45:12Z INFO gateway ARP pin removed                            gateway_ip=192.168.1.1
2026-04-04T10:45:12Z INFO original MAC address restored                      interface=wlan0 mac=aa:bb:cc:dd:ee:ff
2026-04-04T10:45:12Z INFO bulwark daemon stopped
```

Everything rolls back cleanly. No residual state.

---

## Scenario 2: Hotel with Captive Portal

Hotels use captive portals that redirect DNS and block traffic until you authenticate. Running bulwark naively will fire false-positive DNS poisoning alerts during portal auth.

### Solution: grace period

```toml
# Wait 90 seconds after startup before alerting — enough time to
# open the portal and log in
startup_grace_secs = 90

# Don't auto-harden during grace period (or at all, until you trust the network)
[hardener]
enabled = true
auto_harden = false

[protect]
# MAC randomization and client isolation still work, no need to disable
mac_randomize = true
client_isolation = true
# Don't enable DNS encryption until AFTER you've authenticated
dns_encrypt = false
```

### Workflow

```bash
# Start bulwark, complete captive portal login within 90s
sudo bulwark --foreground &

# Open browser, log in to hotel WiFi
# ... portal authenticated ...

# After grace period ends, alerts resume normally
```

### Expected output

```
2026-04-04T18:30:00Z INFO bulwark starting                                   version=0.1.0
2026-04-04T18:30:00Z INFO captive portal grace period active — alerts suppressed  grace_secs=90
... (portal auth happens here) ...
2026-04-04T18:31:30Z INFO bulwark daemon running (grace period ended)
```

After the grace period, if anything suspicious happens, you'll see normal alerts.

---

## Scenario 3: Airport Lounge

Airports are notorious for:
- Multiple overlapping WiFi networks with similar names
- Evil twin APs impersonating legitimate ones
- Captive portals

### Configuration

```toml
# Airport: paranoid mode
startup_grace_secs = 60

[bssid]
enabled = true
poll_interval_secs = 5   # Check BSSID every 5s for quick evil-twin detection

[protect]
mac_randomize = true
arp_pin = true
client_isolation = true

[hardener]
enabled = true
auto_harden = true
```

### What happens if an evil twin appears

You're connected to `AirportFreeWiFi` with BSSID `aa:11:22:33:44:55`. Someone sets up a fake AP with the same SSID but BSSID `ff:ee:dd:cc:bb:aa` nearby. Your device roams to the stronger signal — the attacker's AP.

```
2026-04-04T15:42:15Z ERROR THREAT: BSSID changed on 'AirportFreeWiFi': aa:11:22:33:44:55 -> ff:ee:dd:cc:bb:aa (possible evil twin)  severity=HIGH detector=bssid
2026-04-04T15:42:15Z WARN  high-severity threat detected, auto-activating firewall hardening
2026-04-04T15:42:15Z INFO  firewall hardening activated
```

You also get a desktop notification:

> **bulwark: HIGH threat detected**
> BSSID changed on 'AirportFreeWiFi': aa:11:22:33:44:55 -> ff:ee:dd:cc:bb:aa (possible evil twin)

Your firewall is now locked down and you can decide whether to disconnect.

---

## Scenario 4: Security Conference

Security conferences (DEF CON, Black Hat, etc.) are famously hostile — half the attendees are running attacks for fun. You want **maximum paranoia**.

### Configuration

```toml
# DEF CON mode: trust nothing

[arp]
enabled = true
poll_interval_secs = 2   # Check ARP every 2s

[gateway]
enabled = true
poll_interval_secs = 3

[dns]
enabled = true
poll_interval_secs = 10  # Cross-validate DNS every 10s

[dhcp]
enabled = true

[bssid]
enabled = true
poll_interval_secs = 3

[protect]
mac_randomize = true
arp_pin = true
client_isolation = true
dns_encrypt = true
dns_resolvers = ["1.1.1.1:853", "9.9.9.9:853", "8.8.8.8:853"]  # Multiple fallbacks

[hardener]
enabled = true
auto_harden = true
# Restrictive port list — only what you actually need
allowed_outbound_ports = [443, 853]  # HTTPS + DNS-over-TLS only
```

### Best practices

1. **Use a VPN on top of bulwark**. bulwark can't encrypt arbitrary traffic — a VPN adds that layer.
2. **Disable non-essential services** on your machine (sshd, smbd, etc.).
3. **Run everything in a VM** if possible, destroy it after the conference.
4. **Watch the logs continuously** during the event.

---

## Scenario 5: Home Network Monitoring

Even on your home network, bulwark is useful — it can catch IoT devices misbehaving, devices getting compromised, or routers getting ARP poisoned by malware.

### Configuration

```toml
# Home: detect-only, no active protections (don't break the LAN)

[arp]
enabled = true
poll_interval_secs = 30   # Relaxed polling

[gateway]
enabled = true
poll_interval_secs = 60

[dns]
enabled = true
poll_interval_secs = 120

[dhcp]
enabled = true

[bssid]
enabled = true

# Don't enable active protections — we trust the LAN
[protect]
arp_pin = false
client_isolation = false
dns_encrypt = false
mac_randomize = false

# Don't auto-harden on home network
[hardener]
enabled = false
```

Run as systemd service, forget about it. If something weird happens, you'll get a notification.

---

## Scenario 6: Detecting an Active Attack

Here's what it looks like when bulwark catches someone MITM-ing your traffic with `arpspoof`:

### Attacker runs:
```bash
# On a different machine on the same LAN
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
```

### bulwark's output:
```
2026-04-04T12:03:17Z ERROR THREAT: ARP spoof: 192.168.1.1 changed from de:ad:be:ef:00:01 to c0:ff:ee:00:00:99  severity=CRITICAL detector=arp
2026-04-04T12:03:17Z WARN  high-severity threat detected, auto-activating firewall hardening
2026-04-04T12:03:17Z INFO  firewall hardening activated
2026-04-04T12:03:22Z ERROR THREAT: Gateway 192.168.1.1 MAC changed: de:ad:be:ef:00:01 -> c0:ff:ee:00:00:99  severity=CRITICAL detector=gateway
```

**Desktop notification:**
> **bulwark: CRITICAL threat detected**
> ARP spoof: 192.168.1.1 changed from de:ad:be:ef:00:01 to c0:ff:ee:00:00:99

At this point:
- If `arp_pin = true`, the spoofing attempt actually failed at the kernel level — you're still routing through the real gateway.
- If `auto_harden = true`, the firewall is now in lockdown mode.
- You're informed immediately and can take action (disconnect, move to another network).

---

## Scenario 7: Validating Configuration

Always validate your config before deploying:

```bash
bulwark --check-config --config ./bulwark.toml
```

### Output:
```
Configuration OK
  Interface: (auto-detect)
  ARP detector: enabled
  Gateway detector: enabled
  DNS detector: enabled
  DHCP detector: enabled
  Hardener: enabled
  Protections:
    ARP pinning: enabled
    Client isolation: enabled
    DNS encryption: enabled
    MAC randomization: enabled
```

### Invalid config:
```bash
bulwark --check-config --config ./broken.toml
```

```
error: configuration error: dns.trusted_resolvers contains invalid IP: not-an-ip
```

---

## Scenario 8: Previewing Firewall Rules

See exactly what nftables rules will be applied without actually applying them:

```bash
bulwark --print-rules
```

### Output:
```
#!/usr/sbin/nft -f

# bulwark: open network hardening rules
# Auto-generated — do not edit manually

table inet bulwark {
    chain bulwark_input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established/related connections
        ct state established,related accept

        # Allow DHCP client responses
        udp sport 67 udp dport 68 accept

        # Allow ICMPv4 echo reply and essential types
        ip protocol icmp icmp type { echo-reply, destination-unreachable, time-exceeded } accept

        # Allow ICMPv6 essential types
        ip6 nexthdr icmpv6 icmpv6 type { echo-reply, destination-unreachable, packet-too-big, time-exceeded, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept

        # Log and drop everything else
        counter log prefix "bulwark_drop_in: " drop
    }

    chain bulwark_output {
        type filter hook output priority 0; policy drop;

        # Allow loopback
        oif lo accept

        # Allow established/related
        ct state established,related accept

        # Allow DHCP client requests
        udp sport 68 udp dport 67 accept

        # Allow DNS (UDP and TCP)
        udp dport 53 accept
        tcp dport 53 accept

        # Allow configured outbound ports
        tcp dport { 53, 80, 443, 853, 993, 587 } accept

        # Allow ICMP echo request (ping)
        ip protocol icmp icmp type echo-request accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request accept

        # Log and drop everything else
        counter log prefix "bulwark_drop_out: " drop
    }
}
```

You can pipe this to `nft -f -` manually if you want to apply the rules without running the daemon:
```bash
bulwark --print-rules | sudo nft -f -
```

---

## Systemd service

Enable bulwark as a persistent background service:

```bash
sudo systemctl enable --now bulwark
sudo systemctl status bulwark
sudo journalctl -u bulwark -f
```

### Example journald output

```bash
$ sudo journalctl -u bulwark -f --output=short

Apr 04 10:15:00 laptop bulwark[1234]: bulwark starting version=0.1.0
Apr 04 10:15:00 laptop bulwark[1234]: monitoring interface interface=wlan0
Apr 04 10:15:03 laptop bulwark[1234]: bulwark daemon running detectors=5 hardener=true
Apr 04 11:22:47 laptop bulwark[1234]: THREAT: ARP spoof: 192.168.1.1 changed from aa:bb:cc:dd:ee:ff to de:ad:be:ef:00:01 severity=CRITICAL detector=arp
Apr 04 11:22:47 laptop bulwark[1234]: high-severity threat detected, auto-activating firewall hardening
```

---

## Testing your installation

After installing, run the full test suite to verify everything works:

```bash
cd /path/to/bulwark
cargo test
```

### Expected:
```
running 196 tests
test alert::tests::test_severity_ordering ... ok
test alert::tests::test_severity_display ... ok
test config::tests::test_validate_default_config_passes ... ok
...
test result: ok. 196 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

All 196 tests should pass on any Linux system with a recent Rust toolchain.

---

## Common tasks

### Check if bulwark is running
```bash
systemctl is-active bulwark
```

### View live logs
```bash
sudo journalctl -u bulwark -f
```

### Reload config (restart daemon)
```bash
sudo systemctl restart bulwark
```

### Temporarily disable for one session
```bash
sudo systemctl stop bulwark
# ... do your thing ...
sudo systemctl start bulwark
```

### Run in debug mode for one session
```bash
sudo systemctl stop bulwark
sudo bulwark --foreground --log-level debug
```

### Check what threats have been detected recently
```bash
sudo journalctl -u bulwark --since "1 hour ago" | grep THREAT
```

### Verify firewall state after a threat
```bash
sudo nft list table inet bulwark
```

---

## Getting help

- **Configuration reference:** see [README.md](README.md#configuration)
- **Threat model:** see [README.md](README.md#threat-model)
- **Security policy:** see [SECURITY.md](SECURITY.md)
- **Issues:** https://github.com/Artaeon/bulwark/issues
