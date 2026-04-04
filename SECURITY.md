# Security Policy

## Scope

bulwark is a **network security monitoring tool**. Its attack surface includes:

- **Parsed network data** — ARP tables, route tables, DNS packets, DHCP packets, and lease files from the local system. These are treated as untrusted input and validated at every step.
- **Configuration files** — TOML config parsed via serde with validation at load time.
- **nftables interaction** — Rules are generated internally and applied via `nft -f -` (stdin). No user-supplied strings are interpolated into nftables rules.

## Supported Versions

| Version | Supported |
|:---|:---:|
| 0.1.x (current) | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in bulwark, please report it responsibly:

1. **Do NOT open a public issue.**
2. Email **raphael.lugmayr@stoicera.com** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

You can expect an initial response within 48 hours. We will work with you to understand the issue and coordinate disclosure.

## Security Design

### What we enforce

- **No panics in production code** — `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` at the crate root.
- **Bounds-checked parsing** — All packet parsers use explicit length checks and `checked_add()` for offset arithmetic.
- **Loop limits** — DNS name traversal capped at 128 iterations; section counts capped at 64.
- **Minimal unsafe** — Two `unsafe` blocks total, each with documented `SAFETY` invariants.
- **Bounded memory** — Threat deduplication tracks at most 1024 unique keys with automatic eviction.
- **No string interpolation in shell commands** — nftables rules are generated from typed data, not string concatenation of user input.
- **Config validation** — All values validated at load time; invalid configs are rejected before the daemon starts.

### What we do NOT claim

- bulwark does not protect against kernel-level exploits or compromised root.
- bulwark does not encrypt traffic — it is a detection tool, not a VPN.
- The DHCP detector requires `CAP_NET_RAW`; without it, detection falls back to lease file monitoring (reduced coverage).
- The firewall hardener requires `CAP_NET_ADMIN` and `nft` to be installed.
