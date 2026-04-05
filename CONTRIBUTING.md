# Contributing to bulwark

First off, thank you for taking the time to contribute. bulwark is a small but serious security tool — every contribution helps make it more reliable and useful.

This document describes how to set up a development environment, the standards contributions must meet, and the review process.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Security Issues](#security-issues)
- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)
- [Project Structure](#project-structure)

---

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold it. Report unacceptable behavior to raphael.lugmayr@stoicera.com.

---

## Reporting Bugs

Before filing a bug report:

1. **Search existing issues** to avoid duplicates.
2. **Run the latest version** from master to see if it's already fixed.
3. **Collect diagnostics:**
   - `bulwark --version`
   - `bulwark --check-config --config /path/to/your.toml`
   - Relevant log output (`sudo journalctl -u bulwark --since "10 minutes ago"` or stderr from `--foreground`)
   - Your OS / kernel version (`uname -a`)
   - Whether you're running via systemd or manually

File bugs using the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).

---

## Suggesting Features

Feature requests are welcome, but please keep in mind that bulwark aims to stay **minimal and focused**. Before proposing a new feature, consider:

- Does it fit the scope of "network security monitoring for open wireless"?
- Does it add a new dependency? (We try very hard to keep the dep graph small.)
- Can it be implemented without `unsafe`?
- How will it be tested?

Open a [feature request](.github/ISSUE_TEMPLATE/feature_request.md) and we'll discuss before you invest effort in implementation.

---

## Security Issues

**Do not file security vulnerabilities as public issues.** See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## Development Setup

### Prerequisites

- **Rust 1.70 or later** (install via [rustup](https://rustup.rs))
- **Linux** (bulwark uses `/proc`, `/sys`, and nftables)
- **nftables, iproute2, iw** (for running the daemon; not required to build/test)

### Clone and build

```bash
git clone https://github.com/Artaeon/bulwark.git
cd bulwark

# Debug build
cargo build

# Release build (for performance testing)
cargo build --release

# Run tests
cargo test
```

### Running from source

```bash
# Detect-only (no sudo needed for most checks)
cargo run -- --check-config --config bulwark.toml

# Full run (requires root for raw sockets, nftables, etc.)
sudo ./target/debug/bulwark --foreground --config bulwark.toml

# Or via make:
sudo make run
```

### Useful make targets

```bash
make test           # cargo test
make clippy         # cargo clippy --all-targets -- -D warnings
make fmt            # cargo fmt
make doc            # build and open rustdoc
make fuzz           # build fuzz targets (requires nightly + cargo-fuzz)
make check          # validate example config
make release        # optimized build
```

---

## Code Standards

bulwark is a security tool. Code quality is not optional.

### Required before every commit

All PRs must pass these checks (CI enforces them):

```bash
cargo fmt --check                          # formatting
cargo clippy --all-targets -- -D warnings  # lints (strict)
cargo test                                 # all tests pass
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps  # docs clean
```

If you're iterating, `make` runs the binary and `make test` runs tests — both are fast.

### Coding rules

1. **No `unwrap()`, `expect()`, or `panic!()` in production code.** These are denied at compile time via `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]`. Tests can use them freely.

2. **All `unsafe` blocks must have a `SAFETY:` comment** explaining the invariants that make them sound. See `src/detectors/dhcp.rs` for examples.

3. **Checked arithmetic on untrusted data.** When parsing network input, use `checked_add`, `try_from`, etc. Never use `as` for narrowing casts of untrusted values.

4. **Parsers must not panic on malformed input.** Every parser should gracefully return `None` or `Err` on garbage. This is enforced via fuzz tests.

5. **Minimal dependencies.** Before adding a new crate, consider whether the feature can be implemented with what we already have. If a new dep is necessary, prefer well-maintained, widely-used crates with minimal transitive dependencies.

6. **Pure detection logic.** Detection algorithms should be separated from I/O so they can be tested with synthetic input. See `ArpDetector::analyze` for the pattern.

7. **Structured logging via `tracing`**, not `println!` or `eprintln!` (except in the CLI entry point for user-facing errors).

8. **Document public items.** Every public function, struct, and module should have a doc comment explaining what it does, when to use it, and any invariants.

### Style

- Run `cargo fmt` before committing. The project uses default rustfmt style plus [rustfmt.toml](rustfmt.toml) overrides.
- Line length: 100 chars soft limit.
- Use `snake_case` for functions and variables, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Prefer explicit type annotations where they aid readability, omit where obvious.

---

## Testing Requirements

Every new feature or bug fix must include tests.

### Test categories

- **Unit tests** (in `#[cfg(test)] mod tests`): test pure functions and detection logic.
- **Adversarial tests**: for parsers, include tests with malformed, truncated, and garbage input.
- **Integration tests** (in `tests/`): test end-to-end behavior of public APIs.
- **Doctests**: for public functions, include a small usage example when it aids understanding.

### What to test

| Adding a new… | Must include tests for… |
|:---|:---|
| Parser | Valid input, malformed input, truncated input, overflow attempts, bounds |
| Detector | Baseline, positive detection, negative (no-threat), edge cases |
| Protection | Activate/deactivate lifecycle, failure modes |
| Config field | Default, validation success, validation failure |
| CLI flag | Help output, valid use, invalid use |

### Running tests

```bash
cargo test                         # all tests
cargo test --package bulwark       # library tests only
cargo test config::                # just the config module
cargo test -- --nocapture          # show println! output during tests
```

### Fuzzing

Parsers have fuzz targets under `fuzz/`. To run:

```bash
# Requires nightly + cargo-fuzz
rustup toolchain install nightly
cargo install cargo-fuzz

cd fuzz
cargo +nightly fuzz run fuzz_dns_parser
cargo +nightly fuzz run fuzz_dhcp_parser
cargo +nightly fuzz run fuzz_arp_parser
cargo +nightly fuzz run fuzz_dns_query
```

Let each target run for at least a few minutes before calling it "fuzzed". Any crashes should be reported as security issues.

---

## Commit Message Guidelines

We use a minimal style derived from the Linux kernel / conventional commits:

```
short imperative summary (< 72 chars)

Optional longer description explaining what the change does and why.
Wrap at ~72 chars. Reference issues with #123.

Breaking changes, migration notes, and performance implications go here.
```

**Good examples:**
```
add ARP gateway pinning to prevent spoofing at the kernel level

fix stdin deadlock in nft subprocess invocation

The pipe was borrowed via &mut rather than take()n, so it stayed
open past wait_with_output(), causing nft to block indefinitely.
```

**Avoid:**
- "fix bug" (what bug?)
- "update code" (what updated? why?)
- "WIP" (commits should be atomic — if it's not done, don't commit it)
- All-caps shouting

Prefer **multiple small commits** over one giant commit. Each commit should be a single logical change that passes all tests.

---

## Pull Request Process

1. **Fork the repo** and create a feature branch from `master`:
   ```bash
   git checkout -b feature/my-thing
   ```

2. **Make your changes** in small, logical commits. Each commit should pass all tests.

3. **Run the full verification suite** locally:
   ```bash
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
   ```

4. **Update documentation** if your change affects user-visible behavior:
   - `README.md` for features, config, or install changes
   - `EXAMPLES.md` for new use cases
   - `CHANGELOG.md` under the `[Unreleased]` section
   - Doc comments for public API changes

5. **Push and open a PR** using the [PR template](.github/PULL_REQUEST_TEMPLATE.md). Describe:
   - What the change does
   - Why it's needed
   - How it's tested
   - Any breaking changes

6. **Respond to review feedback.** CI must pass green before merge.

7. **Squash or rebase** as requested by maintainers. We generally prefer a clean linear history.

---

## Project Structure

```
src/
  main.rs              CLI entry point (thin wrapper around lib)
  lib.rs               Library root — all modules exported here
  error.rs             Central Error type
  config.rs            TOML config + validation
  alert.rs             Severity, ThreatKind, Threat
  daemon.rs            Async orchestrator, threat dedup, grace period
  hardener.rs          nftables rule generation
  net_util.rs          MacAddr, /proc parsers, DNS codec
  notify.rs            Desktop notifications (notify-send)
  detectors/           Passive threat detection
    arp.rs             ARP spoof + flood
    gateway.rs         Default gateway IP + MAC
    dns.rs             DNS cross-validation
    dhcp.rs            Rogue DHCP server detection
    bssid.rs           BSSID change / evil twin
  protect/             Active protection measures
    arp_pin.rs         Static ARP gateway pinning
    dns_crypt.rs       DNS-over-TLS proxy
    isolation.rs       nftables client isolation
    mac_rand.rs        MAC address randomization

tests/                 Integration tests
fuzz/                  libFuzzer targets for all parsers
packaging/arch/        Arch Linux PKGBUILD
.github/workflows/     CI and release pipelines
assets/                Banner and images
```

### Where to add new code

- **New detector:** create `src/detectors/your_detector.rs`, register in `src/detectors/mod.rs`, add config section in `src/config.rs`, spawn in `src/daemon.rs`.
- **New protection:** create `src/protect/your_protection.rs`, register in `src/protect/mod.rs`, add config section, wire into daemon lifecycle.
- **New threat kind:** add variant to `ThreatKind` in `src/alert.rs` with `Display` impl, emit from your detector.
- **New config field:** add field + `Default` + validation in `src/config.rs`, document in `bulwark.toml`.

---

## Questions?

- Open a [discussion](https://github.com/Artaeon/bulwark/discussions) for design questions or help.
- Tag maintainers in an issue for clarification on specific problems.
- Email raphael.lugmayr@stoicera.com for anything sensitive.

Thank you again — every contribution matters.
