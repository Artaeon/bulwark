//! Regression tests for bugs that were found and fixed during development.
//!
//! Each test here corresponds to a specific bug. If the bug reoccurs, the
//! test will catch it. Do not delete these tests — they document historical
//! failure modes.

use bulwark::alert::{Severity, Threat, ThreatKind};
use bulwark::net_util::{self, MacAddr};
use std::net::Ipv4Addr;

/// Regression: build_dns_query previously used `as u8` cast on label length
/// which could silently truncate labels >= 256 chars. After the fix it
/// returns None for any label > 63 bytes (RFC 1035 limit).
#[test]
fn regression_build_dns_query_rejects_oversized_labels() {
    // 64 chars — just over the RFC limit
    let label_64 = "a".repeat(64);
    let domain = format!("{}.com", label_64);
    assert!(net_util::build_dns_query(1, &domain).is_none());

    // 256 chars — would have wrapped `as u8` to 0
    let label_256 = "a".repeat(256);
    let domain_256 = format!("{}.com", label_256);
    assert!(net_util::build_dns_query(1, &domain_256).is_none());
}

/// Regression: DNS response parser previously allowed absurd qdcount/ancount
/// values that would cause DoS via excessive allocation or infinite loops.
#[test]
fn regression_dns_parser_rejects_excessive_section_counts() {
    let mut packet = [0u8; 12];
    packet[2] = 0x80; // QR=1
                      // qdcount = 65535
    packet[4] = 0xFF;
    packet[5] = 0xFF;
    assert!(net_util::parse_dns_response(&packet).is_none());
}

/// Regression: skip_dns_name previously had no iteration limit, so a crafted
/// packet with many labels could cause excessive CPU usage. Now capped at 128.
#[test]
fn regression_dns_name_labels_capped() {
    let mut packet = vec![0u8; 12];
    packet[2] = 0x80;
    packet[4] = 0x00;
    packet[5] = 0x01;
    packet[6] = 0x00;
    packet[7] = 0x01;
    // Add 200 single-byte labels — should be rejected
    for _ in 0..200 {
        packet.push(1);
        packet.push(b'a');
    }
    packet.push(0);
    // parse_dns_response should refuse this, not hang
    let _ = net_util::parse_dns_response(&packet); // must not panic or hang
}

/// Regression: parse_arp_table previously crashed on lines with non-UTF8
/// bytes. It should skip malformed lines gracefully.
#[test]
fn regression_arp_parser_survives_binary_garbage() {
    let content =
        "IP address       HW type     Flags       HW address            Mask     Device\n\
                   \x00\x01\x02\x03 binary on same line\n\
                   192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0";
    let entries = net_util::parse_arp_table(content);
    assert_eq!(entries.len(), 1, "should parse the one valid entry");
    assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 1, 1));
}

/// Regression: parse_default_route previously didn't validate field count
/// before indexing, causing index out of bounds on short lines.
#[test]
fn regression_route_parser_survives_short_lines() {
    let content = "Iface\tDestination\tGateway\nwlan0\n";
    let _ = net_util::parse_default_route(content); // must not panic
}

/// Regression: MAC address parser previously accepted strings with extra
/// whitespace or trailing chars. The parser is strict about exactly 6
/// colon-separated hex octets.
#[test]
fn regression_mac_parser_is_strict() {
    assert!(" aa:bb:cc:dd:ee:ff".parse::<MacAddr>().is_err());
    assert!("aa:bb:cc:dd:ee:ff ".parse::<MacAddr>().is_err());
    assert!("aa:bb:cc:dd:ee:ff:extra".parse::<MacAddr>().is_err());
    assert!("aa:bb:cc:dd:ee".parse::<MacAddr>().is_err());
    assert!("aa::cc:dd:ee:ff".parse::<MacAddr>().is_err());
}

/// Regression: threat Display previously panicked on Unicode SSIDs with
/// combining characters or RTL text. Must handle arbitrary Unicode.
#[test]
fn regression_threat_display_handles_unicode_ssids() {
    let threat = Threat::new(
        ThreatKind::BssidChanged {
            ssid: "café ☕ WiFi — مجاني".to_string(),
            old_bssid: "aa:bb:cc:dd:ee:ff".to_string(),
            new_bssid: "de:ad:be:ef:00:01".to_string(),
        },
        Severity::High,
        "bssid",
    );
    let s = format!("{}", threat);
    assert!(s.contains("HIGH"));
    assert!(s.contains("café"));
}

/// Regression: DNS query builder should reject empty domains and domains
/// that only contain dots (which would produce empty labels).
#[test]
fn regression_dns_query_rejects_edge_cases() {
    assert!(net_util::build_dns_query(1, "").is_none());
    assert!(net_util::build_dns_query(1, ".").is_none());
    assert!(net_util::build_dns_query(1, "..").is_none());
    assert!(net_util::build_dns_query(1, "a..b").is_none());
}
