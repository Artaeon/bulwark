//! Integration tests for the bulwark library.
//!
//! These tests exercise the public API across module boundaries and verify
//! end-to-end behavior that unit tests alone cannot cover.

use bulwark::alert::{Severity, Threat, ThreatKind};
use bulwark::config::Config;
use bulwark::hardener::Hardener;
use bulwark::net_util::{self, MacAddr};
use std::net::Ipv4Addr;

/// Full pipeline: build a DNS query, parse a crafted response, verify IPs roundtrip.
#[test]
fn dns_query_response_roundtrip() {
    let id = 0xBEEF;
    let query = net_util::build_dns_query(id, "example.com").expect("valid query");

    // Verify header
    assert_eq!(query[0..2], [0xBE, 0xEF], "ID in query");
    assert_eq!(query[4..6], [0x00, 0x01], "QDCOUNT=1");

    // Build a matching response with one A record
    let mut response = query.clone();
    // Set response flags
    response[2] = 0x81;
    response[3] = 0x80;
    // Set ANCOUNT=1
    response[6] = 0x00;
    response[7] = 0x01;
    // Append answer: name pointer + A record
    response.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
    response.extend_from_slice(&[0x00, 0x01]); // TYPE A
    response.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    response.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // TTL
    response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    response.extend_from_slice(&[93, 184, 216, 34]); // RDATA

    let ips = net_util::parse_dns_response(&response).expect("parseable");
    assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
}

/// Default config must pass validation out of the box.
#[test]
fn default_config_validates() {
    let config = Config::default();
    assert!(config.validate().is_ok());
}

/// Hardener ruleset generation is deterministic and contains expected constructs.
#[test]
fn hardener_ruleset_is_well_formed() {
    let config = Config::default();
    let h = Hardener::new(config.hardener);
    let ruleset = h.generate_ruleset();

    // Essential constructs
    assert!(ruleset.contains("table inet bulwark"));
    assert!(ruleset.contains("type filter hook input"));
    assert!(ruleset.contains("type filter hook output"));
    assert!(ruleset.contains("policy drop"));
    assert!(ruleset.contains("ct state established,related accept"));

    // Two calls produce identical output
    let ruleset2 = h.generate_ruleset();
    assert_eq!(ruleset, ruleset2);
}

/// Threat Display output contains all relevant fields for log inspection.
#[test]
fn threat_display_includes_all_fields() {
    let threat = Threat::new(
        ThreatKind::ArpSpoof {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            old_mac: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            new_mac: MacAddr([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        },
        Severity::Critical,
        "arp",
    );
    let s = format!("{}", threat);
    assert!(s.contains("CRITICAL"));
    assert!(s.contains("arp"));
    assert!(s.contains("192.168.1.1"));
    assert!(s.contains("aa:bb:cc:dd:ee:ff"));
    assert!(s.contains("de:ad:be:ef:00:01"));
}

/// Adversarial: parsers must never panic on garbage input.
#[test]
fn parsers_handle_garbage_gracefully() {
    // Binary garbage
    let garbage = vec![0xFFu8; 1024];
    let _ = net_util::parse_dns_response(&garbage);

    // Empty input
    assert!(net_util::parse_dns_response(&[]).is_none());
    assert!(net_util::parse_default_route("").is_none());
    assert_eq!(net_util::parse_arp_table("").len(), 0);

    // Truncated DNS header
    let _ = net_util::parse_dns_response(&[0x00; 5]);
}

/// MAC address roundtrip: parse -> display -> parse yields same value.
#[test]
fn mac_addr_roundtrip_through_display() {
    let inputs = ["aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff"];
    for s in inputs {
        let mac: MacAddr = s.parse().expect("valid");
        assert_eq!(format!("{}", mac), s);
    }
}
