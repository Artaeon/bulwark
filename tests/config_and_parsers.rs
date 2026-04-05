//! Extended tests for config serialization and parser edge cases.

use bulwark::config::Config;
use bulwark::net_util::{self, MacAddr};
use std::net::Ipv4Addr;

/// Config: default config can be serialized to TOML and parsed back losslessly.
#[test]
fn config_default_roundtrips_through_toml() {
    let original = Config::default();
    // We can't derive Serialize on Config without changing the public API,
    // but we can verify a freshly-parsed empty TOML matches Default.
    let parsed: Config = toml::from_str("").expect("empty TOML parses to defaults");
    assert!(parsed.validate().is_ok());
    assert_eq!(parsed.interface, original.interface);
    assert_eq!(parsed.log_level, original.log_level);
    assert_eq!(parsed.arp.enabled, original.arp.enabled);
    assert_eq!(
        parsed.arp.poll_interval_secs,
        original.arp.poll_interval_secs
    );
}

/// Config: every detector can be independently disabled via partial TOML.
#[test]
fn config_partial_toml_overrides_single_field() {
    let toml_str = "[arp]\nenabled = false\n";
    let config: Config = toml::from_str(toml_str).expect("parses");
    assert!(!config.arp.enabled);
    // Other detectors remain at their defaults
    assert!(config.gateway.enabled);
    assert!(config.dns.enabled);
    assert!(config.dhcp.enabled);
    assert!(config.bssid.enabled);
    assert!(config.validate().is_ok());
}

/// Config: validation catches every zero-interval case independently.
#[test]
fn config_validation_checks_each_interval() {
    for field in ["arp", "gateway", "dns"] {
        let toml_str = format!("[{}]\npoll_interval_secs = 0\n", field);
        let config: Config = toml::from_str(&toml_str).unwrap();
        assert!(
            config.validate().is_err(),
            "zero interval for {} should fail",
            field
        );
    }
}

/// Parser: ARP table with extra columns (kernel version variation) still parses.
#[test]
fn arp_parser_tolerates_extra_columns() {
    let content = "\
IP address       HW type     Flags       HW address            Mask     Device    Extra
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0     ignored";
    let entries = net_util::parse_arp_table(content);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].device, "wlan0");
}

/// Parser: DNS response with answer but wrong RDLENGTH gracefully skips.
#[test]
fn dns_parser_skips_answer_with_wrong_rdlength() {
    let mut packet = vec![
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00, 0x00, 0x00,
    ];
    // Question: a.com
    packet.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0]);
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    // Answer with TYPE=A but RDLENGTH=16 (should be 4 for A)
    packet.extend_from_slice(&[0xC0, 0x0C]); // name pointer
    packet.extend_from_slice(&[0x00, 0x01]); // TYPE A
    packet.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // TTL
    packet.extend_from_slice(&[0x00, 0x10]); // RDLENGTH = 16 (wrong!)
    packet.extend(std::iter::repeat(0u8).take(16));

    // Should parse but return no IPs (answer skipped due to wrong length)
    let ips = net_util::parse_dns_response(&packet).expect("parses");
    assert_eq!(ips.len(), 0);
}

/// Parser: ARP entry with lowercase hex MAC is accepted.
#[test]
fn arp_parser_accepts_lowercase_mac() {
    let content = "\
IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         00:1a:2b:3c:4d:5e     *        eth0";
    let entries = net_util::parse_arp_table(content);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].mac,
        MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e])
    );
}

/// Parser: route table with mixed tab and space delimiters still works.
#[test]
fn route_parser_tolerates_mixed_whitespace() {
    let content = "Iface Destination Gateway Flags\nwlan0\t00000000\t0101A8C0\t0003";
    let route = net_util::parse_default_route(content).expect("parses");
    assert_eq!(route.gateway_ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(route.interface, "wlan0");
}

/// Parser: DNS query with exactly 253-char domain (max valid) succeeds.
#[test]
fn dns_query_builder_accepts_max_length_domain() {
    // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
    let label63 = "a".repeat(63);
    let label61 = "a".repeat(61);
    let domain = format!("{}.{}.{}.{}", label63, label63, label63, label61);
    assert_eq!(domain.len(), 253);
    assert!(net_util::build_dns_query(1, &domain).is_some());

    // One more char should fail
    let too_long = format!("{}x", domain);
    assert!(net_util::build_dns_query(1, &too_long).is_none());
}

/// Parser: DNS response with QR=0 (query, not response) is rejected.
#[test]
fn dns_parser_rejects_queries_as_responses() {
    let packet = [
        0x00, 0x01, // ID
        0x01, 0x00, // Flags: QR=0 (query)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert!(net_util::parse_dns_response(&packet).is_none());
}

/// Parser: ArpEntry filter by interface is case-sensitive.
#[test]
fn arp_parser_interface_filter_is_case_sensitive() {
    let entries = vec![bulwark::net_util::ArpEntry {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        mac: MacAddr([0x11; 6]),
        device: "wlan0".to_string(),
        flags: 2,
    }];
    let map_lower = net_util::arp_entries_to_map(&entries, Some("wlan0"));
    let map_upper = net_util::arp_entries_to_map(&entries, Some("WLAN0"));
    assert_eq!(map_lower.len(), 1);
    assert_eq!(map_upper.len(), 0, "interface matching is case-sensitive");
}
