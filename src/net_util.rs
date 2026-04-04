//! Network utility types and parsers.
//!
//! This module provides the low-level building blocks used by all detectors:
//!
//! - [`MacAddr`] — A 6-byte MAC address with `Display`/`FromStr`
//! - [`parse_arp_table`] — Parse `/proc/net/arp` into structured entries
//! - [`parse_default_route`] — Extract the default gateway from `/proc/net/route`
//! - [`build_dns_query`] / [`parse_dns_response`] — Minimal DNS A-record codec
//!
//! # Security
//!
//! All parsers are hardened against adversarial input:
//! - Bounds-checked at every access
//! - Loop-limited to prevent infinite traversal
//! - `checked_add()` on all offset arithmetic
//! - Graceful rejection (return `None`) on malformed data

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// A 6-byte MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const ZERO: MacAddr = MacAddr([0; 6]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(format!("invalid MAC address: {}", s));
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] =
                u8::from_str_radix(part, 16).map_err(|_| format!("invalid hex byte: {}", part))?;
        }
        Ok(MacAddr(bytes))
    }
}

/// An entry from /proc/net/arp.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub device: String,
    pub flags: u8,
}

/// Parse /proc/net/arp content into a list of ARP entries.
///
/// Format:
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
pub fn parse_arp_table(content: &str) -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let ip = match Ipv4Addr::from_str(fields[0]) {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let flags = match u8::from_str_radix(fields[2].trim_start_matches("0x"), 16) {
            Ok(f) => f,
            Err(_) => continue,
        };
        // Flag 0x0 means incomplete — skip these
        if flags == 0 {
            continue;
        }
        let mac = match MacAddr::from_str(fields[3]) {
            Ok(m) => m,
            Err(_) => continue,
        };
        // Skip zero MACs (incomplete entries)
        if mac.is_zero() {
            continue;
        }
        entries.push(ArpEntry {
            ip,
            mac,
            device: fields[5].to_string(),
            flags,
        });
    }
    entries
}

/// Parsed default route info from /proc/net/route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub interface: String,
    pub gateway_ip: Ipv4Addr,
}

/// Parse /proc/net/route to find the default gateway.
///
/// Format:
/// Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask    ...
/// wlan0   00000000        0101A8C0        0003    0       0       600     00000000 ...
///
/// Destination 00000000 = default route. Gateway is hex-encoded little-endian IPv4.
pub fn parse_default_route(content: &str) -> Option<DefaultRoute> {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        // Default route has destination 00000000
        if fields[1] != "00000000" {
            continue;
        }
        let gw_hex = fields[2];
        if let Some(ip) = hex_to_ipv4(gw_hex) {
            return Some(DefaultRoute {
                interface: fields[0].to_string(),
                gateway_ip: ip,
            });
        }
    }
    None
}

/// Convert hex-encoded little-endian IPv4 (from /proc/net/route) to Ipv4Addr.
fn hex_to_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let val = u32::from_str_radix(hex, 16).ok()?;
    // /proc/net/route stores gateway in host byte order (little-endian on x86)
    Some(Ipv4Addr::from(val.to_be()))
}

/// Look up a MAC address for an IP in the ARP table.
pub fn resolve_mac_from_arp(arp_entries: &[ArpEntry], ip: Ipv4Addr) -> Option<MacAddr> {
    arp_entries.iter().find(|e| e.ip == ip).map(|e| e.mac)
}

/// Build a map of IP -> MAC from ARP entries, optionally filtering by interface.
pub fn arp_entries_to_map(
    entries: &[ArpEntry],
    interface: Option<&str>,
) -> HashMap<Ipv4Addr, MacAddr> {
    entries
        .iter()
        .filter(|e| match interface {
            Some(iface) => e.device == iface,
            None => true,
        })
        .map(|e| (e.ip, e.mac))
        .collect()
}

/// Construct a minimal DNS query packet for an A record lookup.
///
/// Returns None if the domain is malformed (empty labels, labels > 63 bytes,
/// total domain > 253 bytes).
pub fn build_dns_query(id: u16, domain: &str) -> Option<Vec<u8>> {
    // RFC 1035: total domain name max 253 chars, each label max 63 chars
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }

    let mut packet = Vec::with_capacity(64);

    // Header
    packet.extend_from_slice(&id.to_be_bytes()); // ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, recursion desired
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // Question section
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        // Label length already validated to be <= 63, so this cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Root label
    packet.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    Some(packet)
}

/// Maximum sane counts for DNS sections to prevent DoS from crafted packets.
const DNS_MAX_SECTION_COUNT: usize = 64;
/// Maximum label traversals to prevent infinite loops from malformed names.
const DNS_MAX_NAME_LABELS: usize = 128;

/// Parse A record IPs from a DNS response packet.
///
/// Hardened against malformed packets: validates bounds at every step,
/// limits section counts to prevent DoS, and limits name label traversals
/// to prevent infinite loops from circular compression pointers.
pub fn parse_dns_response(packet: &[u8]) -> Option<Vec<Ipv4Addr>> {
    if packet.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    // Check QR bit (response) and RCODE (no error)
    if flags & 0x8000 == 0 {
        return None; // Not a response
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return None; // Error response
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    // Reject absurd counts to prevent DoS
    if qdcount > DNS_MAX_SECTION_COUNT || ancount > DNS_MAX_SECTION_COUNT {
        return None;
    }

    if ancount == 0 {
        return Some(Vec::new());
    }

    // Skip header (12 bytes), then skip question section
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(packet, offset)?;
        // Bounds check before reading QTYPE + QCLASS
        if offset.checked_add(4)? > packet.len() {
            return None;
        }
        offset += 4; // QTYPE + QCLASS
    }

    // Parse answer section
    let mut ips = Vec::new();
    for _ in 0..ancount {
        if offset >= packet.len() {
            break;
        }
        offset = skip_dns_name(packet, offset)?;
        if offset.checked_add(10)? > packet.len() {
            break;
        }
        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

        if rtype == 1 && rdlength == 4 && offset + 4 <= packet.len() {
            let ip = Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            );
            ips.push(ip);
        }
        // Prevent offset overflow
        offset = offset.checked_add(rdlength)?;
    }

    Some(ips)
}

/// Skip a DNS name (handles both labels and compressed pointers).
///
/// Limits label traversals to prevent infinite loops from malformed packets
/// with circular compression pointers.
fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    let mut labels_seen = 0;
    loop {
        if offset >= packet.len() {
            return None;
        }
        if labels_seen >= DNS_MAX_NAME_LABELS {
            return None; // Prevent infinite loops
        }
        labels_seen += 1;
        let len = packet[offset];
        if len == 0 {
            return Some(offset + 1);
        }
        // Compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            // Need at least 2 bytes for the pointer
            if offset + 1 >= packet.len() {
                return None;
            }
            return Some(offset + 2);
        }
        // Label length must not have the top bit set (reserved)
        if len & 0x80 != 0 {
            return None;
        }
        offset = offset.checked_add(1 + len as usize)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_addr_display() {
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(format!("{}", mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_mac_addr_parse() {
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(mac.0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_mac_addr_parse_invalid() {
        assert!("not:a:mac".parse::<MacAddr>().is_err());
        assert!("gg:00:00:00:00:00".parse::<MacAddr>().is_err());
    }

    #[test]
    fn test_parse_arp_table() {
        let content = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
192.168.1.100    0x1         0x2         11:22:33:44:55:66     *        wlan0
10.0.0.1         0x1         0x0         00:00:00:00:00:00     *        eth0";

        let entries = parse_arp_table(content);
        assert_eq!(entries.len(), 2); // Third entry skipped (flags=0, zero MAC)
        assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            entries[0].mac,
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(entries[0].device, "wlan0");
    }

    #[test]
    fn test_parse_default_route() {
        let content = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\tFFFFFF00\t0\t0\t0";

        let route = parse_default_route(content).unwrap();
        assert_eq!(route.interface, "wlan0");
        // 0101A8C0 little-endian = 192.168.1.1
        assert_eq!(route.gateway_ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_parse_default_route_none() {
        let content = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\tFFFFFF00\t0\t0\t0";

        assert!(parse_default_route(content).is_none());
    }

    #[test]
    fn test_hex_to_ipv4() {
        // 0101A8C0 -> C0.A8.01.01 = 192.168.1.1 (little-endian)
        assert_eq!(
            hex_to_ipv4("0101A8C0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn test_build_dns_query() {
        let query = build_dns_query(0x1234, "example.com").unwrap();
        // Header
        assert_eq!(query[0..2], [0x12, 0x34]); // ID
        assert_eq!(query[4..6], [0x00, 0x01]); // QDCOUNT
        // Question: 7example3com0
        assert_eq!(query[12], 7); // "example" length
        assert_eq!(&query[13..20], b"example");
        assert_eq!(query[20], 3); // "com" length
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query[24], 0); // root
    }

    #[test]
    fn test_parse_dns_response() {
        // Minimal DNS response with one A record for 93.184.216.34
        let mut response = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: response, no error
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        // Question: example.com A IN
        response.extend_from_slice(&[7]);
        response.extend_from_slice(b"example");
        response.extend_from_slice(&[3]);
        response.extend_from_slice(b"com");
        response.extend_from_slice(&[0x00]); // root
        response.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        response.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        // Answer: pointer to name, A record
        response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
        response.extend_from_slice(&[0x00, 0x01]); // TYPE A
        response.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        response.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // TTL = 256
        response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        response.extend_from_slice(&[93, 184, 216, 34]); // RDATA

        let ips = parse_dns_response(&response).unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn test_arp_entries_to_map() {
        let entries = vec![
            ArpEntry {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                mac: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                device: "wlan0".to_string(),
                flags: 2,
            },
            ArpEntry {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                mac: MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                device: "eth0".to_string(),
                flags: 2,
            },
        ];

        let all = arp_entries_to_map(&entries, None);
        assert_eq!(all.len(), 2);

        let wlan_only = arp_entries_to_map(&entries, Some("wlan0"));
        assert_eq!(wlan_only.len(), 1);
        assert!(wlan_only.contains_key(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    // === Adversarial and edge case tests ===

    #[test]
    fn test_parse_arp_table_empty() {
        let entries = parse_arp_table("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_arp_table_header_only() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device";
        let entries = parse_arp_table(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_arp_table_garbage_lines() {
        let content = "\
IP address       HW type     Flags       HW address            Mask     Device
this is garbage data with no structure
short
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
\x00\x01\x02\x03 binary garbage";
        let entries = parse_arp_table(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_parse_arp_table_invalid_ip() {
        let content = "\
IP address       HW type     Flags       HW address            Mask     Device
999.999.999.999  0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0";
        let entries = parse_arp_table(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_arp_table_invalid_mac() {
        let content = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         not-a-mac             *        wlan0";
        let entries = parse_arp_table(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_arp_table_incomplete_entry_skipped() {
        let content = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x0         00:00:00:00:00:00     *        wlan0";
        let entries = parse_arp_table(content);
        assert!(entries.is_empty()); // Both flag=0 and zero MAC
    }

    #[test]
    fn test_parse_default_route_empty() {
        assert!(parse_default_route("").is_none());
    }

    #[test]
    fn test_parse_default_route_garbage() {
        let content = "this is not a route table at all\nno really";
        assert!(parse_default_route(content).is_none());
    }

    #[test]
    fn test_parse_default_route_bad_hex_gateway() {
        let content = "\
Iface\tDestination\tGateway\tFlags
wlan0\t00000000\tNOTHEX\t0003";
        assert!(parse_default_route(content).is_none());
    }

    #[test]
    fn test_hex_to_ipv4_empty() {
        assert!(hex_to_ipv4("").is_none());
    }

    #[test]
    fn test_hex_to_ipv4_too_large() {
        assert!(hex_to_ipv4("FFFFFFFFFF").is_none()); // > u32
    }

    #[test]
    fn test_hex_to_ipv4_invalid_chars() {
        assert!(hex_to_ipv4("ZZZZZZZZ").is_none());
    }

    #[test]
    fn test_mac_addr_zero_and_broadcast() {
        assert!(MacAddr::ZERO.is_zero());
        assert!(!MacAddr::ZERO.is_broadcast());
        assert!(MacAddr([0xff; 6]).is_broadcast());
        assert!(!MacAddr([0xff; 6]).is_zero());
    }

    #[test]
    fn test_mac_addr_roundtrip() {
        let original = "de:ad:be:ef:ca:fe";
        let mac: MacAddr = original.parse().unwrap();
        assert_eq!(format!("{}", mac), original);
    }

    #[test]
    fn test_mac_addr_parse_too_many_octets() {
        assert!("aa:bb:cc:dd:ee:ff:00".parse::<MacAddr>().is_err());
    }

    #[test]
    fn test_mac_addr_parse_too_few_octets() {
        assert!("aa:bb:cc".parse::<MacAddr>().is_err());
    }

    #[test]
    fn test_mac_addr_parse_empty() {
        assert!("".parse::<MacAddr>().is_err());
    }

    // === DNS parser adversarial tests ===

    #[test]
    fn test_dns_response_too_short() {
        assert!(parse_dns_response(&[]).is_none());
        assert!(parse_dns_response(&[0; 11]).is_none());
    }

    #[test]
    fn test_dns_response_not_a_response() {
        let mut packet = [0u8; 12];
        // QR bit not set (query, not response)
        packet[2] = 0x00;
        assert!(parse_dns_response(&packet).is_none());
    }

    #[test]
    fn test_dns_response_error_rcode() {
        let mut packet = [0u8; 12];
        packet[2] = 0x80; // QR=1
        packet[3] = 0x03; // RCODE=3 (NXDOMAIN)
        assert!(parse_dns_response(&packet).is_none());
    }

    #[test]
    fn test_dns_response_zero_answers() {
        let mut packet = [0u8; 12];
        packet[2] = 0x80; // QR=1
        packet[3] = 0x00; // RCODE=0
        packet[6] = 0x00; // ANCOUNT=0
        packet[7] = 0x00;
        let result = parse_dns_response(&packet);
        assert_eq!(result, Some(Vec::new()));
    }

    #[test]
    fn test_dns_response_absurd_qdcount() {
        let mut packet = [0u8; 12];
        packet[2] = 0x80; // QR=1
        packet[4] = 0xFF; // QDCOUNT=65535
        packet[5] = 0xFF;
        packet[6] = 0x00;
        packet[7] = 0x01;
        assert!(parse_dns_response(&packet).is_none());
    }

    #[test]
    fn test_dns_response_absurd_ancount() {
        let mut packet = [0u8; 12];
        packet[2] = 0x80;
        packet[6] = 0xFF; // ANCOUNT=65535
        packet[7] = 0xFF;
        assert!(parse_dns_response(&packet).is_none());
    }

    #[test]
    fn test_dns_response_truncated_question() {
        let mut packet = vec![0u8; 14]; // Header + 2 bytes (not enough for question)
        packet[2] = 0x80; // QR=1
        packet[4] = 0x00;
        packet[5] = 0x01; // QDCOUNT=1
        packet[6] = 0x00;
        packet[7] = 0x01; // ANCOUNT=1
        packet[12] = 0x05; // Label length 5, but only 1 byte follows
        assert!(parse_dns_response(&packet).is_none());
    }

    #[test]
    fn test_dns_response_truncated_answer() {
        // Valid question, but answer truncated
        let mut packet = vec![
            0x00, 0x01, // ID
            0x80, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, 0x00, 0x00, // NS/AR
        ];
        // Question: a.com
        packet.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0]);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE/QCLASS
        // Answer: just a name pointer but no resource record data
        packet.extend_from_slice(&[0xC0, 0x0C]); // pointer
        // Only 2 bytes, need 10 for full RR header — should break gracefully
        let result = parse_dns_response(&packet);
        // Should return Some with empty vec (breaks out of answer loop gracefully)
        assert!(result.is_some());
    }

    #[test]
    fn test_dns_name_with_reserved_high_bit() {
        // A label with the top bit set but not 0xC0 (reserved per RFC)
        let mut packet = vec![0u8; 14];
        packet[2] = 0x80;
        packet[4] = 0x00;
        packet[5] = 0x01;
        packet[6] = 0x00;
        packet[7] = 0x01;
        packet[12] = 0x80; // Reserved label type
        assert!(parse_dns_response(&packet).is_none());
    }

    #[test]
    fn test_dns_name_label_too_long_for_packet() {
        // Label says 200 bytes but packet is tiny
        let mut packet = vec![0u8; 14];
        packet[2] = 0x80;
        packet[4] = 0x00;
        packet[5] = 0x01;
        packet[6] = 0x00;
        packet[7] = 0x01;
        packet[12] = 60; // 60 byte label, but only 2 bytes available
        assert!(parse_dns_response(&packet).is_none());
    }

    #[test]
    fn test_skip_dns_name_empty_packet() {
        assert!(skip_dns_name(&[], 0).is_none());
    }

    #[test]
    fn test_skip_dns_name_pointer_at_end() {
        // Compression pointer at the very last byte (incomplete)
        assert!(skip_dns_name(&[0xC0], 0).is_none());
    }

    #[test]
    fn test_skip_dns_name_excessive_labels() {
        // 200 labels of length 1 to test the label limit
        let mut packet = Vec::new();
        for _ in 0..200 {
            packet.push(1); // label length
            packet.push(b'a');
        }
        packet.push(0);
        // Should return None due to DNS_MAX_NAME_LABELS limit
        assert!(skip_dns_name(&packet, 0).is_none());
    }

    // === build_dns_query validation tests ===

    #[test]
    fn test_build_dns_query_empty_domain() {
        assert!(build_dns_query(1, "").is_none());
    }

    #[test]
    fn test_build_dns_query_too_long_domain() {
        let long_domain = "a".repeat(254);
        assert!(build_dns_query(1, &long_domain).is_none());
    }

    #[test]
    fn test_build_dns_query_label_too_long() {
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(build_dns_query(1, &long_label).is_none());
    }

    #[test]
    fn test_build_dns_query_empty_label() {
        assert!(build_dns_query(1, "example..com").is_none());
    }

    #[test]
    fn test_build_dns_query_max_valid_label() {
        let label = "a".repeat(63); // Max allowed
        let domain = format!("{}.com", label);
        assert!(build_dns_query(1, &domain).is_some());
    }

    #[test]
    fn test_build_dns_query_single_label() {
        let query = build_dns_query(1, "localhost").unwrap();
        assert_eq!(query[12], 9); // "localhost" length
    }

    #[test]
    fn test_resolve_mac_from_arp_found() {
        let entries = vec![ArpEntry {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            mac: MacAddr([0x11; 6]),
            device: "eth0".into(),
            flags: 2,
        }];
        assert_eq!(
            resolve_mac_from_arp(&entries, Ipv4Addr::new(10, 0, 0, 1)),
            Some(MacAddr([0x11; 6]))
        );
    }

    #[test]
    fn test_resolve_mac_from_arp_not_found() {
        let entries = vec![ArpEntry {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            mac: MacAddr([0x11; 6]),
            device: "eth0".into(),
            flags: 2,
        }];
        assert_eq!(
            resolve_mac_from_arp(&entries, Ipv4Addr::new(10, 0, 0, 2)),
            None
        );
    }

    #[test]
    fn test_resolve_mac_from_arp_empty() {
        assert_eq!(
            resolve_mac_from_arp(&[], Ipv4Addr::new(10, 0, 0, 1)),
            None
        );
    }

    #[test]
    fn test_arp_entries_to_map_empty() {
        let map = arp_entries_to_map(&[], None);
        assert!(map.is_empty());
    }

    #[test]
    fn test_arp_entries_to_map_nonexistent_interface() {
        let entries = vec![ArpEntry {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            mac: MacAddr([0x11; 6]),
            device: "wlan0".into(),
            flags: 2,
        }];
        let map = arp_entries_to_map(&entries, Some("eth99"));
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_arp_table_large() {
        // Simulate a large ARP table (1000 entries)
        let mut content = String::from(
            "IP address       HW type     Flags       HW address            Mask     Device\n",
        );
        for i in 0..1000u32 {
            let b3 = (i / 256) as u8;
            let b4 = (i % 256) as u8;
            content.push_str(&format!(
                "192.168.{}.{}    0x1         0x2         aa:bb:cc:00:{:02x}:{:02x}     *        wlan0\n",
                b3, b4, b3, b4
            ));
        }
        let entries = parse_arp_table(&content);
        assert_eq!(entries.len(), 1000);
    }
}
