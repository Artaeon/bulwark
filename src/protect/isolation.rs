//! Client isolation — block all LAN traffic except the gateway.
//!
//! On an open network, other clients can scan, probe, and attack your machine
//! directly over the local subnet. Client isolation adds nftables rules that
//! drop all traffic to/from the local subnet **except** the default gateway.
//!
//! This prevents:
//! - Port scanning and service exploitation from other network clients
//! - ARP-based attacks from hosts other than the gateway
//! - LLMNR/mDNS/NetBIOS probing and poisoning
//!
//! Combined with ARP pinning, this creates a strong defense-in-depth posture
//! where only verified gateway traffic is allowed.

use std::net::Ipv4Addr;
use std::process::Command;

use tracing::{info, warn};

use crate::net_util;

const TABLE_NAME: &str = "bulwark_isolation";

/// Manages client isolation rules via nftables.
pub struct ClientIsolation {
    active: bool,
}

impl Default for ClientIsolation {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientIsolation {
    pub fn new() -> Self {
        Self { active: false }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Discover the local subnet and gateway, then apply isolation rules.
    pub fn activate(&mut self, interface: &str) -> Result<(), crate::Error> {
        if self.active {
            info!("client isolation already active");
            return Ok(());
        }

        let (gateway_ip, subnet, prefix_len) = discover_network(interface)?;

        let ruleset = generate_isolation_rules(interface, gateway_ip, subnet, prefix_len);

        let output = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(ruleset.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map_err(|e| crate::Error::Hardener(format!("failed to run nft: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::Error::Hardener(format!(
                "nft isolation rules failed: {}",
                stderr.trim()
            )));
        }

        self.active = true;
        info!(
            interface = %interface,
            gateway = %gateway_ip,
            subnet = %format!("{}/{}", subnet, prefix_len),
            "client isolation activated"
        );

        Ok(())
    }

    /// Remove isolation rules.
    pub fn deactivate(&mut self) -> Result<(), crate::Error> {
        if !self.active {
            return Ok(());
        }

        let output = Command::new("nft")
            .args(["delete", "table", "inet", TABLE_NAME])
            .output()
            .map_err(|e| crate::Error::Hardener(format!("failed to run nft: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(error = %stderr.trim(), "failed to remove isolation rules");
        }

        self.active = false;
        info!("client isolation deactivated");
        Ok(())
    }
}

/// Generate nftables rules that block LAN traffic except the gateway.
pub fn generate_isolation_rules(
    interface: &str,
    gateway_ip: Ipv4Addr,
    subnet: Ipv4Addr,
    prefix_len: u8,
) -> String {
    format!(
        r#"#!/usr/sbin/nft -f

# bulwark: client isolation rules
# Block all LAN traffic except gateway

table inet {table} {{
    chain isolate_input {{
        type filter hook input priority -10; policy accept;

        # Allow traffic from gateway
        iifname "{iface}" ip saddr {gateway} accept

        # Drop all other LAN traffic on this interface
        iifname "{iface}" ip saddr {subnet}/{prefix} counter log prefix "bulwark_isolate: " drop
    }}

    chain isolate_output {{
        type filter hook output priority -10; policy accept;

        # Allow traffic to gateway
        oifname "{iface}" ip daddr {gateway} accept

        # Allow DHCP broadcast (needed for lease renewal)
        oifname "{iface}" ip daddr 255.255.255.255 udp dport 67 accept

        # Drop all other LAN traffic on this interface
        oifname "{iface}" ip daddr {subnet}/{prefix} counter log prefix "bulwark_isolate: " drop
    }}
}}
"#,
        table = TABLE_NAME,
        iface = interface,
        gateway = gateway_ip,
        subnet = subnet,
        prefix = prefix_len,
    )
}

/// Discover the local network: gateway IP, subnet address, and prefix length.
fn discover_network(interface: &str) -> Result<(Ipv4Addr, Ipv4Addr, u8), crate::Error> {
    let route_content = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| crate::Error::Network(format!("failed to read /proc/net/route: {}", e)))?;

    let route = net_util::parse_default_route(&route_content)
        .ok_or_else(|| crate::Error::Network("no default route found".into()))?;

    // Find the subnet route for this interface
    let (subnet, prefix_len) = parse_interface_subnet(&route_content, interface)
        .unwrap_or_else(|| {
            // Fallback: assume /24
            let octets = route.gateway_ip.octets();
            (Ipv4Addr::new(octets[0], octets[1], octets[2], 0), 24)
        });

    Ok((route.gateway_ip, subnet, prefix_len))
}

/// Parse the subnet and prefix length for an interface from /proc/net/route.
fn parse_interface_subnet(content: &str, interface: &str) -> Option<(Ipv4Addr, u8)> {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        if fields[0] != interface {
            continue;
        }
        // Skip default route (destination 00000000)
        if fields[1] == "00000000" {
            continue;
        }

        let dest = u32::from_str_radix(fields[1], 16).ok()?;
        let mask = u32::from_str_radix(fields[7], 16).ok()?;

        let dest_ip = Ipv4Addr::from(dest.to_be());
        // count_ones on a u32 returns 0..=32, always fits in u8
        let prefix_len = u8::try_from(mask.count_ones()).ok()?;

        if (8..=30).contains(&prefix_len) {
            return Some((dest_ip, prefix_len));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_isolation_rules_contains_gateway() {
        let rules = generate_isolation_rules(
            "wlan0",
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 0),
            24,
        );
        assert!(rules.contains("192.168.1.1"));
        assert!(rules.contains("192.168.1.0/24"));
        assert!(rules.contains("wlan0"));
    }

    #[test]
    fn test_generate_isolation_rules_allows_dhcp_broadcast() {
        let rules = generate_isolation_rules(
            "wlan0",
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 0),
            24,
        );
        assert!(rules.contains("255.255.255.255"));
        assert!(rules.contains("udp dport 67"));
    }

    #[test]
    fn test_generate_isolation_rules_has_logging() {
        let rules = generate_isolation_rules(
            "wlan0",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 0),
            24,
        );
        assert!(rules.contains("log prefix \"bulwark_isolate: \""));
    }

    #[test]
    fn test_parse_interface_subnet() {
        let content = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0";

        let result = parse_interface_subnet(content, "wlan0");
        assert!(result.is_some());
        let (subnet, prefix) = result.unwrap();
        assert_eq!(subnet, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_interface_subnet_no_match() {
        let content = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0";

        // Only default route, no subnet route
        let result = parse_interface_subnet(content, "wlan0");
        assert!(result.is_none());
    }

    #[test]
    fn test_client_isolation_initial_state() {
        let iso = ClientIsolation::new();
        assert!(!iso.is_active());
    }

    #[test]
    fn test_deactivate_when_not_active_is_ok() {
        let mut iso = ClientIsolation::new();
        assert!(iso.deactivate().is_ok());
    }

    #[test]
    fn test_different_subnets() {
        // /16 subnet
        let rules = generate_isolation_rules(
            "wlan0",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 0),
            16,
        );
        assert!(rules.contains("10.0.0.0/16"));

        // /28 subnet
        let rules = generate_isolation_rules(
            "wlan0",
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(172, 16, 0, 0),
            28,
        );
        assert!(rules.contains("172.16.0.0/28"));
    }
}
