//! ARP gateway pinning — prevent ARP spoofing at the kernel level.
//!
//! When activated, this module sets the gateway's ARP entry to `PERMANENT` state
//! using `ip neigh replace`, which makes the kernel ignore ARP replies that try
//! to change the gateway's MAC address. This is the single most effective
//! countermeasure against ARP cache poisoning.
//!
//! The pin is removed on deactivation by deleting the static entry and allowing
//! normal ARP resolution to resume.

use std::net::Ipv4Addr;
use std::process::Command;

use tracing::{info, warn};

use crate::net_util::{self, MacAddr};

/// Manages a static ARP entry for the default gateway.
pub struct ArpPin {
    /// The pinned gateway state, if active.
    pinned: Option<PinnedGateway>,
}

#[derive(Debug, Clone)]
struct PinnedGateway {
    ip: Ipv4Addr,
    interface: String,
}

impl Default for ArpPin {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpPin {
    pub fn new() -> Self {
        Self { pinned: None }
    }

    pub fn is_active(&self) -> bool {
        self.pinned.is_some()
    }

    /// Discover the current default gateway and pin its MAC as a static ARP entry.
    ///
    /// Reads `/proc/net/route` and `/proc/net/arp` to find the gateway IP and MAC,
    /// then executes `ip neigh replace <ip> lladdr <mac> nud permanent dev <iface>`.
    pub fn activate(&mut self) -> Result<(), crate::Error> {
        if self.pinned.is_some() {
            info!("ARP pin already active");
            return Ok(());
        }

        let (gw_ip, gw_mac, iface) = discover_gateway()?;

        let mac_str = format!("{}", gw_mac);
        let ip_str = format!("{}", gw_ip);

        let output = Command::new("ip")
            .args([
                "neigh",
                "replace",
                &ip_str,
                "lladdr",
                &mac_str,
                "nud",
                "permanent",
                "dev",
                &iface,
            ])
            .output()
            .map_err(|e| crate::Error::Network(format!("failed to run ip neigh: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::Error::Network(format!(
                "ip neigh replace failed: {}",
                stderr.trim()
            )));
        }

        info!(
            gateway_ip = %gw_ip,
            gateway_mac = %gw_mac,
            interface = %iface,
            "gateway ARP entry pinned as permanent"
        );

        // PinnedGateway only needs ip + interface to remove the pin later;
        // the MAC was used to create the pin and has already been logged.
        self.pinned = Some(PinnedGateway {
            ip: gw_ip,
            interface: iface,
        });

        Ok(())
    }

    /// Remove the static ARP entry and allow normal ARP resolution to resume.
    pub fn deactivate(&mut self) -> Result<(), crate::Error> {
        let gw = match self.pinned.take() {
            Some(gw) => gw,
            None => return Ok(()),
        };

        let ip_str = format!("{}", gw.ip);

        let output = Command::new("ip")
            .args(["neigh", "del", &ip_str, "dev", &gw.interface])
            .output()
            .map_err(|e| crate::Error::Network(format!("failed to run ip neigh del: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(error = %stderr.trim(), "failed to remove ARP pin (entry may not exist)");
        }

        info!(
            gateway_ip = %gw.ip,
            "gateway ARP pin removed"
        );

        Ok(())
    }
}

/// Discover the default gateway IP, MAC, and interface from /proc.
fn discover_gateway() -> Result<(Ipv4Addr, MacAddr, String), crate::Error> {
    let route_content = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| crate::Error::Network(format!("failed to read /proc/net/route: {}", e)))?;

    let route = net_util::parse_default_route(&route_content)
        .ok_or_else(|| crate::Error::Network("no default route found".into()))?;

    let arp_content = std::fs::read_to_string("/proc/net/arp")
        .map_err(|e| crate::Error::Network(format!("failed to read /proc/net/arp: {}", e)))?;

    let arp_entries = net_util::parse_arp_table(&arp_content);
    let gw_mac =
        net_util::resolve_mac_from_arp(&arp_entries, route.gateway_ip).ok_or_else(|| {
            crate::Error::Network(format!(
                "gateway {} not found in ARP table (try pinging it first)",
                route.gateway_ip
            ))
        })?;

    Ok((route.gateway_ip, gw_mac, route.interface))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_pin_initial_state() {
        let pin = ArpPin::new();
        assert!(!pin.is_active());
    }

    #[test]
    fn test_deactivate_when_not_active_is_ok() {
        let mut pin = ArpPin::new();
        assert!(pin.deactivate().is_ok());
    }

    #[test]
    fn test_discover_gateway_returns_result() {
        // Environment-dependent — just verify no panic
        let _ = discover_gateway();
    }

    #[test]
    fn test_default_impl() {
        let pin = ArpPin::default();
        assert!(!pin.is_active());
    }

    #[test]
    fn test_new_is_equivalent_to_default() {
        let a = ArpPin::new();
        let b = ArpPin::default();
        assert_eq!(a.is_active(), b.is_active());
        assert_eq!(a.pinned.is_none(), b.pinned.is_none());
    }

    #[test]
    fn test_multiple_deactivate_calls_are_ok() {
        let mut pin = ArpPin::new();
        assert!(pin.deactivate().is_ok());
        assert!(pin.deactivate().is_ok());
        assert!(pin.deactivate().is_ok());
    }

    #[test]
    fn test_is_active_matches_pinned_state() {
        let pin = ArpPin::new();
        assert_eq!(pin.is_active(), pin.pinned.is_some());
    }
}
