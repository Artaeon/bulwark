//! MAC address randomization — prevent cross-network tracking.
//!
//! On open WiFi, your real MAC address is broadcast in every frame, allowing
//! tracking across networks and sessions. This module generates a random
//! locally-administered MAC and applies it to the wireless interface.
//!
//! The original MAC is saved and restored on deactivation.
//!
//! # Locally-administered addresses
//!
//! Bit 1 of the first octet is the U/L (universal/local) bit. Setting it to 1
//! marks the address as locally administered, avoiding collisions with
//! hardware vendor OUIs. Bit 0 (multicast) is cleared.

use std::process::Command;

use rand::Rng;
use tracing::{info, warn};

/// Manages MAC address randomization for a network interface.
pub struct MacRandomizer {
    interface: String,
    /// Original MAC saved for restore on deactivation.
    original_mac: Option<String>,
}

impl MacRandomizer {
    pub fn new(interface: String) -> Self {
        Self {
            interface,
            original_mac: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.original_mac.is_some()
    }

    /// Read the current MAC, generate a random one, and apply it.
    ///
    /// Requires the interface to be brought down and back up.
    pub fn activate(&mut self) -> Result<(), crate::Error> {
        if self.original_mac.is_some() {
            info!("MAC randomization already active");
            return Ok(());
        }

        // Save original MAC
        let original = read_interface_mac(&self.interface)?;
        self.original_mac = Some(original.clone());

        // Generate random locally-administered MAC
        let new_mac = generate_random_mac();

        info!(
            interface = %self.interface,
            original = %original,
            randomized = %new_mac,
            "randomizing MAC address"
        );

        apply_mac(&self.interface, &new_mac)?;

        info!(
            interface = %self.interface,
            mac = %new_mac,
            "MAC address randomized"
        );

        Ok(())
    }

    /// Restore the original MAC address.
    pub fn deactivate(&mut self) -> Result<(), crate::Error> {
        let original = match self.original_mac.take() {
            Some(mac) => mac,
            None => return Ok(()),
        };

        info!(
            interface = %self.interface,
            original = %original,
            "restoring original MAC address"
        );

        if let Err(e) = apply_mac(&self.interface, &original) {
            warn!(error = %e, "failed to restore original MAC");
            return Err(e);
        }

        info!(
            interface = %self.interface,
            mac = %original,
            "original MAC address restored"
        );

        Ok(())
    }
}

/// Generate a random locally-administered unicast MAC address.
///
/// Byte 0: bit 1 (U/L) set = locally administered, bit 0 (multicast) cleared.
pub fn generate_random_mac() -> String {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 6];
    rng.fill(&mut bytes);

    // Set locally administered bit (bit 1 of first octet)
    bytes[0] |= 0x02;
    // Clear multicast bit (bit 0 of first octet)
    bytes[0] &= 0xFE;

    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// Read the current MAC address of an interface from /sys.
fn read_interface_mac(interface: &str) -> Result<String, crate::Error> {
    let path = format!("/sys/class/net/{}/address", interface);
    std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .map_err(|e| crate::Error::Network(format!(
            "failed to read MAC from {}: {}",
            path, e
        )))
}

/// Apply a MAC address to an interface (requires ip link down/up cycle).
fn apply_mac(interface: &str, mac: &str) -> Result<(), crate::Error> {
    // Bring interface down
    run_ip_command(&["link", "set", "dev", interface, "down"])?;

    // Set new MAC
    let result = run_ip_command(&["link", "set", "dev", interface, "address", mac]);

    // Always bring interface back up, even if MAC change failed
    let up_result = run_ip_command(&["link", "set", "dev", interface, "up"]);

    // Report the first error
    result?;
    up_result?;

    Ok(())
}

fn run_ip_command(args: &[&str]) -> Result<(), crate::Error> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| crate::Error::Network(format!("failed to run ip {}: {}", args.join(" "), e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::Error::Network(format!(
            "ip {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_mac_format() {
        let mac = generate_random_mac();
        let parts: Vec<&str> = mac.split(':').collect();
        assert_eq!(parts.len(), 6);
        for part in &parts {
            assert_eq!(part.len(), 2);
            assert!(u8::from_str_radix(part, 16).is_ok());
        }
    }

    #[test]
    fn test_generate_random_mac_locally_administered() {
        for _ in 0..100 {
            let mac = generate_random_mac();
            let first_byte = u8::from_str_radix(&mac[..2], 16).unwrap();
            // U/L bit (bit 1) must be set
            assert!(first_byte & 0x02 != 0, "U/L bit not set: {:02x}", first_byte);
            // Multicast bit (bit 0) must be cleared
            assert!(first_byte & 0x01 == 0, "multicast bit set: {:02x}", first_byte);
        }
    }

    #[test]
    fn test_generate_random_mac_not_constant() {
        let mac1 = generate_random_mac();
        let mac2 = generate_random_mac();
        // Technically could be equal, but probability is 1/2^46
        assert_ne!(mac1, mac2, "two random MACs should differ");
    }

    #[test]
    fn test_mac_randomizer_initial_state() {
        let r = MacRandomizer::new("wlan0".into());
        assert!(!r.is_active());
    }

    #[test]
    fn test_deactivate_when_not_active_is_ok() {
        let mut r = MacRandomizer::new("wlan0".into());
        assert!(r.deactivate().is_ok());
    }
}
