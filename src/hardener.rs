use std::process::Command;

use tracing::{info, warn};

use crate::alert::Threat;
use crate::config::HardenerConfig;

const TABLE_NAME: &str = "bulwark";
const CHAIN_INPUT: &str = "bulwark_input";
const CHAIN_OUTPUT: &str = "bulwark_output";

/// Manages nftables-based firewall hardening for open networks.
///
/// When activated, it creates an nftables table with rules that:
/// - Drop all inbound traffic except established/related connections
/// - Allow DHCP client traffic (required for connectivity)
/// - Allow DNS outbound
/// - Restrict outbound to configured ports only
/// - Allow ICMP for basic connectivity diagnostics
pub struct Hardener {
    config: HardenerConfig,
    active: bool,
}

impl Hardener {
    pub fn new(config: HardenerConfig) -> Self {
        Self {
            config,
            active: false,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Generate the nftables ruleset as a string.
    pub fn generate_ruleset(&self) -> String {
        let ports: Vec<String> = self
            .config
            .allowed_outbound_ports
            .iter()
            .map(|p| p.to_string())
            .collect();
        let port_list = ports.join(", ");

        format!(
            r#"#!/usr/sbin/nft -f

# bulwark: open network hardening rules
# Auto-generated — do not edit manually

table inet {TABLE_NAME} {{
    chain {CHAIN_INPUT} {{
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established/related connections
        ct state established,related accept

        # Allow DHCP client responses
        udp sport 67 udp dport 68 accept

        # Allow ICMPv4 echo reply and essential types
        ip protocol icmp icmp type {{ echo-reply, destination-unreachable, time-exceeded }} accept

        # Allow ICMPv6 essential types
        ip6 nexthdr icmpv6 icmpv6 type {{ echo-reply, destination-unreachable, packet-too-big, time-exceeded, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept

        # Log and drop everything else
        counter log prefix "bulwark_drop_in: " drop
    }}

    chain {CHAIN_OUTPUT} {{
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
        tcp dport {{ {port_list} }} accept

        # Allow ICMP echo request (ping)
        ip protocol icmp icmp type echo-request accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request accept

        # Log and drop everything else
        counter log prefix "bulwark_drop_out: " drop
    }}
}}
"#,
            TABLE_NAME = TABLE_NAME,
            CHAIN_INPUT = CHAIN_INPUT,
            CHAIN_OUTPUT = CHAIN_OUTPUT,
            port_list = port_list,
        )
    }

    /// Apply the hardening rules via nft.
    pub fn activate(&mut self) -> Result<(), crate::Error> {
        if self.active {
            info!("hardener already active");
            return Ok(());
        }

        let ruleset = self.generate_ruleset();
        info!("activating firewall hardening");

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
                "nft failed: {}",
                stderr.trim()
            )));
        }

        self.active = true;
        info!("firewall hardening activated");
        Ok(())
    }

    /// Remove the bulwark nftables table (rollback).
    pub fn deactivate(&mut self) -> Result<(), crate::Error> {
        if !self.active {
            return Ok(());
        }

        info!("deactivating firewall hardening");

        let output = Command::new("nft")
            .args(["delete", "table", "inet", TABLE_NAME])
            .output()
            .map_err(|e| crate::Error::Hardener(format!("failed to run nft: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(error = %stderr.trim(), "failed to deactivate hardener (table may not exist)");
        }

        self.active = false;
        info!("firewall hardening deactivated");
        Ok(())
    }

    /// Handle a detected threat — optionally auto-harden.
    pub fn on_threat(&mut self, threat: &Threat) {
        if !self.config.auto_harden {
            return;
        }

        if threat.severity >= crate::alert::Severity::High && !self.active {
            warn!(
                threat = %threat,
                "high-severity threat detected, auto-activating firewall hardening"
            );
            if let Err(e) = self.activate() {
                warn!(error = %e, "failed to auto-activate hardening");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HardenerConfig;

    fn make_hardener() -> Hardener {
        Hardener::new(HardenerConfig {
            enabled: true,
            auto_harden: true,
            allowed_outbound_ports: vec![53, 80, 443],
        })
    }

    #[test]
    fn test_generate_ruleset_contains_table() {
        let h = make_hardener();
        let ruleset = h.generate_ruleset();
        assert!(ruleset.contains("table inet bulwark"));
        assert!(ruleset.contains("chain bulwark_input"));
        assert!(ruleset.contains("chain bulwark_output"));
    }

    #[test]
    fn test_generate_ruleset_contains_ports() {
        let h = make_hardener();
        let ruleset = h.generate_ruleset();
        assert!(ruleset.contains("53, 80, 443"));
    }

    #[test]
    fn test_generate_ruleset_policy_drop() {
        let h = make_hardener();
        let ruleset = h.generate_ruleset();
        assert!(ruleset.contains("policy drop"));
    }

    #[test]
    fn test_generate_ruleset_allows_established() {
        let h = make_hardener();
        let ruleset = h.generate_ruleset();
        assert!(ruleset.contains("ct state established,related accept"));
    }

    #[test]
    fn test_generate_ruleset_allows_dhcp() {
        let h = make_hardener();
        let ruleset = h.generate_ruleset();
        assert!(ruleset.contains("udp sport 67 udp dport 68 accept")); // inbound
        assert!(ruleset.contains("udp sport 68 udp dport 67 accept")); // outbound
    }

    #[test]
    fn test_generate_ruleset_allows_loopback() {
        let h = make_hardener();
        let ruleset = h.generate_ruleset();
        assert!(ruleset.contains("iif lo accept"));
        assert!(ruleset.contains("oif lo accept"));
    }

    #[test]
    fn test_not_active_by_default() {
        let h = make_hardener();
        assert!(!h.is_active());
    }

    #[test]
    fn test_on_threat_auto_harden_skips_low_severity() {
        use crate::alert::{Severity, Threat, ThreatKind};

        let mut h = make_hardener();
        let threat = Threat::new(
            ThreatKind::ArpFlood {
                new_entries: 5,
                window_secs: 5,
            },
            Severity::Low,
            "test",
        );
        // This won't actually call nft (no root in tests), but it shouldn't try
        // because severity is Low
        h.on_threat(&threat);
        assert!(!h.is_active());
    }
}
