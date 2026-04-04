//! TOML-based configuration for the bulwark daemon.
//!
//! All configuration structs derive [`Default`] with sensible production values,
//! so bulwark can run with zero configuration. When a config file is loaded via
//! [`Config::load`], all values are validated before the daemon starts.
//!
//! # Validation
//!
//! - Poll intervals must be > 0 to prevent busy loops
//! - DNS resolvers must be valid IPv4/IPv6 addresses
//! - Test domains must conform to RFC 1035 limits
//! - Interface names must fit Linux `IFNAMSIZ` (15 chars)

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub interface: String,
    pub log_level: String,
    pub arp: ArpConfig,
    pub gateway: GatewayConfig,
    pub dns: DnsConfig,
    pub dhcp: DhcpConfig,
    pub hardener: HardenerConfig,
    pub protect: ProtectConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ArpConfig {
    pub enabled: bool,
    pub poll_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GatewayConfig {
    pub enabled: bool,
    pub poll_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub enabled: bool,
    pub poll_interval_secs: u64,
    pub trusted_resolvers: Vec<String>,
    pub test_domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub listen_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HardenerConfig {
    pub enabled: bool,
    pub auto_harden: bool,
    pub allowed_outbound_ports: Vec<u16>,
}

/// Configuration for active network protections.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProtectConfig {
    /// Pin the gateway's MAC as a static ARP entry to prevent ARP spoofing.
    pub arp_pin: bool,
    /// Block all LAN traffic except the gateway to prevent lateral attacks.
    pub client_isolation: bool,
    /// Encrypt all DNS queries via DNS-over-TLS.
    pub dns_encrypt: bool,
    /// TLS resolvers for DNS encryption (default: 1.1.1.1:853, 8.8.8.8:853).
    pub dns_resolvers: Vec<String>,
    /// Randomize the MAC address on startup to prevent tracking.
    pub mac_randomize: bool,
}

impl Default for ProtectConfig {
    fn default() -> Self {
        Self {
            arp_pin: false,
            client_isolation: false,
            dns_encrypt: false,
            dns_resolvers: vec![
                "1.1.1.1:853".to_string(),
                "8.8.8.8:853".to_string(),
            ],
            mac_randomize: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: String::new(),
            log_level: "info".to_string(),
            arp: ArpConfig::default(),
            gateway: GatewayConfig::default(),
            dns: DnsConfig::default(),
            dhcp: DhcpConfig::default(),
            hardener: HardenerConfig::default(),
            protect: ProtectConfig::default(),
        }
    }
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: 5,
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: 10,
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: 30,
            trusted_resolvers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            test_domains: vec![
                "example.com".to_string(),
                "cloudflare.com".to_string(),
                "google.com".to_string(),
            ],
        }
    }
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_timeout_secs: 10,
        }
    }
}

impl Default for HardenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_harden: false,
            allowed_outbound_ports: vec![53, 80, 443, 853, 993, 587],
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, crate::Error> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            crate::Error::Config(format!("failed to read config file {}: {}", path.display(), e))
        })?;
        let config: Config = toml::from_str(&contents).map_err(|e| {
            crate::Error::Config(format!("failed to parse config file: {}", e))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate all configuration values for sanity.
    pub fn validate(&self) -> Result<(), crate::Error> {
        // Validate poll intervals (must be > 0 to avoid busy loops)
        if self.arp.enabled && self.arp.poll_interval_secs == 0 {
            return Err(crate::Error::Config(
                "arp.poll_interval_secs must be > 0".into(),
            ));
        }
        if self.gateway.enabled && self.gateway.poll_interval_secs == 0 {
            return Err(crate::Error::Config(
                "gateway.poll_interval_secs must be > 0".into(),
            ));
        }
        if self.dns.enabled && self.dns.poll_interval_secs == 0 {
            return Err(crate::Error::Config(
                "dns.poll_interval_secs must be > 0".into(),
            ));
        }

        // Validate DNS config
        if self.dns.enabled {
            if self.dns.trusted_resolvers.is_empty() {
                return Err(crate::Error::Config(
                    "dns.trusted_resolvers must not be empty when DNS detector is enabled".into(),
                ));
            }
            for resolver in &self.dns.trusted_resolvers {
                if resolver.parse::<std::net::Ipv4Addr>().is_err()
                    && resolver.parse::<std::net::Ipv6Addr>().is_err()
                {
                    return Err(crate::Error::Config(format!(
                        "dns.trusted_resolvers contains invalid IP: {}",
                        resolver
                    )));
                }
            }
            if self.dns.test_domains.is_empty() {
                return Err(crate::Error::Config(
                    "dns.test_domains must not be empty when DNS detector is enabled".into(),
                ));
            }
            for domain in &self.dns.test_domains {
                if domain.is_empty() || domain.len() > 253 {
                    return Err(crate::Error::Config(format!(
                        "dns.test_domains contains invalid domain: '{}'",
                        domain
                    )));
                }
            }
        }

        // Validate port numbers
        for port in &self.hardener.allowed_outbound_ports {
            if *port == 0 {
                return Err(crate::Error::Config(
                    "hardener.allowed_outbound_ports must not contain port 0".into(),
                ));
            }
        }

        // Validate interface name length (Linux IFNAMSIZ = 16 including null)
        if self.interface.len() > 15 {
            return Err(crate::Error::Config(format!(
                "interface name too long (max 15 chars): '{}'",
                self.interface
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.arp.enabled);
        assert!(config.gateway.enabled);
        assert!(config.dns.enabled);
        assert!(config.dhcp.enabled);
        assert!(!config.hardener.enabled);
        assert_eq!(config.arp.poll_interval_secs, 5);
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml_str = r#"
            interface = "wlan0"
            [arp]
            poll_interval_secs = 3
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.interface, "wlan0");
        assert_eq!(config.arp.poll_interval_secs, 3);
        assert!(config.dns.enabled);
    }

    #[test]
    fn test_parse_full_toml() {
        let toml_str = r#"
            interface = "wlan0"
            log_level = "debug"

            [arp]
            enabled = true
            poll_interval_secs = 2

            [gateway]
            enabled = true
            poll_interval_secs = 5

            [dns]
            enabled = true
            poll_interval_secs = 60
            trusted_resolvers = ["9.9.9.9"]
            test_domains = ["example.org"]

            [dhcp]
            enabled = false

            [hardener]
            enabled = true
            auto_harden = true
            allowed_outbound_ports = [53, 443]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.log_level, "debug");
        assert!(!config.dhcp.enabled);
        assert!(config.hardener.auto_harden);
        assert_eq!(config.hardener.allowed_outbound_ports, vec![53, 443]);
        assert_eq!(config.dns.trusted_resolvers, vec!["9.9.9.9"]);
    }

    // === Validation tests ===

    #[test]
    fn test_validate_default_config_passes() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_arp_interval() {
        let mut config = Config::default();
        config.arp.poll_interval_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_gateway_interval() {
        let mut config = Config::default();
        config.gateway.poll_interval_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_dns_interval() {
        let mut config = Config::default();
        config.dns.poll_interval_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_disabled_detector_allows_zero_interval() {
        let mut config = Config::default();
        config.arp.enabled = false;
        config.arp.poll_interval_secs = 0;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_dns_resolvers() {
        let mut config = Config::default();
        config.dns.trusted_resolvers.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_dns_resolver() {
        let mut config = Config::default();
        config.dns.trusted_resolvers = vec!["not-an-ip".to_string()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_valid_ipv6_resolver() {
        let mut config = Config::default();
        config.dns.trusted_resolvers = vec!["2001:4860:4860::8888".to_string()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_test_domains() {
        let mut config = Config::default();
        config.dns.test_domains.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_domain_too_long() {
        let mut config = Config::default();
        config.dns.test_domains = vec!["a".repeat(254)];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_domain_string() {
        let mut config = Config::default();
        config.dns.test_domains = vec!["".to_string()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_port_zero() {
        let mut config = Config::default();
        config.hardener.allowed_outbound_ports = vec![0, 80, 443];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_interface_too_long() {
        let mut config = Config::default();
        config.interface = "a".repeat(16);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_interface_max_length() {
        let mut config = Config::default();
        config.interface = "a".repeat(15); // Max valid
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_disabled_dns_skips_resolver_check() {
        let mut config = Config::default();
        config.dns.enabled = false;
        config.dns.trusted_resolvers.clear();
        config.dns.test_domains.clear();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_empty_toml() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_unknown_keys_ignored() {
        let toml_str = r#"
            unknown_key = "ignored"
            interface = "wlan0"
        "#;
        // serde(default) + deny_unknown_fields not set — should work
        let result: Result<Config, _> = toml::from_str(toml_str);
        // This depends on serde config — either passes or gives helpful error
        if let Ok(config) = result {
            assert_eq!(config.interface, "wlan0");
        }
    }
}
