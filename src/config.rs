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
        Ok(config)
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
}
