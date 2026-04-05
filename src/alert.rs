//! Threat and alert types for inter-component communication.
//!
//! This module defines the vocabulary of threats that bulwark can detect.
//! Each detector produces [`Threat`] values containing a [`ThreatKind`] variant,
//! a [`Severity`] level, and metadata. Threats flow through an `mpsc` channel
//! from detectors to the daemon's central event loop.
//!
//! # Severity levels
//!
//! - **Low** — Informational anomaly, may not indicate an attack
//! - **Medium** — Suspicious activity that warrants attention
//! - **High** — Likely active attack (triggers auto-hardening if enabled)
//! - **Critical** — Confirmed attack indicator (always triggers auto-hardening)

use std::fmt;
use std::net::Ipv4Addr;
use std::time::SystemTime;

use crate::net_util::MacAddr;

/// Severity level for detected threats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// The kind of threat detected, with relevant evidence.
#[derive(Debug, Clone)]
pub enum ThreatKind {
    ArpSpoof {
        ip: Ipv4Addr,
        old_mac: MacAddr,
        new_mac: MacAddr,
    },
    ArpFlood {
        new_entries: usize,
        window_secs: u64,
    },
    GatewayIpChanged {
        old_ip: Ipv4Addr,
        new_ip: Ipv4Addr,
    },
    GatewayMacChanged {
        gateway_ip: Ipv4Addr,
        old_mac: MacAddr,
        new_mac: MacAddr,
    },
    RogueDhcpServer {
        expected_server: Ipv4Addr,
        rogue_server: Ipv4Addr,
    },
    DnsPoisoning {
        domain: String,
        system_results: Vec<Ipv4Addr>,
        trusted_results: Vec<Ipv4Addr>,
    },
    BssidChanged {
        ssid: String,
        old_bssid: String,
        new_bssid: String,
    },
}

impl fmt::Display for ThreatKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatKind::ArpSpoof { ip, old_mac, new_mac } => {
                write!(f, "ARP spoof: {} changed from {} to {}", ip, old_mac, new_mac)
            }
            ThreatKind::ArpFlood { new_entries, window_secs } => {
                write!(f, "ARP flood: {} new entries in {}s", new_entries, window_secs)
            }
            ThreatKind::GatewayIpChanged { old_ip, new_ip } => {
                write!(f, "Gateway IP changed: {} -> {}", old_ip, new_ip)
            }
            ThreatKind::GatewayMacChanged { gateway_ip, old_mac, new_mac } => {
                write!(
                    f,
                    "Gateway {} MAC changed: {} -> {}",
                    gateway_ip, old_mac, new_mac
                )
            }
            ThreatKind::RogueDhcpServer { expected_server, rogue_server } => {
                write!(
                    f,
                    "Rogue DHCP server {} (expected {})",
                    rogue_server, expected_server
                )
            }
            ThreatKind::DnsPoisoning { domain, system_results, trusted_results } => {
                write!(
                    f,
                    "DNS poisoning for {}: system={:?}, trusted={:?}",
                    domain, system_results, trusted_results
                )
            }
            ThreatKind::BssidChanged { ssid, old_bssid, new_bssid } => {
                write!(
                    f,
                    "BSSID changed on '{}': {} -> {} (possible evil twin)",
                    ssid, old_bssid, new_bssid
                )
            }
        }
    }
}

/// A detected threat with metadata.
#[derive(Debug, Clone)]
pub struct Threat {
    pub kind: ThreatKind,
    pub severity: Severity,
    pub timestamp: SystemTime,
    pub detector: &'static str,
}

impl Threat {
    pub fn new(kind: ThreatKind, severity: Severity, detector: &'static str) -> Self {
        Self {
            kind,
            severity,
            timestamp: SystemTime::now(),
            detector,
        }
    }
}

impl fmt::Display for Threat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] [{}] {}", self.severity, self.detector, self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_display() {
        let threat = Threat::new(
            ThreatKind::ArpSpoof {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                old_mac: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                new_mac: MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            },
            Severity::Critical,
            "arp",
        );
        let s = format!("{}", threat);
        assert!(s.contains("CRITICAL"));
        assert!(s.contains("arp"));
        assert!(s.contains("192.168.1.1"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Low), "LOW");
        assert_eq!(format!("{}", Severity::Medium), "MEDIUM");
        assert_eq!(format!("{}", Severity::High), "HIGH");
        assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
    }

    #[test]
    fn test_all_threat_kinds_display() {
        let kinds = vec![
            ThreatKind::ArpSpoof {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                old_mac: MacAddr([0xaa; 6]),
                new_mac: MacAddr([0xbb; 6]),
            },
            ThreatKind::ArpFlood {
                new_entries: 50,
                window_secs: 5,
            },
            ThreatKind::GatewayIpChanged {
                old_ip: Ipv4Addr::new(192, 168, 1, 1),
                new_ip: Ipv4Addr::new(10, 0, 0, 1),
            },
            ThreatKind::GatewayMacChanged {
                gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
                old_mac: MacAddr([0xaa; 6]),
                new_mac: MacAddr([0xbb; 6]),
            },
            ThreatKind::RogueDhcpServer {
                expected_server: Ipv4Addr::new(192, 168, 1, 1),
                rogue_server: Ipv4Addr::new(10, 0, 0, 99),
            },
            ThreatKind::DnsPoisoning {
                domain: "evil.com".to_string(),
                system_results: vec![Ipv4Addr::new(1, 2, 3, 4)],
                trusted_results: vec![Ipv4Addr::new(5, 6, 7, 8)],
            },
        ];

        // All Display impls should produce non-empty, non-panicking output
        for kind in kinds {
            let s = format!("{}", kind);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_threat_has_timestamp() {
        let before = std::time::SystemTime::now();
        let threat = Threat::new(
            ThreatKind::ArpFlood {
                new_entries: 10,
                window_secs: 5,
            },
            Severity::High,
            "arp",
        );
        let after = std::time::SystemTime::now();
        assert!(threat.timestamp >= before);
        assert!(threat.timestamp <= after);
    }

    #[test]
    fn test_threat_display_contains_all_parts() {
        let threat = Threat::new(
            ThreatKind::GatewayIpChanged {
                old_ip: Ipv4Addr::new(192, 168, 1, 1),
                new_ip: Ipv4Addr::new(10, 0, 0, 1),
            },
            Severity::High,
            "gateway",
        );
        let s = format!("{}", threat);
        assert!(s.contains("HIGH"));
        assert!(s.contains("gateway"));
        assert!(s.contains("192.168.1.1"));
        assert!(s.contains("10.0.0.1"));
    }

    #[test]
    fn test_severity_equality() {
        assert_eq!(Severity::Critical, Severity::Critical);
        assert_ne!(Severity::Low, Severity::High);
    }
}
