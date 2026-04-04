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
}
