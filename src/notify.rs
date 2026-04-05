//! Desktop notification support via `notify-send`.
//!
//! Sends desktop notifications for high-severity threats using the
//! `notify-send` command (part of `libnotify`), which works on all
//! Linux desktop environments with a notification daemon.
//!
//! Falls back silently if `notify-send` is not installed — this is
//! a best-effort feature that should never block the daemon.

use std::process::Command;

use tracing::debug;

use crate::alert::{Severity, Threat};

/// Send a desktop notification for a threat if severity is high enough.
///
/// Only sends notifications for High and Critical threats to avoid
/// spamming the user with low-severity informational alerts.
pub fn notify_threat(threat: &Threat) {
    if threat.severity < Severity::High {
        return;
    }

    let urgency = match threat.severity {
        Severity::Critical => "critical",
        Severity::High => "normal",
        _ => return,
    };

    let summary = format!("bulwark: {} threat detected", threat.severity);
    let body = format!("{}", threat.kind);

    // Fire and forget — don't block the daemon if notify-send is missing
    let result = Command::new("notify-send")
        .args([
            "--urgency",
            urgency,
            "--app-name",
            "bulwark",
            "--icon",
            "security-high",
            "--category",
            "network.error",
            &summary,
            &body,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    match result {
        Ok(_) => debug!(severity = %threat.severity, "desktop notification sent"),
        Err(e) => debug!(error = %e, "notify-send not available"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{Threat, ThreatKind};
    use std::net::Ipv4Addr;

    #[test]
    fn test_notify_skips_low_severity() {
        // Should not panic or block, even without notify-send
        let threat = Threat::new(
            ThreatKind::ArpFlood {
                new_entries: 5,
                window_secs: 5,
            },
            Severity::Low,
            "test",
        );
        notify_threat(&threat);
    }

    #[test]
    fn test_notify_skips_medium_severity() {
        let threat = Threat::new(
            ThreatKind::ArpFlood {
                new_entries: 5,
                window_secs: 5,
            },
            Severity::Medium,
            "test",
        );
        notify_threat(&threat);
    }

    #[test]
    fn test_notify_high_does_not_panic() {
        // This will try to run notify-send which may not exist — should not panic
        let threat = Threat::new(
            ThreatKind::ArpSpoof {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                old_mac: crate::net_util::MacAddr([0xaa; 6]),
                new_mac: crate::net_util::MacAddr([0xbb; 6]),
            },
            Severity::High,
            "test",
        );
        notify_threat(&threat);
    }

    #[test]
    fn test_notify_critical_does_not_panic() {
        let threat = Threat::new(
            ThreatKind::GatewayMacChanged {
                gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
                old_mac: crate::net_util::MacAddr([0xaa; 6]),
                new_mac: crate::net_util::MacAddr([0xbb; 6]),
            },
            Severity::Critical,
            "test",
        );
        notify_threat(&threat);
    }

    // === Coverage for every ThreatKind variant ===

    #[test]
    fn test_notify_arp_flood_high() {
        let threat = Threat::new(
            ThreatKind::ArpFlood {
                new_entries: 50,
                window_secs: 5,
            },
            Severity::High,
            "arp",
        );
        notify_threat(&threat);
    }

    #[test]
    fn test_notify_gateway_ip_changed_high() {
        let threat = Threat::new(
            ThreatKind::GatewayIpChanged {
                old_ip: Ipv4Addr::new(192, 168, 1, 1),
                new_ip: Ipv4Addr::new(10, 0, 0, 1),
            },
            Severity::High,
            "gateway",
        );
        notify_threat(&threat);
    }

    #[test]
    fn test_notify_rogue_dhcp_critical() {
        let threat = Threat::new(
            ThreatKind::RogueDhcpServer {
                expected_server: Ipv4Addr::new(192, 168, 1, 1),
                rogue_server: Ipv4Addr::new(192, 168, 1, 99),
            },
            Severity::Critical,
            "dhcp",
        );
        notify_threat(&threat);
    }

    #[test]
    fn test_notify_dns_poisoning_high() {
        let threat = Threat::new(
            ThreatKind::DnsPoisoning {
                domain: "example.com".to_string(),
                system_results: vec![Ipv4Addr::new(1, 2, 3, 4)],
                trusted_results: vec![Ipv4Addr::new(5, 6, 7, 8)],
            },
            Severity::High,
            "dns",
        );
        notify_threat(&threat);
    }

    #[test]
    fn test_notify_bssid_changed_high() {
        let threat = Threat::new(
            ThreatKind::BssidChanged {
                ssid: "CafeWiFi".to_string(),
                old_bssid: "aa:bb:cc:dd:ee:ff".to_string(),
                new_bssid: "de:ad:be:ef:00:01".to_string(),
            },
            Severity::High,
            "bssid",
        );
        notify_threat(&threat);
    }

    #[test]
    fn test_notify_unicode_in_ssid_does_not_panic() {
        // Notification bodies may contain arbitrary Unicode (SSIDs)
        let threat = Threat::new(
            ThreatKind::BssidChanged {
                ssid: "café ☕ 🛡️".to_string(),
                old_bssid: "aa:aa:aa:aa:aa:aa".to_string(),
                new_bssid: "bb:bb:bb:bb:bb:bb".to_string(),
            },
            Severity::High,
            "bssid",
        );
        notify_threat(&threat);
    }
}
