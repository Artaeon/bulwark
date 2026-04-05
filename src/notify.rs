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
}
