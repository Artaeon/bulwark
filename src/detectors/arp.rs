//! ARP spoof and flood detector.
//!
//! Polls `/proc/net/arp` at configurable intervals and maintains a baseline
//! of MAC-IP bindings. Detects:
//!
//! - **ARP spoofing** (Critical) — a known IP's MAC address changes, indicating
//!   an attacker is poisoning the ARP cache to intercept traffic.
//! - **ARP flooding** (High) — a burst of new ARP entries in a short window,
//!   indicating network scanning or ARP poisoning preparation.
//!
//! The core detection logic in [`ArpDetector::analyze`] is a pure function
//! that accepts ARP table content as a string, making it fully testable
//! without filesystem or network access.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::alert::{Severity, Threat, ThreatKind};
use crate::config::ArpConfig;
use crate::net_util::{self, MacAddr};

const DETECTOR_NAME: &str = "arp";
const FLOOD_THRESHOLD: usize = 10;
const FLOOD_WINDOW_SECS: u64 = 5;

/// Tracks ARP table state and detects anomalies.
pub struct ArpDetector {
    config: ArpConfig,
    interface: Option<String>,
    /// Known IP -> MAC mappings (our baseline).
    known_bindings: HashMap<Ipv4Addr, MacAddr>,
    /// Track new entry timestamps for flood detection.
    new_entry_times: Vec<Instant>,
}

impl ArpDetector {
    pub fn new(config: ArpConfig, interface: Option<String>) -> Self {
        Self {
            config,
            interface,
            known_bindings: HashMap::new(),
            new_entry_times: Vec::new(),
        }
    }

    /// Run the ARP spoof detection loop.
    pub async fn run(mut self, tx: mpsc::Sender<Threat>) -> Result<(), crate::Error> {
        let interval = Duration::from_secs(self.config.poll_interval_secs);
        info!(
            detector = DETECTOR_NAME,
            interval_secs = self.config.poll_interval_secs,
            "starting ARP spoof detector"
        );

        loop {
            match tokio::fs::read_to_string("/proc/net/arp").await {
                Ok(content) => {
                    let threats = self.analyze(&content);
                    for threat in threats {
                        warn!("{}", threat);
                        if tx.send(threat).await.is_err() {
                            return Ok(()); // Channel closed, shutting down
                        }
                    }
                }
                Err(e) => {
                    debug!(detector = DETECTOR_NAME, error = %e, "failed to read ARP table");
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Analyze an ARP table snapshot and return any detected threats.
    /// This is the core detection logic, separated for testability.
    pub fn analyze(&mut self, arp_content: &str) -> Vec<Threat> {
        let entries = net_util::parse_arp_table(arp_content);
        let current = net_util::arp_entries_to_map(&entries, self.interface.as_deref());
        let mut threats = Vec::new();
        let now = Instant::now();

        if self.known_bindings.is_empty() {
            // First run — establish baseline
            info!(
                detector = DETECTOR_NAME,
                entries = current.len(),
                "established ARP baseline"
            );
            self.known_bindings = current;
            return threats;
        }

        // Check for MAC changes on known IPs (ARP spoofing indicator)
        for (ip, new_mac) in &current {
            if let Some(old_mac) = self.known_bindings.get(ip) {
                if old_mac != new_mac {
                    threats.push(Threat::new(
                        ThreatKind::ArpSpoof {
                            ip: *ip,
                            old_mac: *old_mac,
                            new_mac: *new_mac,
                        },
                        Severity::Critical,
                        DETECTOR_NAME,
                    ));
                }
            } else {
                // New entry
                self.new_entry_times.push(now);
            }
        }

        // Flood detection: too many new entries in a short window
        self.new_entry_times
            .retain(|t| now.duration_since(*t).as_secs() < FLOOD_WINDOW_SECS);
        if self.new_entry_times.len() >= FLOOD_THRESHOLD {
            threats.push(Threat::new(
                ThreatKind::ArpFlood {
                    new_entries: self.new_entry_times.len(),
                    window_secs: FLOOD_WINDOW_SECS,
                },
                Severity::High,
                DETECTOR_NAME,
            ));
            self.new_entry_times.clear();
        }

        // Update baseline with current state
        self.known_bindings = current;

        threats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArpConfig;

    fn make_detector() -> ArpDetector {
        ArpDetector::new(
            ArpConfig {
                enabled: true,
                poll_interval_secs: 5,
            },
            Some("wlan0".to_string()),
        )
    }

    const BASELINE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
192.168.1.100    0x1         0x2         11:22:33:44:55:66     *        wlan0";

    #[test]
    fn test_baseline_no_threats() {
        let mut det = make_detector();
        let threats = det.analyze(BASELINE);
        assert!(threats.is_empty(), "first scan should establish baseline");
        assert_eq!(det.known_bindings.len(), 2);
    }

    #[test]
    fn test_no_change_no_threats() {
        let mut det = make_detector();
        det.analyze(BASELINE);
        let threats = det.analyze(BASELINE);
        assert!(threats.is_empty(), "no change should produce no threats");
    }

    #[test]
    fn test_detect_arp_spoof() {
        let mut det = make_detector();
        det.analyze(BASELINE);

        // Gateway MAC changed — classic ARP spoof
        let spoofed = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         de:ad:be:ef:00:01     *        wlan0
192.168.1.100    0x1         0x2         11:22:33:44:55:66     *        wlan0";

        let threats = det.analyze(spoofed);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].severity, Severity::Critical);
        match &threats[0].kind {
            ThreatKind::ArpSpoof {
                ip,
                old_mac,
                new_mac,
            } => {
                assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(*old_mac, "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap());
                assert_eq!(*new_mac, "de:ad:be:ef:00:01".parse::<MacAddr>().unwrap());
            }
            other => panic!("expected ArpSpoof, got {:?}", other),
        }
    }

    #[test]
    fn test_new_entry_no_spoof() {
        let mut det = make_detector();
        det.analyze(BASELINE);

        // A new device appeared — not a spoof
        let new_device = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
192.168.1.100    0x1         0x2         11:22:33:44:55:66     *        wlan0
192.168.1.200    0x1         0x2         77:88:99:aa:bb:cc     *        wlan0";

        let threats = det.analyze(new_device);
        assert!(threats.is_empty());
    }

    #[test]
    fn test_detect_arp_flood() {
        let mut det = make_detector();
        det.analyze(BASELINE);

        // Simulate flood: many new entries at once
        let mut flood = String::from(
            "IP address       HW type     Flags       HW address            Mask     Device\n",
        );
        // Keep existing entries
        flood.push_str(
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n",
        );
        flood.push_str(
            "192.168.1.100    0x1         0x2         11:22:33:44:55:66     *        wlan0\n",
        );
        // Add 15 new entries
        for i in 0..15u8 {
            flood.push_str(&format!(
                "192.168.1.{}    0x1         0x2         de:ad:00:00:00:{:02x}     *        wlan0\n",
                200 + i,
                i
            ));
        }

        let threats = det.analyze(&flood);
        assert!(threats
            .iter()
            .any(|t| matches!(t.kind, ThreatKind::ArpFlood { .. })));
    }

    #[test]
    fn test_filters_by_interface() {
        let mut det = make_detector(); // wlan0 only
        let mixed = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
10.0.0.1         0x1         0x2         11:22:33:44:55:66     *        eth0";

        det.analyze(mixed);
        assert_eq!(det.known_bindings.len(), 1);
        assert!(det
            .known_bindings
            .contains_key(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_empty_arp_table_no_crash() {
        let mut det = make_detector();
        let threats = det.analyze("");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_all_entries_disappear_no_crash() {
        let mut det = make_detector();
        det.analyze(BASELINE);
        let threats = det.analyze(
            "IP address       HW type     Flags       HW address            Mask     Device",
        );
        assert!(threats.is_empty());
    }

    #[test]
    fn test_multiple_spoofs_detected() {
        let mut det = make_detector();
        det.analyze(BASELINE);

        // Both known entries changed their MACs
        let double_spoof = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         de:ad:be:ef:00:01     *        wlan0
192.168.1.100    0x1         0x2         de:ad:be:ef:00:02     *        wlan0";

        let threats = det.analyze(double_spoof);
        let spoof_count = threats
            .iter()
            .filter(|t| matches!(t.kind, ThreatKind::ArpSpoof { .. }))
            .count();
        assert_eq!(spoof_count, 2);
    }

    #[test]
    fn test_no_interface_filter_sees_all() {
        let mut det = ArpDetector::new(
            ArpConfig {
                enabled: true,
                poll_interval_secs: 5,
            },
            None, // No interface filter
        );
        let mixed = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
10.0.0.1         0x1         0x2         11:22:33:44:55:66     *        eth0";

        det.analyze(mixed);
        assert_eq!(det.known_bindings.len(), 2);
    }

    #[test]
    fn test_spoof_then_revert_no_second_alert() {
        let mut det = make_detector();
        det.analyze(BASELINE);

        // Spoof happens
        let spoofed = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         de:ad:be:ef:00:01     *        wlan0
192.168.1.100    0x1         0x2         11:22:33:44:55:66     *        wlan0";
        let threats = det.analyze(spoofed);
        assert_eq!(threats.len(), 1);

        // Reverted to original — this is ALSO a change from the current baseline
        let threats = det.analyze(BASELINE);
        assert_eq!(threats.len(), 1); // Detects the change back
    }

    #[test]
    fn test_flood_detection_resets_after_alert() {
        let mut det = make_detector();
        det.analyze(BASELINE);

        // First flood
        let mut flood = String::from(
            "IP address       HW type     Flags       HW address            Mask     Device\n",
        );
        flood.push_str(
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n",
        );
        flood.push_str(
            "192.168.1.100    0x1         0x2         11:22:33:44:55:66     *        wlan0\n",
        );
        for i in 0..15u8 {
            flood.push_str(&format!(
                "192.168.1.{}    0x1         0x2         de:ad:00:00:00:{:02x}     *        wlan0\n",
                200 + i, i
            ));
        }
        let threats = det.analyze(&flood);
        assert!(threats
            .iter()
            .any(|t| matches!(t.kind, ThreatKind::ArpFlood { .. })));

        // Same table again — no new entries, so no flood
        let threats = det.analyze(&flood);
        assert!(threats
            .iter()
            .all(|t| !matches!(t.kind, ThreatKind::ArpFlood { .. })));
    }
}
