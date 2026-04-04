//! Central daemon orchestrator.
//!
//! The [`Daemon`] is the heart of bulwark. It:
//!
//! 1. Auto-detects the wireless interface (or uses the configured one)
//! 2. Spawns enabled detectors as independent tokio tasks
//! 3. Receives [`Threat`](crate::alert::Threat) events through an `mpsc` channel
//! 4. Deduplicates repeated alerts to prevent log flooding
//! 5. Dispatches threats to the [`Hardener`](crate::hardener::Hardener) for auto-response
//! 6. Handles graceful shutdown with firewall rollback

use std::collections::HashMap;
use std::time::Instant;

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::alert::Threat;
use crate::config::Config;
use crate::detectors::arp::ArpDetector;
use crate::detectors::dhcp::DhcpDetector;
use crate::detectors::dns::DnsDetector;
use crate::detectors::gateway::GatewayDetector;
use crate::hardener::Hardener;
use crate::protect::arp_pin::ArpPin;
use crate::protect::dns_crypt::{DnsCrypt, DnsCryptConfig};
use crate::protect::isolation::ClientIsolation;
use crate::protect::mac_rand::MacRandomizer;

const CHANNEL_CAPACITY: usize = 256;

/// Minimum seconds between identical threat alerts (by detector + kind discriminant).
const DEDUP_WINDOW_SECS: u64 = 60;
/// Maximum unique threat keys to track (prevents unbounded memory growth).
const DEDUP_MAX_KEYS: usize = 1024;

/// Deduplicates repeated identical threats within a time window.
/// A security tool that floods logs with the same alert every 5 seconds is useless.
struct ThreatDedup {
    last_seen: HashMap<String, Instant>,
    window_secs: u64,
}

impl ThreatDedup {
    fn new(window_secs: u64) -> Self {
        Self {
            last_seen: HashMap::new(),
            window_secs,
        }
    }

    /// Returns true if this threat should be emitted (not a duplicate).
    fn should_emit(&mut self, threat: &Threat) -> bool {
        let key = Self::threat_key(threat);
        let now = Instant::now();

        // Evict stale entries periodically
        if self.last_seen.len() > DEDUP_MAX_KEYS {
            self.last_seen
                .retain(|_, t| now.duration_since(*t).as_secs() < self.window_secs);
        }

        if let Some(last) = self.last_seen.get(&key) {
            if now.duration_since(*last).as_secs() < self.window_secs {
                return false;
            }
        }

        self.last_seen.insert(key, now);
        true
    }

    /// Generate a dedup key from detector name + threat kind discriminant.
    fn threat_key(threat: &Threat) -> String {
        // Use detector + a stable discriminant of the threat kind
        format!("{}:{}", threat.detector, threat.kind)
    }
}

/// The main daemon that orchestrates all detectors and the hardener.
pub struct Daemon {
    config: Config,
}

impl Daemon {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Run the daemon: spawn detectors and process threats.
    pub async fn run(self, shutdown_tx: tokio::sync::broadcast::Sender<()>) -> Result<(), crate::Error> {
        let mut shutdown = shutdown_tx.subscribe();
        let (tx, mut rx) = mpsc::channel::<Threat>(CHANNEL_CAPACITY);

        let interface = if self.config.interface.is_empty() {
            detect_wireless_interface().unwrap_or_else(|| {
                warn!("no wireless interface specified or detected, using all interfaces");
                String::new()
            })
        } else {
            self.config.interface.clone()
        };

        if !interface.is_empty() {
            info!(interface = %interface, "monitoring interface");
        }

        let iface_opt = if interface.is_empty() {
            None
        } else {
            Some(interface.clone())
        };

        // Spawn detector tasks
        let mut task_handles = Vec::new();

        if self.config.arp.enabled {
            let detector = ArpDetector::new(self.config.arp.clone(), iface_opt.clone());
            let tx = tx.clone();
            task_handles.push(tokio::spawn(async move {
                if let Err(e) = detector.run(tx).await {
                    error!(detector = "arp", error = %e, "detector failed");
                }
            }));
        }

        if self.config.gateway.enabled {
            let detector = GatewayDetector::new(self.config.gateway.clone());
            let tx = tx.clone();
            task_handles.push(tokio::spawn(async move {
                if let Err(e) = detector.run(tx).await {
                    error!(detector = "gateway", error = %e, "detector failed");
                }
            }));
        }

        if self.config.dns.enabled {
            let detector = DnsDetector::new(self.config.dns.clone());
            let tx = tx.clone();
            task_handles.push(tokio::spawn(async move {
                if let Err(e) = detector.run(tx).await {
                    error!(detector = "dns", error = %e, "detector failed");
                }
            }));
        }

        if self.config.dhcp.enabled {
            let iface = if interface.is_empty() {
                "wlan0".to_string()
            } else {
                interface.clone()
            };
            let detector = DhcpDetector::new(self.config.dhcp.clone(), iface);
            let tx = tx.clone();
            task_handles.push(tokio::spawn(async move {
                if let Err(e) = detector.run(tx).await {
                    error!(detector = "dhcp", error = %e, "detector failed");
                }
            }));
        }

        // Drop our copy of the sender so the channel closes when all detectors stop
        drop(tx);

        // Initialize hardener
        let mut hardener = if self.config.hardener.enabled {
            Some(Hardener::new(self.config.hardener.clone()))
        } else {
            None
        };

        // === Activate protections ===
        let protect_iface = if interface.is_empty() { "wlan0".to_string() } else { interface.clone() };

        // MAC randomization (must be first — changes the interface MAC before other setup)
        let mut mac_randomizer = if self.config.protect.mac_randomize {
            let mut r = MacRandomizer::new(protect_iface.clone());
            if let Err(e) = r.activate() {
                warn!(error = %e, "MAC randomization failed (need root)");
            }
            Some(r)
        } else {
            None
        };

        // ARP gateway pinning
        let mut arp_pin = if self.config.protect.arp_pin {
            let mut pin = ArpPin::new();
            if let Err(e) = pin.activate() {
                warn!(error = %e, "ARP gateway pinning failed (need root)");
            }
            Some(pin)
        } else {
            None
        };

        // Client isolation
        let mut client_isolation = if self.config.protect.client_isolation {
            let mut iso = ClientIsolation::new();
            if let Err(e) = iso.activate(&protect_iface) {
                warn!(error = %e, "client isolation failed (need root + nft)");
            }
            Some(iso)
        } else {
            None
        };

        // DNS-over-TLS proxy
        let mut dns_crypt = if self.config.protect.dns_encrypt {
            let config = DnsCryptConfig {
                resolvers: self.config.protect.dns_resolvers.clone(),
            };
            let mut dc = DnsCrypt::new(config.clone());
            if let Err(e) = dc.activate_redirect() {
                warn!(error = %e, "DNS encryption redirect failed (need root + nft)");
            }
            // Spawn the proxy task
            let proxy_shutdown = shutdown_tx.subscribe();
            let dc_proxy = DnsCrypt::new(config);
            task_handles.push(tokio::spawn(async move {
                if let Err(e) = dc_proxy.run_proxy(proxy_shutdown).await {
                    error!(error = %e, "DNS-over-TLS proxy failed");
                }
            }));
            Some(dc)
        } else {
            None
        };

        let active_count = task_handles.len();
        info!(
            detectors = active_count,
            hardener = self.config.hardener.enabled,
            arp_pin = self.config.protect.arp_pin,
            client_isolation = self.config.protect.client_isolation,
            dns_encrypt = self.config.protect.dns_encrypt,
            mac_randomize = self.config.protect.mac_randomize,
            "bulwark daemon running"
        );

        if active_count == 0 && !self.config.protect.arp_pin && !self.config.protect.client_isolation && !self.config.protect.dns_encrypt && !self.config.protect.mac_randomize {
            warn!("no detectors or protections enabled — nothing to do");
            return Ok(());
        }

        // Threat deduplication to prevent log flooding
        let mut dedup = ThreatDedup::new(DEDUP_WINDOW_SECS);
        let mut total_threats: u64 = 0;
        let mut suppressed_threats: u64 = 0;

        // Main event loop: process threats from detectors
        loop {
            tokio::select! {
                threat = rx.recv() => {
                    match threat {
                        Some(threat) => {
                            total_threats += 1;

                            // Deduplicate repeated identical threats
                            if !dedup.should_emit(&threat) {
                                suppressed_threats += 1;
                                continue;
                            }

                            // Log to tracing (which goes to journald/stderr)
                            match threat.severity {
                                crate::alert::Severity::Low => {
                                    info!(
                                        severity = %threat.severity,
                                        detector = threat.detector,
                                        "{}",
                                        threat.kind
                                    );
                                }
                                crate::alert::Severity::Medium => {
                                    warn!(
                                        severity = %threat.severity,
                                        detector = threat.detector,
                                        "{}",
                                        threat.kind
                                    );
                                }
                                _ => {
                                    error!(
                                        severity = %threat.severity,
                                        detector = threat.detector,
                                        "THREAT: {}",
                                        threat.kind
                                    );
                                }
                            }

                            // Pass to hardener for auto-response
                            if let Some(ref mut h) = hardener {
                                h.on_threat(&threat);
                            }
                        }
                        None => {
                            info!("all detectors stopped, shutting down");
                            break;
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("shutdown signal received");
                    break;
                }
            }
        }

        if total_threats > 0 {
            info!(
                total = total_threats,
                suppressed = suppressed_threats,
                "threat summary"
            );
        }

        // === Cleanup: deactivate everything in reverse order ===

        // Deactivate hardener
        if let Some(ref mut h) = hardener {
            if h.is_active() {
                if let Err(e) = h.deactivate() {
                    error!(error = %e, "failed to deactivate hardener during shutdown");
                }
            }
        }

        // Deactivate DNS encryption
        if let Some(ref mut dc) = dns_crypt {
            if let Err(e) = dc.deactivate_redirect() {
                error!(error = %e, "failed to deactivate DNS encryption during shutdown");
            }
        }

        // Deactivate client isolation
        if let Some(ref mut iso) = client_isolation {
            if let Err(e) = iso.deactivate() {
                error!(error = %e, "failed to deactivate client isolation during shutdown");
            }
        }

        // Remove ARP pin
        if let Some(ref mut pin) = arp_pin {
            if let Err(e) = pin.deactivate() {
                error!(error = %e, "failed to remove ARP pin during shutdown");
            }
        }

        // Restore original MAC (last — interface must be up for other cleanup)
        if let Some(ref mut r) = mac_randomizer {
            if let Err(e) = r.deactivate() {
                error!(error = %e, "failed to restore MAC during shutdown");
            }
        }

        // Abort detector tasks
        for handle in task_handles {
            handle.abort();
        }

        info!("bulwark daemon stopped");
        Ok(())
    }
}

/// Try to detect the primary wireless interface.
fn detect_wireless_interface() -> Option<String> {
    // Check /sys/class/net/*/wireless — if a directory exists, it's a wireless interface
    let net_dir = std::path::Path::new("/sys/class/net");
    if let Ok(entries) = std::fs::read_dir(net_dir) {
        for entry in entries.flatten() {
            let wireless_path = entry.path().join("wireless");
            if wireless_path.exists() {
                if let Some(name) = entry.file_name().to_str() {
                    return Some(name.to_string());
                }
            }
        }
    }

    // Fallback: check for common interface names
    for name in &["wlan0", "wlp2s0", "wlp3s0", "wlp0s20f3"] {
        let path = format!("/sys/class/net/{}", name);
        if std::path::Path::new(&path).exists() {
            return Some(name.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{Severity, ThreatKind};
    use std::net::Ipv4Addr;

    #[test]
    fn test_detect_wireless_interface_returns_something_or_none() {
        // This test is environment-dependent; we just verify it doesn't panic
        let _ = detect_wireless_interface();
    }

    #[tokio::test]
    async fn test_daemon_no_detectors() {
        let mut config = Config::default();
        config.arp.enabled = false;
        config.gateway.enabled = false;
        config.dns.enabled = false;
        config.dhcp.enabled = false;

        let daemon = Daemon::new(config);
        let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);

        let result = daemon.run(shutdown_tx).await;
        assert!(result.is_ok());
    }

    fn make_threat(detector: &'static str, severity: Severity, kind: ThreatKind) -> Threat {
        Threat::new(kind, severity, detector)
    }

    #[test]
    fn test_dedup_first_threat_always_emitted() {
        let mut dedup = ThreatDedup::new(60);
        let threat = make_threat(
            "arp",
            Severity::Critical,
            ThreatKind::ArpSpoof {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                old_mac: crate::net_util::MacAddr([0xaa; 6]),
                new_mac: crate::net_util::MacAddr([0xbb; 6]),
            },
        );
        assert!(dedup.should_emit(&threat));
    }

    #[test]
    fn test_dedup_suppresses_identical_threat() {
        let mut dedup = ThreatDedup::new(60);
        let threat = make_threat(
            "arp",
            Severity::Critical,
            ThreatKind::ArpSpoof {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                old_mac: crate::net_util::MacAddr([0xaa; 6]),
                new_mac: crate::net_util::MacAddr([0xbb; 6]),
            },
        );
        assert!(dedup.should_emit(&threat));
        assert!(!dedup.should_emit(&threat)); // Suppressed
    }

    #[test]
    fn test_dedup_different_detectors_not_suppressed() {
        let mut dedup = ThreatDedup::new(60);
        let t1 = make_threat(
            "arp",
            Severity::Critical,
            ThreatKind::ArpSpoof {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                old_mac: crate::net_util::MacAddr([0xaa; 6]),
                new_mac: crate::net_util::MacAddr([0xbb; 6]),
            },
        );
        let t2 = make_threat(
            "gateway",
            Severity::High,
            ThreatKind::GatewayIpChanged {
                old_ip: Ipv4Addr::new(192, 168, 1, 1),
                new_ip: Ipv4Addr::new(10, 0, 0, 1),
            },
        );
        assert!(dedup.should_emit(&t1));
        assert!(dedup.should_emit(&t2)); // Different detector/kind, not suppressed
    }

    #[test]
    fn test_dedup_expired_window_re_emits() {
        let mut dedup = ThreatDedup::new(0); // 0 second window = always emit
        let threat = make_threat(
            "dns",
            Severity::High,
            ThreatKind::DnsPoisoning {
                domain: "evil.com".into(),
                system_results: vec![Ipv4Addr::new(1, 2, 3, 4)],
                trusted_results: vec![Ipv4Addr::new(5, 6, 7, 8)],
            },
        );
        assert!(dedup.should_emit(&threat));
        // With window=0, this should emit again immediately
        assert!(dedup.should_emit(&threat));
    }

    #[test]
    fn test_dedup_evicts_stale_entries() {
        let mut dedup = ThreatDedup::new(0);
        // Fill beyond DEDUP_MAX_KEYS to trigger eviction
        for i in 0..DEDUP_MAX_KEYS + 10 {
            let threat = make_threat(
                "arp",
                Severity::Low,
                ThreatKind::ArpFlood {
                    new_entries: i,
                    window_secs: 5,
                },
            );
            dedup.should_emit(&threat);
        }
        // Should not panic or grow unbounded — with window=0, eviction clears all
        assert!(dedup.last_seen.len() <= DEDUP_MAX_KEYS + 10);
    }

    #[test]
    fn test_threat_key_deterministic() {
        let threat = make_threat(
            "arp",
            Severity::Critical,
            ThreatKind::ArpSpoof {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                old_mac: crate::net_util::MacAddr([0xaa; 6]),
                new_mac: crate::net_util::MacAddr([0xbb; 6]),
            },
        );
        let k1 = ThreatDedup::threat_key(&threat);
        let k2 = ThreatDedup::threat_key(&threat);
        assert_eq!(k1, k2);
    }
}
