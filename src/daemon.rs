use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::alert::Threat;
use crate::config::Config;
use crate::detectors::arp::ArpDetector;
use crate::detectors::dhcp::DhcpDetector;
use crate::detectors::dns::DnsDetector;
use crate::detectors::gateway::GatewayDetector;
use crate::hardener::Hardener;

const CHANNEL_CAPACITY: usize = 256;

/// The main daemon that orchestrates all detectors and the hardener.
pub struct Daemon {
    config: Config,
}

impl Daemon {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Run the daemon: spawn detectors and process threats.
    pub async fn run(self, mut shutdown: tokio::sync::broadcast::Receiver<()>) -> Result<(), crate::Error> {
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

        let active_count = task_handles.len();
        info!(
            detectors = active_count,
            hardener = self.config.hardener.enabled,
            "bulwark daemon running"
        );

        if active_count == 0 {
            warn!("no detectors enabled — nothing to monitor");
            return Ok(());
        }

        // Main event loop: process threats from detectors
        loop {
            tokio::select! {
                threat = rx.recv() => {
                    match threat {
                        Some(threat) => {
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

        // Cleanup: deactivate hardener if active
        if let Some(ref mut h) = hardener {
            if h.is_active() {
                if let Err(e) = h.deactivate() {
                    error!(error = %e, "failed to deactivate hardener during shutdown");
                }
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
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        drop(shutdown_tx); // Will cause immediate shutdown

        let result = daemon.run(shutdown_rx).await;
        assert!(result.is_ok());
    }
}
