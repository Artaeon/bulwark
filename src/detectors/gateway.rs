//! Default gateway change detector.
//!
//! Monitors the default gateway by polling `/proc/net/route` and cross-referencing
//! with `/proc/net/arp` to track both the gateway IP and its MAC address.
//!
//! Detects:
//!
//! - **Gateway IP change** (High) — the default route now points to a different IP,
//!   which may indicate an evil twin AP or rogue gateway.
//! - **Gateway MAC change** (Critical) — same gateway IP but different MAC address,
//!   the strongest indicator of active ARP poisoning targeting the gateway itself.

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::alert::{Severity, Threat, ThreatKind};
use crate::config::GatewayConfig;
use crate::net_util::{self, MacAddr};

const DETECTOR_NAME: &str = "gateway";

/// Tracked gateway state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayState {
    ip: Ipv4Addr,
    mac: Option<MacAddr>,
    interface: String,
}

/// Detects changes to the default gateway (IP or MAC), which can indicate
/// ARP poisoning, evil twin attacks, or rogue access points.
pub struct GatewayDetector {
    config: GatewayConfig,
    state: Option<GatewayState>,
}

impl GatewayDetector {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            state: None,
        }
    }

    /// Run the gateway monitoring loop.
    pub async fn run(mut self, tx: mpsc::Sender<Threat>) -> Result<(), crate::Error> {
        let interval = Duration::from_secs(self.config.poll_interval_secs);
        info!(
            detector = DETECTOR_NAME,
            interval_secs = self.config.poll_interval_secs,
            "starting gateway change detector"
        );

        loop {
            let route_content = tokio::fs::read_to_string("/proc/net/route").await;
            let arp_content = tokio::fs::read_to_string("/proc/net/arp").await;

            match (route_content, arp_content) {
                (Ok(route), Ok(arp)) => {
                    let threats = self.analyze(&route, &arp);
                    for threat in threats {
                        warn!("{}", threat);
                        if tx.send(threat).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                (Err(e), _) => {
                    debug!(detector = DETECTOR_NAME, error = %e, "failed to read route table");
                }
                (_, Err(e)) => {
                    debug!(detector = DETECTOR_NAME, error = %e, "failed to read ARP table");
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Analyze route and ARP tables, return threats if gateway changed.
    pub fn analyze(&mut self, route_content: &str, arp_content: &str) -> Vec<Threat> {
        let mut threats = Vec::new();

        let route = match net_util::parse_default_route(route_content) {
            Some(r) => r,
            None => {
                debug!(detector = DETECTOR_NAME, "no default route found");
                return threats;
            }
        };

        let arp_entries = net_util::parse_arp_table(arp_content);
        let gw_mac = net_util::resolve_mac_from_arp(&arp_entries, route.gateway_ip);

        let current = GatewayState {
            ip: route.gateway_ip,
            mac: gw_mac,
            interface: route.interface,
        };

        match &self.state {
            None => {
                info!(
                    detector = DETECTOR_NAME,
                    gateway_ip = %current.ip,
                    gateway_mac = ?current.mac,
                    interface = %current.interface,
                    "established gateway baseline"
                );
            }
            Some(prev) => {
                // Gateway IP changed
                if prev.ip != current.ip {
                    threats.push(Threat::new(
                        ThreatKind::GatewayIpChanged {
                            old_ip: prev.ip,
                            new_ip: current.ip,
                        },
                        Severity::High,
                        DETECTOR_NAME,
                    ));
                }

                // Gateway MAC changed (same IP, different MAC = very suspicious)
                if prev.ip == current.ip {
                    if let (Some(old_mac), Some(new_mac)) = (prev.mac, current.mac) {
                        if old_mac != new_mac {
                            threats.push(Threat::new(
                                ThreatKind::GatewayMacChanged {
                                    gateway_ip: current.ip,
                                    old_mac,
                                    new_mac,
                                },
                                Severity::Critical,
                                DETECTOR_NAME,
                            ));
                        }
                    }
                }
            }
        }

        self.state = Some(current);
        threats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;

    fn make_detector() -> GatewayDetector {
        GatewayDetector::new(GatewayConfig {
            enabled: true,
            poll_interval_secs: 10,
        })
    }

    const ROUTE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\tFFFFFF00\t0\t0\t0";

    const ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0";

    #[test]
    fn test_baseline_no_threats() {
        let mut det = make_detector();
        let threats = det.analyze(ROUTE, ARP);
        assert!(threats.is_empty());
        assert!(det.state.is_some());
        let state = det.state.as_ref().unwrap();
        assert_eq!(state.ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            state.mac,
            Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap())
        );
    }

    #[test]
    fn test_no_change_no_threats() {
        let mut det = make_detector();
        det.analyze(ROUTE, ARP);
        let threats = det.analyze(ROUTE, ARP);
        assert!(threats.is_empty());
    }

    #[test]
    fn test_detect_gateway_mac_change() {
        let mut det = make_detector();
        det.analyze(ROUTE, ARP);

        let spoofed_arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         de:ad:be:ef:00:01     *        wlan0";

        let threats = det.analyze(ROUTE, spoofed_arp);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].severity, Severity::Critical);
        assert!(matches!(
            threats[0].kind,
            ThreatKind::GatewayMacChanged { .. }
        ));
    }

    #[test]
    fn test_detect_gateway_ip_change() {
        let mut det = make_detector();
        det.analyze(ROUTE, ARP);

        // Gateway changed to 192.168.1.2 (0201A8C0)
        let new_route = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0201A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0";

        let new_arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.2      0x1         0x2         ff:ee:dd:cc:bb:aa     *        wlan0";

        let threats = det.analyze(new_route, new_arp);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].severity, Severity::High);
        match &threats[0].kind {
            ThreatKind::GatewayIpChanged { old_ip, new_ip } => {
                assert_eq!(*old_ip, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(*new_ip, Ipv4Addr::new(192, 168, 1, 2));
            }
            other => panic!("expected GatewayIpChanged, got {:?}", other),
        }
    }

    #[test]
    fn test_no_default_route() {
        let mut det = make_detector();
        let no_default = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\tFFFFFF00\t0\t0\t0";

        let threats = det.analyze(no_default, ARP);
        assert!(threats.is_empty());
        assert!(det.state.is_none());
    }

    #[test]
    fn test_gateway_mac_becomes_available() {
        let mut det = make_detector();
        // First scan: no ARP entry for gateway yet
        let empty_arp = "\
IP address       HW type     Flags       HW address            Mask     Device";
        let threats = det.analyze(ROUTE, empty_arp);
        assert!(threats.is_empty());
        assert!(det.state.as_ref().unwrap().mac.is_none());

        // Second scan: ARP entry appears — should NOT be a threat
        // (MAC going from None to Some is not a change)
        let threats = det.analyze(ROUTE, ARP);
        assert!(threats.is_empty());
    }

    #[test]
    fn test_empty_route_table() {
        let mut det = make_detector();
        let threats = det.analyze("", "");
        assert!(threats.is_empty());
        assert!(det.state.is_none());
    }

    #[test]
    fn test_gateway_ip_and_mac_change_simultaneously() {
        let mut det = make_detector();
        det.analyze(ROUTE, ARP);

        // Both IP and MAC change — should report IP change (not MAC change,
        // since MAC comparison only triggers for same-IP gateway)
        let new_route = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0201A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0";
        let new_arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.2      0x1         0x2         ff:ee:dd:cc:bb:aa     *        wlan0";

        let threats = det.analyze(new_route, new_arp);
        assert_eq!(threats.len(), 1);
        assert!(matches!(
            threats[0].kind,
            ThreatKind::GatewayIpChanged { .. }
        ));
    }

    #[test]
    fn test_route_disappears_then_reappears() {
        let mut det = make_detector();
        det.analyze(ROUTE, ARP); // baseline

        // Route disappears
        let threats = det.analyze("", ARP);
        assert!(threats.is_empty());

        // Route reappears with same gateway — no threat
        let threats = det.analyze(ROUTE, ARP);
        assert!(threats.is_empty());
    }
}
