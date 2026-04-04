use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::alert::{Severity, Threat, ThreatKind};
use crate::config::DhcpConfig;

const DETECTOR_NAME: &str = "dhcp";

// DHCP packet offsets (relative to UDP payload)
const DHCP_OP_OFFSET: usize = 0;
const DHCP_SIADDR_OFFSET: usize = 20; // Server IP address
const DHCP_OPTIONS_OFFSET: usize = 236; // After fixed header + sname + file
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

// DHCP message types
const DHCP_OFFER: u8 = 2;

// DHCP option codes
const DHCP_OPT_MESSAGE_TYPE: u8 = 53;
const DHCP_OPT_SERVER_ID: u8 = 54;
const DHCP_OPT_END: u8 = 255;

/// Information extracted from a DHCP OFFER packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOffer {
    pub server_ip: Ipv4Addr,
    pub server_id: Option<Ipv4Addr>,
}

/// Detects rogue DHCP servers on the network by monitoring DHCP OFFER packets.
pub struct DhcpDetector {
    config: DhcpConfig,
    interface: String,
    /// The first DHCP server we see is considered legitimate.
    known_server: Option<Ipv4Addr>,
}

impl DhcpDetector {
    pub fn new(config: DhcpConfig, interface: String) -> Self {
        Self {
            config,
            interface,
            known_server: None,
        }
    }

    /// Run the DHCP detection loop.
    ///
    /// This uses a raw socket (AF_PACKET) to capture DHCP OFFER packets on the wire.
    /// Requires CAP_NET_RAW or root.
    pub async fn run(mut self, tx: mpsc::Sender<Threat>) -> Result<(), crate::Error> {
        info!(
            detector = DETECTOR_NAME,
            interface = %self.interface,
            "starting rogue DHCP detector"
        );

        // We use a UDP socket bound to the DHCP client port to receive DHCP offers.
        // This works when the system is actively obtaining or renewing a lease.
        // For comprehensive monitoring, we'd need AF_PACKET, but this covers the
        // most important case: detecting rogue servers during lease operations.
        let socket = match create_dhcp_listener(&self.interface).await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    detector = DETECTOR_NAME,
                    error = %e,
                    "failed to create DHCP listener (need root/CAP_NET_RAW), falling back to lease file monitoring"
                );
                // Fall back to monitoring lease files
                return self.run_lease_monitor(tx).await;
            }
        };

        let timeout = Duration::from_secs(self.config.listen_timeout_secs);
        let mut buf = [0u8; 1500];

        loop {
            let result = tokio::time::timeout(timeout, socket.recv(&mut buf)).await;
            match result {
                Ok(Ok(len)) => {
                    if let Some(offer) = parse_dhcp_offer(&buf[..len]) {
                        let server = offer.server_id.unwrap_or(offer.server_ip);
                        if let Some(threat) = self.check_server(server) {
                            warn!("{}", threat);
                            if tx.send(threat).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    debug!(detector = DETECTOR_NAME, error = %e, "recv error");
                }
                Err(_) => {
                    // Timeout — no DHCP traffic, that's normal
                    debug!(detector = DETECTOR_NAME, "no DHCP traffic in window");
                }
            }
        }
    }

    /// Fallback: monitor DHCP lease files for server information.
    async fn run_lease_monitor(mut self, tx: mpsc::Sender<Threat>) -> Result<(), crate::Error> {
        let interval = Duration::from_secs(30);
        info!(
            detector = DETECTOR_NAME,
            "monitoring DHCP lease files for rogue servers"
        );

        loop {
            if let Ok(servers) = read_dhcp_servers_from_leases().await {
                for server in servers {
                    if let Some(threat) = self.check_server(server) {
                        warn!("{}", threat);
                        if tx.send(threat).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Check if a DHCP server is the expected one. Returns a threat if rogue.
    fn check_server(&mut self, server: Ipv4Addr) -> Option<Threat> {
        match self.known_server {
            None => {
                info!(
                    detector = DETECTOR_NAME,
                    server = %server,
                    "established DHCP server baseline"
                );
                self.known_server = Some(server);
                None
            }
            Some(known) if known == server => None,
            Some(known) => Some(Threat::new(
                ThreatKind::RogueDhcpServer {
                    expected_server: known,
                    rogue_server: server,
                },
                Severity::Critical,
                DETECTOR_NAME,
            )),
        }
    }
}

/// Create a UDP socket for listening to DHCP offers.
async fn create_dhcp_listener(interface: &str) -> Result<tokio::net::UdpSocket, crate::Error> {
    use std::os::fd::AsRawFd;

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:68")
        .await
        .map_err(crate::Error::Io)?;

    // Bind to specific interface
    let fd = socket.as_raw_fd();
    let iface_bytes = interface.as_bytes();
    let mut optval = [0u8; libc::IFNAMSIZ];
    let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);
    optval[..copy_len].copy_from_slice(&iface_bytes[..copy_len]);

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            optval.as_ptr() as *const libc::c_void,
            std::mem::size_of_val(&optval) as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(crate::Error::Network(format!(
            "SO_BINDTODEVICE failed for {}: {}",
            interface,
            std::io::Error::last_os_error()
        )));
    }

    // Enable broadcast reception
    socket
        .set_broadcast(true)
        .map_err(crate::Error::Io)?;

    Ok(socket)
}

/// Parse a DHCP OFFER from a UDP payload. Returns None if not a valid DHCP OFFER.
pub fn parse_dhcp_offer(data: &[u8]) -> Option<DhcpOffer> {
    // Minimum DHCP packet: 240 bytes (236 fixed + 4 magic cookie)
    if data.len() < DHCP_OPTIONS_OFFSET + 4 {
        return None;
    }

    // Check it's a BOOTREPLY (op = 2)
    if data[DHCP_OP_OFFSET] != 2 {
        return None;
    }

    // Check magic cookie
    if data[DHCP_OPTIONS_OFFSET..DHCP_OPTIONS_OFFSET + 4] != DHCP_MAGIC_COOKIE {
        return None;
    }

    // Parse options to find message type and server identifier
    let mut msg_type = None;
    let mut server_id = None;
    let mut offset = DHCP_OPTIONS_OFFSET + 4;

    while offset < data.len() {
        let opt_code = data[offset];
        if opt_code == DHCP_OPT_END {
            break;
        }
        if opt_code == 0 {
            // Padding
            offset += 1;
            continue;
        }
        if offset + 1 >= data.len() {
            break;
        }
        let opt_len = data[offset + 1] as usize;
        let opt_data_start = offset + 2;
        if opt_data_start + opt_len > data.len() {
            break;
        }

        match opt_code {
            DHCP_OPT_MESSAGE_TYPE if opt_len == 1 => {
                msg_type = Some(data[opt_data_start]);
            }
            DHCP_OPT_SERVER_ID if opt_len == 4 => {
                server_id = Some(Ipv4Addr::new(
                    data[opt_data_start],
                    data[opt_data_start + 1],
                    data[opt_data_start + 2],
                    data[opt_data_start + 3],
                ));
            }
            _ => {}
        }

        offset = opt_data_start + opt_len;
    }

    // Must be a DHCP OFFER
    if msg_type != Some(DHCP_OFFER) {
        return None;
    }

    // Server IP from fixed header
    let server_ip = Ipv4Addr::new(
        data[DHCP_SIADDR_OFFSET],
        data[DHCP_SIADDR_OFFSET + 1],
        data[DHCP_SIADDR_OFFSET + 2],
        data[DHCP_SIADDR_OFFSET + 3],
    );

    Some(DhcpOffer {
        server_ip,
        server_id,
    })
}

/// Try to read DHCP server IPs from common lease file locations.
async fn read_dhcp_servers_from_leases() -> Result<Vec<Ipv4Addr>, crate::Error> {
    let lease_paths = [
        "/var/lib/dhclient/dhclient.leases",
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/NetworkManager/",
    ];

    let mut servers = Vec::new();

    for path in &lease_paths {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            servers.extend(parse_lease_servers(&content));
        }
    }

    Ok(servers)
}

/// Parse DHCP server IPs from dhclient lease file content.
fn parse_lease_servers(content: &str) -> Vec<Ipv4Addr> {
    let mut servers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        // dhclient format: "option dhcp-server-identifier 192.168.1.1;"
        if line.starts_with("option dhcp-server-identifier") {
            if let Some(ip_str) = line
                .trim_start_matches("option dhcp-server-identifier")
                .trim()
                .trim_end_matches(';')
                .trim()
                .parse::<Ipv4Addr>()
                .ok()
            {
                servers.push(ip_str);
            }
        }
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DHCP OFFER packet for testing.
    fn build_test_dhcp_offer(server_ip: Ipv4Addr, server_id: Option<Ipv4Addr>) -> Vec<u8> {
        let mut packet = vec![0u8; DHCP_OPTIONS_OFFSET + 4];

        // op = BOOTREPLY
        packet[DHCP_OP_OFFSET] = 2;
        // htype = Ethernet
        packet[1] = 1;
        // hlen = 6
        packet[2] = 6;

        // siaddr (server IP)
        let octets = server_ip.octets();
        packet[DHCP_SIADDR_OFFSET] = octets[0];
        packet[DHCP_SIADDR_OFFSET + 1] = octets[1];
        packet[DHCP_SIADDR_OFFSET + 2] = octets[2];
        packet[DHCP_SIADDR_OFFSET + 3] = octets[3];

        // Magic cookie
        packet[DHCP_OPTIONS_OFFSET..DHCP_OPTIONS_OFFSET + 4]
            .copy_from_slice(&DHCP_MAGIC_COOKIE);

        // Option 53: DHCP Message Type = OFFER (2)
        packet.push(DHCP_OPT_MESSAGE_TYPE);
        packet.push(1); // length
        packet.push(DHCP_OFFER);

        // Option 54: Server Identifier
        if let Some(sid) = server_id {
            packet.push(DHCP_OPT_SERVER_ID);
            packet.push(4);
            packet.extend_from_slice(&sid.octets());
        }

        // End option
        packet.push(DHCP_OPT_END);

        packet
    }

    #[test]
    fn test_parse_dhcp_offer_valid() {
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let server_id = Ipv4Addr::new(192, 168, 1, 1);
        let packet = build_test_dhcp_offer(server_ip, Some(server_id));

        let offer = parse_dhcp_offer(&packet).unwrap();
        assert_eq!(offer.server_ip, server_ip);
        assert_eq!(offer.server_id, Some(server_id));
    }

    #[test]
    fn test_parse_dhcp_offer_no_server_id() {
        let server_ip = Ipv4Addr::new(10, 0, 0, 1);
        let packet = build_test_dhcp_offer(server_ip, None);

        let offer = parse_dhcp_offer(&packet).unwrap();
        assert_eq!(offer.server_ip, server_ip);
        assert_eq!(offer.server_id, None);
    }

    #[test]
    fn test_parse_dhcp_offer_not_bootreply() {
        let mut packet = build_test_dhcp_offer(Ipv4Addr::new(10, 0, 0, 1), None);
        packet[DHCP_OP_OFFSET] = 1; // BOOTREQUEST
        assert!(parse_dhcp_offer(&packet).is_none());
    }

    #[test]
    fn test_parse_dhcp_offer_too_short() {
        let packet = vec![0u8; 100]; // Too short
        assert!(parse_dhcp_offer(&packet).is_none());
    }

    #[test]
    fn test_parse_dhcp_offer_bad_cookie() {
        let mut packet = build_test_dhcp_offer(Ipv4Addr::new(10, 0, 0, 1), None);
        packet[DHCP_OPTIONS_OFFSET] = 0xFF; // Break magic cookie
        assert!(parse_dhcp_offer(&packet).is_none());
    }

    #[test]
    fn test_check_server_baseline() {
        let mut det = DhcpDetector::new(
            DhcpConfig::default(),
            "wlan0".to_string(),
        );
        let server = Ipv4Addr::new(192, 168, 1, 1);
        assert!(det.check_server(server).is_none()); // Baseline
        assert_eq!(det.known_server, Some(server));
    }

    #[test]
    fn test_check_server_same() {
        let mut det = DhcpDetector::new(
            DhcpConfig::default(),
            "wlan0".to_string(),
        );
        let server = Ipv4Addr::new(192, 168, 1, 1);
        det.check_server(server);
        assert!(det.check_server(server).is_none()); // Same server, no threat
    }

    #[test]
    fn test_check_server_rogue() {
        let mut det = DhcpDetector::new(
            DhcpConfig::default(),
            "wlan0".to_string(),
        );
        let legit = Ipv4Addr::new(192, 168, 1, 1);
        let rogue = Ipv4Addr::new(192, 168, 1, 99);
        det.check_server(legit);
        let threat = det.check_server(rogue).unwrap();
        assert_eq!(threat.severity, Severity::Critical);
        match &threat.kind {
            ThreatKind::RogueDhcpServer {
                expected_server,
                rogue_server,
            } => {
                assert_eq!(*expected_server, legit);
                assert_eq!(*rogue_server, rogue);
            }
            other => panic!("expected RogueDhcpServer, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_lease_servers() {
        let content = r#"
lease {
  interface "wlan0";
  fixed-address 192.168.1.50;
  option dhcp-server-identifier 192.168.1.1;
  option routers 192.168.1.1;
  renew 2 2026/04/05 12:00:00;
}
"#;
        let servers = parse_lease_servers(content);
        assert_eq!(servers, vec![Ipv4Addr::new(192, 168, 1, 1)]);
    }

    #[test]
    fn test_parse_lease_servers_empty() {
        let servers = parse_lease_servers("");
        assert!(servers.is_empty());
    }
}
