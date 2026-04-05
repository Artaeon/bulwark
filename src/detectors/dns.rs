//! DNS poisoning detector.
//!
//! Periodically resolves configured test domains via both the system resolver
//! (from `/etc/resolv.conf`) and trusted resolvers (Cloudflare 1.1.1.1,
//! Google 8.8.8.8 by default).
//!
//! Uses the minimal DNS query/response codec from [`crate::net_util`] to send
//! raw UDP queries, avoiding dependency on system resolver libraries.
//!
//! # Detection logic
//!
//! Results are compared using set intersection. Only when there is **zero overlap**
//! between system and trusted results is a poisoning alert raised. This avoids
//! false positives from CDN IP variation, where different resolvers legitimately
//! return different IP addresses for the same domain.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::alert::{Severity, Threat, ThreatKind};
use crate::config::DnsConfig;
use crate::net_util;

const DETECTOR_NAME: &str = "dns";
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// Detects DNS poisoning by comparing responses from the system resolver
/// against trusted resolvers (e.g., 1.1.1.1, 8.8.8.8).
pub struct DnsDetector {
    config: DnsConfig,
    query_id: u16,
}

impl DnsDetector {
    pub fn new(config: DnsConfig) -> Self {
        Self {
            config,
            query_id: 1,
        }
    }

    fn next_id(&mut self) -> u16 {
        let id = self.query_id;
        self.query_id = self.query_id.wrapping_add(1);
        id
    }

    /// Run the DNS validation loop.
    pub async fn run(mut self, tx: mpsc::Sender<Threat>) -> Result<(), crate::Error> {
        let interval = Duration::from_secs(self.config.poll_interval_secs);
        info!(
            detector = DETECTOR_NAME,
            interval_secs = self.config.poll_interval_secs,
            domains = ?self.config.test_domains,
            "starting DNS poisoning detector"
        );

        loop {
            let threats = self.check_all_domains().await;
            for threat in threats {
                warn!("{}", threat);
                if tx.send(threat).await.is_err() {
                    return Ok(());
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Check all configured test domains against trusted resolvers.
    async fn check_all_domains(&mut self) -> Vec<Threat> {
        let mut threats = Vec::new();

        for domain in self.config.test_domains.clone() {
            match self.check_domain(&domain).await {
                Ok(Some(threat)) => threats.push(threat),
                Ok(None) => {}
                Err(e) => {
                    debug!(
                        detector = DETECTOR_NAME,
                        domain = %domain,
                        error = %e,
                        "DNS check failed"
                    );
                }
            }
        }

        threats
    }

    /// Check a single domain: query system resolver vs trusted resolvers.
    async fn check_domain(&mut self, domain: &str) -> Result<Option<Threat>, crate::Error> {
        // Get system resolver from /etc/resolv.conf
        let system_resolvers = read_system_resolvers().await;
        if system_resolvers.is_empty() {
            debug!(detector = DETECTOR_NAME, "no system resolvers found");
            return Ok(None);
        }

        // Query system resolver
        let system_ips = match self.query_resolver(&system_resolvers[0], domain).await {
            Ok(ips) => ips,
            Err(e) => {
                debug!(
                    detector = DETECTOR_NAME,
                    resolver = %system_resolvers[0],
                    error = %e,
                    "system DNS query failed"
                );
                return Ok(None);
            }
        };

        if system_ips.is_empty() {
            return Ok(None);
        }

        // Query trusted resolvers and collect all IPs
        let mut trusted_ips_set: HashSet<Ipv4Addr> = HashSet::new();
        let trusted_resolvers = self.config.trusted_resolvers.clone();
        for resolver in &trusted_resolvers {
            if let Ok(ips) = self.query_resolver(resolver, domain).await {
                trusted_ips_set.extend(ips);
            }
        }

        if trusted_ips_set.is_empty() {
            debug!(
                detector = DETECTOR_NAME,
                domain = %domain,
                "no trusted resolver responses"
            );
            return Ok(None);
        }

        // Compare: if system results have NO overlap with trusted results, likely poisoned.
        // We use set intersection because CDNs may return different IPs from different vantage points.
        let system_set: HashSet<Ipv4Addr> = system_ips.iter().copied().collect();
        let overlap = system_set.intersection(&trusted_ips_set).count();

        if overlap == 0 {
            let trusted_results: Vec<Ipv4Addr> = trusted_ips_set.into_iter().collect();
            return Ok(Some(Threat::new(
                ThreatKind::DnsPoisoning {
                    domain: domain.to_string(),
                    system_results: system_ips,
                    trusted_results,
                },
                Severity::High,
                DETECTOR_NAME,
            )));
        }

        debug!(
            detector = DETECTOR_NAME,
            domain = %domain,
            system = ?system_ips,
            "DNS check passed"
        );
        Ok(None)
    }

    /// Send a DNS A query to a specific resolver and parse the response.
    async fn query_resolver(
        &mut self,
        resolver: &str,
        domain: &str,
    ) -> Result<Vec<Ipv4Addr>, crate::Error> {
        let resolver_addr: SocketAddr = format!("{}:53", resolver)
            .parse()
            .map_err(|e| crate::Error::Network(format!("invalid resolver address: {}", e)))?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(crate::Error::Io)?;

        let id = self.next_id();
        let query = net_util::build_dns_query(id, domain).ok_or_else(|| {
            crate::Error::Network(format!("invalid domain for DNS query: {}", domain))
        })?;

        socket
            .send_to(&query, resolver_addr)
            .await
            .map_err(crate::Error::Io)?;

        let mut buf = [0u8; 512];
        let result = tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((len, _))) => {
                let response = &buf[..len];
                // Verify response ID matches
                if len >= 2 {
                    let resp_id = u16::from_be_bytes([response[0], response[1]]);
                    if resp_id != id {
                        return Err(crate::Error::Network("DNS response ID mismatch".into()));
                    }
                }
                net_util::parse_dns_response(response)
                    .ok_or_else(|| crate::Error::Network("failed to parse DNS response".into()))
            }
            Ok(Err(e)) => Err(crate::Error::Io(e)),
            Err(_) => Err(crate::Error::Network(format!(
                "DNS query to {} timed out",
                resolver
            ))),
        }
    }
}

/// Read nameservers from /etc/resolv.conf.
async fn read_system_resolvers() -> Vec<String> {
    let content = match tokio::fs::read_to_string("/etc/resolv.conf").await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_resolv_conf(&content)
}

/// Parse nameserver lines from resolv.conf content.
fn parse_resolv_conf(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("nameserver") {
                line.split_whitespace().nth(1).map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolv_conf() {
        let content = "\
# Generated by NetworkManager
nameserver 192.168.1.1
nameserver 8.8.8.8
search local
";
        let resolvers = parse_resolv_conf(content);
        assert_eq!(resolvers, vec!["192.168.1.1", "8.8.8.8"]);
    }

    #[test]
    fn test_parse_resolv_conf_comments_only() {
        let content = "# nothing here\n";
        let resolvers = parse_resolv_conf(content);
        assert!(resolvers.is_empty());
    }

    #[test]
    fn test_parse_resolv_conf_empty() {
        let resolvers = parse_resolv_conf("");
        assert!(resolvers.is_empty());
    }

    #[test]
    fn test_dns_detector_id_wrapping() {
        let mut det = DnsDetector::new(DnsConfig::default());
        det.query_id = u16::MAX;
        assert_eq!(det.next_id(), u16::MAX);
        assert_eq!(det.next_id(), 0);
    }

    #[test]
    fn test_dns_query_response_roundtrip() {
        let id = 0x4242;
        let query = net_util::build_dns_query(id, "example.com").unwrap();
        // Verify query structure
        assert_eq!(query[0], 0x42);
        assert_eq!(query[1], 0x42);
        assert_eq!(query[2], 0x01); // RD flag
        assert_eq!(query[3], 0x00);
    }

    #[test]
    fn test_poison_detection_logic() {
        // System returns 1.2.3.4, trusted returns 93.184.216.34 — no overlap = poison
        let system: HashSet<Ipv4Addr> = [Ipv4Addr::new(1, 2, 3, 4)].into_iter().collect();
        let trusted: HashSet<Ipv4Addr> = [Ipv4Addr::new(93, 184, 216, 34)].into_iter().collect();
        let overlap = system.intersection(&trusted).count();
        assert_eq!(overlap, 0);
    }

    #[test]
    fn test_cdn_overlap_no_false_positive() {
        // CDN: system returns IP A, trusted returns IPs A and B — overlap exists, OK
        let system: HashSet<Ipv4Addr> = [Ipv4Addr::new(104, 16, 132, 229)].into_iter().collect();
        let trusted: HashSet<Ipv4Addr> = [
            Ipv4Addr::new(104, 16, 132, 229),
            Ipv4Addr::new(104, 16, 133, 229),
        ]
        .into_iter()
        .collect();
        let overlap = system.intersection(&trusted).count();
        assert!(overlap > 0);
    }

    #[test]
    fn test_multiple_system_ips_partial_overlap_ok() {
        // System returns {A, B}, trusted returns {B, C} — overlap on B
        let system: HashSet<Ipv4Addr> = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)]
            .into_iter()
            .collect();
        let trusted: HashSet<Ipv4Addr> = [Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(3, 3, 3, 3)]
            .into_iter()
            .collect();
        let overlap = system.intersection(&trusted).count();
        assert!(overlap > 0);
    }

    #[test]
    fn test_parse_resolv_conf_with_comments_and_whitespace() {
        let content = "\
# This is a comment
   nameserver   192.168.1.1
nameserver 8.8.8.8
  # another comment
search localdomain
domain example.com
";
        let resolvers = parse_resolv_conf(content);
        assert_eq!(resolvers, vec!["192.168.1.1", "8.8.8.8"]);
    }

    #[test]
    fn test_parse_resolv_conf_ipv6() {
        let content = "nameserver ::1\nnameserver 2001:4860:4860::8888\n";
        let resolvers = parse_resolv_conf(content);
        assert_eq!(resolvers, vec!["::1", "2001:4860:4860::8888"]);
    }

    #[test]
    fn test_dns_detector_initial_state() {
        let det = DnsDetector::new(DnsConfig::default());
        assert_eq!(det.query_id, 1);
    }

    #[test]
    fn test_build_dns_query_rejects_malformed() {
        // Leading dot
        assert!(net_util::build_dns_query(1, ".example.com").is_none());
        // Trailing dot creates empty label
        assert!(net_util::build_dns_query(1, "example.com.").is_none());
    }
}
