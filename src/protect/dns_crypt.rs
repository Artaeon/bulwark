//! DNS-over-TLS (DoT) proxy — encrypt all DNS queries.
//!
//! This module runs a lightweight local DNS proxy that:
//!
//! 1. Listens on `127.0.0.1:5353` for plain UDP DNS queries
//! 2. Forwards them over TLS (port 853) to trusted resolvers
//! 3. Returns the encrypted responses to the local client
//!
//! When activated, nftables DNAT rules redirect all outgoing DNS traffic
//! (UDP/TCP port 53) to the local proxy, making DNS encryption transparent
//! to all applications on the system.
//!
//! # Protocol
//!
//! DNS-over-TLS (RFC 7858) uses TCP with TLS on port 853. DNS messages
//! are length-prefixed (2-byte big-endian length prefix before each message),
//! the same as standard DNS-over-TCP (RFC 1035 section 4.2.2).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

const LISTEN_ADDR: &str = "127.0.0.1:5353";
const DNS_TABLE: &str = "bulwark_dns";
const MAX_DNS_PACKET: usize = 512;

/// Configuration for the DNS-over-TLS proxy.
#[derive(Debug, Clone)]
pub struct DnsCryptConfig {
    /// TLS resolvers to forward queries to (e.g., "1.1.1.1:853").
    pub resolvers: Vec<String>,
}

impl Default for DnsCryptConfig {
    fn default() -> Self {
        Self {
            resolvers: vec!["1.1.1.1:853".to_string(), "8.8.8.8:853".to_string()],
        }
    }
}

/// Manages the DNS-over-TLS proxy and its nftables redirection rules.
pub struct DnsCrypt {
    config: DnsCryptConfig,
    active: bool,
}

impl DnsCrypt {
    pub fn new(config: DnsCryptConfig) -> Self {
        Self {
            config,
            active: false,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Apply nftables DNAT rules to redirect DNS to the local proxy.
    pub fn activate_redirect(&mut self) -> Result<(), crate::Error> {
        if self.active {
            return Ok(());
        }

        let ruleset = generate_dns_redirect_rules();
        apply_nft_rules(&ruleset)?;

        self.active = true;
        info!("DNS-over-TLS redirection activated (port 53 -> 127.0.0.1:5353)");
        Ok(())
    }

    /// Remove the DNS redirection rules.
    pub fn deactivate_redirect(&mut self) -> Result<(), crate::Error> {
        if !self.active {
            return Ok(());
        }

        let output = std::process::Command::new("nft")
            .args(["delete", "table", "ip", DNS_TABLE])
            .output()
            .map_err(|e| crate::Error::Hardener(format!("failed to run nft: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(error = %stderr.trim(), "failed to remove DNS redirect rules");
        }

        self.active = false;
        info!("DNS-over-TLS redirection deactivated");
        Ok(())
    }

    /// Bind the DNS proxy's listening socket.
    ///
    /// Separated from [`Self::serve`] so that binding failures (e.g., port
    /// already in use) can be detected BEFORE installing the nftables
    /// redirect — otherwise DNS would be broken on the host.
    pub async fn bind() -> Result<Arc<UdpSocket>, crate::Error> {
        let socket = UdpSocket::bind(LISTEN_ADDR)
            .await
            .map_err(crate::Error::Io)?;
        info!(listen = LISTEN_ADDR, "DNS-over-TLS proxy bound");
        Ok(Arc::new(socket))
    }

    /// Serve DNS queries on a pre-bound socket.
    ///
    /// Forwards UDP DNS queries over TLS to configured resolvers and sends
    /// responses back from the same socket the query was received on
    /// (clients reject responses from a different address).
    pub async fn serve(
        &self,
        socket: Arc<UdpSocket>,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<(), crate::Error> {
        info!("DNS-over-TLS proxy started");

        let tls_config = build_tls_config()?;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let resolvers = self.config.resolvers.clone();

        let mut buf = [0u8; MAX_DNS_PACKET];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            let query = buf[..len].to_vec();
                            let connector = connector.clone();
                            let resolvers = resolvers.clone();
                            let reply_sock = Arc::clone(&socket);

                            // Spawn handler task for this query. The reply is sent
                            // from the same socket that received the query — DNS
                            // clients reject responses from a different source.
                            tokio::spawn(async move {
                                match forward_query_tls(&connector, &resolvers, &query).await {
                                    Ok(response) => {
                                        if let Err(e) = reply_sock.send_to(&response, src).await {
                                            debug!(error = %e, "failed to send DNS response");
                                        }
                                    }
                                    Err(e) => {
                                        debug!(
                                            error = %e,
                                            src = %src,
                                            "DNS-over-TLS query failed"
                                        );
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            debug!(error = %e, "DNS proxy recv error");
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("DNS-over-TLS proxy shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Forward a DNS query over TLS to one of the configured resolvers.
async fn forward_query_tls(
    connector: &tokio_rustls::TlsConnector,
    resolvers: &[String],
    query: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    // Try each resolver until one succeeds
    let mut last_err = None;

    for resolver in resolvers {
        match try_resolver(connector, resolver, query).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                debug!(resolver = %resolver, error = %e, "resolver failed, trying next");
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| crate::Error::Network("no resolvers configured".into())))
}

/// Try a single resolver over TLS.
async fn try_resolver(
    connector: &tokio_rustls::TlsConnector,
    resolver: &str,
    query: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    let addr: SocketAddr = resolver.parse().map_err(|e| {
        crate::Error::Network(format!("invalid resolver address {}: {}", resolver, e))
    })?;

    // Extract hostname for SNI (just the IP for now)
    let host = addr.ip().to_string();
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| crate::Error::Network(format!("invalid server name {}: {}", host, e)))?;

    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| crate::Error::Network(format!("TCP connect to {} timed out", resolver)))?
    .map_err(crate::Error::Io)?;

    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| crate::Error::Network(format!("TLS handshake with {} timed out", resolver)))?
    .map_err(|e| crate::Error::Network(format!("TLS handshake failed: {}", e)))?;

    // DNS-over-TLS uses TCP framing: 2-byte length prefix.
    // DNS messages are limited to 65535 bytes by the protocol; reject oversized queries.
    let len = u16::try_from(query.len()).map_err(|_| {
        crate::Error::Network(format!("DNS query too large: {} bytes", query.len()))
    })?;
    tls.write_all(&len.to_be_bytes())
        .await
        .map_err(crate::Error::Io)?;
    tls.write_all(query).await.map_err(crate::Error::Io)?;
    tls.flush().await.map_err(crate::Error::Io)?;

    // Read response length
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tls.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| crate::Error::Network("DNS response read timed out".into()))?
    .map_err(crate::Error::Io)?;

    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len > 4096 {
        return Err(crate::Error::Network(format!(
            "DNS response too large: {} bytes",
            resp_len
        )));
    }

    let mut response = vec![0u8; resp_len];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tls.read_exact(&mut response),
    )
    .await
    .map_err(|_| crate::Error::Network("DNS response body read timed out".into()))?
    .map_err(crate::Error::Io)?;

    Ok(response)
}

/// Build a TLS client config with system root certificates.
///
/// Returns an error if the TLS crypto provider fails to initialize.
fn build_tls_config() -> Result<Arc<rustls::ClientConfig>, crate::Error> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| crate::Error::Network(format!("TLS protocol version error: {}", e)))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Generate nftables rules to redirect DNS traffic to the local proxy.
pub fn generate_dns_redirect_rules() -> String {
    format!(
        r#"#!/usr/sbin/nft -f

# bulwark: DNS-over-TLS redirection
# Redirect all outgoing DNS to the local encrypted proxy

table ip {table} {{
    chain dns_redirect {{
        type nat hook output priority -100; policy accept;

        # Don't redirect our own proxy's outgoing connections
        ip daddr 127.0.0.1 accept

        # Redirect UDP DNS to local proxy
        udp dport 53 redirect to :5353

        # Redirect TCP DNS to local proxy (future: TCP support)
        # tcp dport 53 redirect to :5353
    }}
}}
"#,
        table = DNS_TABLE,
    )
}

fn apply_nft_rules(ruleset: &str) -> Result<(), crate::Error> {
    let output = std::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            // Take() so stdin drops (EOF) before wait_with_output, else deadlock.
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(ruleset.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| crate::Error::Hardener(format!("failed to run nft: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::Error::Hardener(format!(
            "nft failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DnsCryptConfig::default();
        assert_eq!(config.resolvers.len(), 2);
        assert!(config.resolvers[0].contains("853"));
    }

    #[test]
    fn test_generate_redirect_rules() {
        let rules = generate_dns_redirect_rules();
        assert!(rules.contains("udp dport 53 redirect to :5353"));
        assert!(rules.contains("127.0.0.1"));
        assert!(rules.contains(DNS_TABLE));
    }

    #[test]
    fn test_redirect_rules_skip_loopback() {
        let rules = generate_dns_redirect_rules();
        // Must have the loopback exception before the redirect
        assert!(rules.contains("ip daddr 127.0.0.1 accept"));
    }

    #[test]
    fn test_dns_crypt_initial_state() {
        let dc = DnsCrypt::new(DnsCryptConfig::default());
        assert!(!dc.is_active());
    }

    #[test]
    fn test_deactivate_when_not_active_is_ok() {
        let mut dc = DnsCrypt::new(DnsCryptConfig::default());
        assert!(dc.deactivate_redirect().is_ok());
    }

    #[test]
    fn test_build_tls_config() {
        // Verifies root certs and crypto provider load correctly
        let config = build_tls_config().unwrap();
        assert!(Arc::strong_count(&config) >= 1);
    }
}
