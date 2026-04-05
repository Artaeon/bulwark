//! Network threat detectors.
//!
//! Each detector runs as an independent async task that polls a data source
//! (proc filesystem, UDP socket, or lease files) at configurable intervals.
//! When anomalies are detected, they emit [`Threat`](crate::alert::Threat)
//! values through a shared `mpsc` channel to the daemon's event loop.
//!
//! # Detectors
//!
//! - [`arp`] — ARP spoof and flood detection via `/proc/net/arp`
//! - [`gateway`] — Default gateway IP and MAC monitoring via `/proc/net/route`
//! - [`dns`] — DNS poisoning detection by cross-validating resolvers
//! - [`dhcp`] — Rogue DHCP server detection via DHCP OFFER monitoring

pub mod arp;
pub mod bssid;
pub mod dhcp;
pub mod dns;
pub mod gateway;

use tokio::sync::mpsc;

use crate::alert::Threat;

/// Alias for the sender side of the threat channel.
pub type ThreatSender = mpsc::Sender<Threat>;
