pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod gateway;

use tokio::sync::mpsc;

use crate::alert::Threat;

/// Alias for the sender side of the threat channel.
pub type ThreatSender = mpsc::Sender<Threat>;
