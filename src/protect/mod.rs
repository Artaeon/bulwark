//! Active network protection measures.
//!
//! While the [`detectors`](crate::detectors) module passively monitors for threats,
//! the `protect` module actively hardens the network stack to **prevent** attacks:
//!
//! - [`arp_pin`] — Pins the gateway MAC as a static ARP entry, blocking ARP spoofing
//! - [`dns_crypt`] — Encrypts all DNS queries via DNS-over-TLS, preventing DNS poisoning
//! - [`mac_rand`] — Randomizes the interface MAC address, preventing cross-network tracking
//! - [`isolation`] — Blocks LAN traffic except the gateway, preventing lateral movement

pub mod arp_pin;
pub mod dns_crypt;
pub mod isolation;
pub mod mac_rand;
