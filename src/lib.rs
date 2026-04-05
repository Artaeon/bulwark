//! bulwark — network security daemon for open/untrusted wireless networks.
//!
//! This library crate exposes the core detection and parsing modules for
//! use by fuzz targets, integration tests, and external tooling.

// Strict lints for a security tool — enforced in production code only.
// Tests legitimately use unwrap/expect/panic for brevity, so these are
// scoped to `not(test)` rather than the whole crate.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![cfg_attr(not(test), deny(clippy::panic))]
#![deny(arithmetic_overflow)]
#![warn(clippy::cast_possible_truncation)]
#![warn(clippy::cast_sign_loss)]

pub mod alert;
pub mod config;
pub mod daemon;
pub mod detectors;
pub mod error;
pub mod hardener;
pub mod net_util;
pub mod notify;
pub mod protect;

pub use error::Error;
