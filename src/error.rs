//! Central error types for the bulwark daemon.
//!
//! All fallible operations in bulwark return [`Error`], which covers configuration
//! parsing, network operations, I/O, and firewall management failures.

/// Central error type for bulwark.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hardener error: {0}")]
    Hardener(String),
}
