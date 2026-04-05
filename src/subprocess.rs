//! Subprocess utilities with timeout support.
//!
//! Standard `Command::output()` blocks indefinitely if the child process
//! hangs. For a security daemon this is a liability — during an active
//! attack we cannot afford the threat response path to stall forever if
//! `nft` or `ip` hangs for any reason.
//!
//! This module provides [`wait_with_timeout`] which polls for completion
//! and kills the child process if it exceeds the deadline.

use std::process::{Child, Output};
use std::thread;
use std::time::{Duration, Instant};

/// Default timeout for `nft` and `ip` invocations (15 seconds).
///
/// Real invocations complete in milliseconds; this is purely a safety cap
/// for the pathological case where the subprocess hangs indefinitely.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// How often to poll `try_wait` while waiting for the child to exit.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Wait for a child process to exit with a timeout.
///
/// If the child exits within `timeout`, returns its `Output`. If not,
/// sends `SIGKILL` to the child and returns an error.
pub fn wait_with_timeout(mut child: Child, timeout: Duration) -> Result<Output, crate::Error> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process exited — collect output
                return child.wait_with_output().map_err(crate::Error::Io);
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    // Timeout exceeded — kill and reap
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(crate::Error::Hardener(format!(
                        "subprocess timed out after {:?}",
                        timeout
                    )));
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(crate::Error::Io(e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn fast_command_returns_output() {
        let child = Command::new("true")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn true");
        let output = wait_with_timeout(child, Duration::from_secs(5)).expect("succeeds");
        assert!(output.status.success());
    }

    #[test]
    fn slow_command_is_killed_on_timeout() {
        let child = Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sleep");
        let start = Instant::now();
        let result = wait_with_timeout(child, Duration::from_millis(200));
        let elapsed = start.elapsed();
        assert!(result.is_err(), "should time out");
        assert!(
            elapsed < Duration::from_secs(5),
            "should kill quickly, not wait full 30s"
        );
    }

    #[test]
    fn nonzero_exit_is_reported_in_output() {
        let child = Command::new("false")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn false");
        let output = wait_with_timeout(child, Duration::from_secs(5)).expect("succeeds");
        assert!(!output.status.success());
    }
}
