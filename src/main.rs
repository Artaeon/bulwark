use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use bulwark::{config, daemon, hardener};

/// bulwark — network security daemon for open/untrusted wireless networks
///
/// Monitors for ARP spoofing, gateway hijacking, DNS poisoning, rogue DHCP
/// servers, and optionally hardens the firewall when threats are detected.
#[derive(Parser, Debug)]
#[command(name = "bulwark", version, about)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/bulwark/bulwark.toml")]
    config: PathBuf,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,

    /// Override log level (trace, debug, info, warn, error)
    #[arg(short, long)]
    log_level: Option<String>,

    /// Print the generated nftables ruleset and exit
    #[arg(long)]
    print_rules: bool,

    /// Validate config and exit
    #[arg(long)]
    check_config: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Load config (use defaults if file doesn't exist and not explicitly specified)
    let config = if cli.config.exists() {
        match config::Config::load(&cli.config) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else if cli.config == std::path::Path::new("/etc/bulwark/bulwark.toml") {
        // Default path doesn't exist — use defaults
        config::Config::default()
    } else {
        eprintln!("error: config file not found: {}", cli.config.display());
        return ExitCode::FAILURE;
    };

    // Setup logging
    let log_level = cli
        .log_level
        .as_deref()
        .unwrap_or(&config.log_level);
    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        .init();

    // --check-config: validate and exit
    if cli.check_config {
        println!("Configuration OK");
        println!(
            "  Interface: {}",
            if config.interface.is_empty() {
                "(auto-detect)"
            } else {
                &config.interface
            }
        );
        println!("  ARP detector: {}", if config.arp.enabled { "enabled" } else { "disabled" });
        println!("  Gateway detector: {}", if config.gateway.enabled { "enabled" } else { "disabled" });
        println!("  DNS detector: {}", if config.dns.enabled { "enabled" } else { "disabled" });
        println!("  DHCP detector: {}", if config.dhcp.enabled { "enabled" } else { "disabled" });
        println!("  Hardener: {}", if config.hardener.enabled { "enabled" } else { "disabled" });
        println!("  Protections:");
        println!("    ARP pinning: {}", if config.protect.arp_pin { "enabled" } else { "disabled" });
        println!("    Client isolation: {}", if config.protect.client_isolation { "enabled" } else { "disabled" });
        println!("    DNS encryption: {}", if config.protect.dns_encrypt { "enabled" } else { "disabled" });
        println!("    MAC randomization: {}", if config.protect.mac_randomize { "enabled" } else { "disabled" });
        return ExitCode::SUCCESS;
    }

    // --print-rules: show nftables ruleset
    if cli.print_rules {
        let h = hardener::Hardener::new(config.hardener);
        print!("{}", h.generate_ruleset());
        return ExitCode::SUCCESS;
    }

    // Check for root (most features need it)
    // SAFETY: geteuid() is a simple syscall with no preconditions, no pointers, no UB risk.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("warning: bulwark should run as root for full functionality");
        eprintln!(
            "         (raw sockets, nftables, interface binding require root/CAP_NET_RAW)"
        );
    }

    // Run the daemon
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fatal: failed to create tokio runtime: {}", e);
            return ExitCode::FAILURE;
        }
    };

    rt.block_on(async {
        let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

        // Handle SIGINT and SIGTERM for graceful shutdown
        let shutdown_tx_clone = shutdown_tx.clone();
        tokio::spawn(async move {
            let mut sigint = match
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "failed to register SIGINT handler");
                    return;
                }
            };
            let mut sigterm = match
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "failed to register SIGTERM handler");
                    return;
                }
            };

            tokio::select! {
                _ = sigint.recv() => {
                    info!("received SIGINT");
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                }
            }
            let _ = shutdown_tx_clone.send(());
        });

        info!(
            version = env!("CARGO_PKG_VERSION"),
            "bulwark starting"
        );

        let daemon = daemon::Daemon::new(config);
        if let Err(e) = daemon.run(shutdown_tx).await {
            error!(error = %e, "daemon failed");
            std::process::exit(1);
        }
    });

    ExitCode::SUCCESS
}
