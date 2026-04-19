use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use maboroshi_core::{PluggableTransport, PtConfig, TransportType};
use maboroshi_transports::{Obfs4Transport, PlainTransport, WebTunnelTransport};
use tracing::info;

#[derive(Parser)]
#[command(
    name = "maboroshi",
    about = "Pluggable transport framework for censorship-resistant tunneling",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start a PT client (SOCKS5 listener for Tor)
    Client {
        /// Transport to use (plain, webtunnel)
        #[arg(short, long, default_value = "plain")]
        transport: String,

        /// Local address to listen on
        #[arg(short, long, default_value = "127.0.0.1:9050")]
        listen: SocketAddr,

        /// Target address to forward traffic to
        #[arg(long)]
        target: SocketAddr,
    },

    /// Start a PT server
    Server {
        /// Transport to use (plain, webtunnel)
        #[arg(short, long, default_value = "plain")]
        transport: String,

        /// Address to listen on
        #[arg(short, long, default_value = "0.0.0.0:9443")]
        listen: SocketAddr,

        /// Target address to forward decapsulated traffic to
        #[arg(long)]
        target: SocketAddr,
    },

    /// List available transports
    List,
}

fn transport_for(name: &str) -> Result<Box<dyn PluggableTransport>, String> {
    match name {
        "plain" => Ok(Box::new(PlainTransport::new())),
        "webtunnel" => Ok(Box::new(WebTunnelTransport::new())),
        "obfs4" => Ok(Box::new(Obfs4Transport::new([0u8; 20], [0u8; 32]))),
        other => Err(format!("unknown transport: {other}")),
    }
}

#[must_use]
fn available_transports() -> Vec<(&'static str, TransportType)> {
    vec![
        ("plain", TransportType::Plain),
        ("webtunnel", TransportType::WebTunnel),
        ("obfs4", TransportType::Obfs4),
    ]
}

/// Execute the CLI command. Extracted from `main()` for testability.
async fn execute(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Client {
            transport,
            listen,
            target,
        } => {
            let pt = transport_for(&transport).map_err(|e| {
                Box::new(maboroshi_core::Error::UnsupportedTransport(e)) as Box<dyn std::error::Error>
            })?;

            let config = PtConfig {
                transport: transport.clone(),
                client_mode: true,
                listen_addr: listen,
                target_addr: Some(target),
                options: Default::default(),
            };

            let instance = pt.start_client(&config).await?;
            info!(
                transport = %transport,
                socks_addr = %instance.socks_addr,
                "client started"
            );

            // Run until drain signal (SIGTERM or SIGINT).
            tsunagu::ShutdownController::install().token().wait().await;
            info!("draining");
        }

        Command::Server {
            transport,
            listen,
            target,
        } => {
            let pt = transport_for(&transport).map_err(|e| {
                Box::new(maboroshi_core::Error::UnsupportedTransport(e)) as Box<dyn std::error::Error>
            })?;

            let config = PtConfig {
                transport: transport.clone(),
                client_mode: false,
                listen_addr: listen,
                target_addr: Some(target),
                options: Default::default(),
            };

            let instance = pt.start_server(&config).await?;
            info!(
                transport = %transport,
                bound_addr = %instance.bound_addr,
                "server started"
            );

            // Run until drain signal (SIGTERM or SIGINT).
            tsunagu::ShutdownController::install().token().wait().await;
            info!("draining");
        }

        Command::List => {
            println!("Available transports:");
            for (name, tt) in available_transports() {
                println!("  {name:<12} ({tt})");
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    execute(cli).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_for_plain() {
        let pt = transport_for("plain").unwrap();
        assert_eq!(pt.name(), "plain");
        assert_eq!(pt.transport_type(), TransportType::Plain);
    }

    #[test]
    fn transport_for_webtunnel() {
        let pt = transport_for("webtunnel").unwrap();
        assert_eq!(pt.name(), "webtunnel");
        assert_eq!(pt.transport_type(), TransportType::WebTunnel);
    }

    #[test]
    fn transport_for_obfs4() {
        let pt = transport_for("obfs4").unwrap();
        assert_eq!(pt.name(), "obfs4");
        assert_eq!(pt.transport_type(), TransportType::Obfs4);
    }

    #[test]
    fn transport_for_unknown_fails() {
        let result = transport_for("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn available_transports_has_all() {
        let transports = available_transports();
        assert_eq!(transports.len(), 3);
        assert!(transports.iter().any(|(n, _)| *n == "plain"));
        assert!(transports.iter().any(|(n, _)| *n == "webtunnel"));
        assert!(transports.iter().any(|(n, _)| *n == "obfs4"));
    }

    #[tokio::test]
    async fn execute_list_command() {
        let cli = Cli {
            command: Command::List,
        };
        let result = execute(cli).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn execute_client_unknown_transport() {
        let cli = Cli {
            command: Command::Client {
                transport: "nonexistent".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                target: "127.0.0.1:1".parse().unwrap(),
            },
        };
        let result = execute(cli).await;
        assert!(result.is_err());
    }
}
