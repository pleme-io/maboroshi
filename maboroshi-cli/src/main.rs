use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use maboroshi_core::{PluggableTransport, PtConfig, TransportType};
use maboroshi_transports::{PlainTransport, WebTunnelTransport};
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
        other => Err(format!("unknown transport: {other}")),
    }
}

fn available_transports() -> Vec<(&'static str, TransportType)> {
    vec![
        ("plain", TransportType::Plain),
        ("webtunnel", TransportType::WebTunnel),
    ]
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

            // Run until interrupted.
            tokio::signal::ctrl_c().await?;
            info!("shutting down");
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

            // Run until interrupted.
            tokio::signal::ctrl_c().await?;
            info!("shutting down");
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
