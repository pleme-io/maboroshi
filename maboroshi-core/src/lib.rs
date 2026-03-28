pub mod ipc;

use std::collections::HashMap;
use std::net::SocketAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

/// Combined async read+write trait for use in trait objects.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Errors produced by pluggable transport operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("unsupported transport: {0}")]
    UnsupportedTransport(String),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Discriminant for available transport protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Plain,
    WebTunnel,
    Obfs4,
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::WebTunnel => write!(f, "webtunnel"),
            Self::Obfs4 => write!(f, "obfs4"),
        }
    }
}

/// Configuration for a pluggable transport instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtConfig {
    /// Name of the transport to use.
    pub transport: String,

    /// Run as client (`true`) or server (`false`).
    pub client_mode: bool,

    /// Address to listen on (SOCKS5 for client, direct for server).
    pub listen_addr: SocketAddr,

    /// Target address for the server side (where to forward traffic).
    pub target_addr: Option<SocketAddr>,

    /// Transport-specific key/value options.
    #[serde(default)]
    pub options: HashMap<String, String>,
}

/// A running client-side PT instance exposing a SOCKS5 listener.
#[derive(Debug)]
pub struct PtClientInstance {
    /// Local SOCKS5 address Tor connects to.
    pub socks_addr: SocketAddr,
}

/// A running server-side PT instance.
#[derive(Debug)]
pub struct PtServerInstance {
    /// Address the server is bound to.
    pub bound_addr: SocketAddr,

    /// Transport name this instance serves.
    pub transport_name: String,
}

/// Core trait every pluggable transport must implement.
#[async_trait]
pub trait PluggableTransport: Send + Sync {
    /// Human-readable transport name (e.g. "plain", "webtunnel").
    fn name(&self) -> &str;

    /// The transport type discriminant.
    fn transport_type(&self) -> TransportType;

    /// Start a client-side PT that opens a local SOCKS5 listener.
    async fn start_client(&self, config: &PtConfig) -> Result<PtClientInstance>;

    /// Start a server-side PT that accepts obfuscated connections.
    async fn start_server(&self, config: &PtConfig) -> Result<PtServerInstance>;
}

/// Stream obfuscation layer applied on top of a raw connection.
#[async_trait]
pub trait Obfuscator: Send + Sync {
    /// Wrap a raw stream into an obfuscated one.
    ///
    /// Returns a boxed async read+write stream that transparently
    /// encrypts/encodes outgoing bytes and decrypts/decodes incoming bytes.
    async fn wrap(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> Result<Box<dyn AsyncStream>>;
}
