pub mod ipc;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

/// Combined async read+write trait for use in trait objects.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Errors produced by pluggable transport operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("unsupported transport: {0}")]
    UnsupportedTransport(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl Error {
    /// Returns `true` for transient errors that may succeed on retry.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Transport(_) | Self::Handshake(_))
    }
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

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::WebTunnel => write!(f, "webtunnel"),
            Self::Obfs4 => write!(f, "obfs4"),
        }
    }
}

/// Lifecycle state of a pluggable transport instance.
///
/// Modelled after the PT spec IPC protocol state machine. A transport
/// transitions through these states during startup and operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PtState {
    /// Transport process has started, performing internal setup.
    #[default]
    Initializing,
    /// Negotiating protocol version with the parent process.
    NegotiatingVersion,
    /// Validating transport-specific configuration.
    ValidatingConfig,
    /// Configuration accepted, ready to accept connections.
    Ready,
    /// Actively handling connections.
    Active,
    /// Graceful shutdown in progress.
    ShuttingDown,
    /// Terminal error state.
    Failed,
}

impl fmt::Display for PtState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initializing => write!(f, "initializing"),
            Self::NegotiatingVersion => write!(f, "negotiating_version"),
            Self::ValidatingConfig => write!(f, "validating_config"),
            Self::Ready => write!(f, "ready"),
            Self::Active => write!(f, "active"),
            Self::ShuttingDown => write!(f, "shutting_down"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl PtState {
    /// Returns `true` if the transport is operational (ready to handle or
    /// actively handling connections).
    #[must_use]
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Ready | Self::Active)
    }
}

/// Obfuscation strength level.
///
/// Controls the aggressiveness of timing obfuscation, modelled after
/// obfs4's IAT (inter-arrival time) modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ObfuscationLevel {
    /// No timing obfuscation (fastest).
    #[default]
    None,
    /// Moderate timing jitter (obfs4 IAT mode 1).
    Moderate,
    /// Aggressive timing transformation (obfs4 IAT mode 2).
    Paranoid,
}

impl fmt::Display for ObfuscationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Moderate => write!(f, "moderate"),
            Self::Paranoid => write!(f, "paranoid"),
        }
    }
}

/// Transport operating mode (client or server).
///
/// From the PT spec: a transport can run as a client (CMETHOD) exposing
/// a local SOCKS5 listener, or as a server (SMETHOD) accepting obfuscated
/// connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Client-side transport (CMETHOD in PT spec).
    Client,
    /// Server-side transport (SMETHOD in PT spec).
    Server,
}

impl fmt::Display for TransportMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client => write!(f, "client"),
            Self::Server => write!(f, "server"),
        }
    }
}

/// Per-transport status report.
///
/// Combines the PT spec's CMETHOD/SMETHOD output into a unified status
/// structure for monitoring and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportStatus {
    /// Transport protocol name.
    pub name: String,
    /// Whether this is a client or server instance.
    pub mode: TransportMode,
    /// Current lifecycle state.
    pub state: PtState,
    /// Address the transport is listening on, if bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,
    /// Human-readable error message if the transport has failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Configuration for a pluggable transport instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtConfig {
    /// Name of the transport to use.
    pub transport: String,

    /// Run as client (`true`) or server (`false`).
    pub client_mode: bool,

    /// Address to listen on (SOCKS5 for client, direct for server).
    pub listen_addr: SocketAddr,

    /// Target address for the server side (where to forward traffic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_addr: Option<SocketAddr>,

    /// Transport-specific key/value options.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub options: HashMap<String, String>,
}

/// A running client-side PT instance exposing a SOCKS5 listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtClientInstance {
    /// Local SOCKS5 address Tor connects to.
    pub socks_addr: SocketAddr,
}

/// A running server-side PT instance.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Mock pluggable transport for testing — returns config errors for all start operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockPluggableTransport {
    /// Transport type to report.
    pub tt: TransportType,
}

impl MockPluggableTransport {
    /// Create a new mock transport for the given type.
    #[must_use]
    pub fn new(tt: TransportType) -> Self {
        Self { tt }
    }
}

#[async_trait]
impl PluggableTransport for MockPluggableTransport {
    fn name(&self) -> &str {
        match self.tt {
            TransportType::Plain => "mock-plain",
            TransportType::WebTunnel => "mock-webtunnel",
            TransportType::Obfs4 => "mock-obfs4",
        }
    }

    fn transport_type(&self) -> TransportType {
        self.tt
    }

    async fn start_client(&self, _config: &PtConfig) -> Result<PtClientInstance> {
        Err(Error::Transport("mock transport: start_client not implemented".into()))
    }

    async fn start_server(&self, _config: &PtConfig) -> Result<PtServerInstance> {
        Err(Error::Transport("mock transport: start_server not implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    // --- Error tests ---

    #[test]
    fn error_display_variants() {
        assert_eq!(Error::Io("broken".into()).to_string(), "I/O error: broken");
        assert_eq!(
            Error::Transport("fail".into()).to_string(),
            "transport error: fail"
        );
        assert_eq!(
            Error::Config("bad".into()).to_string(),
            "configuration error: bad"
        );
        assert_eq!(
            Error::Handshake("nope".into()).to_string(),
            "handshake failed: nope"
        );
        assert_eq!(
            Error::UnsupportedTransport("foo".into()).to_string(),
            "unsupported transport: foo"
        );
    }

    #[test]
    fn error_clone_and_eq() {
        let e1 = Error::Io("test".into());
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn error_is_retryable() {
        assert!(Error::Io("broken".into()).is_retryable());
        assert!(Error::Transport("fail".into()).is_retryable());
        assert!(Error::Handshake("nope".into()).is_retryable());
        assert!(!Error::Config("bad".into()).is_retryable());
        assert!(!Error::UnsupportedTransport("foo".into()).is_retryable());
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    // --- TransportType tests ---

    #[test]
    fn transport_type_display() {
        assert_eq!(TransportType::Plain.to_string(), "plain");
        assert_eq!(TransportType::WebTunnel.to_string(), "webtunnel");
        assert_eq!(TransportType::Obfs4.to_string(), "obfs4");
    }

    #[test]
    fn transport_type_serde_roundtrip() {
        for tt in [TransportType::Plain, TransportType::WebTunnel, TransportType::Obfs4] {
            let json = serde_json::to_string(&tt).unwrap();
            let parsed: TransportType = serde_json::from_str(&json).unwrap();
            assert_eq!(tt, parsed);
        }
    }

    #[test]
    fn transport_type_serde_lowercase() {
        let json = serde_json::to_string(&TransportType::WebTunnel).unwrap();
        assert_eq!(json, "\"webtunnel\"");
    }

    // --- PtConfig tests ---

    #[test]
    fn pt_config_serde_roundtrip() {
        let config = PtConfig {
            transport: "plain".into(),
            client_mode: true,
            listen_addr: "127.0.0.1:9050".parse().unwrap(),
            target_addr: Some("127.0.0.1:8080".parse().unwrap()),
            options: HashMap::from([("key".into(), "val".into())]),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PtConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn pt_config_skip_empty_options() {
        let config = PtConfig {
            transport: "plain".into(),
            client_mode: true,
            listen_addr: "127.0.0.1:9050".parse().unwrap(),
            target_addr: None,
            options: HashMap::new(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("options"));
        assert!(!json.contains("target_addr"));
    }

    #[test]
    fn pt_config_deserialize_missing_optional() {
        let json = r#"{"transport":"plain","client_mode":true,"listen_addr":"127.0.0.1:9050"}"#;
        let config: PtConfig = serde_json::from_str(json).unwrap();
        assert!(config.target_addr.is_none());
        assert!(config.options.is_empty());
    }

    // --- PtClientInstance / PtServerInstance tests ---

    #[test]
    fn pt_client_instance_clone_eq() {
        let a = PtClientInstance {
            socks_addr: "127.0.0.1:9050".parse().unwrap(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn pt_server_instance_clone_eq() {
        let a = PtServerInstance {
            bound_addr: "0.0.0.0:9443".parse().unwrap(),
            transport_name: "plain".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // --- MockPluggableTransport tests ---

    #[test]
    fn mock_transport_name() {
        let m = MockPluggableTransport::new(TransportType::Plain);
        assert_eq!(m.name(), "mock-plain");
        let m = MockPluggableTransport::new(TransportType::WebTunnel);
        assert_eq!(m.name(), "mock-webtunnel");
        let m = MockPluggableTransport::new(TransportType::Obfs4);
        assert_eq!(m.name(), "mock-obfs4");
    }

    #[test]
    fn mock_transport_type() {
        let m = MockPluggableTransport::new(TransportType::Plain);
        assert_eq!(m.transport_type(), TransportType::Plain);
    }

    #[tokio::test]
    async fn mock_transport_start_client_fails() {
        let m = MockPluggableTransport::new(TransportType::Plain);
        let config = PtConfig {
            transport: "mock-plain".into(),
            client_mode: true,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            target_addr: None,
            options: HashMap::new(),
        };
        let result = m.start_client(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_transport_start_server_fails() {
        let m = MockPluggableTransport::new(TransportType::Plain);
        let config = PtConfig {
            transport: "mock-plain".into(),
            client_mode: false,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            target_addr: None,
            options: HashMap::new(),
        };
        let result = m.start_server(&config).await;
        assert!(result.is_err());
    }

    #[test]
    fn mock_transport_clone_eq() {
        let m1 = MockPluggableTransport::new(TransportType::Obfs4);
        let m2 = m1.clone();
        assert_eq!(m1, m2);
    }

    // --- PtState tests ---

    #[test]
    fn pt_state_default_is_initializing() {
        let state = PtState::default();
        assert_eq!(state, PtState::Initializing);
    }

    #[test]
    fn pt_state_display() {
        assert_eq!(PtState::Initializing.to_string(), "initializing");
        assert_eq!(PtState::NegotiatingVersion.to_string(), "negotiating_version");
        assert_eq!(PtState::ValidatingConfig.to_string(), "validating_config");
        assert_eq!(PtState::Ready.to_string(), "ready");
        assert_eq!(PtState::Active.to_string(), "active");
        assert_eq!(PtState::ShuttingDown.to_string(), "shutting_down");
        assert_eq!(PtState::Failed.to_string(), "failed");
    }

    #[test]
    fn pt_state_is_operational() {
        assert!(!PtState::Initializing.is_operational());
        assert!(!PtState::NegotiatingVersion.is_operational());
        assert!(!PtState::ValidatingConfig.is_operational());
        assert!(PtState::Ready.is_operational());
        assert!(PtState::Active.is_operational());
        assert!(!PtState::ShuttingDown.is_operational());
        assert!(!PtState::Failed.is_operational());
    }

    #[test]
    fn pt_state_serde_roundtrip() {
        for state in [
            PtState::Initializing,
            PtState::NegotiatingVersion,
            PtState::ValidatingConfig,
            PtState::Ready,
            PtState::Active,
            PtState::ShuttingDown,
            PtState::Failed,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: PtState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, parsed);
        }
    }

    #[test]
    fn pt_state_serde_snake_case() {
        let json = serde_json::to_string(&PtState::NegotiatingVersion).unwrap();
        assert_eq!(json, "\"negotiating_version\"");
        let json = serde_json::to_string(&PtState::ShuttingDown).unwrap();
        assert_eq!(json, "\"shutting_down\"");
    }

    #[test]
    fn pt_state_clone_eq() {
        let a = PtState::Ready;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(PtState::Ready, PtState::Failed);
    }

    // --- ObfuscationLevel tests ---

    #[test]
    fn obfuscation_level_default_is_none() {
        let level = ObfuscationLevel::default();
        assert_eq!(level, ObfuscationLevel::None);
    }

    #[test]
    fn obfuscation_level_display() {
        assert_eq!(ObfuscationLevel::None.to_string(), "none");
        assert_eq!(ObfuscationLevel::Moderate.to_string(), "moderate");
        assert_eq!(ObfuscationLevel::Paranoid.to_string(), "paranoid");
    }

    #[test]
    fn obfuscation_level_serde_roundtrip() {
        for level in [
            ObfuscationLevel::None,
            ObfuscationLevel::Moderate,
            ObfuscationLevel::Paranoid,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let parsed: ObfuscationLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, parsed);
        }
    }

    #[test]
    fn obfuscation_level_serde_snake_case() {
        let json = serde_json::to_string(&ObfuscationLevel::Moderate).unwrap();
        assert_eq!(json, "\"moderate\"");
        let json = serde_json::to_string(&ObfuscationLevel::Paranoid).unwrap();
        assert_eq!(json, "\"paranoid\"");
    }

    #[test]
    fn obfuscation_level_clone_eq() {
        let a = ObfuscationLevel::Paranoid;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(ObfuscationLevel::None, ObfuscationLevel::Moderate);
    }

    // --- TransportMode tests ---

    #[test]
    fn transport_mode_display() {
        assert_eq!(TransportMode::Client.to_string(), "client");
        assert_eq!(TransportMode::Server.to_string(), "server");
    }

    #[test]
    fn transport_mode_serde_roundtrip() {
        for mode in [TransportMode::Client, TransportMode::Server] {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: TransportMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn transport_mode_serde_snake_case() {
        let json = serde_json::to_string(&TransportMode::Client).unwrap();
        assert_eq!(json, "\"client\"");
        let json = serde_json::to_string(&TransportMode::Server).unwrap();
        assert_eq!(json, "\"server\"");
    }

    #[test]
    fn transport_mode_clone_eq() {
        let a = TransportMode::Client;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(TransportMode::Client, TransportMode::Server);
    }

    // --- TransportStatus tests ---

    #[test]
    fn transport_status_serde_roundtrip() {
        let status = TransportStatus {
            name: "obfs4".into(),
            mode: TransportMode::Server,
            state: PtState::Active,
            listen_addr: Some("0.0.0.0:9443".into()),
            error: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: TransportStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
    }

    #[test]
    fn transport_status_skip_serializing_none() {
        let status = TransportStatus {
            name: "plain".into(),
            mode: TransportMode::Client,
            state: PtState::Ready,
            listen_addr: None,
            error: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("listen_addr"));
        assert!(!json.contains("error"));
    }

    #[test]
    fn transport_status_with_error() {
        let status = TransportStatus {
            name: "webtunnel".into(),
            mode: TransportMode::Server,
            state: PtState::Failed,
            listen_addr: None,
            error: Some("bind failed: address in use".into()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("bind failed"));
        let parsed: TransportStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.error.as_deref(), Some("bind failed: address in use"));
    }

    #[test]
    fn transport_status_clone_eq() {
        let a = TransportStatus {
            name: "plain".into(),
            mode: TransportMode::Client,
            state: PtState::Active,
            listen_addr: Some("127.0.0.1:9050".into()),
            error: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn transport_status_different_modes_not_equal() {
        let a = TransportStatus {
            name: "plain".into(),
            mode: TransportMode::Client,
            state: PtState::Ready,
            listen_addr: None,
            error: None,
        };
        let b = TransportStatus {
            name: "plain".into(),
            mode: TransportMode::Server,
            state: PtState::Ready,
            listen_addr: None,
            error: None,
        };
        assert_ne!(a, b);
    }
}
