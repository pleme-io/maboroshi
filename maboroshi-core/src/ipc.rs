use std::collections::HashMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Parsed Tor Pluggable Transport IPC environment variables.
///
/// The PT spec requires managed transports to read configuration from
/// `TOR_PT_*` environment variables and report status back via stdout.
#[derive(Debug, Clone)]
pub struct PtEnvironment {
    /// Directory for persistent state (`TOR_PT_STATE_LOCATION`).
    pub state_location: PathBuf,

    /// Protocol version negotiation (`TOR_PT_MANAGED_TRANSPORT_VER`).
    pub managed_transport_ver: String,

    /// Client-side transports requested (`TOR_PT_CLIENT_TRANSPORTS`).
    pub client_transports: Vec<String>,

    /// Server-side transports requested (`TOR_PT_SERVER_TRANSPORTS`).
    pub server_transports: Vec<String>,

    /// Per-transport bind addresses (`TOR_PT_SERVER_BINDADDR`).
    pub server_bindaddr: HashMap<String, SocketAddr>,

    /// Tor's OR port (`TOR_PT_ORPORT`).
    pub orport: Option<SocketAddr>,

    /// Extended server port (`TOR_PT_EXTENDED_SERVER_PORT`).
    pub extended_server_port: Option<SocketAddr>,

    /// Whether this instance is a client (`true`) or server (`false`).
    pub is_client: bool,
}

impl PtEnvironment {
    /// Parse the PT configuration from process environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error when required variables are missing or malformed.
    pub fn from_env() -> Result<Self, PtEnvError> {
        Self::from_env_fn(|key| std::env::var(key))
    }

    /// Parse PT configuration using a custom environment-variable lookup function.
    ///
    /// This is the testable core — callers provide a closure that maps
    /// variable names to values (or returns an error for missing ones).
    fn from_env_fn<F>(env: F) -> Result<Self, PtEnvError>
    where
        F: Fn(&str) -> Result<String, std::env::VarError>,
    {
        let state_location = PathBuf::from(
            env("TOR_PT_STATE_LOCATION").map_err(|_| PtEnvError::MissingVar("TOR_PT_STATE_LOCATION"))?,
        );

        let managed_transport_ver = env("TOR_PT_MANAGED_TRANSPORT_VER")
            .map_err(|_| PtEnvError::MissingVar("TOR_PT_MANAGED_TRANSPORT_VER"))?;

        let client_transports: Vec<String> = env("TOR_PT_CLIENT_TRANSPORTS")
            .ok()
            .map(|v| v.split(',').map(|s| s.trim().to_owned()).collect())
            .unwrap_or_default();

        let server_transports: Vec<String> = env("TOR_PT_SERVER_TRANSPORTS")
            .ok()
            .map(|v| v.split(',').map(|s| s.trim().to_owned()).collect())
            .unwrap_or_default();

        let is_client = !client_transports.is_empty();

        let server_bindaddr = env("TOR_PT_SERVER_BINDADDR")
            .ok()
            .map(|v| parse_bindaddr(&v))
            .transpose()?
            .unwrap_or_default();

        let orport = env("TOR_PT_ORPORT")
            .ok()
            .map(|v| v.parse::<SocketAddr>())
            .transpose()
            .map_err(|e| PtEnvError::InvalidAddr("TOR_PT_ORPORT", e.to_string()))?;

        let extended_server_port = env("TOR_PT_EXTENDED_SERVER_PORT")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| v.parse::<SocketAddr>())
            .transpose()
            .map_err(|e| PtEnvError::InvalidAddr("TOR_PT_EXTENDED_SERVER_PORT", e.to_string()))?;

        Ok(Self {
            state_location,
            managed_transport_ver,
            client_transports,
            server_transports,
            server_bindaddr,
            orport,
            extended_server_port,
            is_client,
        })
    }
}

/// Parse the `TOR_PT_SERVER_BINDADDR` value.
///
/// Format: `transport-addr` pairs separated by commas, each pair separated
/// by a dash: `obfs4-127.0.0.1:1234,webtunnel-127.0.0.1:5678`.
fn parse_bindaddr(value: &str) -> Result<HashMap<String, SocketAddr>, PtEnvError> {
    let mut map = HashMap::new();
    for pair in value.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let dash_pos = pair
            .find('-')
            .ok_or_else(|| PtEnvError::InvalidBindAddr(pair.to_owned()))?;
        let name = &pair[..dash_pos];
        let addr_str = &pair[dash_pos + 1..];
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|_| PtEnvError::InvalidBindAddr(pair.to_owned()))?;
        map.insert(name.to_owned(), addr);
    }
    Ok(map)
}

/// Errors from parsing the PT environment.
#[derive(Debug, thiserror::Error)]
pub enum PtEnvError {
    #[error("missing required environment variable: {0}")]
    MissingVar(&'static str),

    #[error("invalid address in {0}: {1}")]
    InvalidAddr(&'static str, String),

    #[error("invalid TOR_PT_SERVER_BINDADDR entry: {0}")]
    InvalidBindAddr(String),
}

/// Protocol reporter that writes PT IPC status lines.
///
/// Each method emits a single protocol line to the underlying writer
/// (typically stdout for a managed transport). The writer type `W`
/// is generic so tests can use `Vec<u8>` while production code passes
/// `io::stdout()`.
pub struct PtReporter<W: Write> {
    writer: W,
}

impl<W: Write> PtReporter<W> {
    /// Create a new reporter writing to the given writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Consume the reporter and return the inner writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Report a supported protocol version.
    ///
    /// Emits: `VERSION <version>`
    pub fn version(&mut self, version: &str) -> io::Result<()> {
        writeln!(self.writer, "VERSION {version}")
    }

    /// Report a version negotiation error.
    ///
    /// Emits: `VERSION-ERROR <msg>`
    pub fn version_error(&mut self, msg: &str) -> io::Result<()> {
        writeln!(self.writer, "VERSION-ERROR {msg}")
    }

    /// Report an environment parsing error.
    ///
    /// Emits: `ENV-ERROR <msg>`
    pub fn env_error(&mut self, msg: &str) -> io::Result<()> {
        writeln!(self.writer, "ENV-ERROR {msg}")
    }

    /// Report a successful client method.
    ///
    /// Emits: `CMETHOD <name> <socks_ver> <addr>`
    pub fn cmethod(&mut self, name: &str, socks_ver: &str, addr: &SocketAddr) -> io::Result<()> {
        writeln!(self.writer, "CMETHOD {name} {socks_ver} {addr}")
    }

    /// Report that all client methods have been reported.
    ///
    /// Emits: `CMETHODS DONE`
    pub fn cmethods_done(&mut self) -> io::Result<()> {
        writeln!(self.writer, "CMETHODS DONE")
    }

    /// Report a successful server method.
    ///
    /// Emits: `SMETHOD <name> <addr>`
    pub fn smethod(&mut self, name: &str, addr: &SocketAddr) -> io::Result<()> {
        writeln!(self.writer, "SMETHOD {name} {addr}")
    }

    /// Report that all server methods have been reported.
    ///
    /// Emits: `SMETHODS DONE`
    pub fn smethods_done(&mut self) -> io::Result<()> {
        writeln!(self.writer, "SMETHODS DONE")
    }

    /// Report a client method error.
    ///
    /// Emits: `CMETHOD-ERROR <name> <msg>`
    pub fn cmethod_error(&mut self, name: &str, msg: &str) -> io::Result<()> {
        writeln!(self.writer, "CMETHOD-ERROR {name} {msg}")
    }

    /// Report a server method error.
    ///
    /// Emits: `SMETHOD-ERROR <name> <msg>`
    pub fn smethod_error(&mut self, name: &str, msg: &str) -> io::Result<()> {
        writeln!(self.writer, "SMETHOD-ERROR {name} {msg}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper that builds a `PtEnvironment` from a `HashMap` instead of real env vars.
    fn env_from_map(map: &HashMap<&str, &str>) -> Result<PtEnvironment, PtEnvError> {
        let map = map.clone();
        PtEnvironment::from_env_fn(move |key| {
            map.get(key)
                .map(|v| (*v).to_owned())
                .ok_or(std::env::VarError::NotPresent)
        })
    }

    #[test]
    fn parse_empty_env_fails() {
        let map = HashMap::new();
        let result = env_from_map(&map);
        assert!(result.is_err());
    }

    #[test]
    fn parse_client_env() {
        let mut map = HashMap::new();
        map.insert("TOR_PT_STATE_LOCATION", "/tmp/pt_state");
        map.insert("TOR_PT_MANAGED_TRANSPORT_VER", "1");
        map.insert("TOR_PT_CLIENT_TRANSPORTS", "obfs4,webtunnel");

        let env = env_from_map(&map).unwrap();
        assert_eq!(env.state_location, PathBuf::from("/tmp/pt_state"));
        assert_eq!(env.managed_transport_ver, "1");
        assert_eq!(env.client_transports, vec!["obfs4", "webtunnel"]);
        assert!(env.server_transports.is_empty());
        assert!(env.is_client);
        assert!(env.orport.is_none());
    }

    #[test]
    fn parse_server_env() {
        let mut map = HashMap::new();
        map.insert("TOR_PT_STATE_LOCATION", "/var/lib/tor/pt_state");
        map.insert("TOR_PT_MANAGED_TRANSPORT_VER", "1");
        map.insert("TOR_PT_SERVER_TRANSPORTS", "obfs4");
        map.insert("TOR_PT_SERVER_BINDADDR", "obfs4-127.0.0.1:4321");
        map.insert("TOR_PT_ORPORT", "127.0.0.1:9001");

        let env = env_from_map(&map).unwrap();
        assert!(!env.is_client);
        assert_eq!(env.server_transports, vec!["obfs4"]);
        assert_eq!(
            env.server_bindaddr.get("obfs4").unwrap(),
            &"127.0.0.1:4321".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            env.orport.unwrap(),
            "127.0.0.1:9001".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_server_env_multiple_bindaddrs() {
        let mut map = HashMap::new();
        map.insert("TOR_PT_STATE_LOCATION", "/tmp/state");
        map.insert("TOR_PT_MANAGED_TRANSPORT_VER", "1");
        map.insert("TOR_PT_SERVER_TRANSPORTS", "obfs4,webtunnel");
        map.insert(
            "TOR_PT_SERVER_BINDADDR",
            "obfs4-127.0.0.1:4321,webtunnel-127.0.0.1:4322",
        );
        map.insert("TOR_PT_ORPORT", "127.0.0.1:9001");

        let env = env_from_map(&map).unwrap();
        assert_eq!(env.server_bindaddr.len(), 2);
        assert_eq!(
            env.server_bindaddr.get("obfs4").unwrap(),
            &"127.0.0.1:4321".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            env.server_bindaddr.get("webtunnel").unwrap(),
            &"127.0.0.1:4322".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn report_version() {
        let mut reporter = PtReporter::new(Vec::new());
        reporter.version("1").unwrap();
        let buf = reporter.into_inner();
        assert_eq!(String::from_utf8(buf).unwrap(), "VERSION 1\n");
    }

    #[test]
    fn report_version_error() {
        let mut reporter = PtReporter::new(Vec::new());
        reporter.version_error("no-version").unwrap();
        let buf = reporter.into_inner();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "VERSION-ERROR no-version\n"
        );
    }

    #[test]
    fn report_cmethod() {
        let addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let mut reporter = PtReporter::new(Vec::new());
        reporter.cmethod("obfs4", "socks5", &addr).unwrap();
        let buf = reporter.into_inner();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "CMETHOD obfs4 socks5 127.0.0.1:9050\n"
        );
    }

    #[test]
    fn report_cmethods_done() {
        let mut reporter = PtReporter::new(Vec::new());
        reporter.cmethods_done().unwrap();
        let buf = reporter.into_inner();
        assert_eq!(String::from_utf8(buf).unwrap(), "CMETHODS DONE\n");
    }

    #[test]
    fn report_smethod() {
        let addr: SocketAddr = "0.0.0.0:9443".parse().unwrap();
        let mut reporter = PtReporter::new(Vec::new());
        reporter.smethod("obfs4", &addr).unwrap();
        let buf = reporter.into_inner();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "SMETHOD obfs4 0.0.0.0:9443\n"
        );
    }

    #[test]
    fn report_smethods_done() {
        let mut reporter = PtReporter::new(Vec::new());
        reporter.smethods_done().unwrap();
        let buf = reporter.into_inner();
        assert_eq!(String::from_utf8(buf).unwrap(), "SMETHODS DONE\n");
    }

    #[test]
    fn report_env_error() {
        let mut reporter = PtReporter::new(Vec::new());
        reporter.env_error("missing TOR_PT_STATE_LOCATION").unwrap();
        let buf = reporter.into_inner();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "ENV-ERROR missing TOR_PT_STATE_LOCATION\n"
        );
    }

    #[test]
    fn report_full_client_sequence() {
        let addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let mut reporter = PtReporter::new(Vec::new());
        reporter.version("1").unwrap();
        reporter.cmethod("obfs4", "socks5", &addr).unwrap();
        reporter.cmethods_done().unwrap();
        let buf = reporter.into_inner();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(
            output,
            "VERSION 1\nCMETHOD obfs4 socks5 127.0.0.1:9050\nCMETHODS DONE\n"
        );
    }
}
