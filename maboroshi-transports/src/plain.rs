use async_trait::async_trait;
use maboroshi_core::{
    Error, PluggableTransport, PtClientInstance, PtConfig, PtServerInstance, Result, TransportType,
};
use tokio::net::TcpListener;
use tracing::info;

/// Unobfuscated TCP passthrough transport.
///
/// Provides a baseline implementation with no obfuscation — useful for
/// testing and as a reference for implementing new transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainTransport;

impl PlainTransport {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for PlainTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PluggableTransport for PlainTransport {
    fn name(&self) -> &str {
        "plain"
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Plain
    }

    async fn start_client(&self, config: &PtConfig) -> Result<PtClientInstance> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let socks_addr = listener.local_addr()?;
        info!(%socks_addr, "plain client listening");

        let target = config
            .target_addr
            .ok_or_else(|| Error::Config("target_addr required for plain client".into()))?;

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut inbound, peer)) => {
                        info!(%peer, "plain client accepted connection");
                        tokio::spawn(async move {
                            match tokio::net::TcpStream::connect(target).await {
                                Ok(mut outbound) => {
                                    let (mut ri, mut wi) = inbound.split();
                                    let (mut ro, mut wo) = outbound.split();
                                    if let Err(e) = tokio::try_join!(
                                        tokio::io::copy(&mut ri, &mut wo),
                                        tokio::io::copy(&mut ro, &mut wi),
                                    ) {
                                        tracing::debug!(%e, "plain: copy loop ended");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(%e, "plain: failed to connect to target");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(%e, "plain client accept error");
                    }
                }
            }
        });

        Ok(PtClientInstance { socks_addr })
    }

    async fn start_server(&self, config: &PtConfig) -> Result<PtServerInstance> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let bound_addr = listener.local_addr()?;
        let transport_name = self.name().to_owned();
        info!(%bound_addr, "plain server listening");

        let target = config
            .target_addr
            .ok_or_else(|| Error::Config("target_addr required for plain server".into()))?;

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut inbound, peer)) => {
                        info!(%peer, "plain server accepted connection");
                        tokio::spawn(async move {
                            match tokio::net::TcpStream::connect(target).await {
                                Ok(mut outbound) => {
                                    let (mut ri, mut wi) = inbound.split();
                                    let (mut ro, mut wo) = outbound.split();
                                    if let Err(e) = tokio::try_join!(
                                        tokio::io::copy(&mut ri, &mut wo),
                                        tokio::io::copy(&mut ro, &mut wi),
                                    ) {
                                        tracing::debug!(%e, "plain: copy loop ended");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(%e, "plain: failed to connect to target");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(%e, "plain server accept error");
                    }
                }
            }
        });

        Ok(PtServerInstance {
            bound_addr,
            transport_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn name_is_plain() {
        let t = PlainTransport::new();
        assert_eq!(t.name(), "plain");
    }

    #[test]
    fn transport_type_is_plain() {
        let t = PlainTransport::new();
        assert_eq!(t.transport_type(), TransportType::Plain);
    }

    #[tokio::test]
    async fn client_mode_binds() {
        let t = PlainTransport::new();

        // Bind an echo server so the transport has a valid target.
        let echo = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let echo_addr = echo.local_addr().unwrap();

        let config = PtConfig {
            transport: "plain".into(),
            client_mode: true,
            listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
            target_addr: Some(echo_addr),
            options: Default::default(),
        };

        let instance = t.start_client(&config).await.unwrap();
        // The instance should be listening on the address it reports.
        let conn = tokio::net::TcpStream::connect(instance.socks_addr).await;
        assert!(conn.is_ok(), "should be able to connect to the client listener");
    }

    #[tokio::test]
    async fn client_forwards_data() {
        let t = PlainTransport::new();

        // Start a simple echo server.
        let echo_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = echo_listener.accept().await {
                let mut buf = vec![0u8; 1024];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
        });

        let config = PtConfig {
            transport: "plain".into(),
            client_mode: true,
            listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
            target_addr: Some(echo_addr),
            options: Default::default(),
        };

        let instance = t.start_client(&config).await.unwrap();

        let mut conn = tokio::net::TcpStream::connect(instance.socks_addr)
            .await
            .unwrap();
        conn.write_all(b"hello").await.unwrap();
        conn.shutdown().await.unwrap();

        let mut buf = vec![0u8; 16];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn plain_transport_clone_eq() {
        let t1 = PlainTransport::new();
        let t2 = t1;
        assert_eq!(t1, t2);
    }

    #[test]
    fn plain_transport_default() {
        let t = PlainTransport::default();
        assert_eq!(t, PlainTransport::new());
    }
}
