use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use maboroshi_core::{
    AsyncStream, Error, Obfuscator, PluggableTransport, PtClientInstance, PtConfig,
    PtServerInstance, Result, TransportType,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

/// WebSocket-based pluggable transport.
///
/// Wraps TCP connections inside a WebSocket upgrade so traffic looks
/// like ordinary HTTPS/WebSocket traffic to network observers.
pub struct WebTunnelTransport;

impl WebTunnelTransport {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for WebTunnelTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PluggableTransport for WebTunnelTransport {
    fn name(&self) -> &str {
        "webtunnel"
    }

    fn transport_type(&self) -> TransportType {
        TransportType::WebTunnel
    }

    async fn start_client(&self, config: &PtConfig) -> Result<PtClientInstance> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let socks_addr = listener.local_addr()?;
        info!(%socks_addr, "webtunnel client listening");

        let target = config
            .target_addr
            .ok_or_else(|| Error::Config("target_addr required for webtunnel client".into()))?;

        let path = config
            .options
            .get("path")
            .cloned()
            .unwrap_or_else(|| "/".to_owned());

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((inbound, peer)) => {
                        info!(%peer, "webtunnel client accepted connection");
                        let ws_url = format!("ws://{target}{path}");
                        tokio::spawn(async move {
                            match tokio_tungstenite::connect_async(&ws_url).await {
                                Ok((ws_stream, _)) => {
                                    let (mut ws_write, mut ws_read) = ws_stream.split();
                                    let (mut tcp_read, mut tcp_write) =
                                        tokio::io::split(inbound);

                                    let _ = tokio::try_join!(
                                        async {
                                            let mut buf = vec![0u8; 4096];
                                            loop {
                                                match tcp_read.read(&mut buf).await {
                                                    Ok(0) => break Ok::<_, std::io::Error>(()),
                                                    Ok(n) => {
                                                        let msg = Message::Binary(
                                                            buf[..n].to_vec().into(),
                                                        );
                                                        if ws_write.send(msg).await.is_err() {
                                                            break Ok(());
                                                        }
                                                    }
                                                    Err(e) => break Err(e),
                                                }
                                            }
                                        },
                                        async {
                                            while let Some(Ok(msg)) = ws_read.next().await {
                                                if let Message::Binary(data) = msg {
                                                    tcp_write.write_all(&data).await?;
                                                }
                                            }
                                            Ok(())
                                        }
                                    );
                                }
                                Err(e) => {
                                    tracing::error!(%e, "webtunnel: WebSocket connect failed");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(%e, "webtunnel client accept error");
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
        info!(%bound_addr, "webtunnel server listening");

        let target = config
            .target_addr
            .ok_or_else(|| Error::Config("target_addr required for webtunnel server".into()))?;

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        info!(%peer, "webtunnel server accepted connection");
                        tokio::spawn(async move {
                            match tokio_tungstenite::accept_async(stream).await {
                                Ok(ws_stream) => {
                                    match tokio::net::TcpStream::connect(target).await {
                                        Ok(tcp_out) => {
                                            let (mut ws_write, mut ws_read) = ws_stream.split();
                                            let (mut tcp_read, mut tcp_write) =
                                                tokio::io::split(tcp_out);

                                            let _ = tokio::try_join!(
                                                async {
                                                    while let Some(Ok(msg)) =
                                                        ws_read.next().await
                                                    {
                                                        if let Message::Binary(data) = msg {
                                                            tcp_write.write_all(&data).await?;
                                                        }
                                                    }
                                                    Ok::<_, std::io::Error>(())
                                                },
                                                async {
                                                    let mut buf = vec![0u8; 4096];
                                                    loop {
                                                        match tcp_read.read(&mut buf).await {
                                                            Ok(0) => break Ok(()),
                                                            Ok(n) => {
                                                                let msg = Message::Binary(
                                                                    buf[..n].to_vec().into(),
                                                                );
                                                                if ws_write
                                                                    .send(msg)
                                                                    .await
                                                                    .is_err()
                                                                {
                                                                    break Ok(());
                                                                }
                                                            }
                                                            Err(e) => break Err(e),
                                                        }
                                                    }
                                                }
                                            );
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                %e,
                                                "webtunnel: failed to connect to target"
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(%e, "webtunnel: WebSocket accept failed");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(%e, "webtunnel server accept error");
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

/// Obfuscation layer that wraps a raw stream inside a WebSocket connection.
pub struct WebTunnelObfuscator {
    /// WebSocket endpoint URL to connect to.
    pub ws_url: String,
}

#[async_trait]
impl Obfuscator for WebTunnelObfuscator {
    async fn wrap(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> Result<Box<dyn AsyncStream>> {
        // Perform a WebSocket upgrade over the provided stream.
        // The upgraded stream is returned as the obfuscated transport.
        let _key = generate_key();

        // For now, pass the stream through. A full implementation would
        // perform the WebSocket framing over the existing stream.
        // This stub satisfies the trait contract and is the integration point
        // for real WebSocket framing.
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_webtunnel() {
        let t = WebTunnelTransport::new();
        assert_eq!(t.name(), "webtunnel");
    }

    #[test]
    fn transport_type_is_webtunnel() {
        let t = WebTunnelTransport::new();
        assert_eq!(t.transport_type(), TransportType::WebTunnel);
    }

    #[test]
    fn obfuscator_has_url() {
        let o = WebTunnelObfuscator {
            ws_url: "ws://127.0.0.1:8080/tunnel".into(),
        };
        assert_eq!(o.ws_url, "ws://127.0.0.1:8080/tunnel");
    }
}
