use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use maboroshi_core::{
    AsyncStream, Error, Obfuscator, PluggableTransport, PtClientInstance, PtConfig,
    PtServerInstance, Result, TransportType,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

/// WebSocket-based pluggable transport.
///
/// Wraps TCP connections inside a WebSocket upgrade so traffic looks
/// like ordinary HTTPS/WebSocket traffic to network observers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

                                    if let Err(e) = tokio::try_join!(
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
                                    ) {
                                        tracing::debug!(%e, "webtunnel client: copy loop ended");
                                    }
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

                                            if let Err(e) = tokio::try_join!(
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
                                            ) {
                                                tracing::debug!(%e, "webtunnel server: copy loop ended");
                                            }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebTunnelObfuscator {
    /// WebSocket endpoint URL to connect to.
    pub ws_url: String,
}

/// Adapter that delegates `AsyncRead`/`AsyncWrite` to a boxed `AsyncStream`.
///
/// `tokio-tungstenite` needs a concrete type implementing both async I/O
/// traits; this thin wrapper satisfies that requirement.
struct StreamAdapter {
    inner: Box<dyn AsyncStream>,
}

impl AsyncRead for StreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for StreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl Unpin for StreamAdapter {}

/// Wraps a `WebSocketStream` into an `AsyncRead + AsyncWrite` byte stream.
///
/// Incoming WebSocket binary frames are reassembled into a contiguous byte
/// stream. Writes are sent as binary frames.
struct WsStream<S> {
    inner: tokio_tungstenite::WebSocketStream<S>,
    /// Leftover bytes from the last received frame that have not yet been
    /// consumed by a `poll_read` call.
    read_buf: BytesMut,
}

impl<S> WsStream<S> {
    fn new(inner: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: BytesMut::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Unpin for WsStream<S> {}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Return buffered data first.
        if !this.read_buf.is_empty() {
            let len = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf.split_to(len));
            return Poll::Ready(Ok(()));
        }

        // Poll the WebSocket stream for the next frame.
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                let len = data.len().min(buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    this.read_buf.extend_from_slice(&data[len..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                // EOF
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(_))) => {
                // Skip non-binary frames and try again.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let msg = Message::Binary(buf.to_vec().into());
        match Pin::new(&mut this.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                match Pin::new(&mut this.inner).start_send(msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

#[async_trait]
impl Obfuscator for WebTunnelObfuscator {
    async fn wrap(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> Result<Box<dyn AsyncStream>> {
        let uri: tokio_tungstenite::tungstenite::http::Uri = self
            .ws_url
            .parse()
            .map_err(|e| Error::Config(format!("invalid WebSocket URL: {e}")))?;

        let request = tokio_tungstenite::tungstenite::http::Request::builder()
            .method("GET")
            .uri(&uri)
            .header("Host", uri.authority().map_or("localhost", |a| a.as_str()))
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", generate_key())
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .map_err(|e| Error::Transport(format!("failed to build upgrade request: {e}")))?;

        let adapter = StreamAdapter { inner: stream };
        let (ws_stream, _response) =
            tokio_tungstenite::client_async(request, adapter)
                .await
                .map_err(|e| Error::Handshake(format!("WebSocket handshake failed: {e}")))?;

        Ok(Box::new(WsStream::new(ws_stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

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

    #[test]
    fn stream_adapter_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<StreamAdapter>();
    }

    #[tokio::test]
    async fn wrap_performs_websocket_handshake() {
        // Start a minimal WebSocket echo server.
        let ws_listener =
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
        let ws_addr = ws_listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((stream, _)) = ws_listener.accept().await {
                if let Ok(ws) = tokio_tungstenite::accept_async(stream).await {
                    let (mut write, mut read) = ws.split();
                    while let Some(Ok(msg)) = read.next().await {
                        if msg.is_binary() {
                            let _ = write.send(msg).await;
                        }
                    }
                }
            }
        });

        // Connect a raw TCP stream to the WS server.
        let tcp = tokio::net::TcpStream::connect(ws_addr).await.unwrap();
        let stream: Box<dyn AsyncStream> = Box::new(tcp);

        let obfuscator = WebTunnelObfuscator {
            ws_url: format!("ws://{ws_addr}/"),
        };

        let mut wrapped = obfuscator.wrap(stream).await.unwrap();

        // Round-trip some data through the WebSocket layer.
        wrapped.write_all(b"hello").await.unwrap();
        wrapped.flush().await.unwrap();

        let mut buf = [0u8; 16];
        let n = wrapped.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn webtunnel_transport_clone_eq() {
        let t1 = WebTunnelTransport::new();
        let t2 = t1;
        assert_eq!(t1, t2);
    }

    #[test]
    fn webtunnel_transport_default() {
        let t = WebTunnelTransport::default();
        assert_eq!(t, WebTunnelTransport::new());
    }

    #[test]
    fn webtunnel_obfuscator_clone_eq() {
        let o1 = WebTunnelObfuscator {
            ws_url: "ws://127.0.0.1:8080/tunnel".into(),
        };
        let o2 = o1.clone();
        assert_eq!(o1, o2);
    }
}
