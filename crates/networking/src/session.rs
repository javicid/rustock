use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use crate::protocol::{P2pHandler, P2pMessage};
use crate::codec::{P2pCodec};
use crate::handshake::HandshakeCodec;
use alloy_primitives::B512;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tracing::{trace, debug};

use tokio::sync::mpsc;

/// Read-idle timeout: disconnect a peer from which no message has been received
/// within this window. Mirrors rskj's Netty `ReadTimeoutHandler`
/// (`channel.read.timeout = 300`s). The 30s keepalive Ping ensures a live peer
/// always resets this well before it fires.
pub const DEFAULT_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Manages a persistent asynchronous session with a connected peer.
pub struct PeerSession {
    pub peer_id: B512,
    framed: Framed<TcpStream, HandshakeCodec>,
    handlers: Vec<Arc<dyn P2pHandler>>,
    outbound_rx: mpsc::UnboundedReceiver<P2pMessage>,
    read_idle_timeout: Duration,
}

impl PeerSession {
    pub fn new(peer_id: B512, stream: TcpStream, outbound_rx: mpsc::UnboundedReceiver<P2pMessage>) -> Self {
        Self {
            peer_id,
            framed: Framed::new(stream, HandshakeCodec::Plain(P2pCodec)),
            handlers: Vec::new(),
            outbound_rx,
            read_idle_timeout: DEFAULT_READ_IDLE_TIMEOUT,
        }
    }

    pub fn from_framed(peer_id: B512, framed: Framed<TcpStream, HandshakeCodec>, outbound_rx: mpsc::UnboundedReceiver<P2pMessage>) -> Self {
        Self {
            peer_id,
            framed,
            handlers: Vec::new(),
            outbound_rx,
            read_idle_timeout: DEFAULT_READ_IDLE_TIMEOUT,
        }
    }

    /// Appends a message handler to this session.
    pub fn add_handler(&mut self, handler: Arc<dyn P2pHandler>) {
        self.handlers.push(handler);
    }

    /// Overrides the read-idle timeout (primarily for tests / configuration).
    pub fn with_read_idle_timeout(mut self, timeout: Duration) -> Self {
        self.read_idle_timeout = timeout;
        self
    }

    /// Starts the message listening loop.
    pub async fn run(&mut self) -> Result<()> {
        use tokio::time::{interval, sleep_until, Duration, Instant};
        let mut ping_interval = interval(Duration::from_secs(30));
        let mut read_deadline = Instant::now() + self.read_idle_timeout;

        loop {
            tokio::select! {
                _ = ping_interval.tick() => {
                    trace!(target: "rustock::net", "Sending periodic P2P Ping to {:?}", self.peer_id);
                    self.framed.send(P2pMessage::Ping).await?;
                }
                _ = sleep_until(read_deadline) => {
                    debug!(
                        target: "rustock::net",
                        "Peer {:?} read-idle timeout ({}s), disconnecting",
                        self.peer_id, self.read_idle_timeout.as_secs()
                    );
                    break;
                }
                msg_res = self.framed.next() => {
                    let msg = match msg_res {
                        Some(Ok(m)) => m,
                        Some(Err(e)) => {
                            // Connection reset / malformed frame: end the session so
                            // the peer is removed (rskj closes the channel on any
                            // pipeline error). Previously this `continue`d, leaving a
                            // half-open peer pinned until the next ping send failed.
                            debug!(target: "rustock::net", "Connection error from {:?}: {:?}, ending session", self.peer_id, e);
                            break;
                        }
                        None => {
                            debug!(target: "rustock::net", "Peer {:?} closed the connection", self.peer_id);
                            break;
                        }
                    };
                    // Any received frame proves liveness — reset the idle deadline.
                    read_deadline = Instant::now() + self.read_idle_timeout;
                    trace!(target: "rustock::net", "Inbound message from {:?}: {:?}", self.peer_id, msg);
                    
                    match &msg {
                        P2pMessage::Ping => {
                            trace!(target: "rustock::net", "Replying with P2P Pong to {:?}", self.peer_id);
                            self.framed.send(P2pMessage::Pong).await?;
                            continue;
                        }
                        P2pMessage::Pong => {
                            trace!(target: "rustock::net", "Received P2P Pong from {:?}", self.peer_id);
                            continue;
                        }
                        P2pMessage::Disconnect(reason) => {
                            debug!(target: "rustock::net", "Peer {:?} disconnected, reason code: {}", self.peer_id, reason);
                            break;
                        }
                        _ => {}
                    }

                    for handler in &self.handlers {
                        if let Some(resp) = handler.handle_message(self.peer_id, &msg) {
                            trace!(target: "rustock::net", "Outbound response to {:?}: {:?}", self.peer_id, resp);
                            self.framed.send(resp).await?;
                        }
                    }
                }
                Some(msg) = self.outbound_rx.recv() => {
                    trace!(target: "rustock::net", "Sending active outbound message to {:?}: {:?}", self.peer_id, msg);
                    self.framed.send(msg).await?;
                }
            }
        }
        debug!(target: "rustock::net", "Peer {:?} session ended", self.peer_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    
    #[tokio::test]
    async fn test_session_ping_pong_disconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let (_tx, rx) = mpsc::unbounded_channel();
        
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut session = PeerSession::new(B512::ZERO, stream, rx);
            session.run().await.unwrap();
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut framed = Framed::new(client_stream, HandshakeCodec::Plain(P2pCodec));

        // Send Ping
        framed.send(P2pMessage::Ping).await.unwrap();
        // Should receive Pong
        let msg = framed.next().await.unwrap().unwrap();
        assert!(matches!(msg, P2pMessage::Pong));

        // Send Disconnect
        framed.send(P2pMessage::Disconnect(0)).await.unwrap();

        // Server session should end
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_session_read_idle_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (_tx, rx) = mpsc::unbounded_channel();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut session = PeerSession::new(B512::ZERO, stream, rx)
                .with_read_idle_timeout(Duration::from_millis(200));
            session.run().await.unwrap();
        });

        // Client connects but never sends anything; the session must reap it.
        let _client = TcpStream::connect(addr).await.unwrap();

        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("session should end after the read-idle timeout")
            .unwrap();
    }

    #[tokio::test]
    async fn test_session_ends_on_peer_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (_tx, rx) = mpsc::unbounded_channel();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut session = PeerSession::new(B512::ZERO, stream, rx);
            session.run().await.unwrap();
        });

        // Connect then immediately drop the connection (EOF on the server side).
        let client = TcpStream::connect(addr).await.unwrap();
        drop(client);

        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("session should end when the peer closes the connection")
            .unwrap();
    }
}
