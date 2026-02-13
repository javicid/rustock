use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use crate::protocol::{P2pHandler, P2pMessage};
use crate::codec::{P2pCodec};
use crate::handshake::HandshakeCodec;
use alloy_primitives::B512;
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, trace};

use tokio::sync::mpsc;

/// Manages a persistent asynchronous session with a connected peer.
pub struct PeerSession {
    pub peer_id: B512,
    framed: Framed<TcpStream, HandshakeCodec>,
    handlers: Vec<Arc<dyn P2pHandler>>,
    outbound_rx: mpsc::UnboundedReceiver<P2pMessage>,
}

impl PeerSession {
    pub fn new(peer_id: B512, stream: TcpStream, outbound_rx: mpsc::UnboundedReceiver<P2pMessage>) -> Self {
        Self {
            peer_id,
            framed: Framed::new(stream, HandshakeCodec::Plain(P2pCodec)),
            handlers: Vec::new(),
            outbound_rx,
        }
    }

    pub fn from_framed(peer_id: B512, framed: Framed<TcpStream, HandshakeCodec>, outbound_rx: mpsc::UnboundedReceiver<P2pMessage>) -> Self {
        Self {
            peer_id,
            framed,
            handlers: Vec::new(),
            outbound_rx,
        }
    }

    /// Appends a message handler to this session.
    pub fn add_handler(&mut self, handler: Arc<dyn P2pHandler>) {
        self.handlers.push(handler);
    }

    /// Starts the message listening loop.
    pub async fn run(&mut self) -> Result<()> {
        use tokio::time::{interval, Duration};
        let mut ping_interval = interval(Duration::from_secs(30));
        
        loop {
            tokio::select! {
                _ = ping_interval.tick() => {
                    trace!(target: "rustock::net", "Sending periodic P2P Ping to {:?}", self.peer_id);
                    self.framed.send(P2pMessage::Ping).await?;
                }
                Some(msg_res) = self.framed.next() => {
                    let msg: P2pMessage = msg_res?;
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
                        if let Some(resp) = handler.handle_message(self.peer_id, msg.clone()) {
                            trace!(target: "rustock::net", "Outbound response to {:?}: {:?}", self.peer_id, resp);
                            self.framed.send(resp).await?;
                        }
                    }
                }
                Some(msg) = self.outbound_rx.recv() => {
                    trace!(target: "rustock::net", "Sending active outbound message to {:?}: {:?}", self.peer_id, msg);
                    self.framed.send(msg).await?;
                }
                else => break,
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
}
