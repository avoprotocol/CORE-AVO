/// TCP Connection Pool for Real Network Communication
/// Manages persistent TCP connections to peers for gossip and message routing
use crate::AvoError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

/// Maximum time to wait for connection establishment
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time to wait for sending a message
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum message size (10MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Keep-alive interval
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

pub type PeerId = String;

/// Represents a single TCP connection to a peer
#[derive(Debug)]
pub struct TcpConnection {
    pub peer_id: PeerId,
    pub addr: SocketAddr,
    stream: Option<TcpStream>,
    pub connected_at: std::time::SystemTime,
    pub last_activity: std::time::SystemTime,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl TcpConnection {
    /// Create a new TCP connection (not yet connected)
    pub fn new(peer_id: PeerId, addr: SocketAddr) -> Self {
        Self {
            peer_id,
            addr,
            stream: None,
            connected_at: std::time::SystemTime::now(),
            last_activity: std::time::SystemTime::now(),
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Establish TCP connection to the peer
    pub async fn connect(&mut self) -> Result<(), AvoError> {
        info!("🔌 Connecting to peer {} at {}", self.peer_id, self.addr);

        match timeout(CONNECTION_TIMEOUT, TcpStream::connect(self.addr)).await {
            Ok(Ok(stream)) => {
                // Enable TCP keepalive
                let socket = socket2::Socket::from(stream.into_std()?);
                socket.set_keepalive(true)?; // Enable keepalive
                socket.set_nodelay(true)?; // Disable Nagle's algorithm for low latency

                let stream = TcpStream::from_std(socket.into())?;
                self.stream = Some(stream);
                self.connected_at = std::time::SystemTime::now();
                self.last_activity = std::time::SystemTime::now();

                info!("✅ Connected to peer {} at {}", self.peer_id, self.addr);
                Ok(())
            }
            Ok(Err(e)) => {
                error!("❌ Failed to connect to peer {}: {}", self.peer_id, e);
                Err(AvoError::network(format!(
                    "Connection failed to {}: {}",
                    self.addr, e
                )))
            }
            Err(_) => {
                error!("⏱️ Connection timeout to peer {}", self.peer_id);
                Err(AvoError::network(format!(
                    "Connection timeout to {}",
                    self.addr
                )))
            }
        }
    }

    /// Send raw bytes to the peer
    pub async fn send_bytes(&mut self, data: &[u8]) -> Result<(), AvoError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            AvoError::network(format!("Not connected to peer {}", self.peer_id))
        })?;

        // Send message length first (4 bytes, big-endian)
        let len = data.len() as u32;
        let len_bytes = len.to_be_bytes();

        match timeout(SEND_TIMEOUT, stream.write_all(&len_bytes)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                error!("❌ Failed to send length to peer {}: {}", self.peer_id, e);
                self.stream = None; // Mark as disconnected
                return Err(AvoError::network(format!("Send failed: {}", e)));
            }
            Err(_) => {
                error!("⏱️ Send timeout to peer {}", self.peer_id);
                self.stream = None;
                return Err(AvoError::network("Send timeout".to_string()));
            }
        }

        // Send actual message data
        match timeout(SEND_TIMEOUT, stream.write_all(data)).await {
            Ok(Ok(_)) => {
                self.bytes_sent += data.len() as u64 + 4; // Include length prefix
                self.messages_sent += 1;
                self.last_activity = std::time::SystemTime::now();

                debug!(
                    "📤 Sent {} bytes to peer {} (total: {} msgs, {} bytes)",
                    data.len(),
                    self.peer_id,
                    self.messages_sent,
                    self.bytes_sent
                );
                Ok(())
            }
            Ok(Err(e)) => {
                error!(
                    "❌ Failed to send data to peer {}: {}",
                    self.peer_id, e
                );
                self.stream = None;
                Err(AvoError::network(format!("Send failed: {}", e)))
            }
            Err(_) => {
                error!("⏱️ Send timeout to peer {}", self.peer_id);
                self.stream = None;
                Err(AvoError::network("Send timeout".to_string()))
            }
        }
    }

    /// Receive raw bytes from the peer
    pub async fn receive_bytes(&mut self) -> Result<Vec<u8>, AvoError> {
        if self.stream.is_none() {
            return Err(AvoError::network(format!(
                "Not connected to peer {}",
                self.peer_id
            )));
        }

        let stream = self.stream.as_mut().unwrap();

        // Read message length first (4 bytes)
        let mut len_bytes = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut len_bytes).await {
            error!("❌ Failed to read length from peer {}: {}", self.peer_id, e);
            self.stream = None;
            return Err(AvoError::network(format!("Read failed: {}", e)));
        }

        let len = u32::from_be_bytes(len_bytes) as usize;

        // Validate message size
        if len > MAX_MESSAGE_SIZE {
            error!(
                "❌ Message too large from peer {}: {} bytes (max: {})",
                self.peer_id, len, MAX_MESSAGE_SIZE
            );
            self.stream = None;
            return Err(AvoError::network(format!(
                "Message too large: {} bytes",
                len
            )));
        }

        // Read actual message data
        let mut data = vec![0u8; len];
        if let Err(e) = stream.read_exact(&mut data).await {
            error!("❌ Failed to read data from peer {}: {}", self.peer_id, e);
            self.stream = None;
            return Err(AvoError::network(format!("Read failed: {}", e)));
        }

        self.bytes_received += len as u64 + 4;
        self.messages_received += 1;
        self.last_activity = std::time::SystemTime::now();

        debug!(
            "📥 Received {} bytes from peer {} (total: {} msgs, {} bytes)",
            len, self.peer_id, self.messages_received, self.bytes_received
        );

        Ok(data)
    }

    /// Check if connection is still alive
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Check if connection is stale (no activity for too long)
    pub fn is_stale(&self, max_idle: Duration) -> bool {
        if let Ok(elapsed) = self.last_activity.elapsed() {
            elapsed > max_idle
        } else {
            false
        }
    }

    /// Close the connection
    pub async fn close(&mut self) {
        if let Some(_stream) = self.stream.take() {
            info!("🔌 Closing connection to peer {}", self.peer_id);
        }
    }
}

/// Pool of TCP connections to multiple peers
#[derive(Debug)]
pub struct TcpConnectionPool {
    connections: Arc<RwLock<HashMap<PeerId, TcpConnection>>>,
    max_connections: usize,
    max_idle_time: Duration,
}

impl TcpConnectionPool {
    /// Create a new TCP connection pool
    pub fn new(max_connections: usize, max_idle_time: Duration) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            max_connections,
            max_idle_time,
        }
    }

    /// Get or create a connection to a peer
    pub async fn get_or_connect(
        &self,
        peer_id: PeerId,
        addr: SocketAddr,
    ) -> Result<(), AvoError> {
        let mut connections = self.connections.write().await;

        // Check if already connected
        if let Some(conn) = connections.get(&peer_id) {
            if conn.is_connected() && !conn.is_stale(self.max_idle_time) {
                debug!("♻️ Reusing existing connection to peer {}", peer_id);
                return Ok(());
            }
        }

        // Check connection limit
        if connections.len() >= self.max_connections {
            warn!(
                "⚠️ Connection pool full ({}/{}), cleaning stale connections",
                connections.len(),
                self.max_connections
            );
            self.cleanup_stale_connections(&mut connections).await;

            // If still full, reject
            if connections.len() >= self.max_connections {
                return Err(AvoError::network(format!(
                    "Connection pool full ({} connections)",
                    self.max_connections
                )));
            }
        }

        // Create new connection
        let mut conn = TcpConnection::new(peer_id.clone(), addr);
        conn.connect().await?;
        connections.insert(peer_id, conn);

        Ok(())
    }

    /// Send message to a peer
    pub async fn send_to_peer(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), AvoError> {
        let mut connections = self.connections.write().await;

        let conn = connections.get_mut(peer_id).ok_or_else(|| {
            AvoError::network(format!("No connection to peer {}", peer_id))
        })?;

        // Attempt to send
        match conn.send_bytes(data).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Connection failed, remove it
                warn!("⚠️ Removing failed connection to peer {}", peer_id);
                connections.remove(peer_id);
                Err(e)
            }
        }
    }

    /// Receive message from a peer (blocking)
    pub async fn receive_from_peer(&self, peer_id: &PeerId) -> Result<Vec<u8>, AvoError> {
        let mut connections = self.connections.write().await;

        let conn = connections.get_mut(peer_id).ok_or_else(|| {
            AvoError::network(format!("No connection to peer {}", peer_id))
        })?;

        // Attempt to receive
        match conn.receive_bytes().await {
            Ok(data) => Ok(data),
            Err(e) => {
                // Connection failed, remove it
                warn!("⚠️ Removing failed connection to peer {}", peer_id);
                connections.remove(peer_id);
                Err(e)
            }
        }
    }

    /// Get statistics for a peer
    pub async fn get_stats(&self, peer_id: &PeerId) -> Option<ConnectionStats> {
        let connections = self.connections.read().await;
        connections.get(peer_id).map(|conn| ConnectionStats {
            peer_id: conn.peer_id.clone(),
            addr: conn.addr,
            connected: conn.is_connected(),
            connected_at: conn.connected_at,
            last_activity: conn.last_activity,
            messages_sent: conn.messages_sent,
            messages_received: conn.messages_received,
            bytes_sent: conn.bytes_sent,
            bytes_received: conn.bytes_received,
        })
    }

    /// Get list of all connected peers
    pub async fn get_connected_peers(&self) -> Vec<PeerId> {
        let connections = self.connections.read().await;
        connections
            .iter()
            .filter(|(_, conn)| conn.is_connected())
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }

    /// Clean up stale connections
    async fn cleanup_stale_connections(&self, connections: &mut HashMap<PeerId, TcpConnection>) {
        let stale_peers: Vec<PeerId> = connections
            .iter()
            .filter(|(_, conn)| !conn.is_connected() || conn.is_stale(self.max_idle_time))
            .map(|(peer_id, _)| peer_id.clone())
            .collect();

        for peer_id in stale_peers {
            if let Some(mut conn) = connections.remove(&peer_id) {
                conn.close().await;
                info!("🧹 Cleaned up stale connection to peer {}", peer_id);
            }
        }
    }

    /// Close all connections
    pub async fn close_all(&self) {
        let mut connections = self.connections.write().await;
        for (_, mut conn) in connections.drain() {
            conn.close().await;
        }
        info!("🔌 Closed all connections in pool");
    }

    /// Get total number of connections
    pub async fn connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub peer_id: PeerId,
    pub addr: SocketAddr,
    pub connected: bool,
    pub connected_at: std::time::SystemTime,
    pub last_activity: std::time::SystemTime,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl Default for TcpConnectionPool {
    fn default() -> Self {
        Self::new(100, Duration::from_secs(300))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_connection_pool_creation() {
        let pool = TcpConnectionPool::new(100, Duration::from_secs(60));
        assert_eq!(pool.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_connection_stats() {
        let pool = TcpConnectionPool::new(100, Duration::from_secs(60));
        let peers = pool.get_connected_peers().await;
        assert_eq!(peers.len(), 0);
    }
}
