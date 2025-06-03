//! UDP connection management implementation
//!
//! This module provides concrete implementations for managing UDP connections,
//! including connection pooling, idle timeout handling, and metrics tracking.

use super::{ConnectionContext, ConnectionManager, ConnectionMetrics};
use crate::{error::ConnectionError, protocol::udp::UdpProtocol, trace::*, udp_conn::UdpConnectionPool};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::UdpSocket;

/// UDP connection manager responsible for creating and handling UDP connections
#[derive(Clone)]
pub struct UdpConnectionManager {
  /// Connection pool for managing UDP connections
  connection_pool: Arc<UdpConnectionPool>,
  /// Maximum number of concurrent connections allowed
  max_connections: usize,
}

impl std::fmt::Debug for UdpConnectionManager {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("UdpConnectionManager")
      .field("max_connections", &self.max_connections)
      .finish()
  }
}

/// Represents a UDP connection with its associated metadata and sockets
#[derive(Debug)]
pub struct UdpConnection {
  /// Client-facing UDP socket (shared among connections)
  pub client_socket: Arc<UdpSocket>,
  /// Server-facing UDP socket (unique per connection)
  pub server_socket: UdpSocket,
  /// Client address
  pub client_addr: SocketAddr,
  /// Server address
  pub server_addr: SocketAddr,
  /// Connection metrics and metadata
  pub metrics: ConnectionMetrics,
  /// The protocol that was detected for this connection
  pub protocol: UdpProtocol,
  /// Connection context for logging and error reporting
  pub context: ConnectionContext,
  /// Idle timeout duration
  pub idle_timeout: Duration,
}

/// Information needed to create a UDP connection
#[derive(Debug, Clone)]
pub struct UdpConnectionInfo {
  /// The detected protocol
  pub protocol: UdpProtocol,
  /// Idle timeout for the connection
  pub idle_timeout: Duration,
  /// Client-facing socket
  pub client_socket: Arc<UdpSocket>,
}

impl UdpConnectionManager {
  /// Create a new UDP connection manager
  pub fn new(connection_pool: Arc<UdpConnectionPool>, max_connections: usize) -> Self {
    Self {
      connection_pool,
      max_connections,
    }
  }

  /// Get the connection pool
  pub fn connection_pool(&self) -> &Arc<UdpConnectionPool> {
    &self.connection_pool
  }

  /// Check if we can accept a new connection (not at limit)
  pub fn can_accept_connection(&self) -> bool {
    !self.is_connection_limit_reached()
  }

  /// Prune expired connections from the pool
  pub fn prune_expired_connections(&self) {
    // Note: The existing UdpConnectionPool doesn't have this method,
    // so this is a placeholder for future implementation
    // self.connection_pool.prune_expired_connections();
  }
}

#[async_trait::async_trait]
impl ConnectionManager for UdpConnectionManager {
  type Connection = UdpConnection;
  type ConnectionInfo = UdpConnectionInfo;

  async fn create_connection(
    &self,
    src: SocketAddr,
    dst: SocketAddr,
    info: Self::ConnectionInfo,
  ) -> Result<Self::Connection, ConnectionError> {
    // Check connection limit
    if self.is_connection_limit_reached() {
      return Err(ConnectionError::LimitExceeded {
        current: self.connection_count(),
        max: self.max_connections(),
      });
    }

    // Create server-facing socket
    let server_socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| ConnectionError::BindFailed {
      address: "0.0.0.0:0".parse().unwrap(),
      source: e,
    })?;

    // Connect to destination
    server_socket
      .connect(dst)
      .await
      .map_err(|e| ConnectionError::ConnectionFailed { address: dst, source: e })?;

    // Create metrics and context
    let metrics = ConnectionMetrics::new(info.protocol.to_string(), src, dst);
    let context = ConnectionContext::new(src, dst, info.protocol.to_string());

    debug!(
        connection_id = %context.connection_id,
        src_addr = %src,
        dst_addr = %dst,
        protocol = %info.protocol,
        idle_timeout_secs = info.idle_timeout.as_secs(),
        "UDP connection created"
    );

    Ok(UdpConnection {
      client_socket: info.client_socket,
      server_socket,
      client_addr: src,
      server_addr: dst,
      metrics,
      protocol: info.protocol,
      context,
      idle_timeout: info.idle_timeout,
    })
  }

  async fn handle_connection(&self, mut conn: UdpConnection) -> Result<(), ConnectionError> {
    // Log connection start
    info!(
        connection_id = %conn.context.connection_id,
        src_addr = %conn.context.src_addr,
        dst_addr = %conn.context.dst_addr,
        protocol = %conn.context.protocol,
        idle_timeout_secs = conn.idle_timeout.as_secs(),
        "UDP connection started"
    );

    // Set up bidirectional UDP forwarding
    let result = self.handle_udp_forwarding(&mut conn).await;

    // Update metrics based on result
    match &result {
      Ok((bytes_to_server, bytes_to_client)) => {
        conn.metrics.record_bytes_sent(*bytes_to_server);
        conn.metrics.record_bytes_received(*bytes_to_client);
      }
      Err(_) => {
        // Metrics already initialized to 0
      }
    }

    // Log connection end
    info!(
      connection_id = %conn.context.connection_id,
      src_addr = %conn.context.src_addr,
      dst_addr = %conn.context.dst_addr,
      protocol = %conn.context.protocol,
      duration_ms = conn.metrics.duration().as_millis(),
      bytes_sent = conn.metrics.bytes_sent,
      bytes_received = conn.metrics.bytes_received,
      "UDP connection ended"
    );

    result.map(|_| ())
  }

  fn connection_count(&self) -> usize {
    self.connection_pool.local_pool_size()
  }

  fn max_connections(&self) -> usize {
    self.max_connections
  }
}

impl UdpConnectionManager {
  /// Handle UDP forwarding between client and server
  async fn handle_udp_forwarding(&self, conn: &mut UdpConnection) -> Result<(u64, u64), ConnectionError> {
    use tokio::{select, time::sleep};

    let mut bytes_to_server = 0u64;
    let mut bytes_to_client = 0u64;
    let mut client_buffer = vec![0u8; crate::constants::UDP_BUFFER_SIZE];
    let mut server_buffer = vec![0u8; crate::constants::UDP_BUFFER_SIZE];
    let mut last_activity = std::time::Instant::now();

    loop {
      select! {
            // Forward from client to server
            result = conn.client_socket.recv_from(&mut client_buffer) => {
              match result {
                  Ok((len, addr)) if addr == conn.client_addr => {
                      match conn.server_socket.send(&client_buffer[..len]).await {
                          Ok(_) => {
                              bytes_to_server += len as u64;
                              last_activity = std::time::Instant::now();
                              trace!(
                                  connection_id = %conn.context.connection_id,
                                  bytes = len,
                                  "Forwarded data from client to server"
                              );
                          }
                          Err(e) => {
                              warn!(
                                  connection_id = %conn.context.connection_id,
                                  error = %e,
                                  "Failed to send to server"
                              );
                              return Err(ConnectionError::UdpConnectionBroken {
                                  client_addr: conn.client_addr,
                                  reason: format!("Failed to send to server: {}", e),
                              });
                          }
                      }
                  }
                  Ok(_) => {
                      // Packet from different client, ignore
                      continue;
                  }
                  Err(e) => {
                      warn!(
                          connection_id = %conn.context.connection_id,
                          error = %e,
                          "Failed to receive from client"
                      );
                      return Err(ConnectionError::UdpConnectionBroken {
                          client_addr: conn.client_addr,
                          reason: format!("Failed to receive from client: {}", e),
                      });
                  }
              }
          }

          // Forward from server to client
          result = conn.server_socket.recv(&mut server_buffer) => {
              match result {
                  Ok(len) => {
                      match conn.client_socket.send_to(&server_buffer[..len], conn.client_addr).await {
                          Ok(_) => {
                              bytes_to_client += len as u64;
                              last_activity = std::time::Instant::now();
                              trace!(
                                  connection_id = %conn.context.connection_id,
                                  bytes = len,
                                  "Forwarded data from server to client"
                              );
                          }
                          Err(e) => {
                              warn!(
                                  connection_id = %conn.context.connection_id,
                                  error = %e,
                                  "Failed to send to client"
                              );
                              return Err(ConnectionError::UdpConnectionBroken {
                                  client_addr: conn.client_addr,
                                  reason: format!("Failed to send to client: {}", e),
                              });
                          }
                      }
                  }
                  Err(e) => {
                      warn!(
                          connection_id = %conn.context.connection_id,
                          error = %e,
                          "Failed to receive from server"
                      );
                      return Err(ConnectionError::UdpConnectionBroken {
                          client_addr: conn.client_addr,
                          reason: format!("Failed to receive from server: {}", e),
                      });
                  }
              }
          }

          // Check for idle timeout
          _ = sleep(Duration::from_secs(1)) => {
              if last_activity.elapsed() >= conn.idle_timeout {
                  debug!(
                      connection_id = %conn.context.connection_id,
                      idle_duration_secs = last_activity.elapsed().as_secs(),
                      "UDP connection idle timeout"
                  );
                  break;
              }
          }
      }
    }

    Ok((bytes_to_server, bytes_to_client))
  }
}

impl UdpConnection {
  /// Create a new UDP connection
  pub fn new(
    client_socket: Arc<UdpSocket>,
    server_socket: UdpSocket,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    protocol: UdpProtocol,
    idle_timeout: Duration,
  ) -> Self {
    let metrics = ConnectionMetrics::new(protocol.to_string(), client_addr, server_addr);
    let context = ConnectionContext::new(client_addr, server_addr, protocol.to_string());

    Self {
      client_socket,
      server_socket,
      client_addr,
      server_addr,
      metrics,
      protocol,
      context,
      idle_timeout,
    }
  }

  /// Get the protocol for this connection
  pub fn protocol(&self) -> &UdpProtocol {
    &self.protocol
  }

  /// Get the connection context
  pub fn context(&self) -> &ConnectionContext {
    &self.context
  }

  /// Get the connection metrics
  pub fn metrics(&self) -> &ConnectionMetrics {
    &self.metrics
  }

  /// Get mutable reference to connection metrics
  pub fn metrics_mut(&mut self) -> &mut ConnectionMetrics {
    &mut self.metrics
  }

  /// Check if the connection has been idle for longer than the timeout
  pub fn is_idle(&self) -> bool {
    self.metrics.created_at.elapsed() >= self.idle_timeout
  }
}

impl UdpConnectionInfo {
  /// Create new UDP connection info
  pub fn new(protocol: UdpProtocol, idle_timeout: Duration, client_socket: Arc<UdpSocket>) -> Self {
    Self {
      protocol,
      idle_timeout,
      client_socket,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  #[tokio::test]
  async fn test_udp_connection_manager_creation() {
    let runtime_handle = tokio::runtime::Handle::current();
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let pool = Arc::new(UdpConnectionPool::new(runtime_handle, cancel_token));
    let manager = UdpConnectionManager::new(pool, 100);

    assert_eq!(manager.connection_count(), 0);
    assert_eq!(manager.max_connections(), 100);
    assert!(manager.can_accept_connection());
  }

  #[tokio::test]
  async fn test_udp_connection_info_creation() {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let info = UdpConnectionInfo::new(UdpProtocol::Any, Duration::from_secs(30), socket.clone());

    assert_eq!(info.idle_timeout, Duration::from_secs(30));
    assert!(matches!(info.protocol, UdpProtocol::Any));
  }

  #[tokio::test]
  async fn test_udp_connection_creation() {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let client_addr = "127.0.0.1:8080".parse().unwrap();
    let server_addr = "127.0.0.1:8081".parse().unwrap();

    let conn = UdpConnection::new(
      client_socket,
      server_socket,
      client_addr,
      server_addr,
      UdpProtocol::Any,
      Duration::from_secs(30),
    );

    assert_eq!(conn.client_addr, client_addr);
    assert_eq!(conn.server_addr, server_addr);
    assert_eq!(conn.idle_timeout, Duration::from_secs(30));
    assert!(!conn.is_idle()); // Should not be idle immediately
  }
}
