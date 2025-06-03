//! TCP connection management implementation
//!
//! This module provides concrete implementations for managing TCP connections,
//! including connection lifecycle, metrics tracking, and protocol handling.

use super::{ConnectionContext, ConnectionManager, ConnectionMetrics};
use crate::{count::ConnectionCount, error::ConnectionError, protocol::tcp::TcpProtocol, trace::*};
use std::net::SocketAddr;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

/// TCP connection manager responsible for creating and handling TCP connections
#[derive(Debug, Clone)]
pub struct TcpConnectionManager {
  /// Connection counter for tracking active connections
  connection_count: ConnectionCount,
  /// Maximum number of concurrent connections allowed
  max_connections: usize,
}

/// Represents an established TCP connection with its associated metadata
#[derive(Debug)]
pub struct TcpConnection {
  /// Incoming TCP stream from the client
  pub incoming: TcpStream,
  /// Outgoing TCP stream to the destination
  pub outgoing: TcpStream,
  /// Connection metrics and metadata
  pub metrics: ConnectionMetrics,
  /// The protocol that was detected for this connection
  pub protocol: TcpProtocol,
  /// Connection context for logging and error reporting
  pub context: ConnectionContext,
  /// Initial buffer that was read during protocol detection
  pub initial_buffer: bytes::Bytes,
}

impl TcpConnectionManager {
  /// Create a new TCP connection manager
  pub fn new(connection_count: ConnectionCount, max_connections: usize) -> Self {
    Self {
      connection_count,
      max_connections,
    }
  }

  /// Check if we can accept a new connection (not at limit)
  pub fn can_accept_connection(&self) -> bool {
    !self.is_connection_limit_reached()
  }

  /// Increment the connection count
  pub fn increment_connections(&self) {
    self.connection_count.increment();
  }

  /// Decrement the connection count
  pub fn decrement_connections(&self) {
    self.connection_count.decrement();
  }
}

#[async_trait::async_trait]
impl ConnectionManager for TcpConnectionManager {
  type Connection = TcpConnection;
  type ConnectionInfo = (TcpProtocol, bytes::Bytes);

  async fn create_connection(
    &self,
    src: SocketAddr,
    dst: SocketAddr,
    (protocol, initial_buffer): Self::ConnectionInfo,
  ) -> Result<Self::Connection, ConnectionError> {
    // Check connection limit
    if self.is_connection_limit_reached() {
      return Err(ConnectionError::LimitExceeded {
        current: self.connection_count(),
        max: self.max_connections(),
      });
    }

    // Connect to destination
    let outgoing = TcpStream::connect(dst)
      .await
      .map_err(|e| ConnectionError::ConnectionFailed { address: dst, source: e })?;

    // Create metrics and context
    let metrics = ConnectionMetrics::new(protocol.to_string(), src, dst);
    let context = ConnectionContext::new(src, dst, protocol.to_string());

    debug!(
        connection_id = %context.connection_id,
        src_addr = %src,
        dst_addr = %dst,
        protocol = %protocol,
        "TCP connection created"
    );

    // Note: The incoming stream will be provided when handle_connection is called
    // For now, we'll create a placeholder that will be replaced
    let incoming = TcpStream::connect("127.0.0.1:1")
      .await
      .map_err(|e| ConnectionError::ConnectionFailed {
        address: "127.0.0.1:1".parse().unwrap(),
        source: e,
      })?;

    Ok(TcpConnection {
      incoming,
      outgoing,
      metrics,
      protocol,
      context,
      initial_buffer,
    })
  }

  async fn handle_connection(&self, mut conn: TcpConnection) -> Result<(), ConnectionError> {
    // Write initial buffer to outgoing stream
    use tokio::io::AsyncWriteExt;
    conn
      .outgoing
      .write_all(&conn.initial_buffer)
      .await
      .map_err(|e| ConnectionError::Broken {
        source_addr: conn.context.src_addr,
        dest_addr: conn.context.dst_addr,
        reason: format!("Failed to write initial buffer: {}", e),
      })?;

    // Log connection start
    info!(
        connection_id = %conn.context.connection_id,
        src_addr = %conn.context.src_addr,
        dst_addr = %conn.context.dst_addr,
        protocol = %conn.context.protocol,
        "TCP connection started"
    );

    // Perform bidirectional copy
    let copy_result = copy_bidirectional(&mut conn.incoming, &mut conn.outgoing).await;

    // Handle the result
    let (bytes_to_dst, bytes_from_dst) = match copy_result {
      Ok((to_dst, from_dst)) => (to_dst, from_dst),
      Err(e) => {
        warn!(
            connection_id = %conn.context.connection_id,
            error = %e,
            "TCP connection copy failed"
        );
        (0, 0)
      }
    };

    // Update metrics
    conn.metrics.record_bytes_sent(bytes_to_dst);
    conn.metrics.record_bytes_received(bytes_from_dst);

    // Log connection end
    info!(
        connection_id = %conn.context.connection_id,
        src_addr = %conn.context.src_addr,
        dst_addr = %conn.context.dst_addr,
        protocol = %conn.context.protocol,
        duration_ms = conn.metrics.duration().as_millis(),
        bytes_sent = bytes_to_dst,
        bytes_received = bytes_from_dst,
        "TCP connection ended"
    );

    Ok(())
  }

  fn connection_count(&self) -> usize {
    self.connection_count.current()
  }

  fn max_connections(&self) -> usize {
    self.max_connections
  }
}

impl TcpConnection {
  /// Create a new TCP connection with provided streams
  pub fn new(
    incoming: TcpStream,
    outgoing: TcpStream,
    protocol: TcpProtocol,
    initial_buffer: bytes::Bytes,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
  ) -> Self {
    let metrics = ConnectionMetrics::new(protocol.to_string(), src_addr, dst_addr);
    let context = ConnectionContext::new(src_addr, dst_addr, protocol.to_string());

    Self {
      incoming,
      outgoing,
      metrics,
      protocol,
      context,
      initial_buffer,
    }
  }

  /// Get the protocol for this connection
  pub fn protocol(&self) -> &TcpProtocol {
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
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::protocol::tcp::TcpProtocol;

  #[test]
  fn test_tcp_connection_manager_creation() {
    let connection_count = ConnectionCount::default();
    let manager = TcpConnectionManager::new(connection_count, 100);

    assert_eq!(manager.connection_count(), 0);
    assert_eq!(manager.max_connections(), 100);
    assert!(manager.can_accept_connection());
  }

  #[test]
  fn test_connection_limit_logic() {
    let connection_count = ConnectionCount::default();
    let manager = TcpConnectionManager::new(connection_count.clone(), 2);

    // Should be able to accept initially
    assert!(manager.can_accept_connection());

    // Increment to limit
    connection_count.increment();
    connection_count.increment();

    // Should not be able to accept at limit
    assert!(!manager.can_accept_connection());
    assert!(manager.is_connection_limit_reached());
  }

  #[tokio::test]
  async fn test_connection_creation_at_limit() {
    let connection_count = ConnectionCount::default();
    let manager = TcpConnectionManager::new(connection_count.clone(), 1);

    // Fill up to limit
    connection_count.increment();

    let src = "127.0.0.1:8080".parse().unwrap();
    let dst = "127.0.0.1:8081".parse().unwrap();
    let protocol = TcpProtocol::Any;
    let buffer = bytes::Bytes::new();

    let result = manager.create_connection(src, dst, (protocol, buffer)).await;

    assert!(matches!(result, Err(ConnectionError::LimitExceeded { .. })));
  }
}
