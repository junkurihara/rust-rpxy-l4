//! Connection management abstractions and implementations
//!
//! This module provides unified abstractions for managing connection lifecycles
//! across different protocols (TCP, UDP) and enables better testing, monitoring,
//! and resource management.

use crate::error::ConnectionError;
use std::net::SocketAddr;

/// Unified trait for managing connection lifecycles
#[async_trait::async_trait]
pub trait ConnectionManager {
  /// The type representing a connection
  type Connection;
  /// Additional information needed to create a connection
  type ConnectionInfo;

  /// Create a new connection
  async fn create_connection(
    &self,
    src: SocketAddr,
    dst: SocketAddr,
    info: Self::ConnectionInfo,
  ) -> Result<Self::Connection, ConnectionError>;

  /// Handle an established connection
  async fn handle_connection(&self, conn: Self::Connection) -> Result<(), ConnectionError>;

  /// Get current number of active connections
  fn connection_count(&self) -> usize;

  /// Get maximum allowed connections
  fn max_connections(&self) -> usize;

  /// Check if connection limit has been reached
  fn is_connection_limit_reached(&self) -> bool {
    self.connection_count() >= self.max_connections()
  }
}

/// Metrics and metadata for a connection
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
  /// When the connection was created
  pub created_at: std::time::Instant,
  /// Total bytes sent to the destination
  pub bytes_sent: u64,
  /// Total bytes received from the destination
  pub bytes_received: u64,
  /// Protocol that was detected for this connection
  pub protocol: String,
  /// Source address of the connection
  pub src_addr: SocketAddr,
  /// Destination address of the connection
  pub dst_addr: SocketAddr,
}

impl ConnectionMetrics {
  /// Create new connection metrics
  pub fn new(protocol: String, src_addr: SocketAddr, dst_addr: SocketAddr) -> Self {
    Self {
      created_at: std::time::Instant::now(),
      bytes_sent: 0,
      bytes_received: 0,
      protocol,
      src_addr,
      dst_addr,
    }
  }

  /// Get the duration since connection was created
  pub fn duration(&self) -> std::time::Duration {
    self.created_at.elapsed()
  }

  /// Record bytes sent
  pub fn record_bytes_sent(&mut self, bytes: u64) {
    self.bytes_sent = self.bytes_sent.saturating_add(bytes);
  }

  /// Record bytes received
  pub fn record_bytes_received(&mut self, bytes: u64) {
    self.bytes_received = self.bytes_received.saturating_add(bytes);
  }

  /// Get total bytes transferred (sent + received)
  pub fn total_bytes(&self) -> u64 {
    self.bytes_sent.saturating_add(self.bytes_received)
  }
}

/// Connection context for error reporting and logging
#[derive(Debug, Clone)]
pub struct ConnectionContext {
  /// Source address
  pub src_addr: SocketAddr,
  /// Destination address
  pub dst_addr: SocketAddr,
  /// Protocol used
  pub protocol: String,
  /// Unique connection identifier
  pub connection_id: uuid::Uuid,
}

impl ConnectionContext {
  /// Create new connection context
  pub fn new(src_addr: SocketAddr, dst_addr: SocketAddr, protocol: String) -> Self {
    Self {
      src_addr,
      dst_addr,
      protocol,
      connection_id: uuid::Uuid::new_v4(),
    }
  }
}

// Re-export connection type implementations
pub mod pool;
pub mod tcp;
pub mod udp;
