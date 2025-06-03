//! Phase 4: Connection Management Demo
//!
//! This example demonstrates the new connection management abstractions and
//! capabilities introduced in Phase 4, including:
//! - Unified connection management across TCP and UDP
//! - Connection metrics and monitoring
//! - Connection pooling for UDP
//! - Improved error handling and logging

use rpxy_l4_lib::{
  ConnectionContext, ConnectionError, ConnectionManager, ConnectionMetrics, ConnectionPool, DashMapConnectionPool,
  TcpConnectionCount, TcpConnectionManager, TcpProtocol, UdpConnectionInfo, UdpConnectionManager, UdpConnectionPool, UdpProtocol,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("🚀 Phase 4: Connection Management Demo");
  println!("=======================================\n");

  // Initialize logging
  tracing_subscriber::fmt::init();

  demo_tcp_connection_management().await?;
  demo_udp_connection_management().await?;
  demo_connection_pooling().await?;
  demo_connection_metrics().await?;

  println!("\n✅ All Phase 4 demonstrations completed successfully!");
  Ok(())
}

/// Demonstrate TCP connection management capabilities
async fn demo_tcp_connection_management() -> Result<(), Box<dyn std::error::Error>> {
  println!("📡 TCP Connection Management Demo");
  println!("---------------------------------");

  // Create a TCP connection manager
  let connection_count = TcpConnectionCount::default();
  let max_connections = 5;
  let tcp_manager = TcpConnectionManager::new(connection_count.clone(), max_connections);

  println!("✓ Created TCP connection manager");
  println!("  - Max connections: {}", tcp_manager.max_connections());
  println!("  - Current connections: {}", tcp_manager.connection_count());
  println!("  - Can accept connections: {}", tcp_manager.can_accept_connection());

  // Simulate connection limit behavior
  println!("\n🔄 Testing connection limit behavior:");

  // Test connection limit handling
  let src = "127.0.0.1:8080".parse::<SocketAddr>()?;
  let dst = "127.0.0.1:8081".parse::<SocketAddr>()?;
  let protocol = TcpProtocol::Any;
  let buffer = bytes::Bytes::new();

  println!("  - Testing connection creation (may fail due to no actual server):");
  match tcp_manager.create_connection(src, dst, (protocol, buffer)).await {
    Ok(_conn) => {
      println!("  ✓ Connection created successfully");
    }
    Err(e) => {
      println!("  ⚠️  Connection creation failed (expected for demo): {}", e);
    }
  }
  println!("");

  Ok(())
}

/// Demonstrate UDP connection management capabilities
async fn demo_udp_connection_management() -> Result<(), Box<dyn std::error::Error>> {
  println!("📊 UDP Connection Management Demo");
  println!("---------------------------------");

  // Create UDP connection pool and manager
  let runtime_handle = tokio::runtime::Handle::current();
  let cancel_token = CancellationToken::new();
  let udp_pool = Arc::new(UdpConnectionPool::new(runtime_handle, cancel_token));
  let max_connections = 10;
  let udp_manager = UdpConnectionManager::new(udp_pool.clone(), max_connections);

  println!("✓ Created UDP connection manager");
  println!("  - Max connections: {}", udp_manager.max_connections());
  println!("  - Current connections: {}", udp_manager.connection_count());
  println!("  - Can accept connections: {}", udp_manager.can_accept_connection());

  // Create UDP connection info
  let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
  let protocol = UdpProtocol::Any;
  let idle_timeout = Duration::from_secs(30);
  let conn_info = UdpConnectionInfo::new(protocol, idle_timeout, client_socket);

  println!("\n✓ Created UDP connection info");
  println!("  - Protocol: {:?}", conn_info.protocol);
  println!("  - Idle timeout: {:?}", conn_info.idle_timeout);

  // Demonstrate connection creation
  let src = "127.0.0.1:9000".parse::<SocketAddr>()?;
  let dst = "127.0.0.1:9001".parse::<SocketAddr>()?;

  match udp_manager.create_connection(src, dst, conn_info).await {
    Ok(connection) => {
      println!("  ✓ Successfully created UDP connection");
      println!("    - Client addr: {}", connection.client_addr);
      println!("    - Server addr: {}", connection.server_addr);
      println!("    - Idle timeout: {:?}", connection.idle_timeout);
      println!("    - Is idle: {}", connection.is_idle());
    }
    Err(e) => {
      println!("  ⚠️  Connection creation failed (expected for demo): {}", e);
    }
  }

  println!("");
  Ok(())
}

/// Demonstrate connection pooling capabilities
async fn demo_connection_pooling() -> Result<(), Box<dyn std::error::Error>> {
  println!("🏊 Connection Pooling Demo");
  println!("--------------------------");

  // Create a connection pool
  let pool: DashMapConnectionPool<String, i32> = DashMapConnectionPool::new(5, Duration::from_secs(60));

  println!("✓ Created connection pool");
  println!("  - Max size: {}", pool.max_size());
  println!("  - Current size: {}", pool.size());
  println!("  - Is empty: {}", pool.is_empty());

  // Insert some connections
  pool.insert("conn1".to_string(), 100);
  pool.insert("conn2".to_string(), 200);
  pool.insert("conn3".to_string(), 300);

  println!("\n✓ Inserted 3 connections");
  println!("  - Current size: {}", pool.size());
  println!("  - Is at capacity: {}", pool.is_at_capacity());

  // Retrieve connections
  if let Some(value) = pool.get(&"conn1".to_string()) {
    println!("  ✓ Retrieved conn1: {}", value);
  }

  if let Some(value) = pool.get(&"conn2".to_string()) {
    println!("  ✓ Retrieved conn2: {}", value);
  }

  // Test get_or_create functionality
  let factory = |key: String| async move { Ok::<i32, ConnectionError>(key.len() as i32 * 10) };

  let value = pool.get_or_create("conn4".to_string(), factory).await?;
  println!("  ✓ Created new connection conn4: {}", value);
  println!("    - New pool size: {}", pool.size());

  // Get pool statistics
  let stats = pool.stats();
  println!("\n📈 Pool Statistics:");
  println!("  - Size: {}/{}", stats.size, stats.max_size);
  println!("  - Utilization: {:.1}%", stats.utilization() * 100.0);
  println!("  - Expired entries: {}", stats.expired_count);
  println!("  - Average age: {:?}", stats.average_age);

  // Clean up
  pool.clear();
  println!("  ✓ Cleaned up pool: Size = {}", pool.size());
  println!("");

  Ok(())
}

/// Demonstrate connection metrics and monitoring
async fn demo_connection_metrics() -> Result<(), Box<dyn std::error::Error>> {
  println!("📊 Connection Metrics Demo");
  println!("--------------------------");

  let src = "127.0.0.1:8080".parse::<SocketAddr>()?;
  let dst = "192.168.1.1:80".parse::<SocketAddr>()?;
  let protocol = "HTTP".to_string();

  // Create connection metrics
  let mut metrics = ConnectionMetrics::new(protocol.clone(), src, dst);
  println!("✓ Created connection metrics");
  println!("  - Source: {}", metrics.src_addr);
  println!("  - Destination: {}", metrics.dst_addr);
  println!("  - Protocol: {}", metrics.protocol);
  println!("  - Created at: {:?}", metrics.created_at);

  // Simulate some data transfer
  tokio::time::sleep(Duration::from_millis(10)).await;
  metrics.record_bytes_sent(1024);
  metrics.record_bytes_received(2048);

  println!("\n📈 After data transfer:");
  println!("  - Bytes sent: {}", metrics.bytes_sent);
  println!("  - Bytes received: {}", metrics.bytes_received);
  println!("  - Total bytes: {}", metrics.total_bytes());
  println!("  - Duration: {:?}", metrics.duration());

  // Create connection context
  let context = ConnectionContext::new(src, dst, protocol);
  println!("\n🏷️  Connection Context:");
  println!("  - Connection ID: {}", context.connection_id);
  println!("  - Source: {}", context.src_addr);
  println!("  - Destination: {}", context.dst_addr);
  println!("  - Protocol: {}", context.protocol);

  println!("");
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_connection_management_demo() {
    // This test ensures the demo code works correctly
    assert!(demo_tcp_connection_management().await.is_ok());
    assert!(demo_udp_connection_management().await.is_ok());
    assert!(demo_connection_pooling().await.is_ok());
    assert!(demo_connection_metrics().await.is_ok());
  }

  #[test]
  fn test_connection_metrics() {
    let src = "127.0.0.1:8080".parse().unwrap();
    let dst = "192.168.1.1:80".parse().unwrap();
    let mut metrics = ConnectionMetrics::new("HTTP".to_string(), src, dst);

    assert_eq!(metrics.bytes_sent, 0);
    assert_eq!(metrics.bytes_received, 0);
    assert_eq!(metrics.total_bytes(), 0);

    metrics.record_bytes_sent(100);
    metrics.record_bytes_received(200);

    assert_eq!(metrics.bytes_sent, 100);
    assert_eq!(metrics.bytes_received, 200);
    assert_eq!(metrics.total_bytes(), 300);
  }

  #[test]
  fn test_connection_context() {
    let src = "127.0.0.1:8080".parse().unwrap();
    let dst = "192.168.1.1:80".parse().unwrap();
    let context = ConnectionContext::new(src, dst, "HTTP".to_string());

    assert_eq!(context.src_addr, src);
    assert_eq!(context.dst_addr, dst);
    assert_eq!(context.protocol, "HTTP");
    // UUID should be valid
    assert_ne!(context.connection_id.to_string(), "");
  }

  #[tokio::test]
  async fn test_connection_pool() {
    let pool: DashMapConnectionPool<String, i32> = DashMapConnectionPool::new(3, Duration::from_secs(60));

    assert_eq!(pool.size(), 0);
    assert!(pool.is_empty());
    assert!(!pool.is_at_capacity());

    pool.insert("test1".to_string(), 42);
    assert_eq!(pool.size(), 1);
    assert!(!pool.is_empty());

    let value = pool.get(&"test1".to_string());
    assert_eq!(value, Some(42));

    let removed = pool.remove(&"test1".to_string());
    assert_eq!(removed, Some(42));
    assert_eq!(pool.size(), 0);
  }
}
