/// Example demonstrating the new Phase 3 error handling improvements
///
/// This example shows how the enhanced error types provide better context
/// and categorization for debugging and error handling.
use rpxy_l4_lib::{ConfigurationError, ConnectionError, ErrorContext, NetworkError, ProtocolError, ProxyError};
use std::net::SocketAddr;
use std::time::Duration;

fn main() {
  println!("=== Phase 3 Error Handling Demonstration ===\n");

  // 1. Network Error Examples
  println!("1. Network Error Examples:");

  let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
  let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Connection refused");

  let network_err = NetworkError::connection_failed(addr, io_err);
  println!("   Connection Failed: {}", network_err);

  let dns_err = NetworkError::dns_error("example.com", "Name resolution failed");
  println!("   DNS Error: {}", dns_err);

  // 2. Protocol Error Examples
  println!("\n2. Protocol Error Examples:");

  let protocol_err = ProtocolError::detection_failed("Insufficient data for detection");
  println!("   Detection Failed: {}", protocol_err);

  let parse_err = ProtocolError::parse_error("TLS", "Invalid client hello format");
  println!("   Parse Error: {}", parse_err);

  let timeout_err = ProtocolError::tcp_read_timeout(addr, Duration::from_secs(5));
  println!("   Timeout Error: {}", timeout_err);

  // 3. Connection Error Examples
  println!("\n3. Connection Error Examples:");

  let limit_err = ConnectionError::limit_exceeded(150, 100);
  println!("   Limit Exceeded: {}", limit_err);

  let broken_err = ConnectionError::broken(
    "127.0.0.1:8080".parse().unwrap(),
    "192.168.1.1:80".parse().unwrap(),
    "Connection reset by peer",
  );
  println!("   Connection Broken: {}", broken_err);

  // 4. Error Context Examples
  println!("\n4. Error Context Examples:");

  // Simulate adding context to IO errors
  let io_result: Result<(), std::io::Error> = Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied"));

  let with_context = io_result.with_connection_context("127.0.0.1:8080".parse().unwrap(), "192.168.1.1:80".parse().unwrap());

  match with_context {
    Err(ProxyError::Connection(ConnectionError::Broken {
      source_addr,
      dest_addr,
      reason,
    })) => {
      println!(
        "   Context Added - Source: {}, Dest: {}, Reason: {}",
        source_addr, dest_addr, reason
      );
    }
    _ => println!("   Unexpected error type"),
  }

  // 5. Error Chain Examples
  println!("\n5. Error Chain Examples:");

  // Show how errors convert through the hierarchy
  let config_err = rpxy_l4_lib::config::validation::ConfigValidationError::InvalidFieldValue {
    field: "listen_port".to_string(),
    value: "0".to_string(),
    reason: "Port cannot be 0".to_string(),
  };

  let config_err: ConfigurationError = config_err.into();
  let proxy_err: ProxyError = config_err.into();
  println!("   Config validation converted to: {}", proxy_err);

  // 6. Legacy Compatibility
  println!("\n6. Legacy Compatibility:");

  let legacy_err = ProxyError::no_destination_address();
  println!("   Legacy Method: {}", legacy_err);

  let legacy_dns = ProxyError::dns_resolution_error("Custom DNS error message");
  println!("   Legacy DNS: {}", legacy_dns);

  println!("\n=== Demonstration Complete ===");
  println!("\nKey improvements in Phase 3:");
  println!("• Categorized error types with detailed context");
  println!("• Helper methods for creating specific errors");
  println!("• Error context trait for adding connection/network context");
  println!("• Backward compatibility with legacy error patterns");
  println!("• Structured error information for better debugging");
}
