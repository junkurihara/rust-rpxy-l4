/// Comprehensive error handling system for rust-rpxy-l4
///
/// This module provides categorized error types with detailed context information
/// to improve debugging and error handling throughout the application.
use std::net::SocketAddr;
use std::time::Duration;

/// Top-level error type that encompasses all proxy operation errors
#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
  #[error(transparent)]
  Configuration(#[from] ConfigurationError),

  #[error(transparent)]
  Network(#[from] NetworkError),

  #[error(transparent)]
  Protocol(#[from] ProtocolError),

  #[error(transparent)]
  Connection(#[from] ConnectionError),

  #[error(transparent)]
  Build(#[from] ProxyBuildError),
}

/// Configuration-related errors
#[derive(thiserror::Error, Debug)]
pub enum ConfigurationError {
  #[error("Invalid port: {port}")]
  InvalidPort { port: u16 },

  #[error("Invalid target address: {target}")]
  InvalidTarget { target: String },

  #[error("Missing required configuration: {field}")]
  MissingRequired { field: String },

  #[error("Invalid load balance configuration: {config}")]
  InvalidLoadBalance { config: String },

  #[error("ECH configuration error: {reason}")]
  EchConfiguration { reason: String },

  #[error("Protocol configuration error for '{protocol}': {reason}")]
  ProtocolConfiguration { protocol: String, reason: String },

  #[error("Invalid ECH private key: {reason}")]
  InvalidEchPrivateKey { reason: String },

  #[error("Invalid ECH private server name: {server_name}")]
  InvalidEchPrivateServerName { server_name: String },

  #[error("Unsupported protocol: {protocol}")]
  UnsupportedProtocol { protocol: String },
}

/// Network-related errors with context
#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
  #[error("DNS resolution failed for {host}: {source}")]
  DnsResolution {
    host: String,
    #[source]
    source: std::io::Error,
  },

  #[error("Connection failed to {address}: {source}")]
  ConnectionFailed {
    address: SocketAddr,
    #[source]
    source: std::io::Error,
  },

  #[error("Socket bind failed for {address}: {source}")]
  BindFailed {
    address: SocketAddr,
    #[source]
    source: std::io::Error,
  },

  #[error("Connection timeout to {address} after {timeout:?}")]
  ConnectionTimeout { address: SocketAddr, timeout: Duration },

  #[error("DNS resolution error for {hostname}: {reason}")]
  DnsError { hostname: String, reason: String },

  #[error("Invalid address format: {address}")]
  InvalidAddress { address: String },

  #[error("IO error: {source}")]
  IoError {
    #[source]
    source: std::io::Error,
  },
}

/// Protocol detection and parsing errors
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
  #[error("Protocol detection failed: {reason}")]
  DetectionFailed { reason: String },

  #[error("Unsupported protocol: {protocol}")]
  UnsupportedProtocol { protocol: String },

  #[error("Protocol parsing error for {protocol}: {reason}")]
  ParseError { protocol: String, reason: String },

  #[error("TLS parsing error: {source}")]
  TlsError {
    #[source]
    source: quic_tls::TlsClientHelloError,
  },

  #[error("TLS alert write error for connection from {source_addr}")]
  TlsAlertWriteError { source_addr: SocketAddr },

  #[error("Failed to read protocol data from TCP stream from {source_addr}: timeout after {timeout:?}")]
  TcpStreamReadTimeout { source_addr: SocketAddr, timeout: Duration },

  #[error("No data received from TCP stream from {source_addr}")]
  NoDataReceived { source_addr: SocketAddr },

  #[error("Insufficient buffer data for protocol detection: expected at least {expected} bytes, got {actual}")]
  InsufficientData { expected: usize, actual: usize },
}

/// Connection management errors
#[derive(thiserror::Error, Debug)]
pub enum ConnectionError {
  #[error("Connection limit exceeded: {current}/{max} connections")]
  LimitExceeded { current: usize, max: usize },

  #[error("Connection timeout for {address} after {timeout:?}")]
  Timeout { address: SocketAddr, timeout: Duration },

  #[error("Connection broken between {source_addr} and {dest_addr}: {reason}")]
  Broken {
    source_addr: SocketAddr,
    dest_addr: SocketAddr,
    reason: String,
  },

  #[error("UDP connection pool full: {current} connections (max: {max})")]
  UdpPoolFull { current: usize, max: usize },

  #[error("UDP connection broken from {client_addr}: {reason}")]
  UdpConnectionBroken { client_addr: SocketAddr, reason: String },

  #[error("No destination address available for protocol {protocol}")]
  NoDestinationForProtocol { protocol: String },

  #[error("No destination address available")]
  NoDestinationAddress,

  #[error("No ECH private destination server name found")]
  EchNoMatchingPrivateServerName,

  #[error("Connection failed to {address}: {source}")]
  ConnectionFailed {
    address: SocketAddr,
    #[source]
    source: std::io::Error,
  },

  #[error("Socket bind failed for {address}: {source}")]
  BindFailed {
    address: SocketAddr,
    #[source]
    source: std::io::Error,
  },
}

/// Errors that occur during proxy or component building/initialization
#[derive(thiserror::Error, Debug)]
pub enum ProxyBuildError {
  #[error(transparent)]
  Configuration(#[from] ConfigurationError),

  #[error("ECH config list error: {source}")]
  EchConfigError {
    #[source]
    source: quic_tls::EchConfigError,
  },

  #[error("Target destination builder error: {message}")]
  TargetDestinationBuilderError { message: String },

  #[error("UDP destination mux error: {source}")]
  UdpDestinationMuxError {
    #[source]
    source: crate::udp_proxy::UdpDestinationMuxBuilderError,
  },

  #[error("TCP destination mux error: {source}")]
  TcpDestinationMuxError {
    #[source]
    source: crate::tcp_proxy::TcpDestinationMuxBuilderError,
  },

  #[error("Build error for multiplexers: {reason}")]
  BuildMultiplexersError { reason: String },
}

// Legacy compatibility layer
impl ProxyError {
  // Legacy error constructors for backward compatibility
  pub fn no_destination_address() -> Self {
    Self::Connection(ConnectionError::NoDestinationAddress)
  }

  pub fn ech_no_matching_private_server_name() -> Self {
    Self::Connection(ConnectionError::EchNoMatchingPrivateServerName)
  }

  pub fn no_destination_address_for_protocol() -> Self {
    Self::Connection(ConnectionError::NoDestinationForProtocol {
      protocol: "unknown".to_string(),
    })
  }

  pub fn time_out_to_read_tcp_stream() -> Self {
    Self::Protocol(ProtocolError::TcpStreamReadTimeout {
      source_addr: "0.0.0.0:0".parse().unwrap(),
      timeout: Duration::from_secs(5),
    })
  }

  pub fn no_data_received_tcp_stream() -> Self {
    Self::Protocol(ProtocolError::NoDataReceived {
      source_addr: "0.0.0.0:0".parse().unwrap(),
    })
  }

  pub fn too_many_udp_connections() -> Self {
    Self::Connection(ConnectionError::UdpPoolFull { current: 0, max: 0 })
  }

  pub fn broken_udp_connection() -> Self {
    Self::Connection(ConnectionError::UdpConnectionBroken {
      client_addr: "0.0.0.0:0".parse().unwrap(),
      reason: "broken".to_string(),
    })
  }

  pub fn tls_alert_write_error() -> Self {
    Self::Protocol(ProtocolError::TlsAlertWriteError {
      source_addr: "0.0.0.0:0".parse().unwrap(),
    })
  }

  pub fn dns_resolution_error(msg: impl Into<String>) -> Self {
    Self::Network(NetworkError::DnsError {
      hostname: "unknown".to_string(),
      reason: msg.into(),
    })
  }

  pub fn invalid_address(msg: impl Into<String>) -> Self {
    Self::Network(NetworkError::InvalidAddress { address: msg.into() })
  }
}

// Conversion implementations for backward compatibility
impl From<std::io::Error> for ProxyError {
  fn from(err: std::io::Error) -> Self {
    ProxyError::Network(NetworkError::IoError { source: err })
  }
}

impl From<quic_tls::TlsClientHelloError> for ProxyError {
  fn from(err: quic_tls::TlsClientHelloError) -> Self {
    ProxyError::Protocol(ProtocolError::TlsError { source: err })
  }
}

// Configuration validation error integration
impl From<crate::config::validation::ConfigValidationError> for ConfigurationError {
  fn from(err: crate::config::validation::ConfigValidationError) -> Self {
    use crate::config::validation::ConfigValidationError;
    match err {
      ConfigValidationError::MissingRequiredField { field } => ConfigurationError::MissingRequired { field },
      ConfigValidationError::InvalidFieldValue { field, value, reason } => {
        if field == "listen_port" || field.contains("port") {
          if let Ok(port) = value.parse::<u16>() {
            ConfigurationError::InvalidPort { port }
          } else {
            ConfigurationError::MissingRequired { field }
          }
        } else {
          ConfigurationError::MissingRequired {
            field: format!("{}: {}", field, reason),
          }
        }
      }
      ConfigValidationError::ProtocolValidationError { protocol_name, reason } => ConfigurationError::ProtocolConfiguration {
        protocol: protocol_name,
        reason,
      },
      ConfigValidationError::EchConfigurationError { reason } => ConfigurationError::EchConfiguration { reason },
      ConfigValidationError::TargetAddressError { reason } => ConfigurationError::InvalidTarget { target: reason },
      ConfigValidationError::ConflictingConfiguration { reason } => ConfigurationError::MissingRequired {
        field: format!("Conflicting configuration: {}", reason),
      },
    }
  }
}

impl From<quic_tls::EchConfigError> for ProxyBuildError {
  fn from(err: quic_tls::EchConfigError) -> Self {
    ProxyBuildError::EchConfigError { source: err }
  }
}

impl From<String> for ProxyBuildError {
  fn from(err: String) -> Self {
    ProxyBuildError::TargetDestinationBuilderError { message: err }
  }
}

impl From<crate::tcp_proxy::TcpDestinationMuxBuilderError> for ProxyBuildError {
  fn from(err: crate::tcp_proxy::TcpDestinationMuxBuilderError) -> Self {
    ProxyBuildError::TcpDestinationMuxError { source: err }
  }
}

impl From<crate::udp_proxy::UdpDestinationMuxBuilderError> for ProxyBuildError {
  fn from(err: crate::udp_proxy::UdpDestinationMuxBuilderError) -> Self {
    ProxyBuildError::UdpDestinationMuxError { source: err }
  }
}

impl From<crate::config::validation::ConfigValidationError> for ProxyBuildError {
  fn from(err: crate::config::validation::ConfigValidationError) -> Self {
    ProxyBuildError::Configuration(ConfigurationError::from(err))
  }
}

// Legacy compatibility methods for ProxyBuildError
impl ProxyBuildError {
  pub fn invalid_ech_private_key(msg: impl Into<String>) -> Self {
    Self::Configuration(ConfigurationError::InvalidEchPrivateKey { reason: msg.into() })
  }

  pub fn invalid_ech_private_server_name(server_name: impl Into<String>) -> Self {
    Self::Configuration(ConfigurationError::InvalidEchPrivateServerName {
      server_name: server_name.into(),
    })
  }

  pub fn unsupported_protocol(protocol: impl Into<String>) -> Self {
    Self::Configuration(ConfigurationError::UnsupportedProtocol {
      protocol: protocol.into(),
    })
  }

  pub fn invalid_load_balance(config: impl Into<String>) -> Self {
    Self::Configuration(ConfigurationError::InvalidLoadBalance { config: config.into() })
  }

  pub fn build_multiplexers_error(reason: impl Into<String>) -> Self {
    Self::BuildMultiplexersError { reason: reason.into() }
  }
}

// Helper trait for adding context to errors
pub trait ErrorContext<T> {
  /// Add context to a result
  fn with_context<F>(self, f: F) -> Result<T, ProxyError>
  where
    F: FnOnce() -> String;

  /// Add context about a connection
  fn with_connection_context(self, source: SocketAddr, dest: SocketAddr) -> Result<T, ProxyError>;

  /// Add context about a network operation
  fn with_network_context(self, operation: &str, address: SocketAddr) -> Result<T, ProxyError>;
}

impl<T, E> ErrorContext<T> for Result<T, E>
where
  E: Into<ProxyError>,
{
  fn with_context<F>(self, _f: F) -> Result<T, ProxyError>
  where
    F: FnOnce() -> String,
  {
    self.map_err(|e| e.into())
  }

  fn with_connection_context(self, source: SocketAddr, dest: SocketAddr) -> Result<T, ProxyError> {
    self.map_err(|e| {
      let base_error = e.into();
      match &base_error {
        ProxyError::Network(NetworkError::IoError { source: io_err }) => ProxyError::Connection(ConnectionError::Broken {
          source_addr: source,
          dest_addr: dest,
          reason: io_err.to_string(),
        }),
        _ => base_error,
      }
    })
  }

  fn with_network_context(self, operation: &str, address: SocketAddr) -> Result<T, ProxyError> {
    self.map_err(|e| {
      let base_error = e.into();
      match &base_error {
        ProxyError::Network(NetworkError::IoError { source }) => match operation {
          "connect" => ProxyError::Network(NetworkError::ConnectionFailed {
            address,
            source: std::io::Error::new(source.kind(), source.to_string()),
          }),
          "bind" => ProxyError::Network(NetworkError::BindFailed {
            address,
            source: std::io::Error::new(source.kind(), source.to_string()),
          }),
          _ => base_error,
        },
        _ => base_error,
      }
    })
  }
}

/// Helper functions for creating specific error types
impl NetworkError {
  /// Create a DNS resolution error
  pub fn dns_resolution(host: impl Into<String>, source: std::io::Error) -> Self {
    Self::DnsResolution {
      host: host.into(),
      source,
    }
  }

  /// Create a DNS error with custom reason
  pub fn dns_error(hostname: impl Into<String>, reason: impl Into<String>) -> Self {
    Self::DnsError {
      hostname: hostname.into(),
      reason: reason.into(),
    }
  }

  /// Create a connection failed error
  pub fn connection_failed(address: SocketAddr, source: std::io::Error) -> Self {
    Self::ConnectionFailed { address, source }
  }

  /// Create a bind failed error
  pub fn bind_failed(address: SocketAddr, source: std::io::Error) -> Self {
    Self::BindFailed { address, source }
  }
}

impl ProtocolError {
  /// Create a protocol detection failed error
  pub fn detection_failed(reason: impl Into<String>) -> Self {
    Self::DetectionFailed { reason: reason.into() }
  }

  /// Create a protocol parsing error
  pub fn parse_error(protocol: impl Into<String>, reason: impl Into<String>) -> Self {
    Self::ParseError {
      protocol: protocol.into(),
      reason: reason.into(),
    }
  }

  /// Create a TCP stream read timeout error
  pub fn tcp_read_timeout(source_addr: SocketAddr, timeout: Duration) -> Self {
    Self::TcpStreamReadTimeout { source_addr, timeout }
  }

  /// Create a no data received error
  pub fn no_data_received(source_addr: SocketAddr) -> Self {
    Self::NoDataReceived { source_addr }
  }
}

impl ConnectionError {
  /// Create a connection limit exceeded error
  pub fn limit_exceeded(current: usize, max: usize) -> Self {
    Self::LimitExceeded { current, max }
  }

  /// Create a UDP pool full error
  pub fn udp_pool_full(current: usize, max: usize) -> Self {
    Self::UdpPoolFull { current, max }
  }

  /// Create a connection broken error
  pub fn broken(source_addr: SocketAddr, dest_addr: SocketAddr, reason: impl Into<String>) -> Self {
    Self::Broken {
      source_addr,
      dest_addr,
      reason: reason.into(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::str::FromStr;

  #[test]
  fn test_error_context_chain() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Connection refused");
    let source = SocketAddr::from_str("127.0.0.1:8080").unwrap();
    let dest = SocketAddr::from_str("127.0.0.1:9090").unwrap();

    let result: Result<(), std::io::Error> = Err(io_err);
    let with_context = result.with_connection_context(source, dest);

    match with_context {
      Err(ProxyError::Connection(ConnectionError::Broken {
        source_addr,
        dest_addr,
        reason,
      })) => {
        assert_eq!(source_addr, source);
        assert_eq!(dest_addr, dest);
        assert!(reason.contains("Connection refused"));
      }
      _ => panic!("Expected ConnectionError::Broken"),
    }
  }

  #[test]
  fn test_network_error_helpers() {
    let host = "example.com";
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "Not found");
    let addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();

    let dns_err = NetworkError::dns_resolution(host, io_err);
    assert!(format!("{}", dns_err).contains("example.com"));
    assert!(format!("{}", dns_err).contains("Not found"));

    let io_err2 = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Refused");
    let conn_err = NetworkError::connection_failed(addr, io_err2);
    assert!(format!("{}", conn_err).contains("127.0.0.1:8080"));
    assert!(format!("{}", conn_err).contains("Refused"));
  }

  #[test]
  fn test_protocol_error_helpers() {
    let source_addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();
    let timeout = Duration::from_secs(5);

    let timeout_err = ProtocolError::tcp_read_timeout(source_addr, timeout);
    assert!(format!("{}", timeout_err).contains("127.0.0.1:8080"));
    assert!(format!("{}", timeout_err).contains("5s"));

    let no_data_err = ProtocolError::no_data_received(source_addr);
    assert!(format!("{}", no_data_err).contains("127.0.0.1:8080"));
  }

  #[test]
  fn test_connection_error_helpers() {
    let source = SocketAddr::from_str("127.0.0.1:8080").unwrap();
    let dest = SocketAddr::from_str("127.0.0.1:9090").unwrap();

    let limit_err = ConnectionError::limit_exceeded(100, 50);
    assert!(format!("{}", limit_err).contains("100/50"));

    let broken_err = ConnectionError::broken(source, dest, "Test reason");
    assert!(format!("{}", broken_err).contains("127.0.0.1:8080"));
    assert!(format!("{}", broken_err).contains("127.0.0.1:9090"));
    assert!(format!("{}", broken_err).contains("Test reason"));
  }

  #[test]
  fn test_error_conversion_chain() {
    let config_err = crate::config::validation::ConfigValidationError::InvalidFieldValue {
      field: "listen_port".to_string(),
      value: "0".to_string(),
      reason: "Port cannot be 0".to_string(),
    };

    let config_error: ConfigurationError = config_err.into();
    match config_error {
      ConfigurationError::InvalidPort { port } => {
        assert_eq!(port, 0);
      }
      _ => panic!("Expected InvalidPort error"),
    }

    let proxy_error: ProxyError = config_error.into();
    match proxy_error {
      ProxyError::Configuration(ConfigurationError::InvalidPort { port }) => {
        assert_eq!(port, 0);
      }
      _ => panic!("Expected Configuration(InvalidPort) error"),
    }
  }
}
