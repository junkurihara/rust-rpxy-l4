use std::net::SocketAddr;

/// Errors that happens during the proxy operation
#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
  /* --------------------------------------- */
  #[error("IO error: {0}")]
  IoError(#[from] std::io::Error),

  /* --------------------------------------- */
  /// Single destination: failed to get destination address
  #[error("No destination address{}", if .0.is_empty() { String::new() } else { format!(": {}", .0) })]
  NoDestinationAddress(String),

  /// No ECH private destination server name,
  /// happens when the decrypted private server name in ClientHello Inner is not in the configured ECH private server name list
  #[error("No ECH private destination server name{}", if .0.is_empty() { String::new() } else { format!(": {}", .0) })]
  EchNoMatchingPrivateServerName(String),

  /* --------------------------------------- */
  #[error("No destination address for the protocol{}", if .0.is_empty() { String::new() } else { format!(": {}", .0) })]
  NoDestinationAddressForProtocol(String),

  #[error("Failed to read first few bytes of TCP stream{}", if .0.is_empty() { String::new() } else { format!(": {}", .0) })]
  TimeOutToReadTcpStream(String),

  #[error("No data received from TCP stream{}", if .0.is_empty() { String::new() } else { format!(": {}", .0) })]
  NoDataReceivedTcpStream(String),

  #[error("Too many UDP connections{}", if .0.is_empty() { String::new() } else { format!(": {}", .0) })]
  TooManyUdpConnections(String),

  #[error("Broken UDP connection{}", if .0.is_empty() { String::new() } else { format!(": {}", .0) })]
  BrokenUdpConnection(String),

  /* --------------------------------------- */
  #[error("TLS or Quic error: {0}")]
  TlsError(#[from] quic_tls::TlsClientHelloError),

  #[error("TLS Alert write error{}", if .0.is_empty() { String::new() } else { format!(": {}", .0) })]
  TlsAlertWriteError(String),

  /* --------------------------------------- */
  #[error("DNS resolution error: {0}")]
  DnsResolutionError(String),

  #[error("Invalid address: {0}")]
  InvalidAddress(String),
}

impl ProxyError {
  /// Add connection context to the error (source and destination addresses)
  pub fn with_connection_context(self, src_addr: SocketAddr, dst_addr: SocketAddr) -> Self {
    let context = format!("connection {src_addr} -> {dst_addr}");
    match self {
      Self::IoError(io_err) => Self::IoError(std::io::Error::new(io_err.kind(), format!("{context}: {io_err}"))),
      Self::NoDestinationAddress(msg) => Self::NoDestinationAddress(if msg.is_empty() {
        context
      } else {
        format!("{context}: {msg}")
      }),
      Self::DnsResolutionError(msg) => Self::DnsResolutionError(format!("{context}: {msg}")),
      Self::InvalidAddress(addr) => Self::InvalidAddress(format!("{addr} for {context}")),
      _ => self, // For other errors, return as-is
    }
  }

  /// Add protocol context to the error
  pub fn with_protocol_context(self, protocol: &str) -> Self {
    let context = format!("{protocol} protocol");
    match self {
      Self::NoDestinationAddressForProtocol(msg) => Self::NoDestinationAddressForProtocol(if msg.is_empty() {
        format!("no destination configured for {context}")
      } else {
        format!("{context}: {msg}")
      }),
      Self::TimeOutToReadTcpStream(msg) => Self::TimeOutToReadTcpStream(if msg.is_empty() {
        format!("timeout reading {context} stream")
      } else {
        format!("{context}: {msg}")
      }),
      Self::NoDataReceivedTcpStream(msg) => Self::NoDataReceivedTcpStream(if msg.is_empty() {
        format!("no data received from {context} stream")
      } else {
        format!("{context}: {msg}")
      }),
      Self::TooManyUdpConnections(msg) => Self::TooManyUdpConnections(if msg.is_empty() {
        format!("too many {context} connections")
      } else {
        format!("{context}: {msg}")
      }),
      Self::BrokenUdpConnection(msg) => Self::BrokenUdpConnection(if msg.is_empty() {
        format!("broken {context} connection")
      } else {
        format!("{context}: {msg}")
      }),
      Self::TlsAlertWriteError(msg) => Self::TlsAlertWriteError(if msg.is_empty() {
        format!("{context} alert write error")
      } else {
        format!("{context}: {msg}")
      }),
      Self::IoError(io_err) => Self::IoError(std::io::Error::new(io_err.kind(), format!("{context}: {io_err}"))),
      Self::DnsResolutionError(msg) => Self::DnsResolutionError(format!("{context}: {msg}")),
      _ => self,
    }
  }

  /// Add source address context to the error
  pub fn with_source_context(self, src_addr: SocketAddr) -> Self {
    let context = format!("from {src_addr}");
    match self {
      Self::NoDestinationAddressForProtocol(msg) => Self::NoDestinationAddressForProtocol(if msg.is_empty() {
        format!("no destination address for protocol requested {context}")
      } else {
        format!("{context}: {msg}")
      }),
      Self::TimeOutToReadTcpStream(msg) => Self::TimeOutToReadTcpStream(if msg.is_empty() {
        format!("timeout reading TCP stream {context}")
      } else {
        format!("{context}: {msg}")
      }),
      Self::NoDataReceivedTcpStream(msg) => Self::NoDataReceivedTcpStream(if msg.is_empty() {
        format!("no data received from TCP stream {context}")
      } else {
        format!("{context}: {msg}")
      }),
      Self::TooManyUdpConnections(msg) => Self::TooManyUdpConnections(if msg.is_empty() {
        format!("too many UDP connections, rejecting connection {context}")
      } else {
        format!("{context}: {msg}")
      }),
      Self::BrokenUdpConnection(msg) => Self::BrokenUdpConnection(if msg.is_empty() {
        format!("broken UDP connection {context}")
      } else {
        format!("{context}: {msg}")
      }),
      _ => self,
    }
  }
}

/// Errors that happens during building the proxy
#[derive(thiserror::Error, Debug)]
pub enum ProxyBuildError {
  /* --------------------------------------- */
  /// Configuration error: ech
  #[error("ECH config list error: {0}")]
  EchConfigError(#[from] quic_tls::EchConfigError),

  /// Invalid Ech private key
  #[error("Invalid ECH private key: {0}")]
  InvalidEchPrivateKey(String),

  /// Invalid Ech private server name
  #[error("Invalid ECH private server name: {0}")]
  InvalidEchPrivateServerName(String),

  /// Configuration error: protocol
  #[error("Unsupported protocol: {0}")]
  UnsupportedProtocol(String),

  /// Configuration error: load balance
  #[error("Invalid load balance: {0}")]
  InvalidLoadBalance(String),

  /// Single target destination builder error
  #[error("Target destination builder error: {0}")]
  TargetDestinationBuilderError(#[from] crate::destination::TargetDestinationBuilderError),

  /* --------------------------------------- */
  /// Multiplexer builder error UDP
  #[error("UDP destination mux error: {0}")]
  UdpDestinationMuxError(#[from] crate::udp_proxy::UdpDestinationMuxBuilderError),

  /// Multiplexer builder error TCP
  #[error("TCP destination mux error: {0}")]
  TcpDestinationMuxError(#[from] crate::tcp_proxy::TcpDestinationMuxBuilderError),

  /// Both TCP UDP mux builder error called from the top level
  #[error("Build error for multiplexers: {0}")]
  BuildMultiplexersError(String),
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_error_context_helpers() {
    let src_addr = "192.168.1.100:45000".parse().unwrap();
    let dst_addr = "10.0.0.50:443".parse().unwrap();

    // Test connection context
    let io_error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Connection refused");
    let proxy_error = ProxyError::IoError(io_error);
    let contextual_error = proxy_error.with_connection_context(src_addr, dst_addr);

    let error_msg = format!("{contextual_error}");
    assert!(error_msg.contains("192.168.1.100:45000"));
    assert!(error_msg.contains("10.0.0.50:443"));

    // Test protocol context
    let timeout_error = ProxyError::TimeOutToReadTcpStream(String::new());
    let contextual_error = timeout_error.with_protocol_context("TLS");
    let error_msg = format!("{contextual_error}");
    assert!(error_msg.contains("TLS"));
    assert!(error_msg.contains("timeout"));

    // Test source context
    let no_dest_error = ProxyError::NoDestinationAddressForProtocol(String::new());
    let contextual_error = no_dest_error.with_source_context(src_addr);
    let error_msg = format!("{contextual_error}");
    assert!(error_msg.contains("192.168.1.100:45000"));
    assert!(error_msg.contains("protocol"));
  }
}
