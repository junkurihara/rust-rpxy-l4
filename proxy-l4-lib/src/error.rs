/// Errors that happens during the proxy operation
#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
  /* --------------------------------------- */
  #[error("IO error: {0}")]
  IoError(#[from] std::io::Error),

  /* --------------------------------------- */
  /// Single destination: failed to get destination address
  #[error("No destination address, possibly empty destination list")]
  NoDestinationAddress,

  /* --------------------------------------- */
  #[error("No destination address for the protocol")]
  NoDestinationAddressForProtocol,

  #[error("Failed to read first few bytes of TCP stream")]
  TimeOutToReadTcpStream,

  #[error("No data received from TCP stream")]
  NoDataReceivedTcpStream,

  #[error("Too many UDP connections")]
  TooManyUdpConnections,

  #[error("Broken UDP connection")]
  BrokenUdpConnection,

  /* --------------------------------------- */
  #[error("TLS or Quic error: {0}")]
  TlsError(#[from] quic_tls::TlsClientHelloError),

  #[error("TLS Alert write error")]
  TlsAlertWriteError,

  /* --------------------------------------- */
  #[error("DNS resolution error: {0}")]
  DnsResolutionError(String),

  #[error("Invalid address: {0}")]
  InvalidAddress(String),
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
