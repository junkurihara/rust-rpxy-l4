#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
  #[error("IO error: {0}")]
  IoError(#[from] std::io::Error),

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

  #[error("Destination builder error: {0}")]
  DestinationBuilderError(anyhow::Error),

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
