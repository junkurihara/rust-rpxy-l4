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
}
