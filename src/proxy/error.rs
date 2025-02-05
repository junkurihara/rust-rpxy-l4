#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
  #[error("IO error: {0}")]
  IoError(#[from] std::io::Error),

  #[error("No destination address for the protocol")]
  NoDestinationAddressForProtocol,

  #[error("Failed to read first few bytes of TCP stream")]
  FailedToReadFirstFewBytesTcpStream,

  #[error("No data received from TCP stream")]
  NoDataReceivedTcpStream,
}
