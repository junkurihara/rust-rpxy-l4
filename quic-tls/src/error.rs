/// Probe result
pub enum TlsProbeFailure {
  /// Not enough buffer to probe
  PollNext,
  /// Failed to probe
  Failure,
}

/// Error for serializing and deserializing TLS ClientHello
#[derive(Debug, thiserror::Error)]
pub enum TlsClientHelloError {
  /// The input buffer is too short
  #[error("Input buffer is too short")]
  ShortInput,
  // /// The input length is invalid
  // #[error("Invalid input length")]
  // InvalidInputLength,
  #[error("Io error: {0}")]
  IoError(#[from] std::io::Error),

  #[error("Invalid TLS ClientHello")]
  InvalidTlsClientHello,
  #[error("Invalid SNI Extension")]
  InvalidSniExtension,
  #[error("Invalid ALPN Extension")]
  InvalidAlpnExtension,
  #[error("Invalid ECH Extension")]
  InvalidEchExtension,
}

// TODO: Define distinct deserialize error for objects
