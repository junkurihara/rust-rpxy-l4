use crate::{ech_config::EchConfigError, serialize::SerDeserError};

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
  #[error("Invalid TLS ClientHello")]
  InvalidTlsClientHello,

  #[error("Invalid Extension length")]
  InvalidExtensionLength,
  #[error("Invalid SNI Extension")]
  InvalidSniExtension,
  #[error("Invalid ALPN Extension")]
  InvalidAlpnExtension,
  #[error("Invalid ECH Extension")]
  InvalidEchExtension,
  #[error("Invalid OuterExtensions Extension")]
  InvalidOuterExtensionsExtension,
  #[error("Unsupported Hpke Kdf, or Aead")]
  UnsupportedHpkeKdfAead,
  #[error("Hpke error")]
  HpkeError(hpke::HpkeError),
  #[error("ECH config public_name mismatched with SNI in client hello outer")]
  PublicNameMismatch,

  #[error("Error in serialization/deserialization")]
  SerDeserError(#[from] SerDeserError),
  #[error("Error in EchConfig")]
  EchConfigError(#[from] EchConfigError),
}
