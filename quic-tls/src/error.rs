use crate::{ech_config::EchConfigError, serialize::SerDeserError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Reason a TLS probe was rejected instead of treated as a generic mismatch.
pub enum TlsProbeRejection {
  /// A TLSPlaintext record declared a payload larger than the protocol limit.
  RecordOverflow,
  /// A ClientHello declaration cannot fit within the caller's probe budget.
  ClientHelloTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Probe result
pub enum TlsProbeFailure {
  /// Not enough buffer to probe
  PollNext,
  /// Failed to probe
  Failure,
  /// Input matched TLS framing but violated a parser safety or resource limit.
  Rejected(TlsProbeRejection),
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
  #[error("Invalid Ech ClientHello Inner recomposition attempt")]
  InvalidClientHelloRecomposition,
  #[error("No SNI in decrypted ClientHello")]
  NoSniInDecryptedClientHello,

  #[error("Error in serialization/deserialization")]
  SerDeserError(#[from] SerDeserError),
  #[error("Error in EchConfig")]
  EchConfigError(#[from] EchConfigError),
}
