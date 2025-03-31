//! TLS Encrypted ClientHello (ECH) extension based on Draft 24
//! [IETF ECH Draft-24](https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html)

/// TLS Encrypted ClientHello extension type
pub(crate) const ENCRYPTED_CLIENT_HELLO_EXTENSION_TYPE: u16 = 0xfe0d;

#[derive(Debug)]
/// TLS ClientHello EncryptedClientHello extension
pub struct EncryptedClientHello {
  /// Typed payload
  pub payload: EchExtensionPayload,
}

#[derive(Debug)]
/// ClientHello typed payload
pub enum EchExtensionPayload {
  /// outer ClientHello
  Outer(ClientHelloOuter),
  /// inner ClientHello, which is always empty
  Inner,
}

#[derive(Debug)]
/// Outer ClientHello
pub struct ClientHelloOuter {}
