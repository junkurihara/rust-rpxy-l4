//! TLS Encrypted ClientHello (ECH) extension based on Draft 24
//! [IETF ECH Draft-24](https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html)

use bytes::Bytes;

use crate::{
  ech_config::{EchConfigError, HpkeSymmetricCipherSuite},
  error::TlsClientHelloError,
  serialize::{Deserialize, Serialize, read_lengthed},
  trace::*,
};

/* ------------------------------------------- */
/// TLS Encrypted ClientHello extension type
pub(crate) const ENCRYPTED_CLIENT_HELLO_EXTENSION_TYPE: u16 = 0xfe0d;

#[derive(Debug)]
/// TLS ClientHello EncryptedClientHello extension
pub struct EncryptedClientHello {
  /// Typed payload
  payload: EchExtensionPayload,
}

#[derive(Debug)]
/// ClientHello typed payload
pub enum EchExtensionPayload {
  /// outer ClientHello (0)
  Outer(ClientHelloOuter),
  /// inner ClientHello, which is always empty (1)
  Inner,
}

#[derive(Debug)]
/// Outer ClientHello
pub struct ClientHelloOuter {
  /// Cipher suite
  cipher_suite: HpkeSymmetricCipherSuite,
  /// Config ID
  config_id: u8,
  /// enc (e.g, Public key of the peer)
  enc: Bytes,
  /// payload (encrypted body)
  payload: Bytes,
}
/* ------------------------------------------- */

impl Deserialize for ClientHelloOuter {
  type Error = TlsClientHelloError;
  fn deserialize<B: bytes::Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    // Deserialize the outer ClientHello
    let cipher_suite = HpkeSymmetricCipherSuite::deserialize(buf).map_err(|e| {
      if matches!(e, EchConfigError::ShortInput) {
        TlsClientHelloError::ShortInput
      } else {
        TlsClientHelloError::InvalidEchExtension
      }
    })?;
    if buf.remaining() < 5 {
      return Err(TlsClientHelloError::ShortInput);
    }
    let config_id = buf.get_u8();
    let enc = read_lengthed(buf, 2)?;
    let payload = read_lengthed(buf, 2)?;

    if payload.is_empty() {
      error!("Empty ech payload");
      return Err(TlsClientHelloError::InvalidEchExtension);
    }

    Ok(ClientHelloOuter {
      cipher_suite,
      config_id,
      enc,
      payload,
    })
  }
}

impl Serialize for ClientHelloOuter {
  type Error = TlsClientHelloError;
  fn serialize<B: bytes::BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    // Serialize the outer ClientHello
    self.cipher_suite.serialize(buf).map_err(|e| {
      if matches!(e, EchConfigError::ShortInput) {
        TlsClientHelloError::ShortInput
      } else {
        TlsClientHelloError::InvalidEchExtension
      }
    })?;
    buf.put_u8(self.config_id);
    buf.put_slice(&self.enc);
    if self.payload.is_empty() {
      error!("Empty ech payload");
      return Err(TlsClientHelloError::InvalidEchExtension);
    }
    buf.put_slice(&self.payload);

    Ok(())
  }
}
