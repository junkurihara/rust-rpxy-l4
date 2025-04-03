//! TLS Encrypted ClientHello (ECH) extension based on Draft 24
//! [IETF ECH Draft-24](https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html)

use bytes::Bytes;

use crate::{
  ech_config::HpkeSymmetricCipherSuite,
  error::TlsClientHelloError,
  serialize::{Deserialize, SerDeserError, Serialize, read_lengthed},
  trace::*,
};

/* ------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// TLS ClientHello EncryptedClientHello extension
pub enum EncryptedClientHello {
  /// outer ClientHello (0)
  Outer(ClientHelloOuter),
  /// inner ClientHello, which is always empty (1)
  Inner,
}

impl std::fmt::Display for EncryptedClientHello {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      EncryptedClientHello::Outer(payload) => write!(f, "ECH Outer: {:?}", payload),
      EncryptedClientHello::Inner => write!(f, "ECH Inner"),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
impl ClientHelloOuter {
  /// Fill the payload with zeros for AAD calculation
  pub(crate) fn fill_payload_with_zeros(&mut self) {
    // Replace the payload field with zeros
    let payload_len = self.payload.len();
    let payload = vec![0; payload_len];
    self.payload = Bytes::from(payload);
  }
  pub(crate) fn cipher_suite(&self) -> &HpkeSymmetricCipherSuite {
    &self.cipher_suite
  }
  pub(crate) fn config_id(&self) -> u8 {
    self.config_id
  }
  pub(crate) fn enc(&self) -> &Bytes {
    &self.enc
  }
  pub(crate) fn payload(&self) -> &Bytes {
    &self.payload
  }
}
/* ------------------------------------------- */

impl Deserialize for EncryptedClientHello {
  type Error = TlsClientHelloError;
  /// Deserialize the EncryptedClientHello
  fn deserialize<B: bytes::Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    let ech_client_hello_type = buf.get_u8();
    match ech_client_hello_type {
      0 => {
        let payload = ClientHelloOuter::deserialize(buf)?;
        Ok(EncryptedClientHello::Outer(payload))
      }
      1 => Ok(EncryptedClientHello::Inner),
      _ => {
        error!("Unknown ECH ClientHello type: {}", ech_client_hello_type);
        Err(TlsClientHelloError::InvalidEchExtension)
      }
    }
  }
}

impl Serialize for EncryptedClientHello {
  type Error = TlsClientHelloError;
  /// Serialize the EncryptedClientHello
  fn serialize<B: bytes::BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    match self {
      EncryptedClientHello::Outer(payload) => {
        buf.put_u8(0);
        payload.serialize(buf)
      }
      EncryptedClientHello::Inner => {
        buf.put_u8(1);
        Ok(())
      }
    }
  }
}

impl Deserialize for ClientHelloOuter {
  type Error = TlsClientHelloError;
  /// Deserialize the outer ClientHello
  fn deserialize<B: bytes::Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    let cipher_suite = HpkeSymmetricCipherSuite::deserialize(buf)?;
    if buf.remaining() < 5 {
      error!("Not enough data as ECH ClientHelloOuter");
      return Err(SerDeserError::ShortInput.into());
    }
    let config_id = buf.get_u8();
    let enc = read_lengthed(buf, 2)?;
    let payload = read_lengthed(buf, 2)?;

    if payload.is_empty() {
      error!("Empty ech payload for ClientHelloOuter");
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
  /// Serialize the outer ClientHello
  fn serialize<B: bytes::BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    // Serialize the outer ClientHello
    self.cipher_suite.serialize(buf)?;
    buf.put_u8(self.config_id);
    buf.put_u16(self.enc.len() as u16);
    buf.put_slice(&self.enc);
    if self.payload.is_empty() {
      error!("Empty ech payload for ClientHelloOuter");
      return Err(TlsClientHelloError::InvalidEchExtension);
    }
    buf.put_u16(self.payload.len() as u16);
    buf.put_slice(&self.payload);

    Ok(())
  }
}

/* ------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// TLS ClientHello OuterExtensions extension, presented only in inner ClientHello (decrypted ECH payload)
pub struct OuterExtensions {
  /// Extension types removed from the ClientHelloInner
  outer_extensions: Vec<u16>,
}
impl std::fmt::Display for OuterExtensions {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "ECH OuterExtensions: {:?}", self.outer_extensions)
  }
}

impl Deserialize for OuterExtensions {
  type Error = TlsClientHelloError;
  /// Deserialize the OuterExtensions
  fn deserialize<B: bytes::Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    if buf.remaining() < 1 {
      error!("Not enough data as OuterExtensions");
      return Err(SerDeserError::ShortInput.into());
    }

    let outer_extensions = read_lengthed(buf, 1)?;

    if outer_extensions.is_empty() || outer_extensions.len() % 2 != 0 {
      error!("Invalid OuterExtensions");
      return Err(TlsClientHelloError::InvalidOuterExtensionsExtension);
    }

    let outer_extensions = outer_extensions
      .chunks_exact(2)
      .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
      .collect();
    Ok(OuterExtensions { outer_extensions })
  }
}

impl Serialize for OuterExtensions {
  type Error = TlsClientHelloError;
  /// Serialize the OuterExtensions
  fn serialize<B: bytes::BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    // Serialize the outer extensions
    if self.outer_extensions.is_empty() {
      error!("Empty outer extensions");
      return Err(TlsClientHelloError::InvalidOuterExtensionsExtension);
    }
    buf.put_u8(self.outer_extensions.len() as u8);
    for ext in self.outer_extensions {
      buf.put_u16(ext);
    }
    Ok(())
  }
}
