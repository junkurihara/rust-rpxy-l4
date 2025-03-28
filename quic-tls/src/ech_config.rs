//! TLS Encrypted ClientHello Config based on Draft 24
//! [IETF ECH Draft-24](https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html)

/* ------------------------------------------- */
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Describes things that can go wrong in the ECH configuration
#[derive(Debug, thiserror::Error)]
pub(crate) enum EchConfigError {
  /// The input buffer is too short
  #[error("Input buffer is too short")]
  ShortInput,
  /// The input length is invalid
  #[error("Invalid input length")]
  InvalidInputLength,
  /// The version is invalid
  #[error("Invalid version")]
  Version,
}

/* ------------------------------------------- */
// Imported from odoh-rs crate

/// Serialize to IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub(crate) trait Serialize {
  type Error;
  /// Serialize the provided struct into the buf.
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error>;
}

/// Deserialize from IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub(crate) trait Deserialize {
  type Error;
  /// Deserialize a struct from the buf.
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized;
}

/// Convenient function to deserialize a structure from Bytes.
pub(super) fn parse<D: Deserialize, B: Buf>(buf: &mut B) -> Result<D, D::Error> {
  D::deserialize(buf)
}

#[allow(unused)]
/// Convenient function to serialize a structure into a new BytesMut.
pub(super) fn compose<S: Serialize>(s: S) -> Result<BytesMut, S::Error> {
  let mut buf = BytesMut::new();
  s.serialize(&mut buf)?;
  Ok(buf)
}

pub(super) fn read_lengthed<B: Buf>(b: &mut B) -> Result<Bytes, EchConfigError> {
  if b.remaining() < 2 {
    return Err(EchConfigError::ShortInput);
  }

  let len = b.get_u16() as usize;

  if len > b.remaining() {
    return Err(EchConfigError::InvalidInputLength);
  }

  Ok(b.copy_to_bytes(len))
}

/* ------------------------------------------- */
#[derive(Debug)]
pub(crate) struct EchConfigList {
  inner: Vec<EchConfig>,
}

impl Serialize for &EchConfigList {
  type Error = EchConfigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    // calculate total length
    let mut len = 0;
    for c in self.inner.iter() {
      // 2 bytes of version and 2 bytes of length
      len += 2 + 2 + c.length;
    }

    buf.put_u16(len);
    for c in self.inner.iter() {
      c.serialize(buf)?;
    }

    Ok(())
  }
}
impl Deserialize for EchConfigList {
  type Error = EchConfigError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    let mut buf = read_lengthed(buf)?;

    let mut inner = Vec::new();
    loop {
      if buf.is_empty() {
        break;
      }
      let c = parse(&mut buf)?;
      inner.push(c);
    }

    Ok(Self { inner })
  }
}

/* ------------------------------------------- */
#[derive(Debug)]
/// ECH Configuration
pub(crate) struct EchConfig {
  /// Version
  version: u16, // must be 0xfe0d
  /// Length
  length: u16,
  /// Content
  contents: EchConfigContents,
}

impl Serialize for &EchConfig {
  type Error = EchConfigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), EchConfigError> {
    buf.put_u16(self.version);
    buf.put_u16(self.length);
    match &self.version {
      0xfe0d => {
        self.contents.serialize(buf)?;
      }
      _ => {
        return Err(EchConfigError::Version);
      }
    }
    Ok(())
  }
}

impl Deserialize for EchConfig {
  type Error = EchConfigError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 4 {
      return Err(EchConfigError::ShortInput);
    }

    let version = buf.get_u16();
    if version != 0xfe0d {
      return Err(EchConfigError::Version);
    }
    let length = buf.get_u16();
    if length != buf.remaining() as u16 {
      return Err(EchConfigError::InvalidInputLength);
    }
    let contents = buf.copy_to_bytes(length as usize);

    Ok(Self {
      version,
      length,
      contents: parse(&mut &contents[..])?,
    })
  }
}

/* ------------------------------------------- */
#[derive(Debug)]
/// EchConfigContents
pub(crate) struct EchConfigContents {
  /// public key and cipher suites
  key_config: HpkeKeyConfig,
  /// maximum name length
  maximum_name_length: u8,
  /// public name
  public_name: Bytes,
  /// ech_config_extension
  extensions: Vec<EchConfigExtension>,
}

impl Serialize for &EchConfigContents {
  type Error = EchConfigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    self.key_config.serialize(buf)?;
    buf.put_u8(self.maximum_name_length);
    buf.put_u8(self.public_name.len() as u8);
    buf.put_slice(&self.public_name);
    let extensions_len = self.extensions.iter().fold(0, |acc, ext| acc + ext.data.len() as u16);
    buf.put_u16(extensions_len);
    for ext in self.extensions.iter() {
      ext.serialize(buf)?;
    }
    Ok(())
  }
}

impl Deserialize for EchConfigContents {
  type Error = EchConfigError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 8 {
      return Err(EchConfigError::ShortInput);
    }
    let key_config = parse(buf)?;

    if buf.remaining() < 2 {
      return Err(EchConfigError::ShortInput);
    }
    let maximum_name_length = buf.get_u8();

    // public_name is 1..255 bytes, so we need to check the length of 1 byte
    let public_name_len = buf.get_u8() as usize;
    if !(1..=255).contains(&public_name_len) {
      return Err(EchConfigError::InvalidInputLength);
    }
    if buf.remaining() < public_name_len {
      return Err(EchConfigError::ShortInput);
    }
    let public_name = buf.copy_to_bytes(public_name_len);

    if buf.remaining() < 2 {
      return Err(EchConfigError::ShortInput);
    }
    let extensions_len = buf.get_u16() as usize;
    if buf.remaining() < extensions_len {
      return Err(EchConfigError::ShortInput);
    }
    let mut extensions = Vec::new();

    while buf.remaining() > 0 {
      let ext = parse(buf)?;
      extensions.push(ext);
    }

    Ok(Self {
      key_config,
      maximum_name_length,
      public_name,
      extensions,
    })
  }
}

/* ------------------------------------------- */
#[derive(Debug)]
/// EchConfigExtension
pub(crate) struct EchConfigExtension {
  /// EchConfigExtensionType
  ext_type: u16,
  /// content
  data: Bytes,
}

impl Serialize for &EchConfigExtension {
  type Error = EchConfigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    buf.put_u16(self.ext_type);
    buf.put_u16(self.data.len() as u16);
    buf.put_slice(&self.data);
    Ok(())
  }
}

impl Deserialize for EchConfigExtension {
  type Error = EchConfigError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 4 {
      return Err(EchConfigError::ShortInput);
    }
    let ext_type = buf.get_u16();
    let data = read_lengthed(buf)?;
    Ok(Self { ext_type, data })
  }
}

/* ------------------------------------------- */
#[derive(Debug)]
/// HpkeKeyConfig
pub(crate) struct HpkeKeyConfig {
  /// config id
  config_id: u8,
  /// HpkeKemId
  kem_id: u16,
  /// HpkePublicKey
  public_key: Bytes,
  /// HpkeSymmetricCipherSuite
  cipher_suites: Vec<HpkeSymmetricCipherSuite>,
}

impl Serialize for &HpkeKeyConfig {
  type Error = EchConfigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    buf.put_u8(self.config_id);
    buf.put_u16(self.kem_id);
    buf.put_u16(self.public_key.len() as u16);
    buf.put_slice(&self.public_key);
    let cipher_suites_byte_len = self.cipher_suites.len() * 4;
    buf.put_u16(cipher_suites_byte_len as u16);
    for c in self.cipher_suites.iter() {
      c.serialize(buf)?;
    }
    Ok(())
  }
}

impl Deserialize for HpkeKeyConfig {
  type Error = EchConfigError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 9 {
      return Err(EchConfigError::ShortInput);
    }
    let config_id = buf.get_u8();
    let kem_id = buf.get_u16();
    let public_key = read_lengthed(buf)?;

    if buf.remaining() < 4 {
      return Err(EchConfigError::ShortInput);
    }
    let cipher_suites_byte_len = buf.get_u16() as usize;

    if buf.remaining() < cipher_suites_byte_len {
      return Err(EchConfigError::ShortInput);
    }
    let mut cipher_suites = Vec::new();
    for _ in 0..cipher_suites_byte_len / 4 {
      let c = parse(buf)?;
      cipher_suites.push(c);
    }

    Ok(Self {
      config_id,
      kem_id,
      public_key,
      cipher_suites,
    })
  }
}

/* ------------------------------------------- */
#[derive(Debug)]
/// HpkeSymmetricCipherSuite
pub(crate) struct HpkeSymmetricCipherSuite {
  /// HpkeKdfId
  kdf_id: u16,
  /// HpkeAeadId
  aead_id: u16,
}

impl Serialize for &HpkeSymmetricCipherSuite {
  type Error = EchConfigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    buf.put_u16(self.kdf_id);
    buf.put_u16(self.aead_id);
    Ok(())
  }
}

impl Deserialize for HpkeSymmetricCipherSuite {
  type Error = EchConfigError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 4 {
      return Err(EchConfigError::ShortInput);
    }

    let kdf_id = buf.get_u16();
    let aead_id = buf.get_u16();

    Ok(Self { kdf_id, aead_id })
  }
}

/* ------------------------------------------- */

// Investigation for ech integration
#[cfg(test)]
mod tests {
  use super::*;
  use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
  use hex_literal::hex;
  use rustls::{client, crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES, pki_types::EchConfigListBytes};

  #[test]
  fn test_parse_ech_defo_ie() {
    let https_record = "AEb+DQBCqQAgACBlm7cfDx/gKuUAwRTe+Y9MExbIyuLpLcgTORIdi69uewAEAAEAAQATcHVibGljLnRlc3QuZGVmby5pZQAA";
    let https_record_bytes = BASE64_STANDARD_NO_PAD.decode(https_record).unwrap();
    println!("https_record_bytes: {:x?}", https_record_bytes);
    let ech_config_list = EchConfigList::deserialize(&mut &https_record_bytes[..]).unwrap();
    println!("ech_config_list: {:#?}", ech_config_list);

    let serialized = compose(&ech_config_list).unwrap();
    assert_eq!(https_record_bytes, serialized.to_vec());
  }

  #[test]
  fn test_parse_ech() {
    let svcb_hex = hex!(
      "0046fe0d0042a900200020659bb71f0f1fe02ae500c114def98f4c1316c8cae2e92dc81339121d8baf6e7b00040001000100137075626c69632e746573742e6465666f2e69650000"
    );
    let bytes = EchConfigListBytes::from(svcb_hex.as_slice());
    let ech_config = client::EchConfig::new(bytes, ALL_SUPPORTED_SUITES).unwrap();
    println!("{:#?}", ech_config);
  }
}
