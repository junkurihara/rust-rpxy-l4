//! TLS Encrypted ClientHello Config based on Draft 24
//! [IETF ECH Draft-24](https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html)

/* ------------------------------------------- */
use crate::{
  serialize::{Deserialize, SerDeserError, Serialize, compose, parse, read_lengthed},
  trace::*,
};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hpke::{
  Deserializable, Kem, Serializable,
  aead::{Aead, AesGcm128},
  kdf::{HkdfSha256, Kdf},
  kem::{DhP256HkdfSha256, X25519HkdfSha256},
};
use std::sync::LazyLock;

/// Describes things that can go wrong in the ECH configuration
#[derive(Debug, thiserror::Error)]
pub enum EchConfigError {
  /// The version is invalid
  #[error("Invalid version")]
  Version,
  /// Error in serializing/deserializing
  #[error("Error in serializing/deserializing")]
  SerDeser(#[from] SerDeserError),
  /// Error in base64 encoding/decoding
  #[error("Error in base64 encoding/decoding")]
  Base64(#[from] base64::DecodeError),
  /// Error in importing private key
  #[error("Error in importing private key")]
  ImportPrivateKey,
}

/* ------------------------------------------- */

/// default cipher suites for HPKE in ECH Config
static HPKE_KEY_CONFIG_CIPHER_SUITES: LazyLock<Vec<HpkeSymmetricCipherSuite>> = LazyLock::new(|| {
  vec![HpkeSymmetricCipherSuite {
    kdf_id: HkdfSha256::KDF_ID,
    aead_id: AesGcm128::AEAD_ID,
  }]
});

#[derive(Debug)]
/// EchConfigList
pub struct EchConfigList {
  inner: Vec<EchConfig>,
}

impl Serialize for &EchConfigList {
  type Error = EchConfigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    // serialize the inner list
    let serialized_inner = self
      .inner
      .iter()
      .map(|c| {
        let serialized = compose(c)?;
        Ok(serialized) as Result<_, EchConfigError>
      })
      .collect::<Result<Vec<_>, _>>()?;
    // calculate total length
    let total_len = serialized_inner.iter().fold(0, |acc, c: &BytesMut| acc + c.len() as u16);

    buf.put_u16(total_len);
    for c in serialized_inner.iter() {
      buf.put_slice(c);
    }

    Ok(())
  }
}
impl Deserialize for EchConfigList {
  type Error = EchConfigError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    let mut buf = read_lengthed(buf, 2)?;

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

impl From<Vec<EchConfig>> for EchConfigList {
  fn from(inner: Vec<EchConfig>) -> Self {
    Self { inner }
  }
}
impl TryFrom<&str> for EchConfigList {
  type Error = EchConfigError;
  /// Try from base64 encoded string
  fn try_from(s: &str) -> Result<Self, Self::Error> {
    let configs_bytes = BASE64_STANDARD_NO_PAD.decode(s)?;
    EchConfigList::deserialize(&mut &configs_bytes[..])
  }
}

impl EchConfigList {
  /// Iterate over the inner list
  pub fn iter(&self) -> impl Iterator<Item = &EchConfig> {
    self.inner.iter()
  }

  /// Generate a new EchConfigList with randomly generated key pair
  /// By default, it generates a list of size 1 with a single EchConfig [X25519HkdfSha256 + AesGcm128 + HkdfSha256]
  pub fn generate(public_name: &str) -> Result<(Self, Vec<EchPrivateKey>), EchConfigError> {
    let kem_id = X25519HkdfSha256::KEM_ID;
    let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rand::rng());
    // let sk_bytes = Bytes::copy_from_slice(&sk.to_bytes());
    let config_id = rand::random_range(0..=255);
    let public_name = Bytes::copy_from_slice(public_name.as_bytes());

    let key_config = HpkeKeyConfig {
      config_id,
      kem_id,
      public_key: Bytes::copy_from_slice(&pk.to_bytes()),
      cipher_suites: HPKE_KEY_CONFIG_CIPHER_SUITES.clone(),
    };
    let contents = EchConfigContents {
      key_config,
      maximum_name_length: 0,
      public_name,
      extensions: vec![],
    };
    let ech_config = EchConfig {
      version: ECH_CONFIG_VERSION_DRAFT_24,
      contents,
    };
    let ech_config_list = EchConfigList::from(vec![ech_config.clone()]);

    let sk = EchPrivateKey {
      private_key: HpkeKemPrivateKey::X25519(sk),
      config: ech_config,
    };

    Ok((ech_config_list, vec![sk]))
  }
}

#[derive(Clone)]
/// Hpke KEM private key enum
pub enum HpkeKemPrivateKey {
  /// X25519 private key
  X25519(<X25519HkdfSha256 as Kem>::PrivateKey),
  /// P256 private key
  P256(<DhP256HkdfSha256 as Kem>::PrivateKey),
}
impl HpkeKemPrivateKey {
  /// Convert to bytes
  pub fn to_bytes(&self) -> Bytes {
    match self {
      HpkeKemPrivateKey::X25519(sk) => Bytes::copy_from_slice(&sk.to_bytes()),
      HpkeKemPrivateKey::P256(sk) => Bytes::copy_from_slice(&sk.to_bytes()),
    }
  }
  /// Export public key in bytes
  fn to_pk_bytes(&self) -> Bytes {
    match self {
      HpkeKemPrivateKey::X25519(sk) => Bytes::copy_from_slice(&<X25519HkdfSha256 as Kem>::sk_to_pk(sk).to_bytes()),
      HpkeKemPrivateKey::P256(sk) => Bytes::copy_from_slice(&<DhP256HkdfSha256 as Kem>::sk_to_pk(sk).to_bytes()),
    }
  }
}

/// Private key with config id associated with EchConfig.EchConfigContents.key_config
pub struct EchPrivateKey {
  /// Private key
  private_key: HpkeKemPrivateKey,
  /// Associated EchConfig
  config: EchConfig,
}
#[allow(unused)]
impl EchPrivateKey {
  /// Convert to bytes
  pub fn to_bytes(&self) -> Bytes {
    self.private_key.to_bytes()
  }
  /// Get the private key
  pub fn private_key(&self) -> &HpkeKemPrivateKey {
    &self.private_key
  }
  /// Get ech_config
  pub fn ech_config(&self) -> &EchConfig {
    &self.config
  }
  /// Get the config id
  pub(crate) fn config_id(&self) -> u8 {
    self.config.config_id()
  }
  /// Get the public name
  pub(crate) fn public_name(&self) -> Bytes {
    self.config.public_name()
  }
  /// Get the available symmetric cipher suites
  pub(crate) fn cipher_suites(&self) -> &[HpkeSymmetricCipherSuite] {
    self.config.cipher_suites()
  }
  /// Compose private key list matched to given ech_config_list
  pub fn try_compose_list_from_base64_with_config(
    base64_sk_list: &[String],
    ech_config_list: &EchConfigList,
  ) -> Result<Vec<Self>, EchConfigError> {
    let sk_pk_bytes_list = base64_sk_list
      .iter()
      .map(|base64_sk| {
        let sk_bytes = BASE64_STANDARD_NO_PAD.decode(base64_sk)?;
        let sk = if let Ok(sk) = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&sk_bytes) {
          HpkeKemPrivateKey::X25519(sk)
        } else if let Ok(sk) = <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&sk_bytes) {
          HpkeKemPrivateKey::P256(sk)
        } else {
          error!("Failed to import private key");
          return Err(EchConfigError::ImportPrivateKey);
        };
        let pk_bytes = sk.to_pk_bytes();
        Ok((sk, pk_bytes))
      })
      .collect::<Result<Vec<_>, _>>()?;

    let mut sk_list = Vec::new();
    for (sk, pk_bytes) in sk_pk_bytes_list.iter() {
      if let Some(config) = ech_config_list.iter().find(|c| c.public_key() == *pk_bytes) {
        sk_list.push(EchPrivateKey {
          private_key: sk.clone(),
          config: config.clone(),
        });
      } else {
        error!("No matching ECH config found for the given private key");
        return Err(EchConfigError::ImportPrivateKey);
      }
    }

    Ok(sk_list)
  }
}

/* ------------------------------------------- */
const ECH_CONFIG_VERSION_DRAFT_24: u16 = 0xfe0d;
#[derive(Debug, Clone)]
/// ECH Configuration
pub struct EchConfig {
  /// Version, must be 0xfe0d
  version: u16,
  /// Content
  contents: EchConfigContents,
}

impl Serialize for &EchConfig {
  type Error = EchConfigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), EchConfigError> {
    buf.put_u16(self.version);
    match self.version {
      ECH_CONFIG_VERSION_DRAFT_24 => {
        let contents = compose(&self.contents)?;
        buf.put_u16(contents.len() as u16);
        buf.put_slice(&contents);
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
      error!("Short input for EchConfig");
      return Err(SerDeserError::ShortInput.into());
    }

    let version = buf.get_u16();
    if version != 0xfe0d {
      error!("Invalid version for EchConfig");
      return Err(EchConfigError::Version);
    }
    let length = buf.get_u16();
    if length != buf.remaining() as u16 {
      error!("Invalid input length for EchConfig");
      return Err(SerDeserError::InvalidInputLength.into());
    }
    let contents = buf.copy_to_bytes(length as usize);

    Ok(Self {
      version,
      contents: parse(&mut &contents[..])?,
    })
  }
}

#[allow(unused)]
impl EchConfig {
  /// Get the public name
  pub(crate) fn public_name(&self) -> Bytes {
    self.contents.public_name.clone()
  }
  /// Get the config id
  pub(crate) fn config_id(&self) -> u8 {
    self.contents.key_config.config_id
  }
  /// Get the public key in bytes
  pub(crate) fn public_key(&self) -> Bytes {
    self.contents.key_config.public_key.clone()
  }
  /// Get the kem id
  pub(crate) fn kem_id(&self) -> u16 {
    self.contents.key_config.kem_id
  }
  /// Get the available symmetric cipher suites
  pub(crate) fn cipher_suites(&self) -> &[HpkeSymmetricCipherSuite] {
    &self.contents.key_config.cipher_suites
  }
}
/* ------------------------------------------- */
#[derive(Debug, Clone)]
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
  type Error = SerDeserError;
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
  type Error = SerDeserError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 8 {
      error!("Short input for EchConfigContents");
      return Err(SerDeserError::ShortInput);
    }
    let key_config = parse(buf)?;

    if buf.remaining() < 2 {
      error!("Short input for EchConfigContents");
      return Err(SerDeserError::ShortInput);
    }
    let maximum_name_length = buf.get_u8();

    // public_name is 1..255 bytes, so we need to check the length of 1 byte
    let public_name = read_lengthed(buf, 1)?;

    if buf.remaining() < 2 {
      error!("Short input for EchConfigContents");
      return Err(SerDeserError::ShortInput);
    }
    let extensions_len = buf.get_u16() as usize;
    if buf.remaining() < extensions_len {
      error!("Short input for EchConfigContents");
      return Err(SerDeserError::ShortInput);
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
#[derive(Debug, Clone)]
/// EchConfigExtension
pub(crate) struct EchConfigExtension {
  /// EchConfigExtensionType
  ext_type: u16,
  /// content
  data: Bytes,
}

impl Serialize for &EchConfigExtension {
  type Error = SerDeserError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    buf.put_u16(self.ext_type);
    buf.put_u16(self.data.len() as u16);
    buf.put_slice(&self.data);
    Ok(())
  }
}

impl Deserialize for EchConfigExtension {
  type Error = SerDeserError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 4 {
      return Err(SerDeserError::ShortInput);
    }
    let ext_type = buf.get_u16();
    let data = read_lengthed(buf, 2)?;
    Ok(Self { ext_type, data })
  }
}

/* ------------------------------------------- */
#[derive(Debug, Clone)]
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
  type Error = SerDeserError;
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
  type Error = SerDeserError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 9 {
      error!("Short input for HpkeKeyConfig");
      return Err(SerDeserError::ShortInput);
    }
    let config_id = buf.get_u8();
    let kem_id = buf.get_u16();
    let public_key = read_lengthed(buf, 2)?;

    if buf.remaining() < 4 {
      error!("Short input for HpkeKeyConfig");
      return Err(SerDeserError::ShortInput);
    }
    let cipher_suites_byte_len = buf.get_u16() as usize;

    if buf.remaining() < cipher_suites_byte_len {
      error!("Short input for HpkeKeyConfig");
      return Err(SerDeserError::ShortInput);
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// HpkeSymmetricCipherSuite
pub(crate) struct HpkeSymmetricCipherSuite {
  /// HpkeKdfId
  pub(crate) kdf_id: u16,
  /// HpkeAeadId
  pub(crate) aead_id: u16,
}

impl Serialize for &HpkeSymmetricCipherSuite {
  type Error = SerDeserError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    buf.put_u16(self.kdf_id);
    buf.put_u16(self.aead_id);
    Ok(())
  }
}

impl Deserialize for HpkeSymmetricCipherSuite {
  type Error = SerDeserError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 4 {
      error!("Short input for HpkeSymmetricCipherSuite");
      return Err(SerDeserError::ShortInput);
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
  fn test_gen_my_own_ech_config() {
    let (ech_config_list, sk_list) = EchConfigList::generate("my-public-name.example.com").unwrap();
    let sk_bytes = sk_list.first().unwrap().to_bytes();
    let base64_sk = BASE64_STANDARD_NO_PAD.encode(&sk_bytes);
    println!("secret key: {:x?}", base64_sk);
    let config_ids = ech_config_list.iter().map(|c| c.config_id()).collect::<Vec<_>>();
    println!("associated config ids: {:?}", config_ids);
    assert_eq!(config_ids.first().unwrap(), &sk_list.first().unwrap().config_id());
    let sk_list = EchPrivateKey::try_compose_list_from_base64_with_config(&[base64_sk], &ech_config_list);
    assert!(sk_list.is_ok());

    let serialized = compose(&ech_config_list).unwrap();
    let buf_base64 = BASE64_STANDARD_NO_PAD.encode(&serialized);
    println!("ech config list (base64): {}", &buf_base64);

    let record_bytes = BASE64_STANDARD_NO_PAD.decode(&buf_base64).unwrap();
    println!("ech config list (hex): {:x?}", record_bytes);
    let deserialized = EchConfigList::deserialize(&mut &record_bytes[..]).unwrap();
    println!("deserialized: {:#?}", deserialized);

    let serialized_again = compose(&deserialized).unwrap();
    assert_eq!(serialized, serialized_again);

    let buf_base64_again = BASE64_STANDARD_NO_PAD.encode(&serialized_again);
    assert_eq!(buf_base64, buf_base64_again);
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
