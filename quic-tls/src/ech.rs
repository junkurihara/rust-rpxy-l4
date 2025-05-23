use crate::{
  EchPrivateKey,
  client_hello::{TlsClientHello, TlsClientHelloExtension},
  ech_config::{EchConfig, HpkeKemPrivateKey},
  ech_extension::ClientHelloOuter,
  error::TlsClientHelloError,
  serialize::{compose, parse},
  trace::*,
};
use bytes::{Bytes, BytesMut};
use hpke::{
  Deserializable, Kem, OpModeR,
  aead::{Aead, AesGcm128},
  kdf::HkdfSha256,
  kdf::Kdf,
  kem::{DhP256HkdfSha256, X25519HkdfSha256},
};

impl TlsClientHello {
  /// Implementation of the ECH decryption, return the re-composed ClientHelloInner
  /// If ignore_config_id is true, decryption will be attempted for all ech_secret_key
  /// Returns None if no ECH outer is found or decryption failed
  pub fn decrypt_ech(
    &self,
    ech_private_key_list: &[EchPrivateKey],
    ignore_config_id: bool,
  ) -> Result<Option<TlsClientHello>, TlsClientHelloError> {
    let Some(client_hello_outer) = self.get_ech_outer() else {
      // If no ECH outer, it means it is Inner or non-ECH TLS ClientHello, return None
      debug!("No ECH outer found");
      return Ok(None);
    };
    let public_server_names = self.sni().iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>();

    // Decrypt and obtain the ClientHelloInner
    let (decrypted_ch, config) = if ignore_config_id {
      let Some(res) = self._decrypt_ech_brute_force(&client_hello_outer, ech_private_key_list) else {
        warn!("Attempted to decrypt ECH with all keys, but no success");
        return Ok(None);
      };
      res
    } else {
      let config_id = client_hello_outer.config_id();
      let cipher_suite = client_hello_outer.cipher_suite();
      let Some(matched_ech_private_key) = ech_private_key_list
        .iter()
        .find(|key| key.config_id() == config_id && key.cipher_suites().contains(cipher_suite))
      else {
        warn!("No matching ECH private key found for config_id ({config_id}) and cipher_suite, possibly GREASE");
        warn!("Currently, we do no support replying with retry_configs, and just forward the ClientHelloOuter to the backend");
        // TODO: As per https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html#section-7.1
        // we should do:
        // > - If sending a HelloRetryRequest, the server MAY include an "encrypted_client_hello" extension
        // >   with a payload of 8 random bytes; see Section 10.10.4 for details.
        // > - If the server is configured with any ECHConfigs, it MUST include the "encrypted_client_hello"
        // >   extension in its EncryptedExtensions with the "retry_configs" field set to one or more ECHConfig
        // >   structures with up-to-date keys. Servers MAY supply multiple ECHConfig values of different versions.
        // >   This allows a server to support multiple versions at once.
        return Ok(None);
      };
      let res = self._decrypt_ech(&client_hello_outer, matched_ech_private_key)?;
      (res, matched_ech_private_key.ech_config().clone())
    };

    // Check the public name consistency
    let matched_config_public_name = String::from_utf8_lossy(&config.public_name()).to_ascii_lowercase();
    if !public_server_names.contains(&matched_config_public_name) {
      warn!("Public name mismatch: {matched_config_public_name} not in {public_server_names:?}");
      // https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html#section-7.1
      // Dispatch illegal_parameter alert
      return Err(TlsClientHelloError::PublicNameMismatch);
    }

    debug!("Decrypted and recomposed client hello inner: {decrypted_ch:#?}");
    Ok(Some(decrypted_ch))
  }

  /// Decryption with all keys
  fn _decrypt_ech_brute_force(
    &self,
    outer: &ClientHelloOuter,
    ech_private_key_list: &[EchPrivateKey],
  ) -> Option<(TlsClientHello, EchConfig)> {
    for ech_private_key in ech_private_key_list {
      if let Ok(d) = self._decrypt_ech(outer, ech_private_key) {
        return Some((d, ech_private_key.ech_config().clone()));
      }
    }
    None
  }

  /// Decryption
  fn _decrypt_ech(
    &self,
    outer: &ClientHelloOuter,
    ech_private_key: &EchPrivateKey,
  ) -> Result<TlsClientHello, TlsClientHelloError> {
    let ech_config = ech_private_key.ech_config();
    let sk = ech_private_key.private_key();

    // Build info for HKDF
    let config_bytes = compose(ech_config)?.freeze();
    let mut info = BytesMut::new();
    info.extend_from_slice(b"tls ech\0");
    info.extend_from_slice(&config_bytes);

    // Decrypt the payload
    let aad = self.build_aad()?;
    let cipher_suite = outer.cipher_suite();
    let encoded_client_hello_inner = match sk {
      HpkeKemPrivateKey::X25519(sk) => {
        let encapped_key =
          <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(outer.enc()).map_err(TlsClientHelloError::HpkeError)?;
        match (cipher_suite.aead_id, cipher_suite.kdf_id) {
          (AesGcm128::AEAD_ID, HkdfSha256::KDF_ID) => {
            let mut ctx =
              hpke::setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, sk, &encapped_key, &info)
                .map_err(TlsClientHelloError::HpkeError)?;
            ctx.open(outer.payload(), &aad).map_err(TlsClientHelloError::HpkeError)?
          }
          // TODO: Add more cipher suites
          _ => {
            error!(
              "Unsupported cipher suite for HPKE: {:x?}, {:x?}",
              cipher_suite.kdf_id, cipher_suite.aead_id
            );
            return Err(TlsClientHelloError::UnsupportedHpkeKdfAead);
          }
        }
      }
      HpkeKemPrivateKey::P256(sk) => {
        let encapped_key =
          <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(outer.enc()).map_err(TlsClientHelloError::HpkeError)?;
        match (cipher_suite.aead_id, cipher_suite.kdf_id) {
          (AesGcm128::AEAD_ID, HkdfSha256::KDF_ID) => {
            let mut ctx =
              hpke::setup_receiver::<AesGcm128, HkdfSha256, DhP256HkdfSha256>(&OpModeR::Base, sk, &encapped_key, &info)
                .map_err(TlsClientHelloError::HpkeError)?;
            ctx.open(outer.payload(), &aad).map_err(TlsClientHelloError::HpkeError)?
          }
          // TODO: Add more cipher suites
          _ => {
            error!(
              "Unsupported cipher suite for HPKE: {:x?}, {:x?}",
              cipher_suite.kdf_id, cipher_suite.aead_id
            );
            return Err(TlsClientHelloError::UnsupportedHpkeKdfAead);
          }
        }
      }
    };

    let mut client_hello_inner: TlsClientHello = parse(&mut encoded_client_hello_inner.as_slice())?;
    // Recompose the ClientHelloInner
    self.recompose_client_hello_inner(&mut client_hello_inner)?;

    // Check if the ClientHelloInner is valid
    if client_hello_inner.sni().is_empty() {
      error!("ClientHelloInner SNI is empty");
      return Err(TlsClientHelloError::NoSniInDecryptedClientHello);
    }

    Ok(client_hello_inner)
  }

  /// Build aad from incoming TLS ClientHello for ECH decryption
  /// As indicated in https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html#section-5.2,
  /// the aad is serialized TLS ClientHello which matches the ClientHelloOuter except that the payload field of the "encrypted_client_hello" is replaced with a byte string of the same length but whose contents are zeros.
  fn build_aad(&self) -> Result<Bytes, TlsClientHelloError> {
    let mut cloned = self.clone();
    cloned.fill_ech_payload_with_zeros();
    let aad = compose(cloned)?.freeze();
    Ok(aad)
  }

  /// Recompose the full ClientHelloInner from the decrypted and compressed ClientHelloInner with the information of ClientHelloOuter
  fn recompose_client_hello_inner(&self, compressed_inner: &mut TlsClientHello) -> Result<(), TlsClientHelloError> {
    compressed_inner.update_session_id(self.legacy_session_id());
    // Check if self is outer and compressed_inner is inner
    if !self.is_ech_outer() || !compressed_inner.is_ech_inner() {
      error!("Attempted to recompose ClientHelloInner from non-ECH outer or non-ECH inner");
      return Err(TlsClientHelloError::InvalidClientHelloRecomposition);
    }
    let outer_extensions = self.extensions();
    let mut outer_extensions = outer_extensions.iter();

    let mut new_extensions = Vec::new();
    let inner_extensions = compressed_inner.extensions();
    for ext in inner_extensions.iter() {
      if let TlsClientHelloExtension::OuterExtensions(outer_extensions_ext) = ext {
        trace!("OuterExtensions extension found: {:?}", outer_extensions_ext);
        // If outer extensions extension found, copy extensions in self.extensions() matched with extension_type
        let mut exts_in_outer = Vec::new();
        for outer_ext_type in outer_extensions_ext.iter() {
          // Proceed to the next extension until the matched one is found
          for outer_ext in outer_extensions.by_ref() {
            if outer_ext.extension_type() == outer_ext_type {
              exts_in_outer.push(outer_ext.clone());
              break;
            }
          }
        }
        if exts_in_outer.len() != outer_extensions_ext.len() {
          error!("Not all outer extensions found in self.extensions()");
          return Err(TlsClientHelloError::InvalidOuterExtensionsExtension);
        }
        new_extensions.extend(exts_in_outer);
      } else {
        new_extensions.push(ext.clone());
      }
    }

    compressed_inner.add_replace_extensions(&new_extensions);
    Ok(())
  }
}
