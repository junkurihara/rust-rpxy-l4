use crate::{
  EchPrivateKey,
  client_hello::{ExtensionType, TlsClientHello, TlsClientHelloExtension},
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
use std::collections::HashSet;

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
        // TODO: As per https://datatracker.ietf.org/doc/html/rfc9849#section-7.1
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
      // https://datatracker.ietf.org/doc/html/rfc9849#section-7.1
      // Dispatch illegal_parameter alert
      return Err(TlsClientHelloError::PublicNameMismatch);
    }

    trace!("Decrypted and recomposed client hello inner: {decrypted_ch:#?}");
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

    self.decode_client_hello_inner(&encoded_client_hello_inner)
  }

  /// Reconstruct ClientHelloInner from a decrypted EncodedClientHelloInner and validate it
  /// as RFC 9849 Sections 5.1 and 7.1 require
  fn decode_client_hello_inner(&self, mut encoded_client_hello_inner: &[u8]) -> Result<TlsClientHello, TlsClientHelloError> {
    let mut client_hello_inner: TlsClientHello = parse(&mut encoded_client_hello_inner)?;
    // Every byte after the ClientHello is padding and must be zero
    if encoded_client_hello_inner.iter().any(|&byte| byte != 0) {
      error!("Non-zero padding in EncodedClientHelloInner");
      return Err(TlsClientHelloError::NonZeroEchPadding);
    }

    // Recompose the ClientHelloInner
    self.recompose_client_hello_inner(&mut client_hello_inner)?;

    // Checked after recomposition, since "supported_versions" may be copied from ClientHelloOuter
    if !client_hello_inner.offers_no_tls12_or_below() {
      error!("ClientHelloInner offers TLS 1.2 or below");
      return Err(TlsClientHelloError::Tls12OrBelowInDecryptedClientHello);
    }

    // Check if the ClientHelloInner is valid
    if client_hello_inner.sni().is_empty() {
      error!("ClientHelloInner SNI is empty");
      return Err(TlsClientHelloError::NoSniInDecryptedClientHello);
    }

    Ok(client_hello_inner)
  }

  /// Build aad from incoming TLS ClientHello for ECH decryption
  /// As indicated in https://datatracker.ietf.org/doc/html/rfc9849#section-5.2,
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
    let mut referenced_types = HashSet::new();
    let inner_extensions = compressed_inner.extensions();
    for ext in inner_extensions.iter() {
      if let TlsClientHelloExtension::OuterExtensions(outer_extensions_ext) = ext {
        trace!("OuterExtensions extension found: {:?}", outer_extensions_ext);
        // If outer extensions extension found, copy extensions in self.extensions() matched with extension_type
        let mut exts_in_outer = Vec::new();
        for outer_ext_type in outer_extensions_ext.iter() {
          // "encrypted_client_hello" must not be referenced (RFC 9849 Section 5.1)
          if outer_ext_type == ExtensionType::ECH {
            error!("OuterExtensions references encrypted_client_hello");
            return Err(TlsClientHelloError::InvalidOuterExtensionsExtension);
          }
          // No extension may be referenced more than once (RFC 9849 Section 5.1)
          if !referenced_types.insert(outer_ext_type) {
            error!("OuterExtensions references an extension more than once");
            return Err(TlsClientHelloError::InvalidOuterExtensionsExtension);
          }
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    client_hello::{ServerNameIndication, TlsClientHello},
    ech_config::EchConfigList,
    tls::probe_tls_handshake,
  };
  use hpke::{aead::AesGcm128, kdf::HkdfSha256};
  use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    client::{EchConfig as RustlsEchConfig, EchMode},
    crypto::aws_lc_rs,
    pki_types::{EchConfigListBytes, ServerName},
  };
  use std::sync::Arc;

  /// Helper function to create a test ECH configuration and private keys
  fn create_test_ech_config() -> (EchConfigList, Vec<EchPrivateKey>) {
    EchConfigList::generate("test.example.com").unwrap()
  }

  /// Helper function to create a test ClientHello with SNI
  fn create_test_client_hello(server_name: &str) -> TlsClientHello {
    let mut client_hello = TlsClientHello::default();
    let mut sni = ServerNameIndication::default();
    sni.add_server_name(server_name);
    client_hello.add_replace_sni(&sni);
    client_hello
  }

  #[test]
  fn test_no_ech_outer_returns_none() {
    // Create a regular ClientHello without ECH
    let client_hello = create_test_client_hello("test.example.com");
    let (_, private_keys) = create_test_ech_config();

    // Test decryption on non-ECH ClientHello
    let result = client_hello.decrypt_ech(&private_keys, false).unwrap();
    assert!(result.is_none());
  }

  #[test]
  fn test_grease_ech_handling() {
    // Test that we properly handle cases where no matching config is found
    let (_, private_keys) = create_test_ech_config();

    // Create a ClientHello without ECH (simulating no match case)
    let client_hello = create_test_client_hello("test.example.com");

    // Should return None when no ECH extension is present
    let result = client_hello.decrypt_ech(&private_keys, false).unwrap();
    assert!(result.is_none());
  }

  #[test]
  fn test_unsupported_cipher_suite() {
    // Test that we can detect supported cipher suites in ECH configs
    let (config_list, _) = create_test_ech_config();
    let config = config_list.iter().next().unwrap();

    // Get the cipher suites from the config
    let cipher_suites = config.cipher_suites();
    assert!(!cipher_suites.is_empty());

    // Verify AES-GCM-128 + HKDF-SHA256 is supported
    let supported_suite = cipher_suites
      .iter()
      .find(|cs| cs.kdf_id == HkdfSha256::KDF_ID && cs.aead_id == AesGcm128::AEAD_ID);
    assert!(supported_suite.is_some());
  }

  #[test]
  fn test_brute_force_with_multiple_keys() {
    // Create multiple ECH configs and keys
    let (_, keys1) = create_test_ech_config();
    let (_, keys2) = create_test_ech_config();

    // Create a regular ClientHello (no ECH)
    let client_hello = create_test_client_hello("test.example.com");

    // Combine all keys
    let mut all_keys = keys1;
    all_keys.extend(keys2);

    // Test brute force decryption (ignore_config_id = true)
    // Should return None because there's no ECH extension
    let result = client_hello.decrypt_ech(&all_keys, true).unwrap();
    assert!(result.is_none());
  }

  #[test]
  fn test_ech_extension_types() {
    // Test the helper methods for ECH detection
    let regular_hello = create_test_client_hello("regular.example.com");

    // A regular ClientHello should not be ECH inner or outer
    assert!(!regular_hello.is_ech_inner());
    assert!(!regular_hello.is_ech_outer());
  }

  #[test]
  fn test_ech_config_generation_and_validation() {
    // Test that we can generate ECH configs and private keys
    let (config_list, private_keys) = create_test_ech_config();

    assert!(config_list.iter().count() > 0);
    assert!(!private_keys.is_empty());
    assert_eq!(config_list.iter().count(), private_keys.len());

    // Test that config_ids match between configs and keys
    let config = config_list.iter().next().unwrap();
    let private_key = private_keys.first().unwrap();

    assert_eq!(config.config_id(), private_key.config_id());

    // Test that public name is set correctly
    let public_name_bytes = config.public_name();
    let public_name = String::from_utf8_lossy(&public_name_bytes);
    assert_eq!(public_name, "test.example.com");
  }

  #[test]
  fn test_public_name_consistency_validation() {
    // This test validates the concept of public name consistency
    // In a real scenario, the outer ClientHello's SNI should match the ECH config's public name
    let (config_list, _) = create_test_ech_config();
    let config = config_list.iter().next().unwrap();

    let public_name_bytes = config.public_name();
    let public_name = String::from_utf8_lossy(&public_name_bytes);

    // Create outer hello with matching public name
    let matching_outer = create_test_client_hello(&public_name);
    let matching_sni = matching_outer.sni();
    assert_eq!(matching_sni, vec![public_name.to_string()]);

    // Create outer hello with non-matching public name
    let non_matching_outer = create_test_client_hello("different.example.com");
    let non_matching_sni = non_matching_outer.sni();
    assert_ne!(non_matching_sni, vec![public_name.to_string()]);
  }

  #[test]
  fn test_client_hello_serialization() {
    // Test that ClientHello can be serialized and deserialized
    let client_hello = create_test_client_hello("test.example.com");

    // Test serialization
    let serialized = compose(client_hello.clone());
    assert!(serialized.is_ok());

    let bytes = serialized.unwrap();
    assert!(!bytes.is_empty());

    // Verify SNI is present in serialized form
    let sni_list = client_hello.sni();
    assert_eq!(sni_list, vec!["test.example.com"]);
  }

  #[test]
  fn test_ech_private_key_properties() {
    // Test ECH private key properties
    let (config_list, private_keys) = create_test_ech_config();
    let config = config_list.iter().next().unwrap();
    let private_key = private_keys.first().unwrap();

    // Test that private key has expected properties
    assert_eq!(private_key.config_id(), config.config_id());

    let private_key_public_name = private_key.public_name();
    let config_public_name = config.public_name();
    assert_eq!(private_key_public_name, config_public_name);

    let private_key_cipher_suites = private_key.cipher_suites();
    let config_cipher_suites = config.cipher_suites();
    assert_eq!(private_key_cipher_suites, config_cipher_suites);
  }

  #[test]
  fn test_empty_private_key_list() {
    // Test behavior with empty private key list
    let client_hello = create_test_client_hello("test.example.com");
    let empty_keys: Vec<EchPrivateKey> = vec![];

    // Should return None when no private keys are provided
    let result = client_hello.decrypt_ech(&empty_keys, false).unwrap();
    assert!(result.is_none());

    // Same result with brute force mode
    let result_brute_force = client_hello.decrypt_ech(&empty_keys, true).unwrap();
    assert!(result_brute_force.is_none());
  }

  #[test]
  fn test_multiple_ech_configs() {
    // Test generation of multiple ECH configs with different public names
    let (config_list1, keys1) = create_test_ech_config();
    let (config_list2, keys2) = EchConfigList::generate("different.example.com").unwrap();

    // Verify different public names
    let config1 = config_list1.iter().next().unwrap();
    let config2 = config_list2.iter().next().unwrap();

    let public_name1_bytes = config1.public_name();
    let public_name1 = String::from_utf8_lossy(&public_name1_bytes);
    let public_name2_bytes = config2.public_name();
    let public_name2 = String::from_utf8_lossy(&public_name2_bytes);

    assert_eq!(public_name1, "test.example.com");
    assert_eq!(public_name2, "different.example.com");
    assert_ne!(public_name1, public_name2);

    // Random config IDs may legitimately collide across independent generations.
    assert_eq!(config1.config_id(), keys1.first().unwrap().config_id());
    assert_eq!(config2.config_id(), keys2.first().unwrap().config_id());

    // Test that keys can be combined
    let mut combined_keys = keys1;
    combined_keys.extend(keys2);
    assert_eq!(combined_keys.len(), 2);
  }

  #[test]
  fn test_ech_decryption_performance() {
    // Benchmark test: measure performance of ECH decryption operations
    use std::time::Instant;

    let (_, private_keys) = create_test_ech_config();
    let client_hello = create_test_client_hello("test.example.com");

    // Measure time for multiple decryption attempts
    let start = Instant::now();
    let iterations = 1000;

    for _ in 0..iterations {
      let _result = client_hello.decrypt_ech(&private_keys, false).unwrap();
    }

    let duration = start.elapsed();
    println!(
      "ECH decryption (no ECH): {} iterations in {:?} ({:?} per iteration)",
      iterations,
      duration,
      duration / iterations
    );

    // Performance should be reasonable (less than 1ms per operation for non-ECH case)
    assert!(
      duration < std::time::Duration::from_millis(iterations.into()),
      "ECH decryption took too long: {:?}",
      duration
    );
  }

  #[test]
  fn test_ech_config_generation_performance() {
    // Benchmark test: measure performance of ECH config generation
    use std::time::Instant;

    let start = Instant::now();
    let iterations = 10; // Reduced from 100 since config generation is computationally expensive

    for i in 0..iterations {
      let public_name = format!("test{}.example.com", i);
      let _result = EchConfigList::generate(&public_name).unwrap();
    }

    let duration = start.elapsed();
    println!(
      "ECH config generation: {} iterations in {:?} ({:?} per iteration)",
      iterations,
      duration,
      duration / iterations
    );

    // Config generation should be reasonable (less than 50ms per operation)
    assert!(
      duration < std::time::Duration::from_millis((iterations * 50).into()),
      "ECH config generation took too long: {:?}",
      duration
    );
  }

  #[test]
  fn test_ech_decryption_with_many_keys() {
    // Benchmark test: measure performance when searching through many keys
    use std::time::Instant;

    // Generate many ECH configs and keys
    let mut all_keys = Vec::new();
    for i in 0..50 {
      let public_name = format!("test{}.example.com", i);
      let (_, keys) = EchConfigList::generate(&public_name).unwrap();
      all_keys.extend(keys);
    }

    let client_hello = create_test_client_hello("test.example.com");

    // Measure time for brute force decryption with many keys
    let start = Instant::now();
    let iterations = 100;

    for _ in 0..iterations {
      let _result = client_hello.decrypt_ech(&all_keys, true).unwrap();
    }

    let duration = start.elapsed();
    println!(
      "ECH brute force decryption with {} keys: {} iterations in {:?} ({:?} per iteration)",
      all_keys.len(),
      iterations,
      duration,
      duration / iterations
    );

    // Brute force with many keys should still be reasonable
    assert!(
      duration < std::time::Duration::from_millis((iterations * 10).into()),
      "ECH brute force decryption took too long: {:?}",
      duration
    );
  }

  /* ------------------------------------------- */
  // Wire-format builders for ClientHelloOuter and EncodedClientHelloInner

  const SUPPORTED_GROUPS: u16 = 0x000a;
  const SUPPORTED_VERSIONS: u16 = 0x002b;
  const TLS13: u16 = 0x0304;
  const OUTER_SESSION_ID: [u8; 32] = [0x11; 32];

  fn ext(ext_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut ext = ext_type.to_be_bytes().to_vec();
    ext.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    ext.extend_from_slice(payload);
    ext
  }

  fn sni_ext(name: &str) -> Vec<u8> {
    let mut list = vec![0x00];
    list.extend_from_slice(&(name.len() as u16).to_be_bytes());
    list.extend_from_slice(name.as_bytes());
    let mut payload = (list.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(&list);
    ext(0x0000, &payload)
  }

  fn supported_groups_ext() -> Vec<u8> {
    ext(SUPPORTED_GROUPS, &[0x00, 0x02, 0x00, 0x1d])
  }

  fn supported_versions_ext(versions: &[u16]) -> Vec<u8> {
    let mut payload = vec![(versions.len() * 2) as u8];
    for version in versions {
      payload.extend_from_slice(&version.to_be_bytes());
    }
    ext(SUPPORTED_VERSIONS, &payload)
  }

  fn ech_outer_ext() -> Vec<u8> {
    let mut payload = vec![0x00]; // type outer
    payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // HKDF-SHA256, AES-128-GCM
    payload.push(0x2a); // config_id
    payload.extend_from_slice(&[0x00, 0x02, 0xaa, 0xbb]); // enc
    payload.extend_from_slice(&[0x00, 0x03, 0x01, 0x02, 0x03]); // payload
    ext(ExtensionType::ECH, &payload)
  }

  fn ech_inner_ext() -> Vec<u8> {
    ext(ExtensionType::ECH, &[0x01])
  }

  fn outer_extensions_ext(ext_types: &[u16]) -> Vec<u8> {
    let mut payload = vec![(ext_types.len() * 2) as u8];
    for ext_type in ext_types {
      payload.extend_from_slice(&ext_type.to_be_bytes());
    }
    ext(0xfd00, &payload)
  }

  /// ClientHello body (no handshake header) with the given session ID and extensions
  fn client_hello_body(session_id: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut body = 0x0303u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0u8; 32]);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    let extensions = extensions.concat();
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    body
  }

  fn outer_with(extensions: &[Vec<u8>]) -> TlsClientHello {
    parse(&mut client_hello_body(&OUTER_SESSION_ID, extensions).as_slice()).unwrap()
  }

  /// ClientHelloOuter with extensions SNI, supported_groups, supported_versions [TLS 1.3], ECH outer
  fn default_outer() -> TlsClientHello {
    outer_with(&[
      sni_ext("public.example"),
      supported_groups_ext(),
      supported_versions_ext(&[TLS13]),
      ech_outer_ext(),
    ])
  }

  /// EncodedClientHelloInner with SNI and ECH inner followed by `extensions`, without padding
  fn encoded_inner(extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut all = vec![sni_ext("private.example"), ech_inner_ext()];
    all.extend_from_slice(extensions);
    client_hello_body(&[], &all)
  }

  fn extension_types(client_hello: &TlsClientHello) -> Vec<u16> {
    client_hello.extensions().iter().map(|ext| ext.extension_type()).collect()
  }

  #[test]
  fn decode_recomposes_inner_from_outer_extensions() {
    let outer = default_outer();
    let mut encoded = encoded_inner(&[outer_extensions_ext(&[SUPPORTED_GROUPS, SUPPORTED_VERSIONS])]);
    encoded.extend_from_slice(&[0u8; 5]);

    let inner = outer.decode_client_hello_inner(&encoded).unwrap();

    assert_eq!(
      extension_types(&inner),
      vec![0x0000, ExtensionType::ECH, SUPPORTED_GROUPS, SUPPORTED_VERSIONS]
    );
    assert_eq!(inner.extensions()[2..], outer.extensions()[1..3]);
    assert_eq!(inner.legacy_session_id().as_ref(), OUTER_SESSION_ID.as_slice());
    assert_eq!(inner.sni(), vec!["private.example".to_string()]);
  }

  #[test]
  fn decode_rejects_non_zero_padding() {
    let mut encoded = encoded_inner(&[supported_versions_ext(&[TLS13])]);
    encoded.extend_from_slice(&[0x00, 0xff]);

    let result = default_outer().decode_client_hello_inner(&encoded);

    assert!(matches!(result, Err(TlsClientHelloError::NonZeroEchPadding)));
  }

  #[test]
  fn decode_rejects_reference_to_encrypted_client_hello() {
    for referenced in [vec![ExtensionType::ECH], vec![SUPPORTED_GROUPS, ExtensionType::ECH]] {
      let encoded = encoded_inner(&[outer_extensions_ext(&referenced), supported_versions_ext(&[TLS13])]);

      let result = default_outer().decode_client_hello_inner(&encoded);

      assert!(
        matches!(result, Err(TlsClientHelloError::InvalidOuterExtensionsExtension)),
        "OuterExtensions {referenced:x?}: {result:?}"
      );
    }
  }

  #[test]
  fn decode_requires_exactly_one_ech_inner_extension() {
    let supported_versions = supported_versions_ext(&[TLS13]);
    let cases = [
      (
        "ECH outer and ECH inner",
        vec![sni_ext("private.example"), ech_outer_ext(), ech_inner_ext()],
      ),
      (
        "two ECH inner",
        vec![sni_ext("private.example"), ech_inner_ext(), ech_inner_ext()],
      ),
      ("no ECH", vec![sni_ext("private.example")]),
    ];
    for (name, mut extensions) in cases {
      extensions.push(supported_versions.clone());
      let encoded = client_hello_body(&[], &extensions);

      let result = default_outer().decode_client_hello_inner(&encoded);

      assert!(
        matches!(result, Err(TlsClientHelloError::InvalidClientHelloRecomposition)),
        "{name}: {result:?}"
      );
    }
  }

  #[test]
  fn decode_rejects_ech_inner_extension_with_trailing_data() {
    let encoded = client_hello_body(
      &[],
      &[
        sni_ext("private.example"),
        ext(ExtensionType::ECH, &[0x01, 0xff]),
        supported_versions_ext(&[TLS13]),
      ],
    );

    let result = default_outer().decode_client_hello_inner(&encoded);

    assert!(matches!(result, Err(TlsClientHelloError::InvalidTlsClientHello)));
  }

  #[test]
  fn decode_rejects_inner_offering_tls12_or_below() {
    let cases = [
      ("no supported_versions", vec![]),
      ("TLS 1.2", vec![supported_versions_ext(&[0x0303])]),
      ("SSL 3.0", vec![supported_versions_ext(&[0x0300])]),
      ("TLS 1.3 and TLS 1.2", vec![supported_versions_ext(&[TLS13, 0x0303])]),
      ("length mismatch", vec![ext(SUPPORTED_VERSIONS, &[0x03, 0x03, 0x04])]),
      ("empty list", vec![ext(SUPPORTED_VERSIONS, &[0x00])]),
      ("odd length", vec![ext(SUPPORTED_VERSIONS, &[0x01, 0x03])]),
      ("empty payload", vec![ext(SUPPORTED_VERSIONS, &[])]),
      (
        "valid and TLS 1.2 extensions",
        vec![supported_versions_ext(&[TLS13]), supported_versions_ext(&[0x0303])],
      ),
    ];
    for (name, extensions) in cases {
      let result = default_outer().decode_client_hello_inner(&encoded_inner(&extensions));

      assert!(
        matches!(result, Err(TlsClientHelloError::Tls12OrBelowInDecryptedClientHello)),
        "{name}: {result:?}"
      );
    }
  }

  #[test]
  fn decode_ignores_unknown_supported_versions() {
    for versions in [[0x0a0a, TLS13], [TLS13, 0x0001], [0x7f1c, TLS13]] {
      let result = default_outer().decode_client_hello_inner(&encoded_inner(&[supported_versions_ext(&versions)]));

      assert!(result.is_ok(), "supported_versions {versions:x?}: {result:?}");
    }
  }

  #[test]
  fn decode_checks_supported_versions_copied_from_outer() {
    let outer = outer_with(&[
      sni_ext("public.example"),
      supported_versions_ext(&[TLS13, 0x0303]),
      ech_outer_ext(),
    ]);
    let encoded = encoded_inner(&[outer_extensions_ext(&[SUPPORTED_VERSIONS])]);

    let result = outer.decode_client_hello_inner(&encoded);

    assert!(matches!(result, Err(TlsClientHelloError::Tls12OrBelowInDecryptedClientHello)));
  }

  #[test]
  fn decode_rejects_missing_or_out_of_order_references() {
    for referenced in [vec![0x0017], vec![SUPPORTED_VERSIONS, SUPPORTED_GROUPS]] {
      let result = default_outer().decode_client_hello_inner(&encoded_inner(&[outer_extensions_ext(&referenced)]));

      assert!(
        matches!(result, Err(TlsClientHelloError::InvalidOuterExtensionsExtension)),
        "OuterExtensions {referenced:x?}: {result:?}"
      );
    }
  }

  #[test]
  fn decode_rejects_outer_extensions_with_trailing_data() {
    // The declared list is [supported_groups]; a reference to encrypted_client_hello follows outside it
    let outer_extensions = ext(0xfd00, &[0x02, 0x00, 0x0a, 0xfe, 0x0d]);
    let encoded = encoded_inner(&[outer_extensions, supported_versions_ext(&[TLS13])]);

    let result = default_outer().decode_client_hello_inner(&encoded);

    assert!(matches!(result, Err(TlsClientHelloError::InvalidTlsClientHello)));
  }

  #[test]
  fn decode_rejects_duplicate_references() {
    // Two supported_groups extensions in the outer, so a second reference would find a match
    let outer = outer_with(&[
      sni_ext("public.example"),
      supported_groups_ext(),
      supported_groups_ext(),
      supported_versions_ext(&[TLS13]),
      ech_outer_ext(),
    ]);
    let cases = [
      ("one list", vec![outer_extensions_ext(&[SUPPORTED_GROUPS, SUPPORTED_GROUPS])]),
      (
        "two lists",
        vec![
          outer_extensions_ext(&[SUPPORTED_GROUPS]),
          outer_extensions_ext(&[SUPPORTED_GROUPS]),
        ],
      ),
    ];
    for (name, mut extensions) in cases {
      extensions.push(supported_versions_ext(&[TLS13]));

      let result = outer.decode_client_hello_inner(&encoded_inner(&extensions));

      assert!(
        matches!(result, Err(TlsClientHelloError::InvalidOuterExtensionsExtension)),
        "{name}: {result:?}"
      );
    }

    // A single reference is still accepted
    let single = encoded_inner(&[outer_extensions_ext(&[SUPPORTED_GROUPS]), supported_versions_ext(&[TLS13])]);
    assert!(outer.decode_client_hello_inner(&single).is_ok());
  }

  #[test]
  fn rustls_ech_client_hello_is_decrypted() {
    let (config_list, keys) = create_test_ech_config();
    let config_list_bytes = compose(&config_list).unwrap().to_vec();
    let ech_config = RustlsEchConfig::new(
      EchConfigListBytes::from(config_list_bytes),
      aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )
    .unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
      .with_ech(EchMode::from(ech_config))
      .unwrap()
      .with_root_certificates(RootCertStore::empty())
      .with_no_client_auth();
    let mut connection = ClientConnection::new(Arc::new(config), ServerName::try_from("private.example").unwrap()).unwrap();
    let mut wire = Vec::new();
    connection.write_tls(&mut wire).unwrap();

    let outer = probe_tls_handshake(&mut wire.as_slice()).unwrap();
    assert_eq!(outer.client_hello.sni(), vec!["test.example.com".to_string()]);
    let inner = outer.client_hello.decrypt_ech(&keys, false).unwrap().unwrap();

    assert_eq!(inner.sni(), vec!["private.example".to_string()]);
    assert!(inner.offers_no_tls12_or_below());
  }
}
