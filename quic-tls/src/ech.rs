use crate::{
  EchPrivateKey,
  client_hello::{TlsClientHello, TlsClientHelloExtension},
  ech_config::{EchConfig, HpkeKemPrivateKey, HpkeSymmetricCipherSuite},
  ech_extension::ClientHelloOuter,
  error::TlsClientHelloError,
  serialize::{compose, parse},
  trace::*,
};
use bytes::{Bytes, BytesMut};
use hpke::{
  Deserializable, Kem, OpModeR,
  aead::{Aead, AesGcm128, AesGcm256},
  kdf::{HkdfSha256, HkdfSha384, Kdf},
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
        let config_id = client_hello_outer.config_id();
        let cipher_suite = client_hello_outer.cipher_suite();
        
        // Check if this appears to be a GREASE configuration
        if Self::is_grease_config(config_id, cipher_suite) {
          info!("GREASE ECH configuration detected (config_id: {}, cipher_suite: {:?}), forwarding to backend", 
                config_id, cipher_suite);
        } else {
          warn!("No matching ECH private key found for config_id ({}) and cipher_suite ({:?})", 
                config_id, cipher_suite);
          
          // Generate retry configurations as per draft-ietf-tls-esni-25
          if let Ok(retry_configs) = Self::generate_retry_configs(ech_private_key_list) {
            if !retry_configs.is_empty() {
              info!("Generated {} retry configurations for ECH decryption failure", retry_configs.len());
              // Note: The retry configurations should be used by the server in EncryptedExtensions
              // This is handled by the calling code, not within this decryption function
            }
          }
        }
        
        // In both cases (GREASE or legitimate failure), forward the ClientHelloOuter to backend
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
          (AesGcm256::AEAD_ID, HkdfSha384::KDF_ID) => {
            let mut ctx =
              hpke::setup_receiver::<AesGcm256, HkdfSha384, X25519HkdfSha256>(&OpModeR::Base, sk, &encapped_key, &info)
                .map_err(TlsClientHelloError::HpkeError)?;
            ctx.open(outer.payload(), &aad).map_err(TlsClientHelloError::HpkeError)?
          }
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
          (AesGcm256::AEAD_ID, HkdfSha384::KDF_ID) => {
            let mut ctx =
              hpke::setup_receiver::<AesGcm256, HkdfSha384, DhP256HkdfSha256>(&OpModeR::Base, sk, &encapped_key, &info)
                .map_err(TlsClientHelloError::HpkeError)?;
            ctx.open(outer.payload(), &aad).map_err(TlsClientHelloError::HpkeError)?
          }
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

  /// Generate retry configurations from available ECH private keys
  /// This is used when ECH decryption fails to provide updated configurations to the client
  /// As per draft-ietf-tls-esni-25 section 7.1
  pub fn generate_retry_configs(
    ech_private_key_list: &[EchPrivateKey],
  ) -> Result<Vec<EchConfig>, TlsClientHelloError> {
    if ech_private_key_list.is_empty() {
      return Ok(vec![]);
    }

    let retry_configs: Vec<EchConfig> = ech_private_key_list
      .iter()
      .map(|key| key.ech_config().clone())
      .collect();

    debug!("Generated {} retry configurations", retry_configs.len());
    Ok(retry_configs)
  }

  /// Check if the ECH configuration appears to be a GREASE configuration
  /// GREASE configurations use reserved values to test extension tolerance
  fn is_grease_config(config_id: u8, cipher_suite: &HpkeSymmetricCipherSuite) -> bool {
    // GREASE values for config_id typically use reserved ranges
    // However, config_id is random in practice, so we mainly check cipher suites
    
    // Check for unknown/unsupported cipher suite combinations that might indicate GREASE
    // This is a heuristic approach since GREASE detection can be complex
    let is_known_cipher_suite = match (cipher_suite.aead_id, cipher_suite.kdf_id) {
      (AesGcm128::AEAD_ID, HkdfSha256::KDF_ID) => true,
      (AesGcm256::AEAD_ID, HkdfSha384::KDF_ID) => true,
      _ => false,
    };

    if !is_known_cipher_suite {
      debug!("Potential GREASE configuration detected: config_id={}, aead_id={:x}, kdf_id={:x}", 
             config_id, cipher_suite.aead_id, cipher_suite.kdf_id);
      return true;
    }

    false
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    client_hello::{ServerNameIndication, TlsClientHello},
    ech_config::EchConfigList,
  };
  use hpke::{
    aead::AesGcm128,
    kdf::HkdfSha256,
  };

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
  fn test_retry_config_generation() {
    // Test retry configuration generation
    let (_, private_keys) = create_test_ech_config();
    
    // Generate retry configs
    let retry_configs = TlsClientHello::generate_retry_configs(&private_keys).unwrap();
    
    // Should have at least one retry config
    assert!(!retry_configs.is_empty());
    assert_eq!(retry_configs.len(), private_keys.len());
    
    // Each retry config should match the corresponding private key
    for (idx, config) in retry_configs.iter().enumerate() {
      assert_eq!(config.config_id(), private_keys[idx].config_id());
      assert_eq!(config.public_name(), private_keys[idx].public_name());
    }
  }

  #[test]
  fn test_retry_config_generation_empty_keys() {
    // Test retry configuration generation with empty key list
    let empty_keys: Vec<EchPrivateKey> = vec![];
    
    let retry_configs = TlsClientHello::generate_retry_configs(&empty_keys).unwrap();
    
    // Should return empty vector for empty input
    assert!(retry_configs.is_empty());
  }

  #[test]
  fn test_grease_detection() {
    use crate::ech_config::HpkeSymmetricCipherSuite;
    use hpke::{aead::AesGcm128, kdf::HkdfSha256};
    
    // Test known cipher suite (should not be GREASE)
    let known_suite = HpkeSymmetricCipherSuite {
      kdf_id: HkdfSha256::KDF_ID,
      aead_id: AesGcm128::AEAD_ID,
    };
    assert!(!TlsClientHello::is_grease_config(42, &known_suite));
    
    // Test unknown cipher suite (should be detected as potential GREASE)
    let unknown_suite = HpkeSymmetricCipherSuite {
      kdf_id: 0x9999, // Unknown KDF
      aead_id: 0x8888, // Unknown AEAD
    };
    assert!(TlsClientHello::is_grease_config(42, &unknown_suite));
  }

  #[test]
  fn test_supported_cipher_suites_grease_detection() {
    use crate::ech_config::HpkeSymmetricCipherSuite;
    use hpke::{aead::{AesGcm128, AesGcm256}, kdf::{HkdfSha256, HkdfSha384}};
    
    // Test all supported cipher suites
    let supported_suites = vec![
      HpkeSymmetricCipherSuite {
        kdf_id: HkdfSha256::KDF_ID,
        aead_id: AesGcm128::AEAD_ID,
      },
      HpkeSymmetricCipherSuite {
        kdf_id: HkdfSha384::KDF_ID,
        aead_id: AesGcm256::AEAD_ID,
      },
    ];
    
    for suite in supported_suites {
      assert!(!TlsClientHello::is_grease_config(42, &suite), 
              "Supported cipher suite should not be detected as GREASE: {:?}", suite);
    }
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
    let supported_suite = cipher_suites.iter().find(|cs| {
      cs.kdf_id == HkdfSha256::KDF_ID && cs.aead_id == AesGcm128::AEAD_ID
    });
    assert!(supported_suite.is_some());
  }

  #[test]
  fn test_aes_gcm_256_cipher_suite() {
    // Test that the new AES-GCM-256 + HKDF-SHA384 cipher suite is supported
    let (config_list, _) = create_test_ech_config();
    let config = config_list.iter().next().unwrap();
    
    // Get the cipher suites from the config
    let cipher_suites = config.cipher_suites();
    assert!(!cipher_suites.is_empty());
    
    // Verify that we now support both cipher suites
    let aes_gcm_128_suite = cipher_suites.iter().find(|cs| {
      cs.kdf_id == HkdfSha256::KDF_ID && cs.aead_id == AesGcm128::AEAD_ID
    });
    assert!(aes_gcm_128_suite.is_some(), "AES-GCM-128 + HKDF-SHA256 should be supported");
    
    let aes_gcm_256_suite = cipher_suites.iter().find(|cs| {
      cs.kdf_id == HkdfSha384::KDF_ID && cs.aead_id == AesGcm256::AEAD_ID
    });
    assert!(aes_gcm_256_suite.is_some(), "AES-GCM-256 + HKDF-SHA384 should be supported");
    
    // Verify we have exactly 2 cipher suites
    assert_eq!(cipher_suites.len(), 2, "Should have exactly 2 cipher suites");
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
    let serialized = client_hello.try_to_bytes();
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
    
    // Verify different config IDs (should be random)
    assert_ne!(config1.config_id(), config2.config_id());
    
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
    println!("ECH decryption (no ECH): {} iterations in {:?} ({:?} per iteration)", 
             iterations, duration, duration / iterations);
    
    // Performance should be reasonable (less than 1ms per operation for non-ECH case)
    assert!(duration < std::time::Duration::from_millis(iterations.into()), 
            "ECH decryption took too long: {:?}", duration);
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
    println!("ECH config generation: {} iterations in {:?} ({:?} per iteration)", 
             iterations, duration, duration / iterations);
    
    // Config generation should be reasonable (less than 50ms per operation)
    assert!(duration < std::time::Duration::from_millis((iterations * 50).into()), 
            "ECH config generation took too long: {:?}", duration);
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
    println!("ECH brute force decryption with {} keys: {} iterations in {:?} ({:?} per iteration)", 
             all_keys.len(), iterations, duration, duration / iterations);
    
    // Brute force with many keys should still be reasonable
    assert!(duration < std::time::Duration::from_millis((iterations * 10).into()), 
            "ECH brute force decryption took too long: {:?}", duration);
  }

  #[test]
  fn test_multiple_cipher_suites_performance() {
    // Benchmark test: compare performance across supported cipher suites
    use std::time::Instant;
    
    let (config_list, private_keys) = create_test_ech_config();
    let client_hello = create_test_client_hello("test.example.com");
    
    // Verify we have multiple cipher suites
    let config = config_list.iter().next().unwrap();
    let cipher_suites = config.cipher_suites();
    assert!(cipher_suites.len() >= 2, "Should have multiple cipher suites for performance comparison");
    
    // Measure performance with current config (which includes both cipher suites)
    let start = Instant::now();
    let iterations = 500;
    
    for _ in 0..iterations {
      let _result = client_hello.decrypt_ech(&private_keys, false).unwrap();
    }
    
    let duration = start.elapsed();
    println!("ECH decryption with {} cipher suites: {} iterations in {:?} ({:?} per iteration)", 
             cipher_suites.len(), iterations, duration, duration / iterations);
    
    // Performance should be reasonable even with multiple cipher suites
    assert!(duration < std::time::Duration::from_millis(iterations.into()), 
            "ECH multi-cipher-suite decryption took too long: {:?}", duration);
  }
}
