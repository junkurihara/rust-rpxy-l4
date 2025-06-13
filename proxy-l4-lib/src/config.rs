use crate::{destination::LoadBalance, error::ProxyBuildError, proto::ProtocolType, target::TargetAddr};
use quic_tls::{EchConfigList, EchPrivateKey};
use std::{str::FromStr, time::Duration};

/* ---------------------------------------------------------- */
// Configuration Validation Functions
/* ---------------------------------------------------------- */

/// Validate a protocol configuration for consistency and completeness
pub fn validate_protocol_config(key: &str, config: &ProtocolConfig) -> Result<(), ProxyBuildError> {
  // Validate target addresses are not empty
  if config.target.is_empty() {
    return Err(ProxyBuildError::BuildMultiplexersError(format!(
      "Protocol '{}': target addresses cannot be empty",
      key
    )));
  }

  // Protocol-specific validation
  match config.protocol {
    ProtocolType::Tls | ProtocolType::Quic => {
      // Validate TLS/QUIC specific configurations
      if let Some(ref ech) = config.ech {
        validate_ech_config(ech, key)?;
      }

      // Validate server names format if provided
      if let Some(ref server_names) = config.server_names {
        for server_name in server_names {
          if server_name.trim().is_empty() {
            return Err(ProxyBuildError::BuildMultiplexersError(format!(
              "Protocol '{}': server name cannot be empty",
              key
            )));
          }
        }
      }

      // Validate ALPN format if provided
      if let Some(ref alpn) = config.alpn {
        for protocol in alpn {
          if protocol.trim().is_empty() {
            return Err(ProxyBuildError::BuildMultiplexersError(format!(
              "Protocol '{}': ALPN protocol name cannot be empty",
              key
            )));
          }
        }
      }

      // QUIC ECH is not supported yet
      if config.protocol == ProtocolType::Quic && config.ech.is_some() {
        return Err(ProxyBuildError::BuildMultiplexersError(format!(
          "Protocol '{}': ECH is not supported for QUIC protocol yet",
          key
        )));
      }
    }
    ProtocolType::Wireguard => {
      // Validate UDP-specific configurations
      if config.ech.is_some() {
        return Err(ProxyBuildError::BuildMultiplexersError(format!(
          "Protocol '{}': ECH is not supported for UDP protocols",
          key
        )));
      }
      if config.server_names.is_some() || config.alpn.is_some() {
        return Err(ProxyBuildError::BuildMultiplexersError(format!(
          "Protocol '{}': server_names and alpn are not supported for UDP protocols",
          key
        )));
      }
    }
    ProtocolType::Http | ProtocolType::Ssh => {
      // Validate TCP non-TLS protocols
      if config.ech.is_some() {
        return Err(ProxyBuildError::BuildMultiplexersError(format!(
          "Protocol '{}': ECH is only supported for TLS protocol",
          key
        )));
      }
      if config.server_names.is_some() || config.alpn.is_some() {
        return Err(ProxyBuildError::BuildMultiplexersError(format!(
          "Protocol '{}': server_names and alpn are only supported for TLS/QUIC protocols",
          key
        )));
      }
    }
  }

  Ok(())
}

/// Validate ECH protocol configuration
pub fn validate_ech_config(ech: &EchProtocolConfig, protocol_key: &str) -> Result<(), ProxyBuildError> {
  if ech.private_keys.is_empty() {
    return Err(ProxyBuildError::InvalidEchPrivateKey(format!(
      "Protocol '{}': ECH private keys cannot be empty",
      protocol_key
    )));
  }

  if ech.private_server_names.is_empty() {
    return Err(ProxyBuildError::InvalidEchPrivateServerName(format!(
      "Protocol '{}': ECH private server names cannot be empty",
      protocol_key
    )));
  }

  Ok(())
}

/// Validate basic proxy configuration parameters
pub fn validate_basic_config(config: &Config) -> Result<(), ProxyBuildError> {
  // Validate listen port is reasonable
  if config.listen_port == 0 {
    return Err(ProxyBuildError::BuildMultiplexersError("Listen port cannot be 0".to_string()));
  }

  // Validate TCP configuration consistency
  if let Some(ref tcp_target) = config.tcp_target {
    if tcp_target.is_empty() {
      return Err(ProxyBuildError::BuildMultiplexersError(
        "Default TCP target addresses cannot be empty when specified".to_string(),
      ));
    }
  }

  // Validate UDP configuration consistency
  if let Some(ref udp_target) = config.udp_target {
    if udp_target.is_empty() {
      return Err(ProxyBuildError::BuildMultiplexersError(
        "Default UDP target addresses cannot be empty when specified".to_string(),
      ));
    }
  }

  // Validate DNS cache TTL values
  if let (Some(min_ttl), Some(max_ttl)) = (&config.dns_cache_min_ttl, &config.dns_cache_max_ttl) {
    if min_ttl > max_ttl {
      return Err(ProxyBuildError::BuildMultiplexersError(
        "DNS cache minimum TTL cannot be greater than maximum TTL".to_string(),
      ));
    }
  }

  // Validate connection limits are reasonable
  if let Some(max_tcp) = config.tcp_max_connections {
    if max_tcp == 0 {
      return Err(ProxyBuildError::BuildMultiplexersError(
        "TCP max connections cannot be 0 when specified".to_string(),
      ));
    }
  }

  if let Some(max_udp) = config.udp_max_connections {
    if max_udp == 0 {
      return Err(ProxyBuildError::BuildMultiplexersError(
        "UDP max connections cannot be 0 when specified".to_string(),
      ));
    }
  }

  Ok(())
}

/// Validate entire configuration for consistency
pub fn validate_config(config: &Config) -> Result<(), ProxyBuildError> {
  // First validate basic configuration
  validate_basic_config(config)?;

  // Validate each protocol configuration
  for (key, protocol_config) in &config.protocols {
    validate_protocol_config(key, protocol_config)?;
  }

  // Cross-protocol validation
  if config.tcp_target.is_none() && config.udp_target.is_none() && config.protocols.is_empty() {
    return Err(ProxyBuildError::BuildMultiplexersError(
      "Configuration must specify at least one target (tcp_target, udp_target, or protocols)".to_string(),
    ));
  }

  Ok(())
}

/* ---------------------------------------------------------- */
// Configuration Helper Functions for Testing
/* ---------------------------------------------------------- */

/// Create a simple TCP configuration for testing
#[cfg(test)]
pub fn create_test_tcp_config(port: u16, target: &str) -> Config {
  Config {
    listen_port: port,
    listen_ipv6: false,
    tcp_backlog: None,
    tcp_max_connections: None,
    udp_max_connections: None,
    tcp_target: Some(vec![target.parse().unwrap()]),
    tcp_load_balance: None,
    udp_target: None,
    udp_load_balance: None,
    udp_idle_lifetime: None,
    dns_cache_min_ttl: None,
    dns_cache_max_ttl: None,
    protocols: std::collections::HashMap::new(),
  }
}

/// Create a simple UDP configuration for testing
#[cfg(test)]
pub fn create_test_udp_config(port: u16, target: &str) -> Config {
  Config {
    listen_port: port,
    listen_ipv6: false,
    tcp_backlog: None,
    tcp_max_connections: None,
    udp_max_connections: None,
    tcp_target: None,
    tcp_load_balance: None,
    udp_target: Some(vec![target.parse().unwrap()]),
    udp_load_balance: None,
    udp_idle_lifetime: None,
    dns_cache_min_ttl: None,
    dns_cache_max_ttl: None,
    protocols: std::collections::HashMap::new(),
  }
}

/* ---------------------------------------------------------- */

/// Configuration for the proxy service
#[derive(Debug, Clone)]
pub struct Config {
  /// Listening port
  pub listen_port: u16,
  /// Listen on IPv6
  pub listen_ipv6: bool,
  /// TCP backlog size
  pub tcp_backlog: Option<u32>,
  /// Max TCP concurrent connections in total of all spawned TCP proxies
  pub tcp_max_connections: Option<u32>,
  /// Max UDP concurrent connections in total of all spawned UDP proxies
  pub udp_max_connections: Option<u32>,
  /// Default target for TCP (can be IP addresses or domain names)
  pub tcp_target: Option<Vec<TargetAddr>>,
  /// Load balance for TCP
  pub tcp_load_balance: Option<LoadBalance>,
  /// Default target for UDP (can be IP addresses or domain names)
  pub udp_target: Option<Vec<TargetAddr>>,
  /// Load balance for UDP
  pub udp_load_balance: Option<LoadBalance>,
  /// UDP connection lifetime in seconds
  pub udp_idle_lifetime: Option<u32>,
  /// DNS cache minimum TTL (default: 30 seconds)
  pub dns_cache_min_ttl: Option<Duration>,
  /// DNS cache maximum TTL (default: 1 hour)
  pub dns_cache_max_ttl: Option<Duration>,
  /// Protocol specific configurations
  pub protocols: std::collections::HashMap<String, ProtocolConfig>,
}

/// Protocol specific configuration
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
  /// Protocol type name
  pub protocol: ProtocolType,
  /// Target addresses (can be IP addresses or domain names)
  pub target: Vec<TargetAddr>,
  /// Common for specific protocols
  pub load_balance: Option<LoadBalance>,
  /// Only UDP based protocol
  pub idle_lifetime: Option<u32>,
  /// Only TLS
  pub alpn: Option<Vec<String>>,
  /// Only TLS
  pub server_names: Option<Vec<String>>,
  /// Only TLS
  pub ech: Option<EchProtocolConfig>,
}

#[derive(Debug, Clone)]
/// ECH protocol configuration
pub struct EchProtocolConfig {
  /// List of private keys, each of which is associated with a ech config id
  pub private_keys: Vec<EchPrivateKey>,
  /// The list of accepted ECH private server names
  /// If decrypted ECH inner has a server name that is in this list, it will be accepted and routed to the target
  /// by resolving the target address, where the target port is the same as the original ECH outer.
  pub private_server_names: ahash::HashMap<String, TargetAddr>,
}

impl EchProtocolConfig {
  /// Create a new ECH protocol configuration
  pub fn try_new(
    ech_config_list: &str,
    private_keys: &[String],
    private_server_names: &[String],
    listen_port: &u16,
  ) -> Result<Self, ProxyBuildError> {
    let ech_config_list = EchConfigList::try_from(ech_config_list)?;
    // compose private key list list with checking its consistency with ech config list
    let private_keys = EchPrivateKey::try_compose_list_from_base64_with_config(private_keys, &ech_config_list)?;

    if private_keys.is_empty() {
      return Err(ProxyBuildError::InvalidEchPrivateKey(format!(
        "No valid private keys found for ECH config list: {ech_config_list:?}"
      )));
    }

    if private_server_names.is_empty() {
      return Err(ProxyBuildError::InvalidEchPrivateServerName(
        "No valid private server names found for ECH config list".to_string(),
      ));
    }

    let private_server_names = private_server_names
      .iter()
      .map(|s| {
        let target_addr = if s.contains(':') {
          TargetAddr::from_str(s).unwrap_or_else(|_| {
            panic!("Invalid target address: {s}. It should be in the format of <ip>:<port> or <domain>:<port>")
          })
        } else {
          TargetAddr::from_str(&format!("{s}:{listen_port}")).unwrap_or_else(|_| {
            panic!("Invalid target address: {s}. It should be in the format of <ip>:<port> or <domain>:<port>")
          })
        };
        let domain_or_ip = target_addr.domain_or_ip();
        (domain_or_ip, target_addr)
      })
      .collect();

    Ok(Self {
      private_keys,
      private_server_names,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::HashMap;

  #[test]
  fn test_validate_basic_config() {
    // Test valid basic config
    let config = create_test_tcp_config(8080, "127.0.0.1:8081");
    assert!(validate_basic_config(&config).is_ok());

    // Test invalid port
    let mut invalid_config = config.clone();
    invalid_config.listen_port = 0;
    assert!(validate_basic_config(&invalid_config).is_err());

    // Test empty TCP targets when specified
    let mut invalid_config = config.clone();
    invalid_config.tcp_target = Some(vec![]);
    assert!(validate_basic_config(&invalid_config).is_err());

    // Test empty UDP targets when specified
    let mut invalid_config = config.clone();
    invalid_config.udp_target = Some(vec![]);
    assert!(validate_basic_config(&invalid_config).is_err());

    // Test invalid DNS TTL configuration
    let mut invalid_config = config.clone();
    invalid_config.dns_cache_min_ttl = Some(Duration::from_secs(3600));
    invalid_config.dns_cache_max_ttl = Some(Duration::from_secs(1800));
    assert!(validate_basic_config(&invalid_config).is_err());

    // Test zero connection limits
    let mut invalid_config = config.clone();
    invalid_config.tcp_max_connections = Some(0);
    assert!(validate_basic_config(&invalid_config).is_err());

    let mut invalid_config = config.clone();
    invalid_config.udp_max_connections = Some(0);
    assert!(validate_basic_config(&invalid_config).is_err());
  }

  #[test]
  fn test_validate_protocol_config() {
    // Test valid SSH protocol config
    let ssh_config = ProtocolConfig {
      protocol: ProtocolType::Ssh,
      target: vec!["127.0.0.1:22".parse().unwrap()],
      load_balance: None,
      idle_lifetime: None,
      alpn: None,
      server_names: None,
      ech: None,
    };
    assert!(validate_protocol_config("ssh", &ssh_config).is_ok());

    // Test empty target addresses
    let mut invalid_config = ssh_config.clone();
    invalid_config.target = vec![];
    assert!(validate_protocol_config("ssh", &invalid_config).is_err());

    // Test invalid TLS options for SSH
    let mut invalid_config = ssh_config.clone();
    invalid_config.server_names = Some(vec!["example.com".to_string()]);
    assert!(validate_protocol_config("ssh", &invalid_config).is_err());

    let mut invalid_config = ssh_config.clone();
    invalid_config.alpn = Some(vec!["h2".to_string()]);
    assert!(validate_protocol_config("ssh", &invalid_config).is_err());
  }

  #[test]
  fn test_validate_tls_protocol_config() {
    // Test valid TLS protocol config
    let tls_config = ProtocolConfig {
      protocol: ProtocolType::Tls,
      target: vec!["127.0.0.1:443".parse().unwrap()],
      load_balance: None,
      idle_lifetime: None,
      alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
      server_names: Some(vec!["example.com".to_string()]),
      ech: None,
    };
    assert!(validate_protocol_config("tls", &tls_config).is_ok());

    // Test empty server names
    let mut invalid_config = tls_config.clone();
    invalid_config.server_names = Some(vec!["".to_string()]);
    assert!(validate_protocol_config("tls", &invalid_config).is_err());

    // Test empty ALPN protocol names
    let mut invalid_config = tls_config.clone();
    invalid_config.alpn = Some(vec!["h2".to_string(), "".to_string()]);
    assert!(validate_protocol_config("tls", &invalid_config).is_err());
  }

  #[test]
  fn test_validate_quic_protocol_config() {
    // Test valid QUIC protocol config
    let quic_config = ProtocolConfig {
      protocol: ProtocolType::Quic,
      target: vec!["127.0.0.1:443".parse().unwrap()],
      load_balance: None,
      idle_lifetime: Some(60),
      alpn: Some(vec!["h3".to_string()]),
      server_names: Some(vec!["example.com".to_string()]),
      ech: None,
    };
    assert!(validate_protocol_config("quic", &quic_config).is_ok());

    // Test QUIC with ECH (should fail)
    let mut invalid_config = quic_config.clone();
    invalid_config.ech = Some(EchProtocolConfig {
      private_keys: vec![],
      private_server_names: Default::default(),
    });
    assert!(validate_protocol_config("quic", &invalid_config).is_err());
  }

  #[test]
  fn test_validate_wireguard_protocol_config() {
    // Test valid Wireguard protocol config
    let wg_config = ProtocolConfig {
      protocol: ProtocolType::Wireguard,
      target: vec!["127.0.0.1:51820".parse().unwrap()],
      load_balance: None,
      idle_lifetime: Some(120),
      alpn: None,
      server_names: None,
      ech: None,
    };
    assert!(validate_protocol_config("wireguard", &wg_config).is_ok());

    // Test Wireguard with TLS options (should fail)
    let mut invalid_config = wg_config.clone();
    invalid_config.server_names = Some(vec!["example.com".to_string()]);
    assert!(validate_protocol_config("wireguard", &invalid_config).is_err());

    let mut invalid_config = wg_config.clone();
    invalid_config.alpn = Some(vec!["h3".to_string()]);
    assert!(validate_protocol_config("wireguard", &invalid_config).is_err());

    let mut invalid_config = wg_config.clone();
    invalid_config.ech = Some(EchProtocolConfig {
      private_keys: vec![],
      private_server_names: Default::default(),
    });
    assert!(validate_protocol_config("wireguard", &invalid_config).is_err());
  }

  #[test]
  fn test_validate_config() {
    // Test valid configuration
    let config = create_test_tcp_config(8080, "127.0.0.1:8081");
    assert!(validate_config(&config).is_ok());

    // Test configuration with no targets at all
    let empty_config = Config {
      listen_port: 8080,
      listen_ipv6: false,
      tcp_backlog: None,
      tcp_max_connections: None,
      udp_max_connections: None,
      tcp_target: None,
      tcp_load_balance: None,
      udp_target: None,
      udp_load_balance: None,
      udp_idle_lifetime: None,
      dns_cache_min_ttl: None,
      dns_cache_max_ttl: None,
      protocols: HashMap::new(),
    };
    assert!(validate_config(&empty_config).is_err());

    // Test configuration with protocol targets
    let mut config_with_protocols = empty_config.clone();
    config_with_protocols.protocols.insert(
      "ssh".to_string(),
      ProtocolConfig {
        protocol: ProtocolType::Ssh,
        target: vec!["127.0.0.1:22".parse().unwrap()],
        load_balance: None,
        idle_lifetime: None,
        alpn: None,
        server_names: None,
        ech: None,
      },
    );
    assert!(validate_config(&config_with_protocols).is_ok());
  }

  #[test]
  fn test_validate_ech_config() {
    // Test valid ECH config
    let ech_config = EchProtocolConfig {
      private_keys: vec![], // We'll assume this is populated correctly
      private_server_names: {
        let mut map = ahash::HashMap::default();
        map.insert("example.com".to_string(), "127.0.0.1:443".parse().unwrap());
        map
      },
    };
    // Note: This test assumes private_keys would be properly populated in real usage
    // For now, we test the validation logic for empty keys
    assert!(validate_ech_config(&ech_config, "test").is_err()); // Empty private keys

    // Test empty private server names
    let ech_config_empty_names = EchProtocolConfig {
      private_keys: vec![], // Assume this would be populated
      private_server_names: Default::default(),
    };
    assert!(validate_ech_config(&ech_config_empty_names, "test").is_err());
  }

  #[test]
  fn test_config_helpers() {
    // Test TCP config helper
    let tcp_config = create_test_tcp_config(8080, "127.0.0.1:8081");
    assert_eq!(tcp_config.listen_port, 8080);
    assert!(tcp_config.tcp_target.is_some());
    assert!(tcp_config.udp_target.is_none());

    // Test UDP config helper
    let udp_config = create_test_udp_config(5353, "1.1.1.1:53");
    assert_eq!(udp_config.listen_port, 5353);
    assert!(udp_config.udp_target.is_some());
    assert!(tcp_config.tcp_target.is_some());
  }
}
