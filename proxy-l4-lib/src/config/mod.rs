use crate::{destination::LoadBalance, error::ProxyBuildError, proto::ProtocolType, target::TargetAddr};
use quic_tls::{EchConfigList, EchPrivateKey};
use std::{str::FromStr, time::Duration};

pub mod builder;
#[cfg(test)]
mod integration_tests;
pub mod protocols;
pub mod validation;

pub use builder::{ConfigBuilder, ProtocolConfigBuilder};
pub use protocols::*;
pub use validation::{ConfigValidationError, ValidationResult};

/// Configuration for the proxy service
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
#[derive(Debug)]
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
      return Err(ProxyBuildError::invalid_ech_private_key(format!(
        "No valid private keys found for ECH config list: {ech_config_list:?}"
      )));
    }

    if private_server_names.is_empty() {
      return Err(ProxyBuildError::invalid_ech_private_server_name(
        "No valid private server names found for ECH config list",
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
