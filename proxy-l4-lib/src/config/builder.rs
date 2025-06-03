use crate::{
  config::{Config, EchProtocolConfig, ProtocolConfig, validation::*},
  destination::LoadBalance,
  proto::ProtocolType,
  target::TargetAddr,
};
use std::{collections::HashMap, time::Duration};

/// Builder for creating proxy configurations with validation
#[derive(Debug, Default)]
pub struct ConfigBuilder {
  listen_port: Option<u16>,
  listen_ipv6: bool,
  tcp_backlog: Option<u32>,
  tcp_max_connections: Option<u32>,
  udp_max_connections: Option<u32>,
  tcp_target: Option<Vec<TargetAddr>>,
  tcp_load_balance: Option<LoadBalance>,
  udp_target: Option<Vec<TargetAddr>>,
  udp_load_balance: Option<LoadBalance>,
  udp_idle_lifetime: Option<u32>,
  dns_cache_min_ttl: Option<Duration>,
  dns_cache_max_ttl: Option<Duration>,
  protocols: HashMap<String, ProtocolConfig>,
}

impl ConfigBuilder {
  /// Create a new configuration builder
  pub fn new() -> Self {
    Self::default()
  }

  /// Set the listening port (required)
  pub fn with_listen_port(mut self, port: u16) -> Result<Self, ConfigValidationError> {
    BasicConfigValidator::validate_listen_port(port)?;
    self.listen_port = Some(port);
    Ok(self)
  }

  /// Enable or disable IPv6 listening
  pub fn with_ipv6(mut self, enabled: bool) -> Self {
    self.listen_ipv6 = enabled;
    self
  }

  /// Set TCP backlog size
  pub fn with_tcp_backlog(mut self, backlog: u32) -> Result<Self, ConfigValidationError> {
    BasicConfigValidator::validate_tcp_backlog(Some(backlog))?;
    self.tcp_backlog = Some(backlog);
    Ok(self)
  }

  /// Set maximum TCP connections
  pub fn with_tcp_max_connections(mut self, max: u32) -> Result<Self, ConfigValidationError> {
    BasicConfigValidator::validate_connection_limits(Some(max), self.udp_max_connections)?;
    self.tcp_max_connections = Some(max);
    Ok(self)
  }

  /// Set maximum UDP connections
  pub fn with_udp_max_connections(mut self, max: u32) -> Result<Self, ConfigValidationError> {
    BasicConfigValidator::validate_connection_limits(self.tcp_max_connections, Some(max))?;
    self.udp_max_connections = Some(max);
    Ok(self)
  }

  /// Set default TCP targets
  pub fn with_tcp_target(mut self, targets: Vec<&str>) -> Result<Self, ConfigValidationError> {
    let target_addrs: Result<Vec<TargetAddr>, _> = targets
      .iter()
      .map(|s| {
        s.parse::<TargetAddr>()
          .map_err(|e| ConfigValidationError::TargetAddressError {
            reason: format!("Invalid TCP target '{}': {}", s, e),
          })
      })
      .collect();

    let target_addrs = target_addrs?;
    TargetValidator::validate_targets(&target_addrs)?;
    self.tcp_target = Some(target_addrs);
    Ok(self)
  }

  /// Set TCP load balancing strategy
  pub fn with_tcp_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
    if let Some(ref targets) = self.tcp_target {
      TargetValidator::validate_load_balance_with_targets(Some(&lb), targets)?;
    }
    self.tcp_load_balance = Some(lb);
    Ok(self)
  }

  /// Set default UDP targets
  pub fn with_udp_target(mut self, targets: Vec<&str>) -> Result<Self, ConfigValidationError> {
    let target_addrs: Result<Vec<TargetAddr>, _> = targets
      .iter()
      .map(|s| {
        s.parse::<TargetAddr>()
          .map_err(|e| ConfigValidationError::TargetAddressError {
            reason: format!("Invalid UDP target '{}': {}", s, e),
          })
      })
      .collect();

    let target_addrs = target_addrs?;
    TargetValidator::validate_targets(&target_addrs)?;
    self.udp_target = Some(target_addrs);
    Ok(self)
  }

  /// Set UDP load balancing strategy
  pub fn with_udp_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
    if let Some(ref targets) = self.udp_target {
      TargetValidator::validate_load_balance_with_targets(Some(&lb), targets)?;
    }
    self.udp_load_balance = Some(lb);
    Ok(self)
  }

  /// Set UDP idle lifetime
  pub fn with_udp_idle_lifetime(mut self, lifetime: u32) -> Result<Self, ConfigValidationError> {
    if lifetime == 0 {
      return Err(ConfigValidationError::InvalidFieldValue {
        field: "udp_idle_lifetime".to_string(),
        value: lifetime.to_string(),
        reason: "UDP idle lifetime cannot be 0".to_string(),
      });
    }
    self.udp_idle_lifetime = Some(lifetime);
    Ok(self)
  }

  /// Set DNS cache TTL settings
  pub fn with_dns_cache_ttl(
    mut self,
    min_ttl: Option<Duration>,
    max_ttl: Option<Duration>,
  ) -> Result<Self, ConfigValidationError> {
    BasicConfigValidator::validate_dns_cache_ttl(min_ttl, max_ttl)?;
    self.dns_cache_min_ttl = min_ttl;
    self.dns_cache_max_ttl = max_ttl;
    Ok(self)
  }

  /// Add a protocol configuration
  pub fn with_protocol(mut self, name: String, protocol: ProtocolConfig) -> Result<Self, ConfigValidationError> {
    // Validate the protocol configuration
    ProtocolValidator::validate_protocol_config(
      &name,
      &protocol.protocol,
      &protocol.target,
      protocol.load_balance.as_ref(),
      protocol.idle_lifetime,
      protocol.alpn.as_deref(),
      protocol.server_names.as_deref(),
    )?;

    self.protocols.insert(name, protocol);
    Ok(self)
  }

  /// Build the final configuration
  pub fn build(self) -> Result<Config, ConfigValidationError> {
    let listen_port = self.listen_port.ok_or(ConfigValidationError::MissingRequiredField {
      field: "listen_port".to_string(),
    })?;

    // Final validation
    BasicConfigValidator::validate_listen_port(listen_port)?;
    BasicConfigValidator::validate_tcp_backlog(self.tcp_backlog)?;
    BasicConfigValidator::validate_connection_limits(self.tcp_max_connections, self.udp_max_connections)?;
    BasicConfigValidator::validate_dns_cache_ttl(self.dns_cache_min_ttl, self.dns_cache_max_ttl)?;

    Ok(Config {
      listen_port,
      listen_ipv6: self.listen_ipv6,
      tcp_backlog: self.tcp_backlog,
      tcp_max_connections: self.tcp_max_connections,
      udp_max_connections: self.udp_max_connections,
      tcp_target: self.tcp_target,
      tcp_load_balance: self.tcp_load_balance,
      udp_target: self.udp_target,
      udp_load_balance: self.udp_load_balance,
      udp_idle_lifetime: self.udp_idle_lifetime,
      dns_cache_min_ttl: self.dns_cache_min_ttl,
      dns_cache_max_ttl: self.dns_cache_max_ttl,
      protocols: self.protocols,
    })
  }
}

/// Builder for creating protocol configurations with validation
#[derive(Debug, Default)]
pub struct ProtocolConfigBuilder {
  protocol: Option<ProtocolType>,
  target: Vec<TargetAddr>,
  load_balance: Option<LoadBalance>,
  idle_lifetime: Option<u32>,
  alpn: Option<Vec<String>>,
  server_names: Option<Vec<String>>,
  ech: Option<EchProtocolConfig>,
}

impl ProtocolConfigBuilder {
  /// Create a new protocol configuration builder
  pub fn new() -> Self {
    Self::default()
  }

  /// Set the protocol type
  pub fn with_protocol(mut self, protocol: ProtocolType) -> Self {
    self.protocol = Some(protocol);
    self
  }

  /// Set target addresses
  pub fn with_targets(mut self, targets: Vec<&str>) -> Result<Self, ConfigValidationError> {
    let target_addrs: Result<Vec<TargetAddr>, _> = targets
      .iter()
      .map(|s| {
        s.parse::<TargetAddr>()
          .map_err(|e| ConfigValidationError::TargetAddressError {
            reason: format!("Invalid target '{}': {}", s, e),
          })
      })
      .collect();

    let target_addrs = target_addrs?;
    TargetValidator::validate_targets(&target_addrs)?;
    self.target = target_addrs;
    Ok(self)
  }

  /// Set load balancing strategy
  pub fn with_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
    TargetValidator::validate_load_balance_with_targets(Some(&lb), &self.target)?;
    self.load_balance = Some(lb);
    Ok(self)
  }

  /// Set idle lifetime (for UDP protocols)
  pub fn with_idle_lifetime(mut self, lifetime: u32) -> Result<Self, ConfigValidationError> {
    if lifetime == 0 {
      return Err(ConfigValidationError::InvalidFieldValue {
        field: "idle_lifetime".to_string(),
        value: lifetime.to_string(),
        reason: "Idle lifetime cannot be 0".to_string(),
      });
    }
    self.idle_lifetime = Some(lifetime);
    Ok(self)
  }

  /// Set ALPN protocols (for TLS/QUIC)
  pub fn with_alpn(mut self, alpn: Vec<String>) -> Result<Self, ConfigValidationError> {
    for alpn_proto in &alpn {
      if alpn_proto.is_empty() {
        return Err(ConfigValidationError::ProtocolValidationError {
          protocol_name: "protocol".to_string(),
          reason: "ALPN protocol name cannot be empty".to_string(),
        });
      }
    }
    self.alpn = Some(alpn);
    Ok(self)
  }

  /// Set server names/SNI (for TLS/QUIC)
  pub fn with_server_names(mut self, server_names: Vec<String>) -> Result<Self, ConfigValidationError> {
    for server_name in &server_names {
      if server_name.is_empty() {
        return Err(ConfigValidationError::ProtocolValidationError {
          protocol_name: "protocol".to_string(),
          reason: "Server name cannot be empty".to_string(),
        });
      }
      if server_name.contains(' ') {
        return Err(ConfigValidationError::ProtocolValidationError {
          protocol_name: "protocol".to_string(),
          reason: format!("Invalid server name '{}': cannot contain spaces", server_name),
        });
      }
    }
    self.server_names = Some(server_names);
    Ok(self)
  }

  /// Set ECH configuration (for TLS/QUIC)
  pub fn with_ech(mut self, ech: EchProtocolConfig) -> Self {
    self.ech = Some(ech);
    self
  }

  /// Build the protocol configuration
  pub fn build(self) -> Result<ProtocolConfig, ConfigValidationError> {
    let protocol = self.protocol.ok_or(ConfigValidationError::MissingRequiredField {
      field: "protocol".to_string(),
    })?;

    if self.target.is_empty() {
      return Err(ConfigValidationError::MissingRequiredField {
        field: "target".to_string(),
      });
    }

    // Validate the complete configuration
    ProtocolValidator::validate_protocol_config(
      "protocol",
      &protocol,
      &self.target,
      self.load_balance.as_ref(),
      self.idle_lifetime,
      self.alpn.as_deref(),
      self.server_names.as_deref(),
    )?;

    Ok(ProtocolConfig {
      protocol,
      target: self.target,
      load_balance: self.load_balance,
      idle_lifetime: self.idle_lifetime,
      alpn: self.alpn,
      server_names: self.server_names,
      ech: self.ech,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_config_builder_basic() {
    let config = ConfigBuilder::new()
      .with_listen_port(8080)
      .unwrap()
      .with_ipv6(true)
      .build()
      .unwrap();

    assert_eq!(config.listen_port, 8080);
    assert_eq!(config.listen_ipv6, true);
  }

  #[test]
  fn test_config_builder_with_targets() {
    let config = ConfigBuilder::new()
      .with_listen_port(8080)
      .unwrap()
      .with_tcp_target(vec!["192.168.1.1:80", "example.com:80"])
      .unwrap()
      .with_tcp_load_balance(LoadBalance::SourceIp)
      .unwrap()
      .build()
      .unwrap();

    assert!(config.tcp_target.is_some());
    assert_eq!(config.tcp_target.as_ref().unwrap().len(), 2);
    assert_eq!(config.tcp_load_balance, Some(LoadBalance::SourceIp));
  }

  #[test]
  fn test_config_builder_validation_errors() {
    // Missing listen port
    let result = ConfigBuilder::new().build();
    assert!(result.is_err());

    // Invalid port
    let result = ConfigBuilder::new().with_listen_port(0);
    assert!(result.is_err());

    // Invalid targets
    let result = ConfigBuilder::new()
      .with_listen_port(8080)
      .unwrap()
      .with_tcp_target(vec!["invalid-address"]);
    assert!(result.is_err());
  }

  #[test]
  fn test_protocol_config_builder() {
    let protocol_config = ProtocolConfigBuilder::new()
      .with_protocol(ProtocolType::Tls)
      .with_targets(vec!["192.168.1.1:443"])
      .unwrap()
      .with_alpn(vec!["h2".to_string(), "http/1.1".to_string()])
      .unwrap()
      .with_server_names(vec!["example.com".to_string()])
      .unwrap()
      .build()
      .unwrap();

    assert_eq!(protocol_config.protocol, ProtocolType::Tls);
    assert_eq!(protocol_config.target.len(), 1);
    assert!(protocol_config.alpn.is_some());
    assert!(protocol_config.server_names.is_some());
  }

  #[test]
  fn test_protocol_builder_validation() {
    // Missing protocol type
    let result = ProtocolConfigBuilder::new()
      .with_targets(vec!["192.168.1.1:443"])
      .unwrap()
      .build();
    assert!(result.is_err());

    // Missing targets
    let result = ProtocolConfigBuilder::new().with_protocol(ProtocolType::Tls).build();
    assert!(result.is_err());

    // Invalid ALPN
    let result = ProtocolConfigBuilder::new()
      .with_protocol(ProtocolType::Tls)
      .with_targets(vec!["192.168.1.1:443"])
      .unwrap()
      .with_alpn(vec!["".to_string()]);
    assert!(result.is_err());
  }

  #[test]
  fn test_builder_chaining() {
    let config = ConfigBuilder::new()
      .with_listen_port(8443)
      .unwrap()
      .with_ipv6(true)
      .with_tcp_backlog(2048)
      .unwrap()
      .with_tcp_max_connections(1000)
      .unwrap()
      .with_udp_max_connections(2000)
      .unwrap()
      .with_dns_cache_ttl(Some(Duration::from_secs(60)), Some(Duration::from_secs(3600)))
      .unwrap()
      .build()
      .unwrap();

    assert_eq!(config.listen_port, 8443);
    assert_eq!(config.listen_ipv6, true);
    assert_eq!(config.tcp_backlog, Some(2048));
    assert_eq!(config.tcp_max_connections, Some(1000));
    assert_eq!(config.udp_max_connections, Some(2000));
  }
}
