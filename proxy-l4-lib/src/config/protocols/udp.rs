use crate::{
  config::{EchProtocolConfig, validation::*},
  destination::LoadBalance,
  target::TargetAddr,
};

/// Configuration specific to UDP protocols
#[derive(Debug, Clone)]
pub struct UdpProtocolConfig {
  /// Target addresses
  pub targets: Vec<TargetAddr>,
  /// Load balancing strategy
  pub load_balance: Option<LoadBalance>,
  /// Connection idle lifetime in seconds
  pub idle_lifetime: Option<u32>,
}

impl UdpProtocolConfig {
  /// Create a new UDP protocol configuration
  pub fn new(targets: Vec<TargetAddr>) -> Result<Self, ConfigValidationError> {
    TargetValidator::validate_targets(&targets)?;
    Ok(Self {
      targets,
      load_balance: None,
      idle_lifetime: None,
    })
  }

  /// Set load balancing strategy
  pub fn with_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
    TargetValidator::validate_load_balance_with_targets(Some(&lb), &self.targets)?;
    self.load_balance = Some(lb);
    Ok(self)
  }

  /// Set idle lifetime
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
}

/// Configuration specific to WireGuard protocol
#[derive(Debug, Clone)]
pub struct WireguardConfig {
  /// Base UDP configuration
  pub udp: UdpProtocolConfig,
}

impl WireguardConfig {
  /// Create a new WireGuard configuration
  pub fn new(targets: Vec<TargetAddr>) -> Result<Self, ConfigValidationError> {
    let udp = UdpProtocolConfig::new(targets)?;
    Ok(Self { udp })
  }

  /// Set load balancing strategy
  pub fn with_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
    self.udp = self.udp.with_load_balance(lb)?;
    Ok(self)
  }

  /// Set idle lifetime (should be longer than WireGuard keepalive interval)
  pub fn with_idle_lifetime(mut self, lifetime: u32) -> Result<Self, ConfigValidationError> {
    ProtocolValidator::validate_wireguard_config("wireguard", Some(lifetime))?;
    self.udp = self.udp.with_idle_lifetime(lifetime)?;
    Ok(self)
  }
}

/// Configuration specific to QUIC protocol
#[derive(Debug, Clone)]
pub struct QuicConfig {
  /// Base UDP configuration
  pub udp: UdpProtocolConfig,
  /// ALPN protocols
  pub alpn: Option<Vec<String>>,
  /// Server names (SNI)
  pub server_names: Option<Vec<String>>,
  /// ECH configuration (currently not supported for QUIC)
  pub ech: Option<EchProtocolConfig>,
}

impl QuicConfig {
  /// Create a new QUIC configuration
  pub fn new(targets: Vec<TargetAddr>) -> Result<Self, ConfigValidationError> {
    let udp = UdpProtocolConfig::new(targets)?;
    Ok(Self {
      udp,
      alpn: None,
      server_names: None,
      ech: None,
    })
  }

  /// Set load balancing strategy
  pub fn with_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
    self.udp = self.udp.with_load_balance(lb)?;
    Ok(self)
  }

  /// Set idle lifetime
  pub fn with_idle_lifetime(mut self, lifetime: u32) -> Result<Self, ConfigValidationError> {
    ProtocolValidator::validate_quic_config("quic", self.alpn.as_deref(), self.server_names.as_deref(), Some(lifetime))?;
    self.udp = self.udp.with_idle_lifetime(lifetime)?;
    Ok(self)
  }

  /// Set ALPN protocols
  pub fn with_alpn(mut self, alpn: Vec<String>) -> Result<Self, ConfigValidationError> {
    ProtocolValidator::validate_quic_config("quic", Some(&alpn), self.server_names.as_deref(), self.udp.idle_lifetime)?;
    self.alpn = Some(alpn);
    Ok(self)
  }

  /// Set server names (SNI)
  pub fn with_server_names(mut self, server_names: Vec<String>) -> Result<Self, ConfigValidationError> {
    ProtocolValidator::validate_quic_config("quic", self.alpn.as_deref(), Some(&server_names), self.udp.idle_lifetime)?;
    self.server_names = Some(server_names);
    Ok(self)
  }

  /// Set ECH configuration (will log warning as QUIC ECH is not yet supported)
  pub fn with_ech(mut self, ech: EchProtocolConfig) -> Self {
    crate::trace::warn!("QUIC ECH is not supported yet, but configuration is accepted");
    self.ech = Some(ech);
    self
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::str::FromStr;

  #[test]
  fn test_udp_protocol_config() {
    let targets = vec![TargetAddr::from_str("192.168.1.1:1234").unwrap()];
    let config = UdpProtocolConfig::new(targets).unwrap();
    assert_eq!(config.targets.len(), 1);
    assert!(config.load_balance.is_none());
    assert!(config.idle_lifetime.is_none());
  }

  #[test]
  fn test_udp_with_idle_lifetime() {
    let targets = vec![TargetAddr::from_str("192.168.1.1:1234").unwrap()];
    let config = UdpProtocolConfig::new(targets).unwrap().with_idle_lifetime(30).unwrap();
    assert_eq!(config.idle_lifetime, Some(30));
  }

  #[test]
  fn test_udp_invalid_idle_lifetime() {
    let targets = vec![TargetAddr::from_str("192.168.1.1:1234").unwrap()];
    let result = UdpProtocolConfig::new(targets).unwrap().with_idle_lifetime(0);
    assert!(result.is_err());
  }

  #[test]
  fn test_wireguard_config() {
    let targets = vec![TargetAddr::from_str("192.168.1.1:51820").unwrap()];
    let config = WireguardConfig::new(targets).unwrap().with_idle_lifetime(30).unwrap();
    assert_eq!(config.udp.targets.len(), 1);
    assert_eq!(config.udp.idle_lifetime, Some(30));
  }

  #[test]
  fn test_quic_config() {
    let targets = vec![TargetAddr::from_str("192.168.1.1:443").unwrap()];
    let config = QuicConfig::new(targets)
      .unwrap()
      .with_alpn(vec!["h3".to_string()])
      .unwrap()
      .with_server_names(vec!["example.com".to_string()])
      .unwrap()
      .with_idle_lifetime(30)
      .unwrap();

    assert!(config.alpn.is_some());
    assert!(config.server_names.is_some());
    assert_eq!(config.alpn.as_ref().unwrap()[0], "h3");
    assert_eq!(config.server_names.as_ref().unwrap()[0], "example.com");
    assert_eq!(config.udp.idle_lifetime, Some(30));
  }

  #[test]
  fn test_quic_config_validation() {
    let targets = vec![TargetAddr::from_str("192.168.1.1:443").unwrap()];

    // Test with very short idle lifetime (should generate warning but not error)
    let config = QuicConfig::new(targets).unwrap().with_idle_lifetime(1).unwrap();
    assert_eq!(config.udp.idle_lifetime, Some(1));
  }

  #[test]
  fn test_load_balance_with_single_target() {
    let targets = vec![TargetAddr::from_str("192.168.1.1:1234").unwrap()];
    // Should work but may generate a warning
    let config = UdpProtocolConfig::new(targets)
      .unwrap()
      .with_load_balance(LoadBalance::SourceIp)
      .unwrap();
    assert_eq!(config.load_balance, Some(LoadBalance::SourceIp));
  }
}
