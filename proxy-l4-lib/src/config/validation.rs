use crate::{destination::LoadBalance, proto::ProtocolType, target::TargetAddr};
use std::time::Duration;

/// Validation errors specific to configuration
#[derive(thiserror::Error, Debug)]
pub enum ConfigValidationError {
  #[error("Missing required field: {field}")]
  MissingRequiredField { field: String },

  #[error("Invalid value for field {field}: {value}. {reason}")]
  InvalidFieldValue { field: String, value: String, reason: String },

  #[error("Protocol validation error for '{protocol_name}': {reason}")]
  ProtocolValidationError { protocol_name: String, reason: String },

  #[error("ECH configuration error: {reason}")]
  EchConfigurationError { reason: String },

  #[error("Target address validation error: {reason}")]
  TargetAddressError { reason: String },

  #[error("Conflicting configuration: {reason}")]
  ConflictingConfiguration { reason: String },
}

/// Result type for configuration validation
pub type ValidationResult<T> = Result<T, ConfigValidationError>;

/// Validator for basic configuration fields
pub struct BasicConfigValidator;

impl BasicConfigValidator {
  /// Validate listening port
  pub fn validate_listen_port(port: u16) -> ValidationResult<()> {
    if port == 0 {
      return Err(ConfigValidationError::InvalidFieldValue {
        field: "listen_port".to_string(),
        value: port.to_string(),
        reason: "Port cannot be 0".to_string(),
      });
    }

    if port < 1024 {
      // This is a warning case, not an error, but we can log it
      crate::trace::warn!("Using privileged port {}: requires appropriate permissions", port);
    }

    Ok(())
  }

  /// Validate TCP backlog size
  pub fn validate_tcp_backlog(backlog: Option<u32>) -> ValidationResult<()> {
    if let Some(backlog) = backlog {
      if backlog == 0 {
        return Err(ConfigValidationError::InvalidFieldValue {
          field: "tcp_backlog".to_string(),
          value: backlog.to_string(),
          reason: "TCP backlog cannot be 0".to_string(),
        });
      }

      if backlog > 65535 {
        return Err(ConfigValidationError::InvalidFieldValue {
          field: "tcp_backlog".to_string(),
          value: backlog.to_string(),
          reason: "TCP backlog is too large (max 65535)".to_string(),
        });
      }
    }
    Ok(())
  }

  /// Validate connection limits
  pub fn validate_connection_limits(tcp_max: Option<u32>, udp_max: Option<u32>) -> ValidationResult<()> {
    if let Some(tcp_max) = tcp_max {
      if tcp_max == 0 {
        return Err(ConfigValidationError::InvalidFieldValue {
          field: "tcp_max_connections".to_string(),
          value: tcp_max.to_string(),
          reason: "Max connections cannot be 0".to_string(),
        });
      }
    }

    if let Some(udp_max) = udp_max {
      if udp_max == 0 {
        return Err(ConfigValidationError::InvalidFieldValue {
          field: "udp_max_connections".to_string(),
          value: udp_max.to_string(),
          reason: "Max connections cannot be 0".to_string(),
        });
      }
    }

    Ok(())
  }

  /// Validate DNS cache TTL settings
  pub fn validate_dns_cache_ttl(min_ttl: Option<Duration>, max_ttl: Option<Duration>) -> ValidationResult<()> {
    match (min_ttl, max_ttl) {
      (Some(min), Some(max)) => {
        if min > max {
          return Err(ConfigValidationError::ConflictingConfiguration {
            reason: format!("DNS cache min_ttl ({:?}) cannot be greater than max_ttl ({:?})", min, max),
          });
        }
      }
      _ => {}
    }

    // Validate reasonable TTL ranges
    if let Some(min) = min_ttl {
      if min < Duration::from_secs(1) {
        return Err(ConfigValidationError::InvalidFieldValue {
          field: "dns_cache_min_ttl".to_string(),
          value: format!("{:?}", min),
          reason: "Min TTL must be at least 1 second".to_string(),
        });
      }
    }

    if let Some(max) = max_ttl {
      if max > Duration::from_secs(86400) {
        // 24 hours
        crate::trace::warn!(
          "DNS cache max_ttl is very large ({:?}). Consider a shorter TTL for better responsiveness.",
          max
        );
      }
    }

    Ok(())
  }
}

/// Validator for target addresses
pub struct TargetValidator;

impl TargetValidator {
  /// Validate a list of target addresses
  pub fn validate_targets(targets: &[TargetAddr]) -> ValidationResult<()> {
    if targets.is_empty() {
      return Err(ConfigValidationError::TargetAddressError {
        reason: "Target list cannot be empty".to_string(),
      });
    }

    for (i, target) in targets.iter().enumerate() {
      Self::validate_single_target(target, i)?;
    }

    Ok(())
  }

  /// Validate a single target address
  fn validate_single_target(target: &TargetAddr, index: usize) -> ValidationResult<()> {
    // Check if target format is valid (this is partially done by TargetAddr parsing)
    let target_str = target.to_string();

    // Check for common issues
    if target_str.contains("localhost") || target_str.contains("127.0.0.1") {
      crate::trace::warn!(
        "Target {} uses localhost/127.0.0.1 - ensure this is intended for development",
        target_str
      );
    }

    // Validate port range - extract port from string representation
    let port = if let Some((_, port_str)) = target_str.rsplit_once(':') {
      port_str.parse::<u16>().unwrap_or(0)
    } else {
      0
    };

    if port == 0 {
      return Err(ConfigValidationError::TargetAddressError {
        reason: format!("Target {} at index {} has invalid port", target_str, index),
      });
    }

    Ok(())
  }

  /// Validate load balance configuration with targets
  pub fn validate_load_balance_with_targets(load_balance: Option<&LoadBalance>, targets: &[TargetAddr]) -> ValidationResult<()> {
    Self::validate_targets(targets)?;

    // If there's only one target, load balancing doesn't make much sense
    if targets.len() == 1 {
      if let Some(lb) = load_balance {
        if !matches!(lb, LoadBalance::None) {
          crate::trace::warn!(
            "Load balancing strategy {:?} specified with only one target - consider using 'none'",
            lb
          );
        }
      }
    }

    Ok(())
  }
}

/// Validator for protocol-specific configurations
pub struct ProtocolValidator;

impl ProtocolValidator {
  /// Validate a protocol configuration
  pub fn validate_protocol_config(
    name: &str,
    protocol_type: &ProtocolType,
    targets: &[TargetAddr],
    load_balance: Option<&LoadBalance>,
    idle_lifetime: Option<u32>,
    alpn: Option<&[String]>,
    server_names: Option<&[String]>,
  ) -> ValidationResult<()> {
    // Validate targets
    TargetValidator::validate_load_balance_with_targets(load_balance, targets)?;

    // Protocol-specific validation
    match protocol_type {
      ProtocolType::Http => Self::validate_http_config(name)?,
      ProtocolType::Ssh => Self::validate_ssh_config(name)?,
      ProtocolType::Tls => Self::validate_tls_config(name, alpn, server_names)?,
      ProtocolType::Quic => Self::validate_quic_config(name, alpn, server_names, idle_lifetime)?,
      ProtocolType::Wireguard => Self::validate_wireguard_config(name, idle_lifetime)?,
    }

    Ok(())
  }

  fn validate_http_config(name: &str) -> ValidationResult<()> {
    // HTTP is straightforward, no special validation needed
    crate::trace::debug!("Validated HTTP protocol config for '{}'", name);
    Ok(())
  }

  fn validate_ssh_config(name: &str) -> ValidationResult<()> {
    // SSH is straightforward, no special validation needed
    crate::trace::debug!("Validated SSH protocol config for '{}'", name);
    Ok(())
  }

  pub fn validate_tls_config(name: &str, alpn: Option<&[String]>, server_names: Option<&[String]>) -> ValidationResult<()> {
    // Validate ALPN protocols
    if let Some(alpn_list) = alpn {
      for alpn_proto in alpn_list {
        if alpn_proto.is_empty() {
          return Err(ConfigValidationError::ProtocolValidationError {
            protocol_name: name.to_string(),
            reason: "ALPN protocol name cannot be empty".to_string(),
          });
        }

        // Check for common ALPN protocol names
        if !["h2", "http/1.1", "dot", "h3"].contains(&alpn_proto.as_str()) {
          crate::trace::warn!(
            "Unknown ALPN protocol '{}' in TLS config '{}' - ensure this is correct",
            alpn_proto,
            name
          );
        }
      }
    }

    // Validate server names
    if let Some(sni_list) = server_names {
      for server_name in sni_list {
        if server_name.is_empty() {
          return Err(ConfigValidationError::ProtocolValidationError {
            protocol_name: name.to_string(),
            reason: "Server name cannot be empty".to_string(),
          });
        }

        // Basic domain name validation
        if server_name.contains(' ') {
          return Err(ConfigValidationError::ProtocolValidationError {
            protocol_name: name.to_string(),
            reason: format!("Invalid server name '{}': cannot contain spaces", server_name),
          });
        }
      }
    }

    crate::trace::debug!("Validated TLS protocol config for '{}'", name);
    Ok(())
  }

  pub fn validate_quic_config(
    name: &str,
    alpn: Option<&[String]>,
    server_names: Option<&[String]>,
    idle_lifetime: Option<u32>,
  ) -> ValidationResult<()> {
    // QUIC includes TLS validation
    Self::validate_tls_config(name, alpn, server_names)?;

    // Validate idle lifetime for QUIC
    if let Some(lifetime) = idle_lifetime {
      if lifetime == 0 {
        return Err(ConfigValidationError::ProtocolValidationError {
          protocol_name: name.to_string(),
          reason: "QUIC idle lifetime cannot be 0".to_string(),
        });
      }

      if lifetime < 5 {
        crate::trace::warn!(
          "QUIC idle lifetime {} seconds is very short for '{}' - may cause connection drops",
          lifetime,
          name
        );
      }
    }

    // Check for QUIC-specific ALPN
    if let Some(alpn_list) = alpn {
      let has_quic_alpn = alpn_list.iter().any(|alpn| alpn == "h3" || alpn.starts_with("h3-"));
      if !has_quic_alpn {
        crate::trace::warn!("QUIC config '{}' doesn't specify h3 ALPN - ensure this is intended", name);
      }
    }

    crate::trace::debug!("Validated QUIC protocol config for '{}'", name);
    Ok(())
  }

  pub fn validate_wireguard_config(name: &str, idle_lifetime: Option<u32>) -> ValidationResult<()> {
    // Validate idle lifetime for WireGuard
    if let Some(lifetime) = idle_lifetime {
      if lifetime == 0 {
        return Err(ConfigValidationError::ProtocolValidationError {
          protocol_name: name.to_string(),
          reason: "WireGuard idle lifetime cannot be 0".to_string(),
        });
      }

      if lifetime < 25 {
        crate::trace::warn!(
          "WireGuard idle lifetime {} seconds might be too short for '{}' - typical keepalive is 25s",
          lifetime,
          name
        );
      }
    }

    crate::trace::debug!("Validated WireGuard protocol config for '{}'", name);
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::str::FromStr;

  #[test]
  fn test_validate_listen_port() {
    // Valid ports
    assert!(BasicConfigValidator::validate_listen_port(8080).is_ok());
    assert!(BasicConfigValidator::validate_listen_port(443).is_ok());

    // Invalid port
    assert!(BasicConfigValidator::validate_listen_port(0).is_err());
  }

  #[test]
  fn test_validate_tcp_backlog() {
    assert!(BasicConfigValidator::validate_tcp_backlog(Some(1024)).is_ok());
    assert!(BasicConfigValidator::validate_tcp_backlog(None).is_ok());
    assert!(BasicConfigValidator::validate_tcp_backlog(Some(0)).is_err());
    assert!(BasicConfigValidator::validate_tcp_backlog(Some(100000)).is_err());
  }

  #[test]
  fn test_validate_dns_cache_ttl() {
    let min_ttl = Some(Duration::from_secs(30));
    let max_ttl = Some(Duration::from_secs(3600));

    // Valid configuration
    assert!(BasicConfigValidator::validate_dns_cache_ttl(min_ttl, max_ttl).is_ok());

    // Invalid: min > max
    let invalid_min = Some(Duration::from_secs(7200));
    assert!(BasicConfigValidator::validate_dns_cache_ttl(invalid_min, max_ttl).is_err());

    // Invalid: too short min
    let too_short = Some(Duration::from_millis(500));
    assert!(BasicConfigValidator::validate_dns_cache_ttl(too_short, max_ttl).is_err());
  }

  #[test]
  fn test_validate_targets() {
    let valid_targets = vec![
      TargetAddr::from_str("192.168.1.1:80").unwrap(),
      TargetAddr::from_str("example.com:443").unwrap(),
    ];
    assert!(TargetValidator::validate_targets(&valid_targets).is_ok());

    // Empty targets
    assert!(TargetValidator::validate_targets(&[]).is_err());
  }

  #[test]
  fn test_validate_tls_config() {
    // Valid configuration
    let alpn = Some(vec!["h2".to_string(), "http/1.1".to_string()]);
    let server_names = Some(vec!["example.com".to_string()]);
    assert!(ProtocolValidator::validate_tls_config("test", alpn.as_deref(), server_names.as_deref()).is_ok());

    // Invalid: empty ALPN
    let invalid_alpn = Some(vec!["".to_string()]);
    assert!(ProtocolValidator::validate_tls_config("test", invalid_alpn.as_deref(), None).is_err());

    // Invalid: server name with spaces
    let invalid_sni = Some(vec!["invalid domain.com".to_string()]);
    assert!(ProtocolValidator::validate_tls_config("test", None, invalid_sni.as_deref()).is_err());
  }
}
