//! Load balancing configuration
//!
//! This module contains the configuration types for different load balancing strategies.

use crate::error::ProxyBuildError;

/// Load balancing policy
/// Note that in the `SourceIp` and `SourceSocket` policies, a selected server
/// for a source IP/socket might differ when new [Destination] is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadBalance {
  /// Choose a server by the source IP address
  /// If the source IP is not changed, the same backend will be selected.
  SourceIp,

  /// Choose a server by the source socket address (IP + port).
  /// Even if the source IP is not changed, the same backend might not be selected when the source port is different.
  SourceSocket,

  /// Randomly select a server
  Random,

  #[default]
  /// Always select the first server [default]
  None,
}

impl TryFrom<&str> for LoadBalance {
  type Error = ProxyBuildError;
  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match value {
      "source_ip" => Ok(LoadBalance::SourceIp),
      "source_socket" => Ok(LoadBalance::SourceSocket),
      "random" => Ok(LoadBalance::Random),
      "none" => Ok(LoadBalance::None),
      _ => Err(ProxyBuildError::invalid_load_balance(value.to_string())),
    }
  }
}
