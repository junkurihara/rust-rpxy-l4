use crate::{destination::LoadBalance, proto::ProtocolType};
use std::net::SocketAddr;

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
  /// Default target for TCP
  pub tcp_target: Option<Vec<SocketAddr>>,
  /// Load balance for TCP
  pub tcp_load_balance: Option<LoadBalance>,
  /// Default target for UDP
  pub udp_target: Option<Vec<SocketAddr>>,
  /// Load balance for UDP
  pub udp_load_balance: Option<LoadBalance>,
  /// UDP connection lifetime in seconds
  pub udp_idle_lifetime: Option<u32>,
  /// Protocol specific configurations
  pub protocols: std::collections::HashMap<String, ProtocolConfig>,
}

/// Protocol specific configuration
pub struct ProtocolConfig {
  /// Protocol type name
  pub protocol: ProtocolType,
  /// Common for specific protocols
  pub target: Vec<SocketAddr>,
  /// Common for specific protocols
  pub load_balance: Option<LoadBalance>,
  /// Only UDP based protocol
  pub idle_lifetime: Option<u32>,
  /// Only TLS
  pub alpn: Option<Vec<String>>,
  /// Only TLS
  pub server_names: Option<Vec<String>>,
}
