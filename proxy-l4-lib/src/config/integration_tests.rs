//! Integration tests for Phase 2 Config Builder Implementation

#[cfg(test)]
mod tests {
  use crate::{ConfigBuilder, LoadBalance, ProtocolConfigBuilder, ProtocolType};

  #[test]
  fn test_config_builder_basic_usage() {
    let config = ConfigBuilder::new()
      .with_listen_port(8080)
      .unwrap()
      .with_ipv6(true)
      .with_tcp_backlog(1024)
      .unwrap()
      .with_tcp_max_connections(1000)
      .unwrap()
      .with_udp_max_connections(2000)
      .unwrap()
      .with_tcp_target(vec!["192.168.1.1:80", "192.168.1.2:80"])
      .unwrap()
      .with_tcp_load_balance(LoadBalance::SourceIp)
      .unwrap()
      .build()
      .unwrap();

    assert_eq!(config.listen_port, 8080);
    assert_eq!(config.listen_ipv6, true);
    assert_eq!(config.tcp_backlog, Some(1024));
    assert_eq!(config.tcp_max_connections, Some(1000));
    assert_eq!(config.udp_max_connections, Some(2000));

    assert!(config.tcp_target.is_some());
    assert_eq!(config.tcp_target.as_ref().unwrap().len(), 2);
    assert_eq!(config.tcp_load_balance, Some(LoadBalance::SourceIp));
  }

  #[test]
  fn test_protocol_config_builder() {
    let tls_protocol = ProtocolConfigBuilder::new()
      .with_protocol(ProtocolType::Tls)
      .with_targets(vec!["192.168.1.1:443", "192.168.1.2:443"])
      .unwrap()
      .with_load_balance(LoadBalance::SourceIp)
      .unwrap()
      .with_alpn(vec!["h2".to_string(), "http/1.1".to_string()])
      .unwrap()
      .with_server_names(vec!["example.com".to_string()])
      .unwrap()
      .build()
      .unwrap();

    assert_eq!(tls_protocol.protocol, ProtocolType::Tls);
    assert_eq!(tls_protocol.target.len(), 2);
    assert_eq!(tls_protocol.load_balance, Some(LoadBalance::SourceIp));
    assert!(tls_protocol.alpn.is_some());
    assert!(tls_protocol.server_names.is_some());
  }

  #[test]
  fn test_config_builder_with_protocol() {
    let tls_protocol = ProtocolConfigBuilder::new()
      .with_protocol(ProtocolType::Tls)
      .with_targets(vec!["192.168.1.1:443"])
      .unwrap()
      .with_alpn(vec!["h2".to_string()])
      .unwrap()
      .build()
      .unwrap();

    let config = ConfigBuilder::new()
      .with_listen_port(443)
      .unwrap()
      .with_protocol("https".to_string(), tls_protocol)
      .unwrap()
      .build()
      .unwrap();

    assert_eq!(config.listen_port, 443);
    assert_eq!(config.protocols.len(), 1);
    assert!(config.protocols.contains_key("https"));

    let https_config = config.protocols.get("https").unwrap();
    assert_eq!(https_config.protocol, ProtocolType::Tls);
    assert!(https_config.alpn.is_some());
  }

  #[test]
  fn test_validation_errors() {
    // Test invalid port
    let result = ConfigBuilder::new().with_listen_port(0);
    assert!(result.is_err());

    // Test invalid targets
    let result = ConfigBuilder::new()
      .with_listen_port(8080)
      .unwrap()
      .with_tcp_target(vec!["invalid-address"]);
    assert!(result.is_err());

    // Test missing required fields
    let result = ConfigBuilder::new().build();
    assert!(result.is_err());

    // Test protocol validation
    let result = ProtocolConfigBuilder::new()
      .with_protocol(ProtocolType::Tls)
      .with_targets(vec!["192.168.1.1:443"])
      .unwrap()
      .with_server_names(vec!["invalid domain.com".to_string()]);
    assert!(result.is_err());
  }

  #[test]
  fn test_comprehensive_config_build() {
    // Test building a comprehensive configuration
    let ssh_protocol = ProtocolConfigBuilder::new()
      .with_protocol(ProtocolType::Ssh)
      .with_targets(vec!["10.0.0.1:22"])
      .unwrap()
      .build()
      .unwrap();

    let wireguard_protocol = ProtocolConfigBuilder::new()
      .with_protocol(ProtocolType::Wireguard)
      .with_targets(vec!["10.0.0.1:51820"])
      .unwrap()
      .with_idle_lifetime(60)
      .unwrap()
      .build()
      .unwrap();

    let config = ConfigBuilder::new()
      .with_listen_port(8080)
      .unwrap()
      .with_ipv6(false)
      .with_tcp_backlog(2048)
      .unwrap()
      .with_tcp_target(vec!["192.168.1.1:80"])
      .unwrap()
      .with_udp_target(vec!["8.8.8.8:53"])
      .unwrap()
      .with_udp_idle_lifetime(30)
      .unwrap()
      .with_protocol("ssh".to_string(), ssh_protocol)
      .unwrap()
      .with_protocol("wireguard".to_string(), wireguard_protocol)
      .unwrap()
      .build()
      .unwrap();

    assert_eq!(config.listen_port, 8080);
    assert_eq!(config.listen_ipv6, false);
    assert_eq!(config.tcp_backlog, Some(2048));
    assert_eq!(config.udp_idle_lifetime, Some(30));
    assert_eq!(config.protocols.len(), 2);

    // Verify protocols were added correctly
    assert!(config.protocols.contains_key("ssh"));
    assert!(config.protocols.contains_key("wireguard"));

    let ssh_config = config.protocols.get("ssh").unwrap();
    assert_eq!(ssh_config.protocol, ProtocolType::Ssh);

    let wg_config = config.protocols.get("wireguard").unwrap();
    assert_eq!(wg_config.protocol, ProtocolType::Wireguard);
    assert_eq!(wg_config.idle_lifetime, Some(60));
  }
}
