use crate::log::warn;
use anyhow::anyhow;
use rpxy_l4_lib::{Config, EchProtocolConfig, LoadBalance, ProtocolType};
use serde::Deserialize;
use std::{
  collections::{HashMap, HashSet},
  fs,
  time::Duration,
};

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct ConfigToml {
  pub listen_port: Option<u16>,
  pub listen_ipv6: Option<bool>,
  pub tcp_backlog: Option<u32>,
  pub tcp_max_connections: Option<u32>,
  pub udp_max_connections: Option<u32>,
  // tcp default target
  pub tcp_target: Option<Vec<String>>,
  pub tcp_load_balance: Option<String>,
  // udp default target
  pub udp_target: Option<Vec<String>>,
  pub udp_load_balance: Option<String>,
  pub udp_idle_lifetime: Option<u32>,
  // DNS cache configuration
  pub dns_cache_min_ttl: Option<String>,
  pub dns_cache_max_ttl: Option<String>,
  // protocols
  pub protocols: Option<ProtocolsToml>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct ProtocolsToml(pub HashMap<String, ProtocolToml>);

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct ProtocolToml {
  /// Protocol type name
  pub protocol: Option<String>,
  /// Common for specific protocols
  pub target: Option<Vec<String>>,
  /// Common for specific protocols
  pub load_balance: Option<String>,
  /// Only UDP based protocol
  pub idle_lifetime: Option<u32>,
  /// Only TLS
  pub alpn: Option<Vec<String>>,
  /// Only TLS
  pub server_names: Option<Vec<String>>,
  /// Only TLS
  pub ech: Option<EchToml>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct EchToml {
  /// Base64 encoded ECH config list object
  pub ech_config_list: String,
  /// List of base64 encoded raw private keys
  pub private_keys: Vec<String>,
  /// The list of accepted ECH private server names
  pub private_server_names: Vec<String>,
}

impl ConfigToml {
  pub fn new(config_file: &str) -> Result<Self, anyhow::Error> {
    let config_str = fs::read_to_string(config_file)?;

    // Check unused fields during deserialization
    let t = toml::de::Deserializer::new(&config_str);
    let mut unused = HashSet::new();

    let res = serde_ignored::deserialize(t, |path| {
      unused.insert(path.to_string());
    })
    .map_err(|e| anyhow::anyhow!(e));

    if !unused.is_empty() {
      let str = unused.iter().fold(String::new(), |acc, x| acc + x + "\n");
      warn!("Configuration file contains unsupported fields. Check typos:\n{}", str);
    }

    res
  }
}

impl TryFrom<ConfigToml> for Config {
  type Error = anyhow::Error;

  fn try_from(config_toml: ConfigToml) -> Result<Self, Self::Error> {
    use rpxy_l4_lib::config::{ConfigBuilder, ProtocolConfigBuilder};

    let Some(listen_port) = config_toml.listen_port else {
      return Err(anyhow!("listen_port is required"));
    };

    // Use the new ConfigBuilder with validation
    let mut builder = ConfigBuilder::new()
      .with_listen_port(listen_port)
      .map_err(|e| anyhow!("Invalid listen port: {}", e))?
      .with_ipv6(config_toml.listen_ipv6.unwrap_or(false));

    // Set TCP configuration
    if let Some(backlog) = config_toml.tcp_backlog {
      builder = builder
        .with_tcp_backlog(backlog)
        .map_err(|e| anyhow!("Invalid TCP backlog: {}", e))?;
    }

    if let Some(max_conn) = config_toml.tcp_max_connections {
      builder = builder
        .with_tcp_max_connections(max_conn)
        .map_err(|e| anyhow!("Invalid TCP max connections: {}", e))?;
    }

    if let Some(max_conn) = config_toml.udp_max_connections {
      builder = builder
        .with_udp_max_connections(max_conn)
        .map_err(|e| anyhow!("Invalid UDP max connections: {}", e))?;
    }

    // Set TCP target and load balance
    if let Some(tcp_targets) = config_toml.tcp_target {
      let tcp_target_strs: Vec<&str> = tcp_targets.iter().map(|s| s.as_str()).collect();
      builder = builder
        .with_tcp_target(tcp_target_strs)
        .map_err(|e| anyhow!("Invalid TCP targets: {}", e))?;

      if let Some(lb) = config_toml.tcp_load_balance {
        let load_balance: LoadBalance = lb.as_str().try_into()?;
        builder = builder
          .with_tcp_load_balance(load_balance)
          .map_err(|e| anyhow!("Invalid TCP load balance: {}", e))?;
      }
    }

    // Set UDP target and load balance
    if let Some(udp_targets) = config_toml.udp_target {
      let udp_target_strs: Vec<&str> = udp_targets.iter().map(|s| s.as_str()).collect();
      builder = builder
        .with_udp_target(udp_target_strs)
        .map_err(|e| anyhow!("Invalid UDP targets: {}", e))?;

      if let Some(lb) = config_toml.udp_load_balance {
        let load_balance: LoadBalance = lb.as_str().try_into()?;
        builder = builder
          .with_udp_load_balance(load_balance)
          .map_err(|e| anyhow!("Invalid UDP load balance: {}", e))?;
      }
    }

    if let Some(lifetime) = config_toml.udp_idle_lifetime {
      builder = builder
        .with_udp_idle_lifetime(lifetime)
        .map_err(|e| anyhow!("Invalid UDP idle lifetime: {}", e))?;
    }

    // Parse and set DNS cache configuration
    let dns_cache_min_ttl = config_toml
      .dns_cache_min_ttl
      .as_ref()
      .map(|x| parse_duration(x))
      .transpose()?;
    let dns_cache_max_ttl = config_toml
      .dns_cache_max_ttl
      .as_ref()
      .map(|x| parse_duration(x))
      .transpose()?;

    if dns_cache_min_ttl.is_some() || dns_cache_max_ttl.is_some() {
      builder = builder
        .with_dns_cache_ttl(dns_cache_min_ttl, dns_cache_max_ttl)
        .map_err(|e| anyhow!("Invalid DNS cache TTL: {}", e))?;
    }

    // Process protocol configurations using ProtocolConfigBuilder
    if let Some(protocols_toml) = config_toml.protocols {
      for (name, protocol_toml) in protocols_toml.0 {
        let Some(proto_type) = protocol_toml.protocol.as_ref() else {
          return Err(anyhow!("protocol is required for key: {name}"));
        };
        let proto_type: ProtocolType = proto_type.as_str().try_into()?;
        let Some(target) = protocol_toml.target.as_ref() else {
          return Err(anyhow!("target is required for key: {name}"));
        };
        if target.is_empty() {
          return Err(anyhow!("target is empty for key: {name}"));
        }

        // Use ProtocolConfigBuilder for validation
        let target_strs: Vec<&str> = target.iter().map(|s| s.as_str()).collect();
        let mut protocol_builder = ProtocolConfigBuilder::new()
          .with_protocol(proto_type)
          .with_targets(target_strs)
          .map_err(|e| anyhow!("Invalid targets for protocol '{}': {}", name, e))?;

        if let Some(lb) = protocol_toml.load_balance {
          let load_balance: LoadBalance = lb.as_str().try_into()?;
          protocol_builder = protocol_builder
            .with_load_balance(load_balance)
            .map_err(|e| anyhow!("Invalid load balance for protocol '{}': {}", name, e))?;
        }

        if let Some(lifetime) = protocol_toml.idle_lifetime {
          protocol_builder = protocol_builder
            .with_idle_lifetime(lifetime)
            .map_err(|e| anyhow!("Invalid idle lifetime for protocol '{}': {}", name, e))?;
        }

        if let Some(alpn) = protocol_toml.alpn {
          protocol_builder = protocol_builder
            .with_alpn(alpn)
            .map_err(|e| anyhow!("Invalid ALPN for protocol '{}': {}", name, e))?;
        }

        if let Some(server_names) = protocol_toml.server_names {
          protocol_builder = protocol_builder
            .with_server_names(server_names)
            .map_err(|e| anyhow!("Invalid server names for protocol '{}': {}", name, e))?;
        }

        if let Some(ech_toml) = protocol_toml.ech {
          let ech = EchProtocolConfig::try_new(
            &ech_toml.ech_config_list,
            &ech_toml.private_keys,
            &ech_toml.private_server_names,
            &listen_port,
          )?;

          warn!("ECH is configured for protocol: {name}");
          warn!("Make sure that the ECH config has been set up correctly as the client can refer to it.");
          warn!(
            "If DNS HTTPS RR is used for that, check if its value contains \"ech={}\"",
            &ech_toml.ech_config_list
          );
          warn!(
            "For the configuration, ECH private server names accepted and routed are: {:?}",
            ech_toml.private_server_names
          );

          protocol_builder = protocol_builder.with_ech(ech);
        }

        let protocol_config = protocol_builder
          .build()
          .map_err(|e| anyhow!("Failed to build protocol config for '{}': {}", name, e))?;

        builder = builder
          .with_protocol(name, protocol_config)
          .map_err(|e| anyhow!("Failed to add protocol: {}", e))?;
      }
    }

    // Build the final configuration with validation
    builder.build().map_err(|e| anyhow!("Configuration validation failed: {}", e))
  }
}

/// Parse duration string like "30s", "5m", "1h" into Duration
fn parse_duration(s: &str) -> Result<Duration, anyhow::Error> {
  let s = s.trim();
  if s.is_empty() {
    return Err(anyhow!("Empty duration string"));
  }

  let (num_part, unit_part) = if let Some(pos) = s.find(|c: char| c.is_alphabetic()) {
    (&s[..pos], &s[pos..])
  } else {
    return Err(anyhow!("Duration must include a unit (s, m, h)"));
  };

  let num: u64 = num_part
    .parse()
    .map_err(|_| anyhow!("Invalid number in duration: {}", num_part))?;

  let duration = match unit_part.to_lowercase().as_str() {
    "s" | "sec" | "secs" | "second" | "seconds" => Duration::from_secs(num),
    "m" | "min" | "mins" | "minute" | "minutes" => Duration::from_secs(num * 60),
    "h" | "hr" | "hrs" | "hour" | "hours" => Duration::from_secs(num * 3600),
    _ => return Err(anyhow!("Invalid duration unit: {}. Use s, m, or h", unit_part)),
  };

  Ok(duration)
}
