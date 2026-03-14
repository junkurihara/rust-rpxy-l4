use crate::log::warn;
use anyhow::anyhow;
#[cfg(feature = "proxy-protocol")]
use rpxy_l4_lib::reexport::IpNet;
use rpxy_l4_lib::{
  Config, DEFAULT_LISTEN_ADDRESS_V4, DEFAULT_LISTEN_ADDRESS_V6, EchProtocolConfig, LoadBalance, ProtocolConfig, ProtocolType,
  TargetAddr,
};
#[cfg(feature = "proxy-protocol")]
use rpxy_l4_lib::{ProxyProtocolVersion, SendProxyProtocol};
use serde::Deserialize;
use std::{
  collections::{HashMap, HashSet},
  fs,
  net::{Ipv4Addr, Ipv6Addr},
  time::Duration,
};

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum OneOrMany {
  One(String),
  Many(Vec<String>),
}

impl OneOrMany {
  fn into_vec(self) -> Vec<String> {
    match self {
      Self::One(value) => vec![value],
      Self::Many(values) => values,
    }
  }
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct ConfigToml {
  pub listen_port: Option<u16>,
  pub listen_address_v4: Option<OneOrMany>,
  pub listen_address_v6: Option<OneOrMany>,
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
  // proxy protocol
  #[cfg(feature = "proxy-protocol")]
  pub tcp_send_proxy_protocol: Option<String>,
  #[cfg(feature = "proxy-protocol")]
  pub tcp_recv_proxy_protocol: Option<bool>,
  #[cfg(feature = "proxy-protocol")]
  pub tcp_trusted_proxies: Option<Vec<String>>,
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
  /// PROXY protocol version override for this protocol
  #[cfg(feature = "proxy-protocol")]
  pub send_proxy_protocol: Option<String>,
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
    let t = toml::Deserializer::parse(&config_str)?;
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
    let Some(listen_port) = config_toml.listen_port else {
      return Err(anyhow!("listen_port is required"));
    };

    let mut protocols = HashMap::new();

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
        let target = target.iter().map(|x| x.parse()).collect::<Result<Vec<TargetAddr>, _>>()?;

        let load_balance: Option<LoadBalance> = protocol_toml
          .load_balance
          .as_ref()
          .map(|x| x.as_str().try_into())
          .transpose()?;

        let ech = protocol_toml
          .ech
          .as_ref()
          .map(|v| EchProtocolConfig::try_new(&v.ech_config_list, &v.private_keys, &v.private_server_names, &listen_port))
          .transpose()?;
        if ech.is_some() {
          warn!("ECH is configured for protocol: {name}");
          warn!("Make sure that the ECH config has been set up correctly as the client can refer to it.");
          warn!(
            "If DNS HTTPS RR is used for that, check if its value contains \"ech={}\"",
            &protocol_toml.ech.as_ref().unwrap().ech_config_list
          );
          warn!(
            "For the configuration, ECH private server names accepted and routed are: {:?}",
            protocol_toml.ech.as_ref().unwrap().private_server_names
          );
        }

        #[cfg(feature = "proxy-protocol")]
        // Produce a tri-state SendProxyProtocol:
        // - absent           → Inherit (fall back to global tcp_send_proxy_protocol)
        // - "none"           → Disable (explicitly suppress, even if global is enabled)
        // - "v1" / "v2"     → Version(v) (override global with this version)
        let send_proxy_protocol = match protocol_toml.send_proxy_protocol.as_deref() {
          None => SendProxyProtocol::Inherit,
          Some(v) if v.eq_ignore_ascii_case("none") => SendProxyProtocol::Disable,
          Some(v) => {
            warn!("PROXY protocol is enabled for protocol: {name} with version: {v}");
            SendProxyProtocol::Version(v.parse::<ProxyProtocolVersion>()?)
          }
        };

        let protocol = ProtocolConfig {
          protocol: proto_type,
          target,
          load_balance,
          idle_lifetime: protocol_toml.idle_lifetime,
          alpn: protocol_toml.alpn,
          server_names: protocol_toml.server_names,
          ech,
          #[cfg(feature = "proxy-protocol")]
          send_proxy_protocol,
        };

        protocols.insert(name, protocol);
      }
    }

    let tcp_target = config_toml
      .tcp_target
      .map(|x| x.iter().map(|x| x.parse()).collect::<Result<Vec<TargetAddr>, _>>())
      .transpose()?;
    let tcp_load_balance = config_toml
      .tcp_load_balance
      .as_ref()
      .map(|x| x.as_str().try_into())
      .transpose()?;
    let udp_target = config_toml
      .udp_target
      .map(|x| x.iter().map(|x| x.parse()).collect::<Result<Vec<TargetAddr>, _>>())
      .transpose()?;
    let udp_load_balance = config_toml
      .udp_load_balance
      .as_ref()
      .map(|x| x.as_str().try_into())
      .transpose()?;

    // Parse DNS cache configuration
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

    #[cfg(feature = "proxy-protocol")]
    // If "none" is specified or None, treat it as None (disabled). Otherwise, parse the version string.
    let tcp_send_proxy_protocol = config_toml
      .tcp_send_proxy_protocol
      .as_ref()
      .map(|v| match v.to_ascii_lowercase().as_str() {
        "none" => None,
        other => Some(other.to_string()),
      })
      .flatten()
      .map(|v| {
        warn!("PROXY protocol is enabled for TCP connections by default with version: {v}");
        v.parse::<ProxyProtocolVersion>()
      })
      .transpose()?;

    #[cfg(feature = "proxy-protocol")]
    let tcp_recv_proxy_protocol = config_toml.tcp_recv_proxy_protocol.unwrap_or(false);
    #[cfg(feature = "proxy-protocol")]
    let tcp_trusted_proxies = tcp_recv_proxy_protocol
      .then(|| {
        config_toml
          .tcp_trusted_proxies
          .map(|proxies| {
            let trusted = proxies
              .iter()
              .map(|cidr| {
                cidr
                  .parse::<IpNet>()
                  .map_err(|e| anyhow!("Invalid CIDR in tcp_trusted_proxies '{}': {e}", cidr))
              })
              .collect::<Result<Vec<IpNet>, _>>();
            if let Ok(trusted) = &trusted {
              warn!("Inbound PROXY protocol is enabled with trusted proxies: {:?}", trusted);
            }
            trusted
          })
          .transpose()
      })
      .transpose()?
      .flatten();

    let listen_addresses_v4 = parse_listen_addresses_v4(config_toml.listen_address_v4.map(OneOrMany::into_vec))?;
    let listen_addresses_v6 = parse_listen_addresses_v6(
      config_toml.listen_address_v6.map(OneOrMany::into_vec),
      config_toml.listen_ipv6.unwrap_or(false),
    )?;

    Ok(Self {
      listen_port,
      listen_addresses_v4,
      listen_addresses_v6,
      tcp_backlog: config_toml.tcp_backlog,
      tcp_max_connections: config_toml.tcp_max_connections,
      udp_max_connections: config_toml.udp_max_connections,
      tcp_target,
      tcp_load_balance,
      udp_target,
      udp_load_balance,
      udp_idle_lifetime: config_toml.udp_idle_lifetime,
      dns_cache_min_ttl,
      dns_cache_max_ttl,
      #[cfg(feature = "proxy-protocol")]
      tcp_send_proxy_protocol,
      #[cfg(feature = "proxy-protocol")]
      tcp_recv_proxy_protocol,
      #[cfg(feature = "proxy-protocol")]
      tcp_trusted_proxies,
      protocols,
    })
  }
}

fn parse_listen_addresses_v4(listen_addresses_v4: Option<Vec<String>>) -> Result<Vec<Ipv4Addr>, anyhow::Error> {
  let Some(addrs) = listen_addresses_v4 else {
    return Ok(vec![DEFAULT_LISTEN_ADDRESS_V4]);
  };
  if addrs.is_empty() {
    return Err(anyhow!("listen_address_v4 must not be an empty array"));
  }

  let mut parsed = Vec::new();
  let mut seen = HashSet::new();

  for addr_str in addrs {
    let addr = addr_str
      .parse::<Ipv4Addr>()
      .map_err(|e| anyhow!("Invalid listen_address_v4 '{}': {}", addr_str, e))?;
    if seen.insert(addr) {
      parsed.push(addr);
    }
  }

  if parsed.len() > 1 && parsed.iter().any(Ipv4Addr::is_unspecified) {
    return Err(anyhow!(
      "listen_address_v4 must not contain the wildcard address '0.0.0.0' when multiple addresses are specified"
    ));
  }

  Ok(parsed)
}

fn parse_listen_addresses_v6(
  listen_addresses_v6: Option<Vec<String>>,
  listen_ipv6: bool,
) -> Result<Vec<Ipv6Addr>, anyhow::Error> {
  let Some(addrs) = listen_addresses_v6 else {
    return if listen_ipv6 {
      Ok(vec![DEFAULT_LISTEN_ADDRESS_V6])
    } else {
      Ok(Vec::new())
    };
  };
  if addrs.is_empty() {
    return Err(anyhow!("listen_address_v6 must not be an empty array"));
  }

  let mut parsed = Vec::new();
  let mut seen = HashSet::new();

  for addr_str in addrs {
    let bare = addr_str
      .strip_prefix('[')
      .and_then(|s| s.strip_suffix(']'))
      .unwrap_or(&addr_str);
    let addr = bare
      .parse::<Ipv6Addr>()
      .map_err(|e| anyhow!("Invalid listen_address_v6 '{}': {}", addr_str, e))?;
    if seen.insert(addr) {
      parsed.push(addr);
    }
  }

  if parsed.len() > 1 && parsed.iter().any(Ipv6Addr::is_unspecified) {
    return Err(anyhow!(
      "listen_address_v6 must not contain the wildcard address '::' when multiple addresses are specified"
    ));
  }

  Ok(parsed)
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

#[cfg(test)]
mod tests {
  use super::*;

  fn parse_config_toml(toml_str: &str) -> ConfigToml {
    toml::from_str::<ConfigToml>(toml_str).expect("failed to parse ConfigToml")
  }

  #[test]
  fn test_one_or_many_deserializes_single_value() {
    let parsed = parse_config_toml(
      r#"
listen_port = 8448
listen_address_v4 = "127.0.0.1"
tcp_target = ["127.0.0.1:80"]
"#,
    );
    assert_eq!(parsed.listen_address_v4, Some(OneOrMany::One("127.0.0.1".to_string())));
  }

  #[test]
  fn test_one_or_many_deserializes_array() {
    let parsed = parse_config_toml(
      r#"
listen_port = 8448
listen_address_v4 = ["127.0.0.1", "10.0.0.1"]
tcp_target = ["127.0.0.1:80"]
"#,
    );
    assert_eq!(
      parsed.listen_address_v4,
      Some(OneOrMany::Many(vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()]))
    );
  }

  #[test]
  fn test_toml_parse_minimal_config() {
    let toml_str = r#"
listen_port = 8448
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    assert_eq!(config_toml.listen_port, Some(8448));
    assert_eq!(config_toml.tcp_target, Some(vec!["127.0.0.1:80".to_string()]));
  }

  #[cfg(feature = "proxy-protocol")]
  #[test]
  fn test_proxy_protocol_global_and_per_protocol_parsing() {
    let toml_str = r#"
listen_port = 8448
tcp_send_proxy_protocol = "v2"

[protocols.ssh_main]
protocol = "ssh"
target = ["127.0.0.1:22"]
send_proxy_protocol = "v1"
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");

    assert_eq!(config.tcp_send_proxy_protocol, Some(ProxyProtocolVersion::V2));
    let ssh = config.protocols.get("ssh_main").expect("missing ssh_main protocol");
    assert_eq!(ssh.send_proxy_protocol, SendProxyProtocol::Version(ProxyProtocolVersion::V1));
  }

  #[cfg(feature = "proxy-protocol")]
  #[test]
  fn test_proxy_protocol_none_disables_header() {
    let toml_str = r#"
listen_port = 8448
tcp_send_proxy_protocol = "none"

[protocols.http_main]
protocol = "http"
target = ["127.0.0.1:8080"]
send_proxy_protocol = "none"
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");

    // Global "none" → disabled
    assert_eq!(config.tcp_send_proxy_protocol, None);
    let http = config.protocols.get("http_main").expect("missing http_main protocol");
    // Per-protocol "none" → explicit Disable (distinguishable from absent/Inherit)
    assert_eq!(http.send_proxy_protocol, SendProxyProtocol::Disable);
  }

  #[cfg(feature = "proxy-protocol")]
  #[test]
  fn test_proxy_protocol_per_protocol_absent_inherits() {
    // When send_proxy_protocol is absent for a protocol, it should be Inherit.
    let toml_str = r#"
listen_port = 8448
tcp_send_proxy_protocol = "v2"

[protocols.ssh_main]
protocol = "ssh"
target = ["127.0.0.1:22"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");

    let ssh = config.protocols.get("ssh_main").expect("missing ssh_main protocol");
    assert_eq!(ssh.send_proxy_protocol, SendProxyProtocol::Inherit);
  }

  #[cfg(feature = "proxy-protocol")]
  #[test]
  fn test_proxy_protocol_disable_overrides_global() {
    // Per-protocol Disable must override a non-None global setting.
    // This test documents the intended resolution semantics (exercised in lib.rs build_multiplexers).
    let toml_str = r#"
listen_port = 8448
tcp_send_proxy_protocol = "v1"

[protocols.http_main]
protocol = "http"
target = ["127.0.0.1:8080"]
send_proxy_protocol = "none"
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");

    assert_eq!(config.tcp_send_proxy_protocol, Some(ProxyProtocolVersion::V1));
    let http = config.protocols.get("http_main").expect("missing http_main protocol");
    assert_eq!(http.send_proxy_protocol, SendProxyProtocol::Disable);
  }

  #[cfg(feature = "proxy-protocol")]
  #[test]
  fn test_proxy_protocol_invalid_version_returns_error() {
    let toml_str = r#"
listen_port = 8448
tcp_send_proxy_protocol = "v3"
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let err = Config::try_from(config_toml).expect_err("expected invalid proxy protocol version");
    let msg = err.to_string();
    assert!(msg.contains("Invalid proxy protocol version"), "unexpected error: {msg}");
  }

  #[test]
  fn test_listen_address_defaults() {
    let toml_str = r#"
listen_port = 8448
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");
    assert_eq!(config.listen_addresses_v4, vec![std::net::Ipv4Addr::UNSPECIFIED]);
    assert!(config.listen_addresses_v6.is_empty());
  }

  #[test]
  fn test_listen_address_v4_custom() {
    let toml_str = r#"
listen_port = 8448
listen_address_v4 = "127.0.0.1"
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");
    assert_eq!(config.listen_addresses_v4, vec![std::net::Ipv4Addr::LOCALHOST]);
  }

  #[test]
  fn test_listen_address_v4_multiple() {
    let toml_str = r#"
listen_port = 8448
listen_address_v4 = ["127.0.0.1", "10.0.0.1"]
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");
    assert_eq!(
      config.listen_addresses_v4,
      vec![std::net::Ipv4Addr::LOCALHOST, std::net::Ipv4Addr::new(10, 0, 0, 1)]
    );
  }

  #[test]
  fn test_listen_address_v4_duplicate_deduplicated() {
    let toml_str = r#"
listen_port = 8448
listen_address_v4 = ["127.0.0.1", "127.0.0.1"]
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");
    assert_eq!(config.listen_addresses_v4, vec![std::net::Ipv4Addr::LOCALHOST]);
  }

  #[test]
  fn test_listen_address_v6_bare() {
    let toml_str = r#"
listen_port = 8448
listen_address_v6 = "::1"
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");
    assert_eq!(config.listen_addresses_v6, vec![std::net::Ipv6Addr::LOCALHOST]);
  }

  #[test]
  fn test_listen_address_v6_bracketed() {
    let toml_str = r#"
listen_port = 8448
listen_address_v6 = "[::1]"
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");
    assert_eq!(config.listen_addresses_v6, vec![std::net::Ipv6Addr::LOCALHOST]);
  }

  #[test]
  fn test_listen_address_v6_multiple() {
    let toml_str = r#"
listen_port = 8448
listen_address_v6 = ["::1", "[fe80::1]"]
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");
    assert_eq!(
      config.listen_addresses_v6,
      vec![
        std::net::Ipv6Addr::LOCALHOST,
        "fe80::1".parse::<std::net::Ipv6Addr>().unwrap()
      ]
    );
  }

  #[test]
  fn test_listen_ipv6_enables_default_v6() {
    let toml_str = r#"
listen_port = 8448
listen_ipv6 = true
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");
    assert_eq!(config.listen_addresses_v6, vec![std::net::Ipv6Addr::UNSPECIFIED]);
  }

  #[test]
  fn test_listen_address_v6_overrides_listen_ipv6() {
    // listen_address_v6 implicitly enables IPv6, listen_ipv6 is ignored
    let toml_str = r#"
listen_port = 8448
listen_ipv6 = false
listen_address_v6 = "[::1]"
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");
    assert_eq!(config.listen_addresses_v6, vec![std::net::Ipv6Addr::LOCALHOST]);
  }

  #[test]
  fn test_listen_address_v4_rejects_v6() {
    let toml_str = r#"
listen_port = 8448
listen_address_v4 = "::1"
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let err = Config::try_from(config_toml).expect_err("expected error for v6 in v4 field");
    assert!(err.to_string().contains("Invalid listen_address_v4"));
  }

  #[test]
  fn test_listen_address_v6_rejects_v4() {
    let toml_str = r#"
listen_port = 8448
listen_address_v6 = "127.0.0.1"
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let err = Config::try_from(config_toml).expect_err("expected error for v4 in v6 field");
    assert!(err.to_string().contains("Invalid listen_address_v6"));
  }

  #[test]
  fn test_listen_address_invalid_string() {
    let toml_str = r#"
listen_port = 8448
listen_address_v4 = "not-an-ip"
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let err = Config::try_from(config_toml).expect_err("expected error for invalid address");
    assert!(err.to_string().contains("Invalid listen_address_v4"));
  }

  #[test]
  fn test_listen_address_empty_array_rejected() {
    let toml_str = r#"
listen_port = 8448
listen_address_v4 = []
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let err = Config::try_from(config_toml).expect_err("expected error for empty array");
    assert!(err.to_string().contains("must not be an empty array"));
  }

  #[test]
  fn test_listen_address_v4_wildcard_mixed_with_specific_rejected() {
    let toml_str = r#"
listen_port = 8448
listen_address_v4 = ["0.0.0.0", "127.0.0.1"]
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let err = Config::try_from(config_toml).expect_err("expected wildcard mix rejection");
    assert!(err.to_string().contains("must not contain the wildcard address '0.0.0.0'"));
  }

  #[test]
  fn test_listen_address_v6_wildcard_mixed_with_specific_rejected() {
    let toml_str = r#"
listen_port = 8448
listen_address_v6 = ["::", "::1"]
tcp_target = ["127.0.0.1:80"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let err = Config::try_from(config_toml).expect_err("expected wildcard mix rejection");
    assert!(err.to_string().contains("must not contain the wildcard address '::'"));
  }

  #[cfg(feature = "proxy-protocol")]
  #[test]
  fn test_inbound_proxy_protocol_parsing() {
    let toml_str = r#"
listen_port = 8448
tcp_target = ["127.0.0.1:80"]
tcp_recv_proxy_protocol = true
tcp_trusted_proxies = ["10.0.0.0/8", "192.168.0.0/16"]
"#;
    let config_toml = parse_config_toml(toml_str);
    let config: Config = config_toml.try_into().expect("failed to convert config");

    assert!(config.tcp_recv_proxy_protocol);
    assert_eq!(config.tcp_trusted_proxies.as_ref().map(|v| v.len()), Some(2));
  }
}
