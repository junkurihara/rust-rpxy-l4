use crate::log::warn;
use anyhow::anyhow;
use rpxy_l4_lib::{Config, LoadBalance, ProtocolConfig, ProtocolType};
use serde::Deserialize;
use std::{
  collections::{HashMap, HashSet},
  fs,
  net::SocketAddr,
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
        let target = target.iter().map(|x| x.parse()).collect::<Result<Vec<SocketAddr>, _>>()?;

        let load_balance: Option<LoadBalance> = protocol_toml
          .load_balance
          .as_ref()
          .map(|x| x.as_str().try_into())
          .transpose()?;

        let protocol = ProtocolConfig {
          protocol: proto_type,
          target,
          load_balance,
          idle_lifetime: protocol_toml.idle_lifetime,
          alpn: protocol_toml.alpn,
          server_names: protocol_toml.server_names,
        };

        protocols.insert(name, protocol);
      }
    }

    let Some(listen_port) = config_toml.listen_port else {
      return Err(anyhow!("listen_port is required"));
    };
    let tcp_target = config_toml
      .tcp_target
      .map(|x| x.iter().map(|x| x.parse()).collect::<Result<Vec<SocketAddr>, _>>())
      .transpose()?;
    let tcp_load_balance = config_toml
      .tcp_load_balance
      .as_ref()
      .map(|x| x.as_str().try_into())
      .transpose()?;
    let udp_target = config_toml
      .udp_target
      .map(|x| x.iter().map(|x| x.parse()).collect::<Result<Vec<SocketAddr>, _>>())
      .transpose()?;
    let udp_load_balance = config_toml
      .udp_load_balance
      .as_ref()
      .map(|x| x.as_str().try_into())
      .transpose()?;

    Ok(Self {
      listen_port,
      listen_ipv6: config_toml.listen_ipv6.unwrap_or(false),
      tcp_backlog: config_toml.tcp_backlog,
      tcp_max_connections: config_toml.tcp_max_connections,
      udp_max_connections: config_toml.udp_max_connections,
      tcp_target,
      tcp_load_balance,
      udp_target,
      udp_load_balance,
      udp_idle_lifetime: config_toml.udp_idle_lifetime,
      protocols,
    })
  }
}
