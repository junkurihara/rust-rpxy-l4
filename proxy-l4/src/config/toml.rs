use crate::{
  //   constants::*,
  //   error::{anyhow, ensure},
  log::warn,
};
// use ahash::HashMap;
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
  pub tcp_target: Option<Vec<SocketAddr>>,
  pub tcp_load_balance: Option<String>,
  // udp default target
  pub udp_target: Option<Vec<SocketAddr>>,
  pub udp_load_balance: Option<String>,
  // protocols
  pub protocols: Option<Protocols>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Protocols(pub HashMap<String, Protocol>);

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Protocol {
  pub protocol: Option<String>,
  pub target: Option<Vec<SocketAddr>>,
  pub load_balance: Option<String>,
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
