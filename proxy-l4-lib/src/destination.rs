use rand::Rng;
use std::net::SocketAddr;

/* ---------------------------------------------------------- */
/// Load balancing policy
/// Note that in the `SourceIp` and `SourceSocket` policies, a selected servers
/// for a source IP/socket might differs when new [Destination] is created.
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
  type Error = anyhow::Error;
  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match value {
      "source_ip" => Ok(LoadBalance::SourceIp),
      "source_socket" => Ok(LoadBalance::SourceSocket),
      "random" => Ok(LoadBalance::Random),
      "none" => Ok(LoadBalance::None),
      _ => Err(anyhow::anyhow!("Invalid load balance: {}", value)),
    }
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, derive_builder::Builder)]
#[builder(build_fn(validate = "Self::validate"))]
/// Destination inner struct, contained in TcpDestination and UdpDestination
pub(crate) struct Destination {
  /// Destination socket address
  dst_addrs: Vec<SocketAddr>,

  #[builder(default = "LoadBalance::default()")]
  /// Load balancing policy
  load_balance: LoadBalance,

  /// Random source leveraged for load balancing policies [LoadBalance::SourceIp] and [LoadBalance::SourceSocket]
  #[builder(setter(skip), default = "ahash::RandomState::default()")]
  random: ahash::RandomState,
}
impl DestinationBuilder {
  fn validate(&self) -> Result<(), String> {
    if self.dst_addrs.is_none() {
      return Err("dst_addrs is required".to_string());
    }
    if self.dst_addrs.as_ref().unwrap().is_empty() {
      return Err("dst_addrs is empty".to_string());
    }
    Ok(())
  }
}
impl Destination {
  /// Get the destination socket address according to the given load balancing policy
  pub(crate) fn get_destination(&self, src_addr: &SocketAddr) -> Result<&SocketAddr, anyhow::Error> {
    let index = match self.load_balance {
      LoadBalance::SourceIp => {
        let src_ip = src_addr.ip();
        let hash = self.random.hash_one(src_ip);
        (hash % self.dst_addrs.len() as u64) as usize
      }
      LoadBalance::SourceSocket => {
        let hash = self.random.hash_one(src_addr);
        (hash % self.dst_addrs.len() as u64) as usize
      }
      LoadBalance::Random => rand::rng().random_range(0..self.dst_addrs.len()),
      LoadBalance::None => 0,
    };
    self
      .dst_addrs
      .get(index)
      .ok_or_else(|| anyhow::anyhow!("No destination address"))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_load_balance() {
    let dest = DestinationBuilder::default()
      .dst_addrs(vec!["127.0.0.1:12345".parse().unwrap(), "127.0.0.1:12346".parse().unwrap()])
      .load_balance(LoadBalance::SourceIp)
      .build()
      .unwrap();

    let dst_addr_1 = dest.get_destination(&"127.0.0.1:54321".parse().unwrap()).unwrap();
    let dst_addr_2 = dest.get_destination(&"127.0.0.1:55555".parse().unwrap()).unwrap();
    assert_eq!(dst_addr_1, dst_addr_2);
    let dst_addr_3 = dest.get_destination(&"127.0.0.3:54321".parse().unwrap()).unwrap();
    println!("{:?} - (not always equals) - {:?}", dst_addr_1, dst_addr_3);

    let dest = DestinationBuilder::default()
      .dst_addrs(vec!["127.0.0.1:12345".parse().unwrap(), "127.0.0.1:12346".parse().unwrap()])
      .build()
      .unwrap();
    let dst_addr_1 = dest.get_destination(&"127.0.0.1:54321".parse().unwrap()).unwrap();
    let dst_addr_2 = dest.get_destination(&"127.0.0.1:55555".parse().unwrap()).unwrap();
    assert_eq!(dst_addr_1, dst_addr_2);
    assert_eq!(dst_addr_1, &"127.0.0.1:12345".parse().unwrap());

    let dest = DestinationBuilder::default().build();
    assert!(dest.is_err());
    let dest = DestinationBuilder::default().dst_addrs(vec![]).build();
    assert!(dest.is_err());
  }

  #[test]
  fn test_hash() {
    let src_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let hash = ahash::RandomState::default();
    let val = hash.hash_one(src_addr);

    let val2 = hash.hash_one(src_addr);
    assert_eq!(val, val2);

    let hash = ahash::RandomState::default();
    let val2 = hash.hash_one(src_addr);

    assert_ne!(val, val2);
  }
}
