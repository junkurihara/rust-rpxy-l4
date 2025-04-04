use crate::{
  config::EchProtocolConfig,
  error::{ProxyBuildError, ProxyError},
};
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
  type Error = ProxyBuildError;
  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match value {
      "source_ip" => Ok(LoadBalance::SourceIp),
      "source_socket" => Ok(LoadBalance::SourceSocket),
      "random" => Ok(LoadBalance::Random),
      "none" => Ok(LoadBalance::None),
      _ => Err(ProxyBuildError::InvalidLoadBalance(value.to_string())),
    }
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, derive_builder::Builder)]
#[builder(build_fn(validate = "Self::validate"))]
/// Destination inner struct, contained in TcpDestination and UdpDestination
pub struct Destination {
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
  pub(crate) fn get_destination(&self, src_addr: &SocketAddr) -> Result<&SocketAddr, ProxyError> {
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
    self.dst_addrs.get(index).ok_or(ProxyError::NoDestinationAddress)
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, Default)]
/// Matching rule of TLS Server Name Indication (SNI) and Application-Layer Protocol Negotiation (ALPN) for routing
pub(crate) struct TlsMatchingRule {
  /// Matched SNIs for the destination
  /// If empty, any SNI is allowed
  sni: Vec<String>,
  /// Matched ALPNs for the destination
  /// If empty, any ALPN is allowed
  alpn: Vec<String>,
}
impl From<(&[&str], &[&str])> for TlsMatchingRule {
  fn from((server_names, alpn): (&[&str], &[&str])) -> Self {
    Self {
      sni: server_names.iter().map(|s| s.to_lowercase()).collect(),
      alpn: alpn.iter().map(|s| s.to_lowercase()).collect(),
    }
  }
}

#[derive(Clone, Debug, Default)]
/// TCP/UDP destinations + EchProtocolConfig
pub(crate) struct TlsDestinationItem<T> {
  /// Destination (UdpDestination or TcpDestination)
  dest: T,
  // /// EchProtocolConfig
  ech: Option<EchProtocolConfig>,
}
impl<T> TlsDestinationItem<T> {
  /// Create a new instance
  pub fn new(dest: T, ech: Option<EchProtocolConfig>) -> Self {
    Self { dest, ech }
  }
  /// Get the destination
  pub fn destination(&self) -> &T {
    &self.dest
  }
  /// Get the ECH config
  pub fn ech(&self) -> Option<&EchProtocolConfig> {
    self.ech.as_ref()
  }
}

#[derive(Debug, Clone, Default)]
/// Router for TLS/QUIC destinations
pub(crate) struct TlsDestinations<T> {
  /// inner
  inner: Vec<(TlsMatchingRule, TlsDestinationItem<T>)>,
}
impl<T> TlsDestinations<T> {
  /// Create a new instance
  pub fn new() -> Self {
    Self { inner: Vec::new() }
  }
  /// Add a destination with SNI and ALPN
  pub fn add(&mut self, server_names: &[&str], alpn: &[&str], dest: T, ech: Option<EchProtocolConfig>) {
    let item = TlsDestinationItem::new(dest, ech);
    self.inner.push((TlsMatchingRule::from((server_names, alpn)), item));
  }
  /// Find a destination by SNI and ALPN
  pub fn find(&self, received_client_hello: &quic_tls::TlsClientHello) -> Option<&TlsDestinationItem<T>> {
    let sni = received_client_hello.sni();
    let alpn = received_client_hello.alpn();
    let received_sni = sni.iter().map(|v| v.to_lowercase());
    let received_alpn = alpn.iter().map(|v| v.to_lowercase());

    let filtered = {
      let filtered = self.inner.iter().filter(|(rule, _)| {
        let is_sni_match = rule
          .sni
          .iter()
          .any(|server_name| received_sni.clone().any(|r| r.eq(server_name)))
          || rule.sni.is_empty();
        let is_alpn_match = rule.alpn.iter().any(|alpn| received_alpn.clone().any(|r| r.eq(alpn))) || rule.alpn.is_empty();
        is_sni_match && is_alpn_match
      });
      // Extract the most specific match
      if let Some(both_matched) = filtered
        .clone()
        .find(|(rule, _)| !rule.sni.is_empty() && !rule.alpn.is_empty())
      {
        Some(both_matched)
      } else if let Some(sni_matched) = filtered.clone().find(|(rule, _)| !rule.sni.is_empty()) {
        Some(sni_matched)
      } else if let Some(alpn_matched) = filtered.clone().find(|(rule, _)| !rule.alpn.is_empty()) {
        Some(alpn_matched)
      } else {
        filtered.clone().next()
      }
    };
    filtered.map(|(_, dest)| dest)
  }
}

/* ---------------------------------------------------------- */
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

  #[test]
  fn test_tls_destinations() {
    let mut tls_destinations = TlsDestinations::new();
    tls_destinations.add(&["example.com"], &[], "127.0.0.1", None);
    tls_destinations.add(&["example.org"], &[], "192.168.0.1", None);
    tls_destinations.add(&[], &[], "1.1.1.1", None);

    tls_destinations.add(&[], &["h2"], "8.8.8.8", None);
    tls_destinations.add(&["example.com"], &["h2"], "127.0.0.2", None);

    // Test SNI
    // Match only sni
    let mut received = quic_tls::TlsClientHello::default();

    let mut sni = quic_tls::extension::ServerNameIndication::default();
    sni.add_server_name("example.com");
    received.add_replace_sni(&sni);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("127.0.0.1"));

    let mut sni = quic_tls::extension::ServerNameIndication::default();
    sni.add_server_name("example.org");
    received.add_replace_sni(&sni);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("192.168.0.1"));

    // Doesn't match sni
    let mut sni = quic_tls::extension::ServerNameIndication::default();
    sni.add_server_name("example.net");
    received.add_replace_sni(&sni);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("1.1.1.1"));

    // Doesn't match sni
    let mut sni = quic_tls::extension::ServerNameIndication::default();
    sni.add_server_name("example.io");
    received.add_replace_sni(&sni);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("1.1.1.1"));

    // Test ALPN
    // Match only alpn
    let mut received = quic_tls::TlsClientHello::default();
    let mut alpn = quic_tls::extension::ApplicationLayerProtocolNegotiation::default();
    alpn.add_protocol_name("h2");
    received.add_replace_alpn(&alpn);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("8.8.8.8"));

    // Doesn't match alpn
    let mut alpn = quic_tls::extension::ApplicationLayerProtocolNegotiation::default();
    alpn.add_protocol_name("h3");
    received.add_replace_alpn(&alpn);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("1.1.1.1"));

    // Test both SNI and ALPN
    // Match both sni and alpn to single destination
    let mut sni = quic_tls::extension::ServerNameIndication::default();
    sni.add_server_name("example.com");
    received.add_replace_sni(&sni);
    let mut alpn = quic_tls::extension::ApplicationLayerProtocolNegotiation::default();
    alpn.add_protocol_name("h2");
    received.add_replace_alpn(&alpn);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("127.0.0.2"));

    // Match sni but doesn't match alpn
    let mut alpn = quic_tls::extension::ApplicationLayerProtocolNegotiation::default();
    alpn.add_protocol_name("h3");
    received.add_replace_alpn(&alpn);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("127.0.0.1"));

    // Match sni and alpn "independently", sni is prioritized
    let mut sni = quic_tls::extension::ServerNameIndication::default();
    sni.add_server_name("example.org");
    received.add_replace_sni(&sni);
    let mut alpn = quic_tls::extension::ApplicationLayerProtocolNegotiation::default();
    alpn.add_protocol_name("h2");
    received.add_replace_alpn(&alpn);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("192.168.0.1"));

    // Match neither sni nor alpn
    let mut sni = quic_tls::extension::ServerNameIndication::default();
    sni.add_server_name("example.net");
    received.add_replace_sni(&sni);
    let mut alpn = quic_tls::extension::ApplicationLayerProtocolNegotiation::default();
    alpn.add_protocol_name("h3");
    received.add_replace_alpn(&alpn);
    let dest = tls_destinations.find(&received);
    assert_eq!(dest.map(|v| v.dest), Some("1.1.1.1"));
  }
}
