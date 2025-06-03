//! Legacy destination types
//!
//! This module contains the original destination functionality for backward compatibility
//! during the Phase 5 refactoring.

use crate::{
  config::EchProtocolConfig,
  error::{ProxyBuildError, ProxyError},
  target::{DnsCache, TargetAddr},
};
use rand::Rng;
use std::{net::SocketAddr, sync::Arc};

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
      _ => Err(ProxyBuildError::invalid_load_balance(value.to_string())),
    }
  }
}

/* ---------------------------------------------------------- */
/// Enhanced destination that supports both IP addresses and domain names with DNS caching
#[derive(Debug, Clone, derive_builder::Builder)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct TargetDestination {
  /// Target addresses (can be IP addresses or domain names)
  dst_addrs: Vec<TargetAddr>,

  #[builder(default = "LoadBalance::default()")]
  /// Load balancing policy
  load_balance: LoadBalance,

  /// DNS cache reference
  dns_cache: Arc<DnsCache>,

  /// Random source leveraged for load balancing policies
  #[builder(setter(skip), default = "ahash::RandomState::default()")]
  random: ahash::RandomState,
}

impl TargetDestinationBuilder {
  fn validate(&self) -> Result<(), String> {
    if self.dst_addrs.is_none() {
      return Err("dst_addrs is required".to_string());
    }
    if self.dst_addrs.as_ref().unwrap().is_empty() {
      return Err("dst_addrs is empty".to_string());
    }
    if self.dns_cache.is_none() {
      return Err("dns_cache is required".to_string());
    }
    Ok(())
  }
}

impl TargetDestination {
  /// Get the destination socket address according to the given load balancing policy
  /// This method resolves domain names using the DNS cache if needed
  pub async fn get_destination(&self, src_addr: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    // First select which target to use based on load balancing
    let target_index = match self.load_balance {
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

    let target = self.dst_addrs.get(target_index).ok_or(ProxyError::no_destination_address())?;

    // Resolve the target to get actual socket addresses
    let resolved_addrs = target.resolve_cached(&self.dns_cache).await?;

    if resolved_addrs.is_empty() {
      return Err(ProxyError::no_destination_address());
    }

    // If we have multiple resolved addresses, select one consistently
    let addr_index = if resolved_addrs.len() == 1 {
      0
    } else {
      // Use a secondary hash combining source address and target for consistent selection
      let combined_hash = self.random.hash_one((src_addr, target_index));
      (combined_hash % resolved_addrs.len() as u64) as usize
    };

    Ok(resolved_addrs[addr_index])
  }

  #[allow(unused)]
  /// Get all possible destination addresses (for protocols that need to know all targets)
  pub async fn get_all_destinations(&self) -> Result<Vec<SocketAddr>, ProxyError> {
    let mut all_addrs = Vec::new();

    for target in &self.dst_addrs {
      let resolved = target.resolve_cached(&self.dns_cache).await?;
      all_addrs.extend(resolved);
    }

    Ok(all_addrs)
  }
}

impl TryFrom<(&[TargetAddr], Option<&LoadBalance>, Arc<DnsCache>)> for TargetDestination {
  type Error = ProxyBuildError;
  fn try_from(
    (dst_addrs, load_balance, dns_cache): (&[TargetAddr], Option<&LoadBalance>, Arc<DnsCache>),
  ) -> Result<Self, Self::Error> {
    let binding = LoadBalance::default();
    let load_balance = load_balance.unwrap_or(&binding);
    TargetDestinationBuilder::default()
      .dst_addrs(dst_addrs.to_vec())
      .load_balance(*load_balance)
      .dns_cache(dns_cache)
      .build()
      .map_err(|e| ProxyBuildError::TargetDestinationBuilderError {
        message: format!("{}", e),
      })
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, Default)]
/// Matching rule of TLS Server Name Indication (SNI) and Application-Layer Protocol Negotiation (ALPN) for routing
pub struct TlsMatchingRule {
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
pub struct TlsDestinationItem<T> {
  /// Destination (UdpDestination or TcpDestination)
  /// If ECH decryption is failed (no matched ECH config), this destination will be used as the default destination
  dest: T,
  /// EchProtocolConfig
  ech: Option<EchProtocolConfig>,
  /// DnsCache
  dns_cache: Arc<DnsCache>,
}
impl<T> TlsDestinationItem<T> {
  /// Create a new instance
  pub fn new(dest: T, ech: Option<EchProtocolConfig>, dns_cache: Arc<DnsCache>) -> Self {
    Self { dest, ech, dns_cache }
  }
  /// Get the destination
  pub fn destination(&self) -> &T {
    &self.dest
  }
  /// Get the ECH config
  pub fn ech(&self) -> Option<&EchProtocolConfig> {
    self.ech.as_ref()
  }
  /// Get the DNS cache
  pub fn dns_cache(&self) -> &Arc<DnsCache> {
    &self.dns_cache
  }
}

#[derive(Debug, Clone, Default)]
/// Router for TLS/QUIC destinations
pub struct TlsDestinations<T> {
  /// inner
  inner: Vec<(TlsMatchingRule, TlsDestinationItem<T>)>,
}
impl<T> TlsDestinations<T> {
  /// Create a new instance
  pub fn new() -> Self {
    Self { inner: Vec::new() }
  }
  /// Add a destination with SNI and ALPN
  pub fn add(
    &mut self,
    server_names: &[&str],
    alpn: &[&str],
    dest: T,
    ech: Option<EchProtocolConfig>,
    dns_cache: &Arc<DnsCache>,
  ) {
    let item = TlsDestinationItem::new(dest, ech, dns_cache.clone());
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
