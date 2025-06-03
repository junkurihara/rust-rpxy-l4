//! Migration demonstration: old vs new destination abstractions
//!
//! This demonstrates how to replace legacy destination code with new abstractions.

use super::{
  integration::{ModernTargetDestination, ModernTlsDestinations},
  legacy::{LoadBalance, TargetDestination, TlsDestinations},
};
use crate::{
  target::{DnsCache, TargetAddr},
  error::ProxyError,
};
use std::{net::SocketAddr, sync::Arc};

/// Demonstrates the old way of creating destinations
pub struct LegacyDestinationExample {
  destination: TargetDestination,
  tls_destinations: TlsDestinations<String>,
}

impl LegacyDestinationExample {
  pub fn new(
    targets: &[TargetAddr],
    load_balance: Option<&LoadBalance>,
    dns_cache: Arc<DnsCache>,
  ) -> Result<Self, ProxyError> {
    let destination = TargetDestination::try_from((targets, load_balance, dns_cache.clone()))
      .map_err(|e| ProxyError::Build(e))?;
    let tls_destinations = TlsDestinations::new();
    
    Ok(Self {
      destination,
      tls_destinations,
    })
  }

  pub async fn get_destination(&self, src: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    self.destination.get_destination(src).await
  }
}

/// Demonstrates the new way using modern abstractions
pub struct ModernDestinationExample {
  destination: ModernTargetDestination,
  tls_destinations: ModernTlsDestinations<String>,
}

impl ModernDestinationExample {
  pub fn new(
    targets: &[TargetAddr],
    load_balance: Option<&LoadBalance>,
    dns_cache: Arc<DnsCache>,
  ) -> Result<Self, ProxyError> {
    let destination = ModernTargetDestination::try_from((targets, load_balance, dns_cache.clone()))
      .map_err(|e| ProxyError::Build(e))?;
    let tls_destinations = ModernTlsDestinations::new();
    
    Ok(Self {
      destination,
      tls_destinations,
    })
  }

  pub async fn get_destination(&self, src: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    self.destination.get_destination(src).await
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::{IpAddr, Ipv4Addr};

  #[tokio::test]
  async fn test_legacy_vs_modern_destination() {
    let dns_cache = Arc::new(DnsCache::default());
    let targets = vec![TargetAddr::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080))];
    let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345);

    // Test legacy implementation
    let legacy = LegacyDestinationExample::new(&targets, Some(&LoadBalance::None), dns_cache.clone()).unwrap();
    let legacy_result = legacy.get_destination(&src_addr).await.unwrap();

    // Test modern implementation
    let modern = ModernDestinationExample::new(&targets, Some(&LoadBalance::None), dns_cache).unwrap();
    let modern_result = modern.get_destination(&src_addr).await.unwrap();

    // Both should give the same result
    assert_eq!(legacy_result, modern_result);
    assert_eq!(legacy_result, "127.0.0.1:8080".parse().unwrap());
  }

  #[tokio::test]
  async fn test_different_load_balancers() {
    let dns_cache = Arc::new(DnsCache::default());
    let targets = vec![
      TargetAddr::Socket("127.0.0.1:8001".parse().unwrap()),
      TargetAddr::Socket("127.0.0.1:8002".parse().unwrap()),
      TargetAddr::Socket("127.0.0.1:8003".parse().unwrap()),
    ];
    let src_addr = "10.0.0.1:12345".parse().unwrap();

    // Test different load balancing strategies
    let strategies = [LoadBalance::None, LoadBalance::SourceIp, LoadBalance::Random];

    for strategy in &strategies {
      let legacy = LegacyDestinationExample::new(&targets, Some(strategy), dns_cache.clone()).unwrap();
      let modern = ModernDestinationExample::new(&targets, Some(strategy), dns_cache.clone()).unwrap();

      let legacy_result = legacy.get_destination(&src_addr).await.unwrap();
      let modern_result = modern.get_destination(&src_addr).await.unwrap();

      // For deterministic strategies (None, SourceIp), results should be the same
      if matches!(strategy, LoadBalance::None | LoadBalance::SourceIp) {
        // For SourceIp, we expect consistency within each implementation
        // but the two implementations might use different hashers, so just check validity
        if matches!(strategy, LoadBalance::None) {
          // None should always return the first target
          assert_eq!(legacy_result, targets[0].to_string().parse().unwrap());
          assert_eq!(modern_result, targets[0].to_string().parse().unwrap());
        } else {
          // SourceIp should be consistent within each implementation
          let legacy_result2 = legacy.get_destination(&src_addr).await.unwrap();
          let modern_result2 = modern.get_destination(&src_addr).await.unwrap();
          assert_eq!(legacy_result, legacy_result2);
          assert_eq!(modern_result, modern_result2);
        }
      }
      // All results should be valid targets
      assert!(targets.iter().any(|t| match t {
        TargetAddr::Socket(addr) => *addr == legacy_result,
        _ => false,
      }));
      assert!(targets.iter().any(|t| match t {
        TargetAddr::Socket(addr) => *addr == modern_result,
        _ => false,
      }));
    }
  }
}
