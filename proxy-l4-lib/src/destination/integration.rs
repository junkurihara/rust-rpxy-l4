//! Integration module for migrating from legacy to new destination abstractions
//!
//! This module provides adapters and builders to replace legacy types with new abstractions
//! while maintaining backward compatibility.

use super::{
  dns::{CachingDnsResolver, DnsResolver},
  config::LoadBalance,
  tls::TlsDestinationItem,
  load_balancer::{FirstAvailableLoadBalancer, LoadBalancer, RandomLoadBalancer, SourceIpLoadBalancer, SourceSocketLoadBalancer},
  tls_router::{TlsRouter, TlsRoutingRule},
};
use crate::{
  config::EchProtocolConfig,
  error::{ProxyBuildError, ProxyError},
  target::{DnsCache, TargetAddr},
};
use std::{fmt, net::SocketAddr, sync::Arc};

// Debug implementations for the structs
impl fmt::Debug for ModernTargetDestination {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ModernTargetDestination")
      .field("targets", &self.targets)
      .field("dns_resolver", &"<dyn DnsResolver>")
      .field("load_balancer", &"<dyn LoadBalancer>")
      .finish()
  }
}

impl<T: fmt::Debug> fmt::Debug for ModernTlsDestinations<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ModernTlsDestinations").field("router", &self.router).finish()
  }
}

/// Modern replacement for legacy TargetDestination
/// Combines DNS resolution and load balancing using new abstractions
#[derive(Clone)]
pub struct ModernTargetDestination {
  targets: Vec<TargetAddr>,
  dns_resolver: Arc<dyn DnsResolver>,
  load_balancer: Arc<dyn LoadBalancer>,
}

impl ModernTargetDestination {
  /// Create a new modern target destination
  pub fn new(targets: Vec<TargetAddr>, dns_resolver: Arc<dyn DnsResolver>, load_balancer: Arc<dyn LoadBalancer>) -> Self {
    Self {
      targets,
      dns_resolver,
      load_balancer,
    }
  }

  /// Get destination address using modern abstractions
  pub async fn get_destination(&self, src_addr: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    // Resolve all targets to socket addresses
    let mut all_resolved = Vec::new();

    for target in &self.targets {
      match target {
        TargetAddr::Socket(addr) => {
          all_resolved.push(*addr);
        }
        TargetAddr::Domain(domain, port) => {
          let resolved = self.dns_resolver.resolve(domain, *port).await?;
          all_resolved.extend(resolved);
        }
      }
    }

    if all_resolved.is_empty() {
      return Err(ProxyError::no_destination_address());
    }

    // Use load balancer to select target
    self.load_balancer.select_target(*src_addr, &all_resolved).await
  }
}

/// Factory for creating load balancers from legacy configuration
pub fn create_load_balancer(load_balance: LoadBalance) -> Arc<dyn LoadBalancer> {
  match load_balance {
    LoadBalance::SourceIp => Arc::new(SourceIpLoadBalancer::new()),
    LoadBalance::SourceSocket => Arc::new(SourceSocketLoadBalancer::new()),
    LoadBalance::Random => Arc::new(RandomLoadBalancer::new()),
    LoadBalance::None => Arc::new(FirstAvailableLoadBalancer::new()),
  }
}

/// Convert legacy configuration to modern target destination
impl TryFrom<(&[TargetAddr], Option<&LoadBalance>, Arc<DnsCache>)> for ModernTargetDestination {
  type Error = ProxyBuildError;

  fn try_from(
    (dst_addrs, load_balance, dns_cache): (&[TargetAddr], Option<&LoadBalance>, Arc<DnsCache>),
  ) -> Result<Self, Self::Error> {
    if dst_addrs.is_empty() {
      return Err(ProxyBuildError::build_multiplexers_error("Empty target list".to_string()));
    }

    let load_balance = load_balance.copied().unwrap_or_default();
    let dns_resolver = Arc::new(CachingDnsResolver::new(dns_cache));
    let load_balancer = create_load_balancer(load_balance);

    Ok(Self::new(dst_addrs.to_vec(), dns_resolver, load_balancer))
  }
}

/// Modern replacement for legacy TlsDestinations
/// Uses the new TlsRouter with proper rule-based routing
#[derive(Clone)]
pub struct ModernTlsDestinations<T> {
  router: TlsRouter<TlsDestinationItem<T>>,
}

impl<T> ModernTlsDestinations<T> {
  /// Create a new modern TLS destinations router
  pub fn new() -> Self {
    Self {
      router: TlsRouter::new(),
    }
  }

  /// Add a destination with routing rules
  pub fn add(
    &mut self,
    server_names: &[&str],
    alpn: &[&str],
    dest: T,
    ech: Option<EchProtocolConfig>,
    dns_cache: &Arc<DnsCache>,
  ) {
    let destination_item = TlsDestinationItem::new(dest, ech, dns_cache.clone());

    // Create routing rule with proper priority
    let mut rule = TlsRoutingRule::new();

    if !server_names.is_empty() {
      rule = rule.with_server_names(server_names);
    }

    if !alpn.is_empty() {
      rule = rule.with_alpn_protocols(alpn);
    }
    self.router.add_route(rule, destination_item);
  }

  /// Find destination using the modern router
  pub fn find(&self, client_hello: &quic_tls::TlsClientHello) -> Option<&TlsDestinationItem<T>> {
    self.router.find_destination(client_hello)
  }

  /// Check if router is empty
  pub fn is_empty(&self) -> bool {
    self.router.is_empty()
  }
}

impl<T> Default for ModernTlsDestinations<T> {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::destination::{dns::MockDnsResolver, load_balancer::FirstAvailableLoadBalancer};
  use std::collections::HashMap;

  #[tokio::test]
  async fn test_modern_target_destination() {
    let mut responses = HashMap::new();
    responses.insert("example.com".to_string(), vec!["192.168.1.1:80".parse().unwrap()]);

    let mock_dns = Arc::new(MockDnsResolver::new().with_responses(responses));
    let load_balancer = Arc::new(FirstAvailableLoadBalancer::new());

    let targets = vec![TargetAddr::Domain("example.com".to_string(), 80)];

    let destination = ModernTargetDestination::new(targets, mock_dns, load_balancer);

    let src_addr = "10.0.0.1:12345".parse().unwrap();
    let result = destination.get_destination(&src_addr).await.unwrap();

    assert_eq!(result, "192.168.1.1:80".parse().unwrap());
  }

  #[tokio::test]
  async fn test_modern_tls_destinations() {
    let dns_cache = Arc::new(DnsCache::default());
    let mut tls_destinations = ModernTlsDestinations::new();

    // Mock destination type
    #[derive(Debug, Clone)]
    struct MockDestination {
      address: SocketAddr,
    }

    let dest1 = MockDestination {
      address: "192.168.1.1:443".parse().unwrap(),
    };

    let dest2 = MockDestination {
      address: "192.168.1.2:443".parse().unwrap(),
    };

    // Add destinations with different rules
    tls_destinations.add(&["example.com"], &[], dest1, None, &dns_cache);
    tls_destinations.add(&["test.com"], &["h2"], dest2, None, &dns_cache);

    // Create a mock client hello
    use quic_tls::{TlsClientHello, extension::ServerNameIndication};

    let mut client_hello = TlsClientHello::default();
    let mut sni = ServerNameIndication::default();
    sni.add_server_name("example.com");
    client_hello.add_replace_sni(&sni);

    let found = tls_destinations.find(&client_hello);
    assert!(found.is_some());
  }

  #[test]
  fn test_load_balancer_factory() {
    let lb1 = create_load_balancer(LoadBalance::SourceIp);
    let lb2 = create_load_balancer(LoadBalance::Random);
    let lb3 = create_load_balancer(LoadBalance::None);

    // Verify types are created successfully (this is more of a compilation test)
    // We can't easily compare trait object types, so just ensure they're created
    assert!(!std::ptr::eq(lb1.as_ref(), lb2.as_ref()));
    assert!(!std::ptr::eq(lb2.as_ref(), lb3.as_ref()));
  }
}
