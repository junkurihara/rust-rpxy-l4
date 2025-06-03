//! DNS resolution abstractions
//!
//! This module provides pluggable DNS resolution strategies with caching support.

use crate::error::NetworkError;
use crate::target::DnsCache;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Trait for DNS resolution strategies
#[async_trait::async_trait]
pub trait DnsResolver {
  /// Resolve a hostname to socket addresses
  async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<SocketAddr>, NetworkError>;
}

/// Caching DNS resolver that wraps the existing DnsCache
pub struct CachingDnsResolver {
  cache: Arc<DnsCache>,
  min_ttl: Duration,
  max_ttl: Duration,
}

impl CachingDnsResolver {
  /// Create a new caching DNS resolver
  pub fn new(cache: Arc<DnsCache>) -> Self {
    Self {
      cache,
      min_ttl: Duration::from_secs(30),
      max_ttl: Duration::from_secs(3600),
    }
  }

  /// Create a new caching DNS resolver with custom TTL bounds
  pub fn with_ttl_bounds(cache: Arc<DnsCache>, min_ttl: Duration, max_ttl: Duration) -> Self {
    Self { cache, min_ttl, max_ttl }
  }

  /// Get the underlying DNS cache
  pub fn cache(&self) -> &Arc<DnsCache> {
    &self.cache
  }
}

#[async_trait::async_trait]
impl DnsResolver for CachingDnsResolver {
  async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<SocketAddr>, NetworkError> {
    self.cache.get_or_resolve(hostname, port).await.map_err(|e| match e {
      crate::error::ProxyError::Network(net_err) => net_err,
      other => NetworkError::DnsError {
        hostname: hostname.to_string(),
        reason: other.to_string(),
      },
    })
  }
}

/// Mock DNS resolver for testing
pub struct MockDnsResolver {
  responses: HashMap<String, Vec<SocketAddr>>,
}

impl MockDnsResolver {
  /// Create a new mock DNS resolver
  pub fn new() -> Self {
    Self {
      responses: HashMap::new(),
    }
  }

  /// Add a mock response for a hostname
  pub fn add_response(&mut self, hostname: &str, addresses: Vec<SocketAddr>) {
    self.responses.insert(hostname.to_string(), addresses);
  }

  /// Set multiple responses at once
  pub fn with_responses(mut self, responses: HashMap<String, Vec<SocketAddr>>) -> Self {
    self.responses = responses;
    self
  }
}

impl Default for MockDnsResolver {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait::async_trait]
impl DnsResolver for MockDnsResolver {
  async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<SocketAddr>, NetworkError> {
    if let Some(base_addresses) = self.responses.get(hostname) {
      // Apply the port to all addresses
      let addresses = base_addresses.iter().map(|addr| SocketAddr::new(addr.ip(), port)).collect();
      Ok(addresses)
    } else {
      Err(NetworkError::DnsError {
        hostname: hostname.to_string(),
        reason: "No mock response configured".to_string(),
      })
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::{IpAddr, Ipv4Addr};

  #[tokio::test]
  async fn test_caching_dns_resolver() {
    let cache = Arc::new(DnsCache::default());
    let resolver = CachingDnsResolver::new(cache);

    // Test resolution of localhost
    let result = resolver.resolve("localhost", 8080).await;
    assert!(result.is_ok());
    let addresses = result.unwrap();
    assert!(!addresses.is_empty());
    assert_eq!(addresses[0].port(), 8080);
  }

  #[tokio::test]
  async fn test_mock_dns_resolver() {
    let mut resolver = MockDnsResolver::new();
    resolver.add_response(
      "example.com",
      vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 0)],
    );

    let result = resolver.resolve("example.com", 8080).await;
    assert!(result.is_ok());
    let addresses = result.unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0], "192.0.2.1:8080".parse().unwrap());
  }

  #[tokio::test]
  async fn test_mock_dns_resolver_not_found() {
    let resolver = MockDnsResolver::new();

    let result = resolver.resolve("notfound.example", 8080).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), NetworkError::DnsError { .. }));
  }

  #[test]
  fn test_mock_dns_resolver_with_responses() {
    let mut responses = HashMap::new();
    responses.insert(
      "test1.com".to_string(),
      vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 0)],
    );
    responses.insert(
      "test2.com".to_string(),
      vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 0)],
    );

    let resolver = MockDnsResolver::new().with_responses(responses);
    assert_eq!(resolver.responses.len(), 2);
    assert!(resolver.responses.contains_key("test1.com"));
    assert!(resolver.responses.contains_key("test2.com"));
  }
}
