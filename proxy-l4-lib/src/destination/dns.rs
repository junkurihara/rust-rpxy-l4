//! DNS resolution abstractions
//!
//! This module provides pluggable DNS resolution strategies for improved
//! testability and flexibility.

use crate::{target::DnsCache, error::NetworkError};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

/// Trait for DNS resolution strategies
#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
  /// Resolve a hostname to socket addresses
  async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<SocketAddr>, NetworkError>;
}

/// DNS resolver that uses the shared DNS cache
pub struct CachingDnsResolver {
  cache: Arc<DnsCache>,
  #[allow(dead_code)] // These fields will be used for TTL validation in the future
  min_ttl: Duration,
  #[allow(dead_code)]
  max_ttl: Duration,
}

impl CachingDnsResolver {
  /// Create a new caching DNS resolver
  pub fn new(cache: Arc<DnsCache>) -> Self {
    Self {
      cache,
      min_ttl: Duration::from_secs(300), // 5 minutes
      max_ttl: Duration::from_secs(3600), // 1 hour
    }
  }
}

#[async_trait::async_trait]
impl DnsResolver for CachingDnsResolver {
  async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<SocketAddr>, NetworkError> {
    let target = crate::target::TargetAddr::Domain(hostname.to_string(), port);
    target.resolve_cached(&self.cache).await
      .map_err(|e| NetworkError::dns_error(hostname, format!("DNS resolution failed: {}", e)))
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

  /// Add a response for a hostname
  pub fn with_responses(mut self, responses: HashMap<String, Vec<SocketAddr>>) -> Self {
    self.responses = responses;
    self
  }

  /// Add a single response for a hostname
  pub fn add_response(&mut self, hostname: String, addresses: Vec<SocketAddr>) {
    self.responses.insert(hostname, addresses);
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
    if let Some(addresses) = self.responses.get(hostname) {
      Ok(addresses.clone())
    } else {
      // Return a default based on port for testing
      let default_addr = format!("127.0.0.1:{}", port).parse()
        .map_err(|_| NetworkError::dns_error(hostname, "Invalid address format"))?;
      Ok(vec![default_addr])
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::target::DnsCache;

  #[tokio::test]
  async fn test_caching_dns_resolver() {
    let cache = Arc::new(DnsCache::default());
    let resolver = CachingDnsResolver::new(cache);
    
    // Test resolution (this will actually resolve DNS)
    let result = resolver.resolve("localhost", 8080).await;
    assert!(result.is_ok());
    let addresses = result.unwrap();
    assert!(!addresses.is_empty());
  }

  #[tokio::test]
  async fn test_mock_dns_resolver() {
    let mut resolver = MockDnsResolver::new();
    resolver.add_response("example.com".to_string(), vec!["192.168.1.1:80".parse().unwrap()]);
    
    let result = resolver.resolve("example.com", 80).await.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "192.168.1.1:80".parse().unwrap());
  }

  #[tokio::test]
  async fn test_mock_dns_resolver_with_responses() {
    let mut responses = HashMap::new();
    responses.insert("test.com".to_string(), vec!["10.0.0.1:443".parse().unwrap()]);
    
    let resolver = MockDnsResolver::new().with_responses(responses);
    
    let result = resolver.resolve("test.com", 443).await.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "10.0.0.1:443".parse().unwrap());
  }

  #[tokio::test]
  async fn test_mock_dns_resolver_not_found() {
    let resolver = MockDnsResolver::new();
    
    // When hostname not found, should return default localhost address
    let result = resolver.resolve("unknown.com", 8080).await.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "127.0.0.1:8080".parse().unwrap());
  }
}
