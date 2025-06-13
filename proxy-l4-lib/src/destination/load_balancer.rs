//! Load balancing strategies
//!
//! This module provides pluggable load balancing algorithms for distributing
//! connections across multiple target servers.

use crate::error::ProxyError;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Trait for load balancing strategies
#[async_trait::async_trait]
pub trait LoadBalancer: Send + Sync {
  /// Select a target from the list of available targets
  async fn select_target(&self, src: SocketAddr, targets: &[SocketAddr]) -> Result<SocketAddr, ProxyError>;
}

/// Source IP-based load balancer
///
/// Routes connections from the same source IP to the same backend server
/// consistently using a hash of the source IP address.
pub struct SourceIpLoadBalancer {
  hasher: ahash::RandomState,
}

impl SourceIpLoadBalancer {
  /// Create a new source IP load balancer
  pub fn new() -> Self {
    Self {
      hasher: ahash::RandomState::default(),
    }
  }

  /// Create a new source IP load balancer with a specific hasher
  pub fn with_hasher(hasher: ahash::RandomState) -> Self {
    Self { hasher }
  }
}

impl Default for SourceIpLoadBalancer {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait::async_trait]
impl LoadBalancer for SourceIpLoadBalancer {
  async fn select_target(&self, src: SocketAddr, targets: &[SocketAddr]) -> Result<SocketAddr, ProxyError> {
    if targets.is_empty() {
      return Err(ProxyError::no_destination_address());
    }

    let hash = self.hasher.hash_one(src.ip());
    let index = (hash % targets.len() as u64) as usize;
    Ok(targets[index])
  }
}

/// Source socket-based load balancer
///
/// Routes connections from the same source socket (IP + port) to the same
/// backend server consistently using a hash of the source socket address.
pub struct SourceSocketLoadBalancer {
  hasher: ahash::RandomState,
}

impl SourceSocketLoadBalancer {
  /// Create a new source socket load balancer
  pub fn new() -> Self {
    Self {
      hasher: ahash::RandomState::default(),
    }
  }

  /// Create a new source socket load balancer with a specific hasher
  pub fn with_hasher(hasher: ahash::RandomState) -> Self {
    Self { hasher }
  }
}

impl Default for SourceSocketLoadBalancer {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait::async_trait]
impl LoadBalancer for SourceSocketLoadBalancer {
  async fn select_target(&self, src: SocketAddr, targets: &[SocketAddr]) -> Result<SocketAddr, ProxyError> {
    if targets.is_empty() {
      return Err(ProxyError::no_destination_address());
    }

    let hash = self.hasher.hash_one(src);
    let index = (hash % targets.len() as u64) as usize;
    Ok(targets[index])
  }
}

/// Random load balancer
///
/// Randomly selects a target server for each connection.
pub struct RandomLoadBalancer;

impl RandomLoadBalancer {
  /// Create a new random load balancer
  pub fn new() -> Self {
    Self
  }
}

impl Default for RandomLoadBalancer {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait::async_trait]
impl LoadBalancer for RandomLoadBalancer {
  async fn select_target(&self, _src: SocketAddr, targets: &[SocketAddr]) -> Result<SocketAddr, ProxyError> {
    if targets.is_empty() {
      return Err(ProxyError::no_destination_address());
    }

    let index = rand::rng().random_range(0..targets.len());
    Ok(targets[index])
  }
}

/// Round-robin load balancer
///
/// Distributes connections evenly across all target servers in a rotating fashion.
pub struct RoundRobinLoadBalancer {
  counter: AtomicUsize,
}

impl RoundRobinLoadBalancer {
  /// Create a new round-robin load balancer
  pub fn new() -> Self {
    Self {
      counter: AtomicUsize::new(0),
    }
  }
}

impl Default for RoundRobinLoadBalancer {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait::async_trait]
impl LoadBalancer for RoundRobinLoadBalancer {
  async fn select_target(&self, _src: SocketAddr, targets: &[SocketAddr]) -> Result<SocketAddr, ProxyError> {
    if targets.is_empty() {
      return Err(ProxyError::no_destination_address());
    }

    let count = self.counter.fetch_add(1, Ordering::Relaxed);
    let index = count % targets.len();
    Ok(targets[index])
  }
}

/// First available load balancer (no balancing)
///
/// Always selects the first target in the list.
pub struct FirstAvailableLoadBalancer;

impl FirstAvailableLoadBalancer {
  /// Create a new first available load balancer
  pub fn new() -> Self {
    Self
  }
}

impl Default for FirstAvailableLoadBalancer {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait::async_trait]
impl LoadBalancer for FirstAvailableLoadBalancer {
  async fn select_target(&self, _src: SocketAddr, targets: &[SocketAddr]) -> Result<SocketAddr, ProxyError> {
    if targets.is_empty() {
      return Err(ProxyError::no_destination_address());
    }

    Ok(targets[0])
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::{IpAddr, Ipv4Addr};

  fn create_test_targets() -> Vec<SocketAddr> {
    vec![
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080),
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 8080),
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 8080),
    ]
  }

  #[tokio::test]
  async fn test_source_ip_load_balancer() {
    let balancer = SourceIpLoadBalancer::new();
    let targets = create_test_targets();
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

    // Same source IP should always get the same target
    let target1 = balancer.select_target(src, &targets).await.unwrap();
    let target2 = balancer.select_target(src, &targets).await.unwrap();
    assert_eq!(target1, target2);

    // Different source IPs might get different targets
    let src2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 12345);
    let target3 = balancer.select_target(src2, &targets).await.unwrap();
    // We can't guarantee they're different due to hash collisions, but they should be valid
    assert!(targets.contains(&target3));
  }

  #[tokio::test]
  async fn test_source_socket_load_balancer() {
    let balancer = SourceSocketLoadBalancer::new();
    let targets = create_test_targets();
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

    // Same source socket should always get the same target
    let target1 = balancer.select_target(src, &targets).await.unwrap();
    let target2 = balancer.select_target(src, &targets).await.unwrap();
    assert_eq!(target1, target2);

    // Different source ports should get different targets (usually)
    let src2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12346);
    let target3 = balancer.select_target(src2, &targets).await.unwrap();
    assert!(targets.contains(&target3));
  }

  #[tokio::test]
  async fn test_random_load_balancer() {
    let balancer = RandomLoadBalancer::new();
    let targets = create_test_targets();
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

    // Should always return a valid target
    for _ in 0..10 {
      let target = balancer.select_target(src, &targets).await.unwrap();
      assert!(targets.contains(&target));
    }
  }

  #[tokio::test]
  async fn test_round_robin_load_balancer() {
    let balancer = RoundRobinLoadBalancer::new();
    let targets = create_test_targets();
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

    // Should cycle through all targets
    let mut selected_targets = Vec::new();
    for _ in 0..6 {
      // 2 full cycles
      let target = balancer.select_target(src, &targets).await.unwrap();
      selected_targets.push(target);
    }

    // Should have visited all targets in order, twice
    assert_eq!(selected_targets[0], targets[0]);
    assert_eq!(selected_targets[1], targets[1]);
    assert_eq!(selected_targets[2], targets[2]);
    assert_eq!(selected_targets[3], targets[0]); // Second cycle
    assert_eq!(selected_targets[4], targets[1]);
    assert_eq!(selected_targets[5], targets[2]);
  }

  #[tokio::test]
  async fn test_first_available_load_balancer() {
    let balancer = FirstAvailableLoadBalancer::new();
    let targets = create_test_targets();
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

    // Should always return the first target
    for _ in 0..10 {
      let target = balancer.select_target(src, &targets).await.unwrap();
      assert_eq!(target, targets[0]);
    }
  }

  #[tokio::test]
  async fn test_empty_targets() {
    let targets = vec![];
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

    let balancers: Vec<Box<dyn LoadBalancer>> = vec![
      Box::new(SourceIpLoadBalancer::new()),
      Box::new(SourceSocketLoadBalancer::new()),
      Box::new(RandomLoadBalancer::new()),
      Box::new(RoundRobinLoadBalancer::new()),
      Box::new(FirstAvailableLoadBalancer::new()),
    ];

    for balancer in balancers {
      let result = balancer.select_target(src, &targets).await;
      assert!(result.is_err());
    }
  }
}
