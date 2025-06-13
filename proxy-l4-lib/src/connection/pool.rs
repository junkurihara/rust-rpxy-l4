//! Connection pool abstractions and implementations
//!
//! This module provides traits and implementations for managing connection pools,
//! which are particularly important for UDP connections that need to maintain
//! state between packets.

use crate::error::ConnectionError;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Generic trait for connection pooling
#[async_trait::async_trait]
pub trait ConnectionPool<K, V>
where
  K: Hash + Eq + Clone + Send + Sync,
  V: Send + Sync,
{
  /// Get an existing connection or create a new one using the factory function
  async fn get_or_create<F, Fut>(&self, key: K, factory: F) -> Result<V, ConnectionError>
  where
    F: FnOnce(K) -> Fut + Send,
    Fut: std::future::Future<Output = Result<V, ConnectionError>> + Send;

  /// Get an existing connection if it exists
  fn get(&self, key: &K) -> Option<V>;

  /// Insert a connection into the pool
  fn insert(&self, key: K, value: V);

  /// Remove a connection from the pool
  fn remove(&self, key: &K) -> Option<V>;

  /// Remove expired connections based on some criteria
  fn prune_expired(&self);

  /// Get the current size of the pool
  fn size(&self) -> usize;

  /// Check if the pool is empty
  fn is_empty(&self) -> bool {
    self.size() == 0
  }

  /// Clear all connections from the pool
  fn clear(&self);
}

/// A connection pool entry with expiration tracking
#[derive(Debug, Clone)]
pub struct PoolEntry<V> {
  /// The actual connection/value
  pub value: V,
  /// When this entry was created
  pub created_at: Instant,
  /// When this entry was last accessed
  pub last_accessed: Instant,
  /// Maximum idle time before expiration
  pub max_idle_time: Duration,
}

impl<V> PoolEntry<V> {
  /// Create a new pool entry
  pub fn new(value: V, max_idle_time: Duration) -> Self {
    let now = Instant::now();
    Self {
      value,
      created_at: now,
      last_accessed: now,
      max_idle_time,
    }
  }

  /// Check if this entry has expired
  pub fn is_expired(&self) -> bool {
    self.last_accessed.elapsed() >= self.max_idle_time
  }

  /// Update the last accessed time
  pub fn touch(&mut self) {
    self.last_accessed = Instant::now();
  }

  /// Get the age of this entry
  pub fn age(&self) -> Duration {
    self.created_at.elapsed()
  }

  /// Get the idle time of this entry
  pub fn idle_time(&self) -> Duration {
    self.last_accessed.elapsed()
  }
}

/// DashMap-based connection pool implementation
pub struct DashMapConnectionPool<K, V>
where
  K: Hash + Eq + Clone + Send + Sync,
  V: Clone + Send + Sync,
{
  /// Internal storage using DashMap for concurrent access
  inner: dashmap::DashMap<K, PoolEntry<V>>,
  /// Maximum number of entries in the pool
  max_size: usize,
  /// Default maximum idle time for entries
  default_max_idle_time: Duration,
}

impl<K, V> std::fmt::Debug for DashMapConnectionPool<K, V>
where
  K: Hash + Eq + Clone + Send + Sync,
  V: Clone + Send + Sync,
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("DashMapConnectionPool")
      .field("size", &self.inner.len())
      .field("max_size", &self.max_size)
      .field("default_max_idle_time", &self.default_max_idle_time)
      .finish()
  }
}

impl<K, V> DashMapConnectionPool<K, V>
where
  K: Hash + Eq + Clone + Send + Sync,
  V: Clone + Send + Sync,
{
  /// Create a new DashMap-based connection pool
  pub fn new(max_size: usize, default_max_idle_time: Duration) -> Self {
    Self {
      inner: dashmap::DashMap::new(),
      max_size,
      default_max_idle_time,
    }
  }

  /// Create a new connection pool with default settings
  pub fn with_defaults() -> Self {
    Self::new(1000, Duration::from_secs(300)) // 5 minutes default
  }

  /// Get the maximum size of the pool
  pub fn max_size(&self) -> usize {
    self.max_size
  }

  /// Get the default maximum idle time
  pub fn default_max_idle_time(&self) -> Duration {
    self.default_max_idle_time
  }

  /// Check if the pool is at capacity
  pub fn is_at_capacity(&self) -> bool {
    self.inner.len() >= self.max_size
  }

  /// Get statistics about the pool
  pub fn stats(&self) -> PoolStats {
    let size = self.inner.len();
    let mut expired_count = 0;
    let mut total_age = Duration::ZERO;
    let mut total_idle = Duration::ZERO;

    for entry in self.inner.iter() {
      if entry.is_expired() {
        expired_count += 1;
      }
      total_age += entry.age();
      total_idle += entry.idle_time();
    }

    PoolStats {
      size,
      max_size: self.max_size,
      expired_count,
      average_age: if size > 0 { total_age / size as u32 } else { Duration::ZERO },
      average_idle: if size > 0 { total_idle / size as u32 } else { Duration::ZERO },
    }
  }
}

#[async_trait::async_trait]
impl<K, V> ConnectionPool<K, V> for DashMapConnectionPool<K, V>
where
  K: Hash + Eq + Clone + Send + Sync,
  V: Clone + Send + Sync,
{
  async fn get_or_create<F, Fut>(&self, key: K, factory: F) -> Result<V, ConnectionError>
  where
    F: FnOnce(K) -> Fut + Send,
    Fut: std::future::Future<Output = Result<V, ConnectionError>> + Send,
  {
    // Try to get existing entry first
    if let Some(mut entry) = self.inner.get_mut(&key) {
      if !entry.is_expired() {
        entry.touch();
        return Ok(entry.value.clone());
      } else {
        // Remove expired entry
        drop(entry);
        self.inner.remove(&key);
      }
    }

    // Check capacity before creating new entry
    if self.is_at_capacity() {
      // Try to prune some expired entries first
      self.prune_expired();

      // If still at capacity, return error
      if self.is_at_capacity() {
        return Err(ConnectionError::LimitExceeded {
          current: self.size(),
          max: self.max_size,
        });
      }
    }

    // Create new connection
    let value = factory(key.clone()).await?;
    let entry = PoolEntry::new(value.clone(), self.default_max_idle_time);
    self.inner.insert(key, entry);

    Ok(value)
  }

  fn get(&self, key: &K) -> Option<V> {
    if let Some(mut entry) = self.inner.get_mut(key) {
      if !entry.is_expired() {
        entry.touch();
        Some(entry.value.clone())
      } else {
        // Remove expired entry
        drop(entry);
        self.inner.remove(key);
        None
      }
    } else {
      None
    }
  }

  fn insert(&self, key: K, value: V) {
    let entry = PoolEntry::new(value, self.default_max_idle_time);
    self.inner.insert(key, entry);
  }

  fn remove(&self, key: &K) -> Option<V> {
    self.inner.remove(key).map(|(_, entry)| entry.value)
  }

  fn prune_expired(&self) {
    let keys_to_remove: Vec<K> = self
      .inner
      .iter()
      .filter_map(|entry| if entry.is_expired() { Some(entry.key().clone()) } else { None })
      .collect();

    for key in keys_to_remove {
      self.inner.remove(&key);
    }
  }

  fn size(&self) -> usize {
    self.inner.len()
  }

  fn clear(&self) {
    self.inner.clear();
  }
}

/// Statistics about a connection pool
#[derive(Debug, Clone)]
pub struct PoolStats {
  /// Current number of entries in the pool
  pub size: usize,
  /// Maximum allowed size
  pub max_size: usize,
  /// Number of expired entries
  pub expired_count: usize,
  /// Average age of entries
  pub average_age: Duration,
  /// Average idle time of entries
  pub average_idle: Duration,
}

impl PoolStats {
  /// Get the utilization ratio (0.0 to 1.0)
  pub fn utilization(&self) -> f64 {
    if self.max_size == 0 {
      0.0
    } else {
      self.size as f64 / self.max_size as f64
    }
  }

  /// Get the expiration ratio (0.0 to 1.0)
  pub fn expiration_ratio(&self) -> f64 {
    if self.size == 0 {
      0.0
    } else {
      self.expired_count as f64 / self.size as f64
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  #[test]
  fn test_pool_entry_creation() {
    let entry = PoolEntry::new("test_value", Duration::from_secs(60));
    assert_eq!(entry.value, "test_value");
    assert!(!entry.is_expired());
    assert!(entry.age() < Duration::from_millis(100));
  }

  #[test]
  fn test_pool_entry_expiration() {
    let mut entry = PoolEntry::new("test_value", Duration::from_millis(10));

    // Should not be expired initially
    assert!(!entry.is_expired());

    // Simulate passage of time by manually setting last_accessed
    entry.last_accessed = Instant::now() - Duration::from_millis(20);
    assert!(entry.is_expired());
  }

  #[test]
  fn test_dashmap_pool_creation() {
    let pool: DashMapConnectionPool<String, i32> = DashMapConnectionPool::new(100, Duration::from_secs(300));
    assert_eq!(pool.max_size(), 100);
    assert_eq!(pool.size(), 0);
    assert!(pool.is_empty());
  }

  #[tokio::test]
  async fn test_pool_get_or_create() {
    let pool = DashMapConnectionPool::new(10, Duration::from_secs(60));

    let factory = |key: String| async move { Ok::<i32, ConnectionError>(key.len() as i32) };

    // First call should create
    let result1 = pool.get_or_create("test".to_string(), factory).await.unwrap();
    assert_eq!(result1, 4);
    assert_eq!(pool.size(), 1);

    // Second call should return existing
    let factory2 = |_key: String| async move {
      Ok::<i32, ConnectionError>(999) // Different value to prove it's not called
    };
    let result2 = pool.get_or_create("test".to_string(), factory2).await.unwrap();
    assert_eq!(result2, 4); // Should be the original value
    assert_eq!(pool.size(), 1);
  }

  #[test]
  fn test_pool_insert_and_get() {
    let pool = DashMapConnectionPool::new(10, Duration::from_secs(60));

    pool.insert("key1".to_string(), 42);
    assert_eq!(pool.size(), 1);

    let value = pool.get(&"key1".to_string());
    assert_eq!(value, Some(42));

    let missing = pool.get(&"missing".to_string());
    assert_eq!(missing, None);
  }

  #[test]
  fn test_pool_remove() {
    let pool = DashMapConnectionPool::new(10, Duration::from_secs(60));

    pool.insert("key1".to_string(), 42);
    assert_eq!(pool.size(), 1);

    let removed = pool.remove(&"key1".to_string());
    assert_eq!(removed, Some(42));
    assert_eq!(pool.size(), 0);

    let missing = pool.remove(&"missing".to_string());
    assert_eq!(missing, None);
  }

  #[test]
  fn test_pool_stats() {
    let pool = DashMapConnectionPool::new(10, Duration::from_secs(60));

    let stats = pool.stats();
    assert_eq!(stats.size, 0);
    assert_eq!(stats.max_size, 10);
    assert_eq!(stats.utilization(), 0.0);

    pool.insert("key1".to_string(), 42);
    pool.insert("key2".to_string(), 43);

    let stats = pool.stats();
    assert_eq!(stats.size, 2);
    assert_eq!(stats.utilization(), 0.2);
  }
}
