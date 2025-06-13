use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};

/// DashMap type alias, uses ahash::RandomState as hashbuilder
type DashMap<K, V> = dashmap::DashMap<K, V, ahash::RandomState>;

#[derive(Debug, Clone, Default)]
/// Counter for serving connections
pub struct ConnectionCount(Arc<AtomicUsize>);

impl ConnectionCount {
  pub(crate) fn current(&self) -> usize {
    self.0.load(Ordering::Relaxed)
  }

  pub(crate) fn increment(&self) -> usize {
    self.0.fetch_add(1, Ordering::Relaxed)
  }

  pub(crate) fn decrement(&self) -> usize {
    let mut count;
    while {
      count = self.0.load(Ordering::Relaxed);
      count > 0
        && self
          .0
          .compare_exchange(count, count - 1, Ordering::Relaxed, Ordering::Relaxed)
          != Ok(count)
    } {}
    count
  }
}

#[derive(Debug, Clone)]
/// Counter for serving connections that must be counted as the sum of integer values given from multiple threads
pub struct ConnectionCountSum<T>(Arc<DashMap<T, usize>>)
where
  T: Eq + std::hash::Hash;

impl<T> ConnectionCountSum<T>
where
  T: Eq + std::hash::Hash,
{
  pub(crate) fn current(&self) -> usize {
    self.0.iter().map(|v| *v.value()).sum()
  }
  /// Set or update the value for the key, returning the previous value for the key
  pub(crate) fn set(&self, key: T, value: usize) -> usize {
    self.0.insert(key, value).unwrap_or(0)
  }
}

impl<T> Default for ConnectionCountSum<T>
where
  T: Eq + std::hash::Hash,
{
  fn default() -> Self {
    Self(Arc::new(DashMap::default()))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_connection_count_basic() {
    let count = ConnectionCount::default();

    assert_eq!(count.current(), 0);

    count.increment();
    assert_eq!(count.current(), 1);

    count.increment();
    assert_eq!(count.current(), 2);

    count.decrement();
    assert_eq!(count.current(), 1);
  }

  #[test]
  fn test_connection_count_multiple_operations() {
    let count = ConnectionCount::default();

    // Simulate multiple connections over time
    for _ in 0..5 {
      count.increment();
      count.decrement();
    }

    assert_eq!(count.current(), 0);
  }

  #[test]
  fn test_connection_count_sum_basic() {
    let count = ConnectionCountSum::<&str>::default();

    assert_eq!(count.current(), 0);

    count.set("addr1", 3);
    assert_eq!(count.current(), 3);

    count.set("addr2", 2);
    assert_eq!(count.current(), 5);

    // Reducing connections
    count.set("addr1", 1);
    assert_eq!(count.current(), 3);
  }

  #[test]
  fn test_connection_count_sum_operations() {
    let count = ConnectionCountSum::<&str>::default();

    // Test setting and updating values
    let old = count.set("addr1", 5);
    assert_eq!(old, 0);
    assert_eq!(count.current(), 5);

    let old = count.set("addr1", 8);
    assert_eq!(old, 5);
    assert_eq!(count.current(), 8);
  }
}
