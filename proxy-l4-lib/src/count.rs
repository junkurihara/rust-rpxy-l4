use std::sync::{
  atomic::{AtomicUsize, Ordering},
  Arc,
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
/// Counter for serving connections that must be counted as the sum of integer values give from multiple threads
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
