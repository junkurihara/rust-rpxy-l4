use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Clone, Default)]
/// Counter for serving connections
pub struct ConnectionCount(Arc<AtomicUsize>);

impl ConnectionCount {
  pub(crate) fn current(&self) -> usize {
    self.0.load(Ordering::Relaxed)
  }

  /// Atomically acquire one connection slot below `max`.
  ///
  /// A maximum of zero rejects every acquisition. The returned permit releases
  /// the slot when dropped and must remain owned for the admitted resource's
  /// complete lifetime.
  pub(crate) fn try_acquire(&self, max: usize) -> Option<ConnectionPermit> {
    self
      .0
      .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (current < max).then(|| current + 1)
      })
      .ok()
      .map(|_| ConnectionPermit { owner: self.clone() })
  }
}

#[derive(Debug)]
/// Non-cloneable ownership token for one admitted connection.
pub(crate) struct ConnectionPermit {
  owner: ConnectionCount,
}

impl Drop for ConnectionPermit {
  fn drop(&mut self) {
    let previous = self.owner.0.fetch_sub(1, Ordering::Relaxed);
    debug_assert!(previous > 0, "connection permit released an empty counter");
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::{
    sync::{
      Arc, Barrier,
      atomic::{AtomicUsize, Ordering},
    },
    thread,
  };

  #[test]
  fn test_connection_count_exact_boundary_and_release() {
    let count = ConnectionCount::default();

    assert_eq!(count.current(), 0);

    let first = count.try_acquire(2).unwrap();
    assert_eq!(count.current(), 1);

    let second = count.try_acquire(2).unwrap();
    assert_eq!(count.current(), 2);
    assert!(count.try_acquire(2).is_none());
    assert_eq!(count.current(), 2);

    drop(first);
    assert_eq!(count.current(), 1);

    let replacement = count.try_acquire(2).unwrap();
    assert_eq!(count.current(), 2);

    drop((second, replacement));
    assert_eq!(count.current(), 0);
  }

  #[test]
  fn test_connection_count_zero_rejects_without_mutation() {
    let count = ConnectionCount::default();
    assert!(count.try_acquire(0).is_none());
    assert_eq!(count.current(), 0);
  }

  #[test]
  fn test_connection_count_scope_drop_releases() {
    let count = ConnectionCount::default();
    {
      let _permit = count.try_acquire(1).unwrap();
      assert_eq!(count.current(), 1);
    }
    assert_eq!(count.current(), 0);
  }

  #[test]
  fn test_connection_count_threaded_contention_never_exceeds_max() {
    const THREADS: usize = 64;
    const MAX: usize = 8;

    let count = ConnectionCount::default();
    let barrier = Arc::new(Barrier::new(THREADS));
    let live = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    let handles = (0..THREADS)
      .map(|_| {
        let count = count.clone();
        let barrier = barrier.clone();
        let live = live.clone();
        let peak = peak.clone();
        thread::spawn(move || {
          barrier.wait();
          if let Some(permit) = count.try_acquire(MAX) {
            let current = live.fetch_add(1, Ordering::Relaxed) + 1;
            peak.fetch_max(current, Ordering::Relaxed);
            for _ in 0..32 {
              thread::yield_now();
            }
            live.fetch_sub(1, Ordering::Relaxed);
            drop(permit);
          }
        })
      })
      .collect::<Vec<_>>();

    for handle in handles {
      handle.join().unwrap();
    }

    assert!(peak.load(Ordering::Relaxed) <= MAX);
    assert_eq!(live.load(Ordering::Relaxed), 0);
    assert_eq!(count.current(), 0);
  }

  #[test]
  fn test_connection_count_shared_generation_limits() {
    let old_generation = ConnectionCount::default();
    let new_generation = old_generation.clone();
    let mut old_permits = (0..4).map(|_| old_generation.try_acquire(4).unwrap()).collect::<Vec<_>>();

    assert!(new_generation.try_acquire(2).is_none());
    drop(old_permits.drain(0..3).collect::<Vec<_>>());
    assert_eq!(new_generation.current(), 1);

    let new_permit = new_generation.try_acquire(2).unwrap();
    assert!(new_generation.try_acquire(2).is_none());
    drop(new_permit);
    assert_eq!(new_generation.current(), 1);
    drop(old_permits);
    assert_eq!(new_generation.current(), 0);
  }

  #[test]
  fn test_connection_count_independent_owners_do_not_interact() {
    let tcp = ConnectionCount::default();
    let udp = ConnectionCount::default();

    let tcp_permit = tcp.try_acquire(1).unwrap();
    let udp_permit = udp.try_acquire(1).unwrap();
    assert!(tcp.try_acquire(1).is_none());
    assert!(udp.try_acquire(1).is_none());

    drop((tcp_permit, udp_permit));
    assert_eq!(tcp.current(), 0);
    assert_eq!(udp.current(), 0);
  }
}
