use std::{sync::OnceLock, time::Instant};

static MONOTONIC_ORIGIN: OnceLock<Instant> = OnceLock::new();

/// Get process-relative monotonic time in seconds.
#[inline]
pub(crate) fn get_monotonic_seconds() -> u64 {
  MONOTONIC_ORIGIN.get_or_init(Instant::now).elapsed().as_secs()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_monotonic_seconds_never_decreases() {
    let first = get_monotonic_seconds();
    let second = get_monotonic_seconds();

    assert!(second >= first);
  }
}
