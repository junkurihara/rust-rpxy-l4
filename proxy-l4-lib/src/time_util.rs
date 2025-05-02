use std::time::{SystemTime, UNIX_EPOCH};

/// Get the current time since the epoch in seconds.
#[inline]
pub(crate) fn get_since_the_epoch() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards!!! Check system time.")
    .as_secs()
}
