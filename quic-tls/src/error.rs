/// Errors that happens during the proxy operation
#[derive(thiserror::Error, Debug)]
pub enum QuicTlsError {/* --------------------------------------- */}

/// Probe result
pub enum TlsProbeFailure {
  /// Not enough buffer to probe
  PollNext,
  /// Failed to probe
  Failure,
}
