/// Probe result
pub enum TlsProbeFailure {
  /// Not enough buffer to probe
  PollNext,
  /// Failed to probe
  Failure,
}
