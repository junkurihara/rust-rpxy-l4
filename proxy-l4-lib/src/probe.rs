#[derive(Clone, Debug, PartialEq, Eq)]
/// Probe result
pub(crate) enum ProbeResult<T> {
  /// Success to probe protocol
  Success(T),
  /// Not enough buffer to probe
  PollNext,
  /// Failed to probe
  Failure,
}
