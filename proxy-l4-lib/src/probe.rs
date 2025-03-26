#[derive(Clone, Debug, PartialEq, Eq)]
/// Probe result
pub(crate) enum ProbeResult<T> {
  /// Success to probe TLS ClientHello
  Success(T),
  /// Not enough buffer to probe
  PollNext,
  /// Failed to probe
  Failure,
}
