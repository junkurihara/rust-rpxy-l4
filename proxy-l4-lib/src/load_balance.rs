/// Load balancing policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LoadBalance {
  /// Choose a server by the source IP address
  /// If the source IP is not changed, the same backend will be selected.
  SourceIp,

  /// Choose a server by the source socket address (IP + port)
  /// Even if the source IP is not changed, the same backend might not be selected when the source port is different.
  SourceSocket,

  /// Randomly select a server
  Random,

  #[default]
  /// Always select the first server [default]
  None,
}
