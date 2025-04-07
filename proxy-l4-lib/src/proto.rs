use crate::error::ProxyBuildError;

/// L5--L7 Protocol specific types
pub enum ProtocolType {
  /// TCP: cleartext HTTP
  Http,
  /// TCP: TLS
  Tls,
  /// TCP: SSH
  Ssh,
  /// Udp: WireGuard
  Wireguard,
  /// Udp: QUIC
  Quic,
}

impl TryFrom<&str> for ProtocolType {
  type Error = ProxyBuildError;
  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match value {
      "http" => Ok(ProtocolType::Http),
      "tls" => Ok(ProtocolType::Tls),
      "ssh" => Ok(ProtocolType::Ssh),
      "wireguard" => Ok(ProtocolType::Wireguard),
      "quic" => Ok(ProtocolType::Quic),
      _ => Err(ProxyBuildError::UnsupportedProtocol(value.to_string())),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// TCP protocol types
pub(crate) enum TcpProtocolType {
  /// TCP: cleartext HTTP
  Http,
  /// TCP: TLS
  Tls,
  /// TCP: SSH
  Ssh,
  /// TCP: Any
  Any,
}
impl std::fmt::Display for TcpProtocolType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      TcpProtocolType::Http => write!(f, "http"),
      TcpProtocolType::Tls => write!(f, "tls"),
      TcpProtocolType::Ssh => write!(f, "ssh"),
      TcpProtocolType::Any => write!(f, "any"),
    }
  }
}
