use crate::error::ProxyBuildError;

/// L5--L7 Protocol specific types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolType {
  /// TCP: cleartext HTTP
  Http,
  /// TCP: TLS
  Tls,
  /// TCP: SSH
  Ssh,
  /// TCP: Socks5
  Socks5,
  /// UDP: WireGuard
  Wireguard,
  /// UDP: QUIC
  Quic,
}

impl TryFrom<&str> for ProtocolType {
  type Error = ProxyBuildError;
  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match value {
      "http" => Ok(ProtocolType::Http),
      "tls" => Ok(ProtocolType::Tls),
      "ssh" => Ok(ProtocolType::Ssh),
      "socks5" => Ok(ProtocolType::Socks5),
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
  /// TCP: Socks5
  Socks5,
  /// TCP: Any
  Any,
}
impl std::fmt::Display for TcpProtocolType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      TcpProtocolType::Http => write!(f, "http"),
      TcpProtocolType::Tls => write!(f, "tls"),
      TcpProtocolType::Ssh => write!(f, "ssh"),
      TcpProtocolType::Socks5 => write!(f, "socks5"),
      TcpProtocolType::Any => write!(f, "any"),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// UDP protocol types
pub(crate) enum UdpProtocolType {
  /// UDP: WireGuard
  Wireguard,
  /// UDP: QUIC
  Quic,
  /// UDP: Any
  Any,
}
impl std::fmt::Display for UdpProtocolType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      UdpProtocolType::Wireguard => write!(f, "wireguard"),
      UdpProtocolType::Quic => write!(f, "quic"),
      UdpProtocolType::Any => write!(f, "any"),
    }
  }
}
