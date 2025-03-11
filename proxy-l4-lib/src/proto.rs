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
  type Error = anyhow::Error;
  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match value {
      "http" => Ok(ProtocolType::Http),
      "tls" => Ok(ProtocolType::Tls),
      "ssh" => Ok(ProtocolType::Ssh),
      "wireguard" => Ok(ProtocolType::Wireguard),
      "quic" => Ok(ProtocolType::Quic),
      _ => Err(anyhow::anyhow!("Invalid protocol type: {}", value)),
    }
  }
}
