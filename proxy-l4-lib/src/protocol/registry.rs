use super::probe::ProbeResult;
use crate::{
  error::ProxyError,
  protocol::{ProtocolDetector, tcp::*, udp::*},
};
use bytes::BytesMut;

/// A concrete implementation of a protocol detector registry for TCP protocols
pub struct TcpProtocolRegistry {
  detectors: Vec<Box<dyn ProtocolDetector<TcpProtocol>>>,
}

impl Default for TcpProtocolRegistry {
  fn default() -> Self {
    let mut registry = Self::new();

    // Register default TCP protocol detectors in priority order
    registry.register(Box::new(SshDetector));
    registry.register(Box::new(HttpDetector));
    registry.register(Box::new(TlsDetector));

    registry
  }
}

impl TcpProtocolRegistry {
  /// Create a new empty TCP protocol registry
  pub fn new() -> Self {
    Self { detectors: Vec::new() }
  }

  /// Add a protocol detector to the registry
  pub fn register(&mut self, detector: Box<dyn ProtocolDetector<TcpProtocol>>) {
    self.detectors.push(detector);
    // Keep detectors sorted by priority (lower numbers first)
    self.detectors.sort_by_key(|d| d.priority());
  }

  /// Run all registered detectors against the provided buffer
  ///
  /// This method will try detectors in priority order and return the first
  /// successful detection, or continue with poll_next results until a
  /// definitive result is reached.
  pub async fn detect_protocol(&mut self, buffer: &mut BytesMut) -> Result<ProbeResult<TcpProtocol>, ProxyError> {
    let mut poll_next_indices = Vec::new();

    // First round: try all detectors
    for (i, detector) in self.detectors.iter().enumerate() {
      match detector.detect(buffer).await? {
        ProbeResult::Success(protocol) => return Ok(ProbeResult::Success(protocol)),
        ProbeResult::PollNext => poll_next_indices.push(i),
        ProbeResult::Failure => continue,
      }
    }

    // If any detectors returned PollNext, we need more data
    // Overwrite detectors with those that returned PollNext
    if !poll_next_indices.is_empty() {
      let mut remaining_detectors = Vec::new();
      for &i in &poll_next_indices {
        remaining_detectors.push(self.detectors.swap_remove(i - remaining_detectors.len()));
      }
      self.detectors = remaining_detectors;
      return Ok(ProbeResult::PollNext);
    }

    // All detectors failed - return Any protocol as fallback
    Ok(ProbeResult::Success(TcpProtocol::Any))
  }

  /// Get the number of registered detectors
  pub fn len(&self) -> usize {
    self.detectors.len()
  }

  /// Check if the registry is empty
  pub fn is_empty(&self) -> bool {
    self.detectors.is_empty()
  }
}

/// A concrete implementation of a protocol detector registry for UDP protocols
pub struct UdpProtocolRegistry {
  detectors: Vec<Box<dyn ProtocolDetector<UdpProtocol>>>,
}

impl Default for UdpProtocolRegistry {
  fn default() -> Self {
    let mut registry = Self::new();

    // Register default UDP protocol detectors in priority order
    registry.register(Box::new(WireguardDetector));
    registry.register(Box::new(QuicDetector));

    registry
  }
}

impl UdpProtocolRegistry {
  /// Create a new empty UDP protocol registry
  pub fn new() -> Self {
    Self { detectors: Vec::new() }
  }

  /// Add a protocol detector to the registry
  pub fn register(&mut self, detector: Box<dyn ProtocolDetector<UdpProtocol>>) {
    self.detectors.push(detector);
    // Keep detectors sorted by priority (lower numbers first)
    self.detectors.sort_by_key(|d| d.priority());
  }

  /// Run all registered detectors against the provided buffer
  ///
  /// This method will try detectors in priority order and return the first
  /// successful detection, or continue with poll_next results until a
  /// definitive result is reached.
  pub async fn detect_protocol(&mut self, buffer: &mut BytesMut) -> Result<ProbeResult<UdpProtocol>, ProxyError> {
    let mut poll_next_indices = Vec::new();

    // First round: try all detectors
    for (i, detector) in self.detectors.iter().enumerate() {
      match detector.detect(buffer).await? {
        ProbeResult::Success(protocol) => return Ok(ProbeResult::Success(protocol)),
        ProbeResult::PollNext => poll_next_indices.push(i),
        ProbeResult::Failure => continue,
      }
    }

    // If any detectors returned PollNext, we need more data
    // Overwrite detectors with those that returned PollNext
    if !poll_next_indices.is_empty() {
      let mut remaining_detectors = Vec::new();
      for &i in &poll_next_indices {
        remaining_detectors.push(self.detectors.swap_remove(i - remaining_detectors.len()));
      }
      self.detectors = remaining_detectors;
      return Ok(ProbeResult::PollNext);
    }

    // All detectors failed - return Any protocol as fallback
    Ok(ProbeResult::Success(UdpProtocol::Any))
  }

  /// Get the number of registered detectors
  pub fn len(&self) -> usize {
    self.detectors.len()
  }

  /// Check if the registry is empty
  pub fn is_empty(&self) -> bool {
    self.detectors.is_empty()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_tcp_protocol_registry_default() {
    let mut registry = TcpProtocolRegistry::default();
    assert_eq!(registry.len(), 3); // SSH, HTTP, TLS
    assert!(!registry.is_empty());

    // Test SSH detection
    let mut ssh_buffer = BytesMut::from("SSH-2.0-OpenSSH_8.0");
    let result = registry.detect_protocol(&mut ssh_buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::Success(TcpProtocol::Ssh)));

    // Test HTTP detection
    let mut http_buffer = BytesMut::from("GET / HTTP/1.1\r\n");
    let result = registry.detect_protocol(&mut http_buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::Success(TcpProtocol::Http)));

    // Test fallback to Any
    let mut unknown_buffer = BytesMut::from("Unknown protocol data");
    let result = registry.detect_protocol(&mut unknown_buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::Success(TcpProtocol::Any)));
  }

  #[tokio::test]
  async fn test_udp_protocol_registry_default() {
    let mut registry = UdpProtocolRegistry::default();
    assert_eq!(registry.len(), 2); // WireGuard, QUIC
    assert!(!registry.is_empty());

    // Test WireGuard detection
    let mut wg_buffer = BytesMut::with_capacity(148);
    wg_buffer.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    wg_buffer.resize(148, 0);
    let result = registry.detect_protocol(&mut wg_buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::Success(UdpProtocol::Wireguard)));

    // Test fallback to Any
    let mut unknown_buffer = BytesMut::from("Unknown UDP data");
    let result = registry.detect_protocol(&mut unknown_buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::Success(UdpProtocol::Any)));
  }

  #[tokio::test]
  async fn test_empty_registry() {
    let mut registry = TcpProtocolRegistry::new();
    assert_eq!(registry.len(), 0);
    assert!(registry.is_empty());

    let mut buffer = BytesMut::from("SSH-2.0-OpenSSH_8.0");
    let result = registry.detect_protocol(&mut buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::Success(TcpProtocol::Any)));
  }
}
