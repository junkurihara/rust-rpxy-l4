use super::probe::ProbeResult;
use crate::{error::ProxyError, proto::TcpProtocolType, protocol::ProtocolDetector};
use bytes::BytesMut;
use quic_tls::{TlsClientHelloBuffer, TlsProbeFailure, probe_tls_handshake};
use std::future::Future;
use std::pin::Pin;

/// Protocol type for TCP connections
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpProtocol {
  /// any, default
  Any,
  /// SSH
  Ssh,
  /// Plaintext HTTP
  Http,
  /// TLS
  Tls(TlsClientHelloBuffer),
}

impl std::fmt::Display for TcpProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Any => write!(f, "Any"),
      Self::Ssh => write!(f, "SSH"),
      Self::Http => write!(f, "HTTP"),
      Self::Tls(_) => write!(f, "TLS"),
    }
  }
}

impl TcpProtocol {
  pub(crate) fn proto_type(&self) -> TcpProtocolType {
    match self {
      Self::Any => TcpProtocolType::Any,
      Self::Ssh => TcpProtocolType::Ssh,
      Self::Http => TcpProtocolType::Http,
      Self::Tls(_) => TcpProtocolType::Tls,
    }
  }
}

/// SSH protocol detector
pub struct SshDetector;

impl ProtocolDetector<TcpProtocol> for SshDetector {
  fn detect<'a>(
    &'a self,
    buffer: &'a mut BytesMut,
  ) -> Pin<Box<dyn Future<Output = Result<ProbeResult<TcpProtocol>, ProxyError>> + Send + 'a>> {
    Box::pin(async move {
      if buffer.len() < 4 {
        return Ok(ProbeResult::PollNext);
      }
      if buffer.starts_with(b"SSH-") {
        crate::trace::debug!("SSH connection detected");
        Ok(ProbeResult::Success(TcpProtocol::Ssh))
      } else {
        Ok(ProbeResult::Failure)
      }
    })
  }

  fn name(&self) -> &'static str {
    "SSH"
  }

  fn priority(&self) -> u8 {
    10 // High priority - SSH has a clear signature
  }
}

/// HTTP protocol detector
pub struct HttpDetector;

impl ProtocolDetector<TcpProtocol> for HttpDetector {
  fn detect<'a>(
    &'a self,
    buffer: &'a mut BytesMut,
  ) -> Pin<Box<dyn Future<Output = Result<ProbeResult<TcpProtocol>, ProxyError>> + Send + 'a>> {
    Box::pin(async move {
      if buffer.len() < 4 {
        return Ok(ProbeResult::PollNext);
      }
      if buffer.windows(4).any(|w| w.eq(b"HTTP")) {
        crate::trace::debug!("HTTP connection detected");
        Ok(ProbeResult::Success(TcpProtocol::Http))
      } else {
        Ok(ProbeResult::Failure)
      }
    })
  }

  fn name(&self) -> &'static str {
    "HTTP"
  }

  fn priority(&self) -> u8 {
    20 // Medium priority
  }
}

/// TLS protocol detector
pub struct TlsDetector;

impl ProtocolDetector<TcpProtocol> for TlsDetector {
  fn detect<'a>(
    &'a self,
    buffer: &'a mut BytesMut,
  ) -> Pin<Box<dyn Future<Output = Result<ProbeResult<TcpProtocol>, ProxyError>> + Send + 'a>> {
    Box::pin(async move {
      match probe_tls_handshake(buffer) {
        Err(TlsProbeFailure::Failure) => Ok(ProbeResult::Failure),
        Err(TlsProbeFailure::PollNext) => Ok(ProbeResult::PollNext),
        Ok(client_hello_buffer) => {
          crate::trace::debug!("TLS connection detected");
          Ok(ProbeResult::Success(TcpProtocol::Tls(client_hello_buffer)))
        }
      }
    })
  }

  fn name(&self) -> &'static str {
    "TLS"
  }

  fn priority(&self) -> u8 {
    30 // Lower priority - TLS detection is more complex
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_ssh_detection() {
    let detector = SshDetector;
    let mut buffer = BytesMut::from("SSH-2.0-OpenSSH_8.0");

    let result = detector.detect(&mut buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::Success(TcpProtocol::Ssh)));
    assert_eq!(detector.name(), "SSH");
    assert_eq!(detector.priority(), 10);
  }

  #[tokio::test]
  async fn test_ssh_detection_insufficient_data() {
    let detector = SshDetector;
    let mut buffer = BytesMut::from("SS");

    let result = detector.detect(&mut buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::PollNext));
  }

  #[tokio::test]
  async fn test_ssh_detection_failure() {
    let detector = SshDetector;
    let mut buffer = BytesMut::from("HTTP/1.1 200 OK");

    let result = detector.detect(&mut buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::Failure));
  }

  #[tokio::test]
  async fn test_http_detection() {
    let detector = HttpDetector;
    let mut buffer = BytesMut::from("GET / HTTP/1.1\r\n");

    let result = detector.detect(&mut buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::Success(TcpProtocol::Http)));
    assert_eq!(detector.name(), "HTTP");
    assert_eq!(detector.priority(), 20);
  }

  #[tokio::test]
  async fn test_http_detection_insufficient_data() {
    let detector = HttpDetector;
    let mut buffer = BytesMut::from("HT");

    let result = detector.detect(&mut buffer).await.unwrap();
    assert!(matches!(result, ProbeResult::PollNext));
  }
}
