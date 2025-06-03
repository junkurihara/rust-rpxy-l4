use crate::{
    error::ProxyError,
    probe::ProbeResult,
    protocol::ProtocolDetector,
};
use bytes::BytesMut;
use quic_tls::{probe_quic_initial_packets, TlsClientHello, TlsProbeFailure};
use std::future::Future;
use std::pin::Pin;

/// Protocol type for UDP connections
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpProtocol {
    /// any, default
    Any,
    /// WireGuard
    Wireguard,
    /// QUIC
    Quic(TlsClientHello),
}

impl std::fmt::Display for UdpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "Any"),
            Self::Wireguard => write!(f, "Wireguard"),
            Self::Quic(_) => write!(f, "QUIC"),
        }
    }
}

/// WireGuard protocol detector
pub struct WireguardDetector;

impl ProtocolDetector<UdpProtocol> for WireguardDetector {
    fn detect<'a>(&'a self, buffer: &'a mut BytesMut) -> Pin<Box<dyn Future<Output = Result<ProbeResult<UdpProtocol>, ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            // WireGuard protocol 'initiation' detection [only Handshake]
            // Thus this may not be a reliable way to detect WireGuard protocol
            // since UDP connection will be lost if the handshake interval is set to be longer than the connection timeout.
            // https://www.wireguard.com/protocol/
            if buffer.len() == 148 && buffer[0] == 0x01 && buffer[1] == 0x00 && buffer[2] == 0x00 && buffer[3] == 0x00 {
                crate::trace::debug!("Wireguard protocol (initiator to responder first message) detected");
                Ok(ProbeResult::Success(UdpProtocol::Wireguard))
            } else {
                Ok(ProbeResult::Failure)
            }
        })
    }

    fn name(&self) -> &'static str {
        "WireGuard"
    }

    fn priority(&self) -> u8 {
        10 // High priority - WireGuard has a very specific signature
    }
}

/// QUIC protocol detector
pub struct QuicDetector;

impl ProtocolDetector<UdpProtocol> for QuicDetector {
    fn detect<'a>(&'a self, buffer: &'a mut BytesMut) -> Pin<Box<dyn Future<Output = Result<ProbeResult<UdpProtocol>, ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            // For QUIC detection, we need to handle the fact that we might be working with
            // a collection of UDP datagrams, but this interface only gives us a single buffer.
            // We'll work with what we have for now and may need to enhance this later.
            let datagrams = vec![buffer.to_vec()];
            
            match probe_quic_initial_packets(&datagrams) {
                Err(TlsProbeFailure::Failure) => Ok(ProbeResult::Failure),
                Err(TlsProbeFailure::PollNext) => Ok(ProbeResult::PollNext),
                Ok(client_hello) => {
                    crate::trace::debug!("QUIC protocol detected");
                    Ok(ProbeResult::Success(UdpProtocol::Quic(client_hello)))
                }
            }
        })
    }

    fn name(&self) -> &'static str {
        "QUIC"
    }

    fn priority(&self) -> u8 {
        20 // Medium priority - QUIC detection is more complex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wireguard_detection() {
        let detector = WireguardDetector;
        // Create a minimal WireGuard initiation packet (148 bytes with correct header)
        let mut buffer = BytesMut::with_capacity(148);
        buffer.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // WireGuard initiation header
        buffer.resize(148, 0); // Fill to exactly 148 bytes
        
        let result = detector.detect(&mut buffer).await.unwrap();
        assert!(matches!(result, ProbeResult::Success(UdpProtocol::Wireguard)));
        assert_eq!(detector.name(), "WireGuard");
        assert_eq!(detector.priority(), 10);
    }

    #[tokio::test]
    async fn test_wireguard_detection_wrong_size() {
        let detector = WireguardDetector;
        let mut buffer = BytesMut::from(&[0x01, 0x00, 0x00, 0x00][..]);
        
        let result = detector.detect(&mut buffer).await.unwrap();
        assert!(matches!(result, ProbeResult::Failure));
    }

    #[tokio::test]
    async fn test_wireguard_detection_wrong_header() {
        let detector = WireguardDetector;
        let mut buffer = BytesMut::with_capacity(148);
        buffer.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // Wrong header
        buffer.resize(148, 0);
        
        let result = detector.detect(&mut buffer).await.unwrap();
        assert!(matches!(result, ProbeResult::Failure));
    }

    #[tokio::test]
    async fn test_quic_detection_invalid_data() {
        let detector = QuicDetector;
        let mut buffer = BytesMut::from("Not QUIC data");
        
        let result = detector.detect(&mut buffer).await.unwrap();
        assert!(matches!(result, ProbeResult::Failure));
        assert_eq!(detector.name(), "QUIC");
        assert_eq!(detector.priority(), 20);
    }
}
