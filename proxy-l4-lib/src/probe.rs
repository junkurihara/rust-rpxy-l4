use crate::{constants::TCP_PROTOCOL_DETECTION_BUFFER_SIZE, error::ProxyError, trace::*};
use bytes::BytesMut;
use quic_tls::{TlsClientHello, TlsClientHelloBuffer, TlsProbeFailure, probe_quic_initial_packets, probe_tls_handshake};
use std::{
  collections::HashSet,
  sync::{Arc, atomic::AtomicU64},
};
use tokio::{io::AsyncReadExt, net::TcpStream};

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

/* ---------------------------------------------------------- */
// TCP Protocol Detection Functions
/* ---------------------------------------------------------- */

#[derive(Debug, Clone, PartialEq, Eq)]
/// Probed TCP proxy protocol, specific protocols like SSH, and default is "any".
pub(crate) enum TcpProbedProtocol {
  /// any, default
  Any,
  /// SSH
  Ssh,
  /// Plaintext HTTP
  Http,
  /// TLS
  Tls(TlsClientHelloBuffer),
  // TODO: and more ...
}

impl TcpProbedProtocol {
  /// Convert to the corresponding protocol type
  pub(crate) fn proto_type(&self) -> crate::proto::TcpProtocolType {
    match self {
      Self::Any => crate::proto::TcpProtocolType::Any,
      Self::Ssh => crate::proto::TcpProtocolType::Ssh,
      Self::Http => crate::proto::TcpProtocolType::Http,
      Self::Tls(_) => crate::proto::TcpProtocolType::Tls,
    }
  }
}

impl std::fmt::Display for TcpProbedProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Any => write!(f, "Any"),
      Self::Ssh => write!(f, "SSH"),
      Self::Http => write!(f, "HTTP"),
      Self::Tls(_) => write!(f, "TLS"),
      // TODO: and more...
    }
  }
}

/// Poll the incoming TCP stream to detect the protocol
async fn read_tcp_stream(incoming_stream: &mut TcpStream, buf: &mut BytesMut) -> Result<usize, ProxyError> {
  let read_len = incoming_stream.read_buf(buf).await?;
  if read_len == 0 {
    error!("No data received");
    return Err(ProxyError::NoDataReceivedTcpStream(String::new()));
  }
  Ok(read_len)
}

/// Detect SSH protocol
pub(crate) fn detect_ssh(buf: &[u8]) -> ProbeResult<TcpProbedProtocol> {
  if buf.len() < 4 {
    return ProbeResult::PollNext;
  }
  if buf.starts_with(b"SSH-") {
    debug!("SSH connection detected");
    ProbeResult::Success(TcpProbedProtocol::Ssh)
  } else {
    ProbeResult::Failure
  }
}

/// Detect HTTP protocol
pub(crate) fn detect_http(buf: &[u8]) -> ProbeResult<TcpProbedProtocol> {
  if buf.len() < 4 {
    return ProbeResult::PollNext;
  }
  if buf.windows(4).any(|w| w.eq(b"HTTP")) {
    debug!("HTTP connection detected");
    ProbeResult::Success(TcpProbedProtocol::Http)
  } else {
    ProbeResult::Failure
  }
}

/// Detect TLS handshake
pub(crate) fn detect_tls_handshake(buf: &[u8]) -> ProbeResult<TcpProbedProtocol> {
  let mut buf = BytesMut::from(buf);
  match probe_tls_handshake(&mut buf) {
    Err(TlsProbeFailure::Failure) => ProbeResult::Failure,
    Err(TlsProbeFailure::PollNext) => ProbeResult::PollNext,
    Ok(chi) => ProbeResult::Success(TcpProbedProtocol::Tls(chi)),
  }
}

impl TcpProbedProtocol {
  /// Detect the protocol from the first few bytes of the incoming stream
  pub(crate) async fn detect_protocol(
    incoming_stream: &mut TcpStream,
    buf: &mut BytesMut,
  ) -> Result<ProbeResult<Self>, ProxyError> {
    let mut probe_functions = vec![detect_ssh, detect_http, detect_tls_handshake];

    while !probe_functions.is_empty() {
      // Read the first several bytes to probe. at the first loop, the buffer is empty.
      let mut next_buf = BytesMut::with_capacity(TCP_PROTOCOL_DETECTION_BUFFER_SIZE);
      let _read_len = read_tcp_stream(incoming_stream, &mut next_buf).await?;
      buf.extend_from_slice(&next_buf[..]);

      // Check probe functions
      #[allow(clippy::type_complexity)]
      let (new_probe_fns, probe_res): (Vec<fn(&[u8]) -> ProbeResult<_>>, Vec<_>) = probe_functions
        .into_iter()
        .filter_map(|f| {
          let res = f(buf);
          match res {
            ProbeResult::Success(_) | ProbeResult::PollNext => Some((f, res)),
            _ => None,
          }
        })
        .unzip();

      // If any of them returns Success, return the protocol.
      if let Some(probe_success) = probe_res.into_iter().find(|r| matches!(r, ProbeResult::Success(_))) {
        return Ok(probe_success);
      };

      // If the rest returned PollNext, fetch more data
      probe_functions = new_probe_fns;
    }

    debug!("Untyped TCP connection");
    Ok(ProbeResult::Success(Self::Any))
  }
}

/* ---------------------------------------------------------- */
// UDP Protocol Detection Functions
/* ---------------------------------------------------------- */

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// UDP probed protocol, specific protocols like Wireguard and QUIC, and default is "any".
pub(crate) enum UdpProbedProtocol {
  /// any, default
  Any,
  /// wireguard
  Wireguard,
  /// quic
  Quic(TlsClientHello),
  // TODO: and more ...
}

impl UdpProbedProtocol {
  /// Convert to the corresponding protocol type
  pub(crate) fn proto_type(&self) -> crate::proto::UdpProtocolType {
    match self {
      Self::Any => crate::proto::UdpProtocolType::Any,
      Self::Wireguard => crate::proto::UdpProtocolType::Wireguard,
      Self::Quic(_) => crate::proto::UdpProtocolType::Quic,
    }
  }
}

impl std::fmt::Display for UdpProbedProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Any => write!(f, "Any"),
      Self::Wireguard => write!(f, "Wireguard"),
      Self::Quic(_) => write!(f, "QUIC"),
      // TODO: and more...
    }
  }
}

#[derive(Clone)]
/// UDP initial datagrams buffer for protocol detection
pub(crate) struct UdpInitialDatagrams {
  /// inner buffer of multiple UDP datagram payloads
  pub(crate) inner: Vec<Vec<u8>>,
  /// created at
  pub(crate) created_at: Arc<AtomicU64>,
  /// Protocols that were detected as 'poll_next'
  pub(crate) probed_as_pollnext: HashSet<UdpProbedProtocol>,
}

impl UdpInitialDatagrams {
  /// Get the first datagram
  pub(crate) fn first(&self) -> Option<&[u8]> {
    self.inner.first().map(|v| v.as_slice())
  }
}

/// Detect Wireguard protocol
pub(crate) fn detect_wireguard(initial_datagrams: &mut UdpInitialDatagrams) -> ProbeResult<UdpProbedProtocol> {
  // Wireguard protocol 'initiation' detection [only Handshake]
  // Thus this may not be a reliable way to detect Wireguard protocol
  // since UDP connection will be lost if the handshake interval is set to be longer than the connection timeout.
  // https://www.wireguard.com/protocol/
  let Some(first) = initial_datagrams.first() else {
    return ProbeResult::Failure; // unreachable. just in case.
  };

  if first.len() == 148 && first[0] == 0x01 && first[1] == 0x00 && first[2] == 0x00 && first[3] == 0x00 {
    debug!("Wireguard protocol (initiator to responder first message) detected");
    ProbeResult::Success(UdpProbedProtocol::Wireguard)
  } else {
    ProbeResult::Failure
  }
}

/// Detect QUIC protocol
pub(crate) fn detect_quic_initial(initial_datagrams: &mut UdpInitialDatagrams) -> ProbeResult<UdpProbedProtocol> {
  let initial_datagrams_inner = initial_datagrams.inner.as_slice();

  match probe_quic_initial_packets(initial_datagrams_inner) {
    Err(TlsProbeFailure::Failure) => ProbeResult::Failure,
    Err(TlsProbeFailure::PollNext) => {
      initial_datagrams
        .probed_as_pollnext
        .insert(UdpProbedProtocol::Quic(Default::default()));
      ProbeResult::PollNext
    }
    Ok(client_hello_info) => ProbeResult::Success(UdpProbedProtocol::Quic(client_hello_info)),
  }
}

impl UdpProbedProtocol {
  /// Detect the protocol from the first few bytes of the incoming datagram
  pub(crate) async fn detect_protocol(initial_datagrams: &mut UdpInitialDatagrams) -> Result<ProbeResult<Self>, ProxyError> {
    // TODO: Add more protocol detection patterns

    // Probe functions
    let probe_functions = if initial_datagrams.probed_as_pollnext.is_empty() {
      // No candidate probed as PollNext, i.e., Round 1
      vec![detect_wireguard, detect_quic_initial]
    } else {
      // Round 2 or later
      initial_datagrams
        .probed_as_pollnext
        .iter()
        .map(|p| match p {
          UdpProbedProtocol::Wireguard => detect_wireguard,
          UdpProbedProtocol::Quic(_) => detect_quic_initial,
          _ => unreachable!(),
        })
        .collect()
    };

    let probe_res = probe_functions.into_iter().map(|f| f(initial_datagrams)).collect::<Vec<_>>();

    // In case any of the probe results is a success, return it
    if let Some(probe_success) = probe_res.iter().find(|r| matches!(r, ProbeResult::Success(_))) {
      return Ok(probe_success.clone());
    };

    // In case any of the probe results is PollNext, return it
    if let Some(probe_pollnext) = probe_res.iter().find(|r| matches!(r, ProbeResult::PollNext)) {
      return Ok(probe_pollnext.to_owned());
    };

    // All detection finished as failure
    debug!("Untyped UDP connection detected");
    Ok(ProbeResult::Success(Self::Any))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::time_util::get_since_the_epoch;

  #[test]
  fn test_ssh_detection() {
    // Test SSH-2.0 protocol detection
    let ssh_data = b"SSH-2.0-OpenSSH_8.3";
    assert_eq!(detect_ssh(ssh_data), ProbeResult::Success(TcpProbedProtocol::Ssh));

    // Test non-SSH data
    let non_ssh_data = b"HTTP/1.1 200 OK";
    assert_eq!(detect_ssh(non_ssh_data), ProbeResult::Failure);

    // Test insufficient data
    let short_data = b"SS";
    assert_eq!(detect_ssh(short_data), ProbeResult::PollNext);
  }

  #[test]
  fn test_http_detection() {
    // Test HTTP detection
    let http_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
    assert_eq!(detect_http(http_data), ProbeResult::Success(TcpProbedProtocol::Http));

    // Test HTTP response detection
    let http_response = b"HTTP/1.1 200 OK\r\n";
    assert_eq!(detect_http(http_response), ProbeResult::Success(TcpProbedProtocol::Http));

    // Test non-HTTP data
    let non_http_data = b"SSH-2.0-OpenSSH_8.3";
    assert_eq!(detect_http(non_http_data), ProbeResult::Failure);

    // Test insufficient data
    let short_data = b"HTT";
    assert_eq!(detect_http(short_data), ProbeResult::PollNext);
  }

  #[test]
  fn test_tls_detection() {
    // Test invalid TLS data - should fail
    let invalid_tls = b"not a tls handshake";
    assert_eq!(detect_tls_handshake(invalid_tls), ProbeResult::Failure);

    // Test insufficient data for TLS detection
    let short_data = b"abc";
    assert_eq!(detect_tls_handshake(short_data), ProbeResult::PollNext);

    // Note: Testing valid TLS handshakes would require constructing complex binary data
    // which is beyond the scope of this unit test. The TLS detection logic is tested
    // via the quic_tls crate's own tests.
  }

  #[test]
  fn test_wireguard_detection() {
    // Create a valid Wireguard initiation packet (148 bytes, starts with 0x01000000)
    let mut wg_data = vec![0u8; 148];
    wg_data[0] = 0x01;
    wg_data[1] = 0x00;
    wg_data[2] = 0x00;
    wg_data[3] = 0x00;

    let mut initial_datagrams = UdpInitialDatagrams {
      inner: vec![wg_data],
      created_at: Arc::new(AtomicU64::new(get_since_the_epoch())),
      probed_as_pollnext: Default::default(),
    };

    assert_eq!(
      detect_wireguard(&mut initial_datagrams),
      ProbeResult::Success(UdpProbedProtocol::Wireguard)
    );

    // Test invalid Wireguard data
    let invalid_wg = vec![0u8; 100]; // Wrong length
    let mut initial_datagrams_invalid = UdpInitialDatagrams {
      inner: vec![invalid_wg],
      created_at: Arc::new(AtomicU64::new(get_since_the_epoch())),
      probed_as_pollnext: Default::default(),
    };

    assert_eq!(detect_wireguard(&mut initial_datagrams_invalid), ProbeResult::Failure);
  }
}
