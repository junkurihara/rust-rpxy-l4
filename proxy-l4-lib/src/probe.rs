use crate::{
  constants::{TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION, TCP_PROTOCOL_DETECTION_READ_CHUNK_SIZE},
  error::ProxyError,
  trace::*,
};
use bytes::{BufMut, BytesMut};
use quic_tls::{
  TlsClientHello, TlsClientHelloBuffer, TlsProbeFailure, probe_quic_initial_packets, probe_tls_handshake_with_max_probe_bytes,
};
use std::collections::HashSet;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Clone, Debug, PartialEq, Eq)]
/// Probe result
pub(crate) enum ProbeResult<T> {
  /// Success to probe protocol
  Success(T),
  /// Not enough buffer to probe
  PollNext,
  /// Failed to probe
  Failure,
  /// Input matched a protocol but violated a parser safety or resource limit.
  Rejected,
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
  /// Socks5
  Socks5,
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
      Self::Socks5 => crate::proto::TcpProtocolType::Socks5,
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
      Self::Socks5 => write!(f, "Socks5"),
      Self::Http => write!(f, "HTTP"),
      Self::Tls(_) => write!(f, "TLS"),
      // TODO: and more...
    }
  }
}

/// Poll the incoming TCP stream to detect the protocol
async fn read_tcp_stream<R: AsyncRead + Unpin>(incoming_stream: &mut R, buf: &mut BytesMut) -> Result<usize, ProxyError> {
  if buf.len() >= TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION {
    return Err(ProxyError::TcpProbeLimitExceeded);
  }

  let read_cap = TCP_PROTOCOL_DETECTION_READ_CHUNK_SIZE.min(TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION - buf.len());
  let mut limited_buf = (&mut *buf).limit(read_cap);
  let read_len = incoming_stream.read_buf(&mut limited_buf).await?;
  if read_len == 0 {
    debug!("No data received while probing TCP protocol");
    return Err(ProxyError::NoDataReceivedTcpStream(String::new()));
  }
  debug_assert!(buf.len() <= TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION);
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

/// Detect Socks5 protocol
/// https://github.com/yrutschle/sslh/blob/86188cdd284932e79bfc8929fc595023bcb01d4d/probe.c#L338-L369
pub(crate) fn detect_socks5(buf: &[u8]) -> ProbeResult<TcpProbedProtocol> {
  if buf.len() < 2 {
    return ProbeResult::PollNext;
  }
  // Socks5 handshake starts with version 0x05
  if buf[0] != 0x05 {
    return ProbeResult::Failure;
  }
  // Second byte should be number of supported authentication methods, assuming maximum of 10,
  // as defined in https://www.iana.org/assignments/socks-methods/socks-methods.xhtml
  if buf[1] == 0 || buf[1] > 10 {
    return ProbeResult::Failure;
  }
  let expected_len = 2 + buf[1] as usize;
  if expected_len > buf.len() {
    return ProbeResult::PollNext;
  }
  // Each authentication method number should be in range 0..9
  // (https://www.iana.org/assignments/socks-methods/socks-methods.xhtml)
  for method in &buf[2..expected_len] {
    if *method > 9 {
      return ProbeResult::Failure;
    }
  }
  debug!("Socks5 connection detected");
  ProbeResult::Success(TcpProbedProtocol::Socks5)
}

/// Detect TLS handshake
pub(crate) fn detect_tls_handshake(buf: &[u8]) -> ProbeResult<TcpProbedProtocol> {
  let mut buf = buf;
  match probe_tls_handshake_with_max_probe_bytes(&mut buf, TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION) {
    Err(TlsProbeFailure::Failure) => ProbeResult::Failure,
    Err(TlsProbeFailure::PollNext) => ProbeResult::PollNext,
    Err(TlsProbeFailure::Rejected(_)) => ProbeResult::Rejected,
    Ok(chi) => ProbeResult::Success(TcpProbedProtocol::Tls(chi)),
  }
}

impl TcpProbedProtocol {
  /// Detect the protocol from the first few bytes of the incoming stream
  pub(crate) async fn detect_protocol<R: AsyncRead + Unpin>(
    incoming_stream: &mut R,
    buf: &mut BytesMut,
  ) -> Result<ProbeResult<Self>, ProxyError> {
    let mut probe_functions = vec![detect_ssh, detect_http, detect_socks5, detect_tls_handshake];

    while !probe_functions.is_empty() {
      // Read directly into the canonical initial buffer through a bounded view.
      let _read_len = read_tcp_stream(incoming_stream, buf).await?;

      let mut next_probe_functions = Vec::with_capacity(probe_functions.len());
      let mut successful_probe = None;
      let mut rejected = false;
      for probe in probe_functions {
        match probe(buf) {
          success @ ProbeResult::Success(_) => {
            if successful_probe.is_none() {
              successful_probe = Some(success);
            }
          }
          ProbeResult::PollNext => next_probe_functions.push(probe),
          ProbeResult::Failure => {}
          ProbeResult::Rejected => rejected = true,
        }
      }

      if rejected {
        return Err(ProxyError::TcpProbeRejected);
      }
      if let Some(success) = successful_probe {
        return Ok(success);
      }

      probe_functions = next_probe_functions;
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

/// UDP initial datagrams buffer for protocol detection
pub(crate) struct UdpInitialDatagrams {
  /// inner buffer of multiple UDP datagram payloads
  pub(crate) inner: Vec<Vec<u8>>,
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
    Err(failure) => map_quic_probe_failure(initial_datagrams, failure),
    Ok(client_hello_info) => ProbeResult::Success(UdpProbedProtocol::Quic(client_hello_info)),
  }
}

fn map_quic_probe_failure(
  initial_datagrams: &mut UdpInitialDatagrams,
  failure: TlsProbeFailure,
) -> ProbeResult<UdpProbedProtocol> {
  match failure {
    TlsProbeFailure::Failure | TlsProbeFailure::Rejected(_) => ProbeResult::Failure,
    TlsProbeFailure::PollNext => {
      initial_datagrams
        .probed_as_pollnext
        .insert(UdpProbedProtocol::Quic(Default::default()));
      ProbeResult::PollNext
    }
  }
}

fn select_udp_probe_result(probe_res: &[ProbeResult<UdpProbedProtocol>]) -> ProbeResult<UdpProbedProtocol> {
  // Keep parser-safety rejections fail-closed even if a future UDP probe
  // returns Rejected directly instead of mapping it to Failure first.
  if probe_res.iter().any(|result| matches!(result, ProbeResult::Rejected)) {
    return ProbeResult::Rejected;
  }

  // In case any of the probe results is a success, return it
  if let Some(probe_success) = probe_res.iter().find(|result| matches!(result, ProbeResult::Success(_))) {
    return probe_success.clone();
  }

  // In case any of the probe results is PollNext, return it
  if probe_res.iter().any(|result| matches!(result, ProbeResult::PollNext)) {
    return ProbeResult::PollNext;
  }

  // All detection finished as failure
  debug!("Untyped UDP connection detected");
  ProbeResult::Success(UdpProbedProtocol::Any)
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
        .filter_map(|p| match p {
          UdpProbedProtocol::Wireguard => Some(detect_wireguard as fn(&mut UdpInitialDatagrams) -> ProbeResult<_>),
          UdpProbedProtocol::Quic(_) => Some(detect_quic_initial),
          UdpProbedProtocol::Any => {
            warn!("Ignoring unexpected Any protocol in UDP poll-next candidates");
            None
          }
        })
        .collect()
    };

    let probe_res = probe_functions.into_iter().map(|f| f(initial_datagrams)).collect::<Vec<_>>();
    Ok(select_udp_probe_result(&probe_res))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::io::AsyncWriteExt;

  fn tls_record(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
  }

  fn valid_client_hello_bytes() -> Vec<u8> {
    let mut sni_extension = Vec::new();
    sni_extension.extend_from_slice(&0x0000u16.to_be_bytes());
    sni_extension.extend_from_slice(&16u16.to_be_bytes());
    sni_extension.extend_from_slice(&14u16.to_be_bytes());
    sni_extension.push(0);
    sni_extension.extend_from_slice(&11u16.to_be_bytes());
    sni_extension.extend_from_slice(b"example.com");

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0xc02fu16.to_be_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
    body.extend_from_slice(&sni_extension);

    let mut handshake = vec![0x01, 0, 0, body.len() as u8];
    handshake.extend_from_slice(&body);
    tls_record(&handshake)
  }

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
  fn test_socks5_detection() {
    // Test valid Socks5 handshake
    let socks5_data = b"\x05\x02\x00\x02"; // Version 5, 2 methods: No Auth (0x00), Username/Password (0x02)
    assert_eq!(detect_socks5(socks5_data), ProbeResult::Success(TcpProbedProtocol::Socks5));

    // Test invalid version
    let invalid_version = b"\x04\x01\x00";
    assert_eq!(detect_socks5(invalid_version), ProbeResult::Failure);

    // Test invalid number of methods
    let invalid_methods = b"\x05\x0B\x00"; // 11 methods, which is invalid
    assert_eq!(detect_socks5(invalid_methods), ProbeResult::Failure);

    // Test insufficient data
    let short_data = b"\x05";
    assert_eq!(detect_socks5(short_data), ProbeResult::PollNext);
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
  fn test_oversized_tls_record_is_rejected() {
    let oversized_record_header = [0x16, 0x03, 0x01, 0x40, 0x01];

    assert_eq!(detect_tls_handshake(&oversized_record_header), ProbeResult::Rejected);
  }

  #[tokio::test]
  async fn test_tcp_read_is_bounded_at_the_per_connection_limit() {
    let (mut reader, mut writer) = tokio::io::duplex(8);
    writer.write_all(b"ab").await.unwrap();

    let mut buf = BytesMut::from(vec![0; TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION - 1].as_slice());
    assert_eq!(read_tcp_stream(&mut reader, &mut buf).await.unwrap(), 1);
    assert_eq!(buf.len(), TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION);
    assert_eq!(buf[buf.len() - 1], b'a');

    assert!(matches!(
      read_tcp_stream(&mut reader, &mut buf).await,
      Err(ProxyError::TcpProbeLimitExceeded)
    ));
    assert_eq!(buf.len(), TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION);

    let mut unread = [0u8; 1];
    reader.read_exact(&mut unread).await.unwrap();
    assert_eq!(unread, [b'b']);
  }

  #[tokio::test]
  async fn test_valid_client_hello_fragmented_across_tcp_reads() {
    let encoded = valid_client_hello_bytes();
    let expected = encoded.clone();
    let (mut reader, mut writer) = tokio::io::duplex(1);
    let writer_task = tokio::spawn(async move {
      writer.write_all(&encoded).await.unwrap();
    });
    let mut initial_buf = BytesMut::new();

    let result = TcpProbedProtocol::detect_protocol(&mut reader, &mut initial_buf)
      .await
      .unwrap();

    assert!(matches!(result, ProbeResult::Success(TcpProbedProtocol::Tls(_))));
    assert_eq!(initial_buf.as_ref(), expected.as_slice());
    writer_task.await.unwrap();
  }

  #[tokio::test]
  async fn test_ghsa_shaped_oversized_record_is_rejected_without_fallback() {
    let (mut reader, mut writer) = tokio::io::duplex(16);
    writer.write_all(&[0x16, 0x03, 0x01, 0xff, 0xff]).await.unwrap();
    let mut initial_buf = BytesMut::new();

    assert!(matches!(
      TcpProbedProtocol::detect_protocol(&mut reader, &mut initial_buf).await,
      Err(ProxyError::TcpProbeRejected)
    ));
    assert_eq!(initial_buf.len(), 5);
  }

  #[tokio::test]
  async fn test_tls_rejection_takes_precedence_over_another_probe_success() {
    let input = b"\x16\x03\x01\xff\xffHTTP";
    let (mut reader, mut writer) = tokio::io::duplex(input.len());
    writer.write_all(input).await.unwrap();
    let mut initial_buf = BytesMut::new();

    assert!(matches!(
      TcpProbedProtocol::detect_protocol(&mut reader, &mut initial_buf).await,
      Err(ProxyError::TcpProbeRejected)
    ));
  }

  #[tokio::test]
  async fn test_incomplete_tls_records_stop_at_the_cumulative_limit() {
    const DECLARED_CLIENT_HELLO_BODY_LEN: usize = 0xff_ffff;
    let mut first_payload = vec![0; 16 * 1024];
    first_payload[..4].copy_from_slice(&[
      0x01,
      (DECLARED_CLIENT_HELLO_BODY_LEN >> 16) as u8,
      (DECLARED_CLIENT_HELLO_BODY_LEN >> 8) as u8,
      DECLARED_CLIENT_HELLO_BODY_LEN as u8,
    ]);

    let mut input = tls_record(&first_payload);
    let zero_payload = vec![0; 16 * 1024];
    for _ in 1..8 {
      input.extend_from_slice(&tls_record(&zero_payload));
    }
    assert!(input.len() > TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION);

    let (mut reader, mut writer) = tokio::io::duplex(input.len());
    writer.write_all(&input).await.unwrap();
    let mut initial_buf = BytesMut::new();

    assert!(matches!(
      TcpProbedProtocol::detect_protocol(&mut reader, &mut initial_buf).await,
      Err(ProxyError::TcpProbeLimitExceeded)
    ));
    assert_eq!(initial_buf.len(), TCP_PROTOCOL_DETECTION_MAX_BYTES_PER_CONNECTION);
  }

  #[tokio::test]
  async fn test_timeout_and_eof_leave_probe_buffer_bounded() {
    let (mut waiting_reader, _waiting_writer) = tokio::io::duplex(1);
    let mut timeout_buf = BytesMut::new();

    assert!(
      tokio::time::timeout(
        std::time::Duration::from_millis(1),
        TcpProbedProtocol::detect_protocol(&mut waiting_reader, &mut timeout_buf),
      )
      .await
      .is_err()
    );
    assert!(timeout_buf.is_empty());

    let (mut eof_reader, eof_writer) = tokio::io::duplex(1);
    drop(eof_writer);
    let mut eof_buf = BytesMut::new();
    assert!(matches!(
      TcpProbedProtocol::detect_protocol(&mut eof_reader, &mut eof_buf).await,
      Err(ProxyError::NoDataReceivedTcpStream(_))
    ));
    assert!(eof_buf.is_empty());
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
      probed_as_pollnext: Default::default(),
    };

    assert_eq!(detect_wireguard(&mut initial_datagrams_invalid), ProbeResult::Failure);
  }

  #[tokio::test]
  async fn test_unexpected_any_pollnext_candidate_falls_back_to_any() {
    let mut initial_datagrams = UdpInitialDatagrams {
      inner: vec![vec![0]],
      probed_as_pollnext: HashSet::from([UdpProbedProtocol::Any]),
    };

    assert_eq!(
      UdpProbedProtocol::detect_protocol(&mut initial_datagrams).await.unwrap(),
      ProbeResult::Success(UdpProbedProtocol::Any)
    );
  }

  #[test]
  fn test_quic_tls_rejection_does_not_poll_next() {
    let mut initial_datagrams = UdpInitialDatagrams {
      inner: vec![vec![0]],
      probed_as_pollnext: HashSet::new(),
    };

    assert_eq!(
      map_quic_probe_failure(
        &mut initial_datagrams,
        TlsProbeFailure::Rejected(quic_tls::TlsProbeRejection::ClientHelloTooLarge),
      ),
      ProbeResult::Failure
    );
    assert!(initial_datagrams.probed_as_pollnext.is_empty());
  }

  #[test]
  fn test_udp_rejection_takes_precedence_and_never_falls_back_to_any() {
    let results = [
      ProbeResult::Success(UdpProbedProtocol::Any),
      ProbeResult::PollNext,
      ProbeResult::Rejected,
    ];

    assert_eq!(select_udp_probe_result(&results), ProbeResult::Rejected);
  }
}
