use crate::{probe::ProbeResult, tcp_proxy::TcpProxyProtocol, trace::*};
use bytes::BytesMut;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, Default)]
/// Matching rule of TLS Server Name Indication (SNI) and Application-Layer Protocol Negotiation (ALPN) for routing
pub(crate) struct TlsMatchingRule {
  /// Matched SNIs for the destination
  /// If empty, any SNI is allowed
  sni: Vec<String>,
  /// Matched ALPNs for the destination
  /// If empty, any ALPN is allowed
  alpn: Vec<String>,
}
impl From<(&[&str], &[&str])> for TlsMatchingRule {
  fn from((server_names, alpn): (&[&str], &[&str])) -> Self {
    Self {
      sni: server_names.iter().map(|s| s.to_lowercase()).collect(),
      alpn: alpn.iter().map(|s| s.to_lowercase()).collect(),
    }
  }
}

#[derive(Debug, Clone)]
/// Router for TLS/QUIC destinations
pub(crate) struct TlsDestinations<T> {
  /// inner
  inner: Vec<(TlsMatchingRule, T)>,
}
impl<T> TlsDestinations<T> {
  /// Create a new instance
  pub(crate) fn new() -> Self {
    Self { inner: Vec::new() }
  }
  /// Add a destination with SNI
  pub(crate) fn add(&mut self, server_names: &[&str], alpn: &[&str], dest: T) {
    self.inner.push((TlsMatchingRule::from((server_names, alpn)), dest));
  }
  /// Find a destination by SNI
  pub(crate) fn find(&self, received_client_hello: &TlsClientHelloInfo) -> Option<&T> {
    let received_sni = received_client_hello.sni.iter().map(|v| v.to_lowercase());
    let received_alpn = received_client_hello.alpn.iter().map(|v| v.to_lowercase());

    let filtered = {
      let filtered = self.inner.iter().filter(|(rule, _)| {
        let is_sni_match = rule
          .sni
          .iter()
          .any(|server_name| received_sni.clone().any(|r| r.eq(server_name)))
          || rule.sni.is_empty();
        let is_alpn_match = rule.alpn.iter().any(|alpn| received_alpn.clone().any(|r| r.eq(alpn))) || rule.alpn.is_empty();
        is_sni_match && is_alpn_match
      });
      // Extract the most specific match
      if let Some(both_matched) = filtered
        .clone()
        .find(|(rule, _)| !rule.sni.is_empty() && !rule.alpn.is_empty())
      {
        Some(both_matched)
      } else if let Some(sni_matched) = filtered.clone().find(|(rule, _)| !rule.sni.is_empty()) {
        Some(sni_matched)
      } else if let Some(alpn_matched) = filtered.clone().find(|(rule, _)| !rule.alpn.is_empty()) {
        Some(alpn_matched)
      } else {
        filtered.clone().next()
      }
    };
    filtered.map(|(_, dest)| dest)
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
/// Probed TLS ClientHello information
pub(crate) struct TlsClientHelloInfo {
  /// SNI
  pub(crate) sni: Vec<String>,
  /// ALPN
  #[allow(unused)]
  pub(crate) alpn: Vec<String>,
  //TODO: /// ECH info
}
/* ---------------------------------------------------------- */
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_MESSAGE_HEADER_LEN: usize = 4;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// Check if the buffer is a TLS handshake
/// This is inspired by https://github.com/yrutschle/sslh/blob/master/tls.c
pub(crate) fn is_tls_handshake(buf: &BytesMut) -> ProbeResult<TcpProxyProtocol> {
  // TLS record header (5) + handshake type (1) + body length (3)
  if buf.len() < TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_MESSAGE_HEADER_LEN {
    return ProbeResult::Failure;
  }
  // TLS record header: https://tools.ietf.org/html/rfc5246#section-6.2 , https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
  // - content type: 1 byte
  // - version: 2 bytes
  // - length: 2 bytes
  // content type should be 0x16 (handshake)
  if !buf[0].eq(&TLS_HANDSHAKE_CONTENT_TYPE) {
    return ProbeResult::Failure;
  }
  // Initial client hello possibly has the legacy versions for interoperability, like 0x03 0x01 = TLS 1.0
  let tls_version_major = buf[1];
  let tls_version_minor = buf[2];
  if tls_version_major < 3 {
    // Omit the legacy SSL
    return ProbeResult::Failure;
  }
  let payload_len = ((buf[3] as usize) << 8) + buf[4] as usize;
  if buf.len() < TLS_RECORD_HEADER_LEN + payload_len {
    debug!("Read buffer for TLS handshake detection is not enough");
    return ProbeResult::PollNext;
  }
  debug!("TLS Payload length: {}", payload_len);

  // Check if the buffer is a TLS handshake
  // https://datatracker.ietf.org/doc/html/rfc8446#page-24
  // https://tools.ietf.org/html/rfc5246#section-7.4
  // -- Handshake message header --
  //  - 1 Handshake Type msg_type
  //  - 3 Length
  let pos = TLS_RECORD_HEADER_LEN;
  let header_probe_res = probe_tls_client_hello_header(buf, pos);
  match header_probe_res {
    ProbeResult::PollNext => return ProbeResult::PollNext,
    ProbeResult::Failure => return ProbeResult::Failure,
    ProbeResult::Success(_) => {}
  }

  match probe_tls_client_hello_body(&buf[TLS_RECORD_HEADER_LEN..], tls_version_major, tls_version_minor) {
    Some(client_hello_info) => ProbeResult::Success(TcpProxyProtocol::Tls(client_hello_info)),
    None => ProbeResult::Failure,
  }
}
/* ---------------------------------------------------------- */
/// Check if the buffer has a valid header as a TLS ClientHello, called from TLS and QUIC
pub(crate) fn probe_tls_client_hello_header(buf: &[u8], pos: usize) -> ProbeResult<()> {
  if buf[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
    return ProbeResult::Failure;
  }
  let client_hello_body_len = ((buf[pos + 1] as usize) << 16) + ((buf[pos + 2] as usize) << 8) + (buf[pos + 3] as usize);
  debug!("TLS ClientHello body length: {}", client_hello_body_len);
  if buf[pos..].len() < client_hello_body_len + TLS_HANDSHAKE_MESSAGE_HEADER_LEN {
    return ProbeResult::PollNext;
  }
  ProbeResult::Success(())
}

/* ---------------------------------------------------------- */
/// Check if the buffer is a TLS ClientHello body, called from TLS and QUIC
pub(crate) fn probe_tls_client_hello_body(
  buf: &[u8],
  tls_version_major: u8,
  tls_version_minor: u8,
) -> Option<TlsClientHelloInfo> {
  let mut pos = 0;
  // -- Handshake message header (4 bytes) --
  // -- Handshake message body if msg_type == Client Hello --
  //  - 2	Version (again)
  //  - 32	Random
  //  - to	Session ID Length
  pos += 38;
  if buf.len() < pos {
    return None;
  }

  // Session ID
  let session_id_len = buf[pos] as usize;
  pos += 1 + session_id_len;
  if buf.len() < pos {
    return None;
  }

  // Cipher Suites
  let cipher_suites_len = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
  if cipher_suites_len < 2 || cipher_suites_len % 2 != 0 {
    return None;
  }
  pos += 2 + cipher_suites_len;
  if buf.len() < pos {
    return None;
  }

  // Compression Methods
  let compression_methods_len = buf[pos] as usize;
  if compression_methods_len < 1 {
    return None;
  }
  pos += 1 + compression_methods_len;
  if buf.len() < pos {
    return None;
  }

  // Now we are at the end of the Client Hello message.
  // If no extensions are present, the next 2 bytes, extension_type, should be 0.
  // Then, if major version == 3 and minor version == 0, it is SSL 3.0, not TLS 1.0, and we should reject it.
  let extensions_len = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
  if tls_version_major == 3 && tls_version_minor == 0 && extensions_len == 0 {
    return None;
  }
  pos += 2;
  if buf.len() < pos {
    return None;
  }
  debug!("TLS extensions_len: {}", extensions_len);
  // Check extensions
  // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
  let mut client_hello_info = TlsClientHelloInfo::default();
  let mut cnt = 0;
  while cnt < extensions_len {
    if buf.len() < pos + 4 {
      return None;
    }
    let extension_type = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
    debug!("TLS extension_type: {:2x}", extension_type);
    pos += 2;
    cnt += 2;
    let extension_len = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
    // debug!("TLS extension_len: {}", extension_len);
    pos += 2;
    cnt += 2;
    let extension_payload = &buf[pos..pos + extension_len];
    // debug!("TLS extension_payload: {:?}", extension_payload);
    /* ---------------- */
    // parse extension for the routing with SNI and ALPN
    match extension_type {
      0x00 => {
        // Server Name Indication
        debug!("Found Server Name Indication extension");
        client_hello_info.sni = parse_sni(extension_payload).unwrap_or_default();
      }
      0x10 => {
        // Application-Layer Protocol Negotiation
        debug!("Found Application-Layer Protocol Negotiation extension");
        client_hello_info.alpn = parse_alpn(extension_payload).unwrap_or_default();
      }
      _ => {}
    }
    /* ---------------- */
    pos += extension_len;
    cnt += extension_len;
  }

  // Check the remaining buffer is all zero, consistent as a TLS ClientHello
  if !buf[pos..].iter().all(|v| v.eq(&0)) {
    return None;
  }

  debug!("TLS ClientHello detected: {:?}", client_hello_info);
  Some(client_hello_info)
}

/// Parse server name from the SNI extension
/// https://datatracker.ietf.org/doc/html/rfc6066#section-3
pub(crate) fn parse_sni(buf: &[u8]) -> Result<Vec<String>, anyhow::Error> {
  let mut pos = 0;

  if buf.len() < 2 {
    error!("Invalid SNI extension");
    return Err(anyhow::anyhow!("Invalid SNI extension"));
  }

  // byte length of the server name list payload
  let server_name_list_len = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
  pos += 2;

  let mut sni_list = Vec::new();
  while pos + 3 < buf.len() {
    let name_type = buf[pos];
    let len = ((buf[pos + 1] as usize) << 8) + buf[pos + 2] as usize;
    if buf.len() < pos + 3 + len {
      error!("Invalid SNI extension");
      return Err(anyhow::anyhow!("Invalid SNI extension"));
    }
    match name_type {
      0x00 => {
        // Hostname
        let name_payload = &buf[pos + 3..pos + 3 + len];
        let name = String::from_utf8_lossy(name_payload).to_ascii_lowercase();
        sni_list.push(name);
      }
      _ => {
        debug!("Unknown SNI name type: {:x}", name_type);
      }
    }

    pos += 3 + len;
  }

  if sni_list.is_empty() {
    error!("No SNI found");
    return Err(anyhow::anyhow!("No SNI found"));
  }

  if pos != server_name_list_len + 2 {
    error!("Invalid SNI extension");
    return Err(anyhow::anyhow!("Invalid SNI extension"));
  }

  Ok(sni_list)
}

/// Parse ALPN extension
/// https://datatracker.ietf.org/doc/html/rfc7301
pub(crate) fn parse_alpn(buf: &[u8]) -> Result<Vec<String>, anyhow::Error> {
  let mut pos = 0;

  if buf.len() < 2 {
    error!("Invalid ALPN extension");
    return Err(anyhow::anyhow!("Invalid ALPN extension"));
  }

  // byte length of the protocol name list payload
  let protocol_name_list_len = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
  pos += 2;

  let mut alpn_list = Vec::new();
  while pos + 1 < buf.len() {
    let len = buf[pos] as usize;
    if buf.len() < pos + 1 + len || len == 0 {
      // 0-length protocol name is invalid
      error!("Invalid ALPN extension");
      return Err(anyhow::anyhow!("Invalid ALPN extension"));
    }
    let name_payload = &buf[pos + 1..pos + 1 + len];
    let protocol_name = String::from_utf8_lossy(name_payload).to_ascii_lowercase();
    alpn_list.push(protocol_name);
    pos += 1 + len;
  }

  if alpn_list.is_empty() {
    error!("No ALPN found");
    return Err(anyhow::anyhow!("No ALPN found"));
  }

  if pos != protocol_name_list_len + 2 {
    error!("Invalid ALPN extension");
    return Err(anyhow::anyhow!("Invalid ALPN extension"));
  }

  Ok(alpn_list)
}

/* ---------------------------------------------------------- */
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_tls_destinations() {
    let mut tls_destinations = TlsDestinations::new();
    tls_destinations.add(&["example.com"], &[], "127.0.0.1");
    tls_destinations.add(&["example.org"], &[], "192.168.0.1");
    tls_destinations.add(&[], &[], "1.1.1.1");

    tls_destinations.add(&[], &["h2"], "8.8.8.8");
    tls_destinations.add(&["example.com"], &["h2"], "127.0.0.2");

    // Test SNI
    // Match only sni
    let mut received = TlsClientHelloInfo {
      sni: vec!["example.com".to_string()],
      alpn: Vec::new(),
    };
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"127.0.0.1"));

    received.sni = vec!["example.org".to_string()];
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"192.168.0.1"));

    // Doesn't match sni
    received.sni = vec!["example.net".to_string()];
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"1.1.1.1"));

    // Doesn't match sni
    received.sni = vec!["example.io".to_string()];
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"1.1.1.1"));

    // Test ALPN
    // Match only alpn
    received.sni = vec![];
    received.alpn = vec!["h2".to_string()];
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"8.8.8.8"));

    // Doesn't match alpn
    received.alpn = vec!["h3".to_string()];
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"1.1.1.1"));

    // Test both SNI and ALPN
    // Match both sni and alpn to single destination
    received.sni = vec!["example.com".to_string()];
    received.alpn = vec!["h2".to_string()];
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"127.0.0.2"));

    // Match sni but doesn't match alpn
    received.sni = vec!["example.com".to_string()];
    received.alpn = vec!["h3".to_string()];
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"127.0.0.1"));

    // Match sni and alpn "independently", sni is prioritized
    received.sni = vec!["example.org".to_string()];
    received.alpn = vec!["h2".to_string()];
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"192.168.0.1"));

    // Match neither sni nor alpn
    received.sni = vec!["example.net".to_string()];
    received.alpn = vec!["h3".to_string()];
    let dest = tls_destinations.find(&received);
    assert_eq!(dest, Some(&"1.1.1.1"));
  }
}
