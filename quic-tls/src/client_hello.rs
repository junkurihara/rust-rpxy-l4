use crate::{trace::*, TlsProbeFailure};
use anyhow::anyhow;

const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
/// Probed TLS ClientHello information
pub struct TlsClientHelloInfo {
  /// SNI
  pub sni: Vec<String>,
  /// ALPN
  #[allow(unused)]
  pub alpn: Vec<String>,
  //TODO: /// ECH info
}

/* ---------------------------------------------------------- */


/* ---------------------------------------------------------- */
/// Check if the buffer has a valid header as a TLS ClientHello, called from TLS and QUIC
pub(crate) fn probe_tls_client_hello_header(buf: &[u8], pos: usize) -> Result<(), TlsProbeFailure> {
  if buf[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
    return Err(TlsProbeFailure::Failure);
  }
  let client_hello_body_len = ((buf[pos + 1] as usize) << 16) + ((buf[pos + 2] as usize) << 8) + (buf[pos + 3] as usize);
  debug!("TLS ClientHello body length: {}", client_hello_body_len);
  if buf[pos..].len() < client_hello_body_len + 4 {
    debug!("TLS ClientHello body is not fully received");
    return Err(TlsProbeFailure::PollNext);
  }
  Ok(())
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
fn parse_sni(buf: &[u8]) -> Result<Vec<String>, anyhow::Error> {
  let mut pos = 0;

  if buf.len() < 2 {
    error!("Invalid SNI extension");
    return Err(anyhow!("Invalid SNI extension"));
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
      return Err(anyhow!("Invalid SNI extension"));
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
    return Err(anyhow!("No SNI found"));
  }

  if pos != server_name_list_len + 2 {
    error!("Invalid SNI extension");
    return Err(anyhow!("Invalid SNI extension"));
  }

  Ok(sni_list)
}

/// Parse ALPN extension
/// https://datatracker.ietf.org/doc/html/rfc7301
fn parse_alpn(buf: &[u8]) -> Result<Vec<String>, anyhow::Error> {
  let mut pos = 0;

  if buf.len() < 2 {
    error!("Invalid ALPN extension");
    return Err(anyhow!("Invalid ALPN extension"));
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
      return Err(anyhow!("Invalid ALPN extension"));
    }
    let name_payload = &buf[pos + 1..pos + 1 + len];
    let protocol_name = String::from_utf8_lossy(name_payload).to_ascii_lowercase();
    alpn_list.push(protocol_name);
    pos += 1 + len;
  }

  if alpn_list.is_empty() {
    error!("No ALPN found");
    return Err(anyhow!("No ALPN found"));
  }

  if pos != protocol_name_list_len + 2 {
    error!("Invalid ALPN extension");
    return Err(anyhow!("Invalid ALPN extension"));
  }

  Ok(alpn_list)
}

/* ---------------------------------------------------------- */
