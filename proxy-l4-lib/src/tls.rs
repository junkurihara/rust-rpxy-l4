use crate::trace::*;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, Default)]
/// TLS Server Name Indication (SNI) for routing
pub(crate) struct TlsServerNames {
  /// Matched SNIs for the destination
  /// If empty, any SNI is allowed
  server_names: Vec<String>,
}
impl From<&[&str]> for TlsServerNames {
  fn from(server_names: &[&str]) -> Self {
    Self {
      server_names: server_names.iter().map(|s| s.to_lowercase()).collect(),
    }
  }
}

#[derive(Debug, Clone)]
/// Router for TLS/QUIC destinations
pub(crate) struct TlsDestinations<T> {
  /// inner
  inner: Vec<(TlsServerNames, T)>,
}
impl<T> TlsDestinations<T> {
  /// Create a new instance
  pub(crate) fn new() -> Self {
    Self { inner: Vec::new() }
  }
  /// Add a destination with SNI
  pub(crate) fn add(&mut self, server_names: &[&str], dest: T) {
    self.inner.push((TlsServerNames::from(server_names), dest));
  }
  /// Find a destination by SNI
  pub(crate) fn find(&self, server_name: &str) -> Option<&T> {
    let server_name = server_name.to_lowercase();
    let filtered = {
      let matched = self.inner.iter().find(|(snis, _)| snis.server_names.contains(&server_name));
      if matched.is_none() {
        self.inner.iter().find(|(snis, _)| snis.server_names.is_empty())
      } else {
        matched
      }
    };
    filtered.map(|(_, dest)| dest)
  }
}
/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
/// Probed TLS ClientHello information
pub(crate) struct TlsClientHelloInfo {
  /// SNI TODO: Make this a list
  pub(crate) server_name: String,
  /// TODO: ALPN Make this a list
  #[allow(unused)]
  pub(crate) alpn: String,
  //TODO: /// ECH info
}
/* ---------------------------------------------------------- */
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// Check if the buffer is a TLS handshake
/// This is inspired by https://github.com/yrutschle/sslh/blob/master/tls.c
pub(crate) fn probe_tls_handshake(buf: &[u8]) -> Option<TlsClientHelloInfo> {
  // TLS record header is 5 bytes
  if buf.len() < TLS_RECORD_HEADER_LEN {
    return None;
  }
  // TLS record header: https://tools.ietf.org/html/rfc5246#section-6.2 , https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
  // - content type: 1 byte
  // - version: 2 bytes
  // - length: 2 bytes
  // content type should be 0x16 (handshake)
  if !buf[0].eq(&TLS_HANDSHAKE_CONTENT_TYPE) {
    return None;
  }
  // Initial client hello possibly has the legacy versions for interoperability, like 0x03 0x01 = TLS 1.0
  let tls_version_major = buf[1];
  let tls_version_minor = buf[2];
  if tls_version_major < 3 {
    // Omit the legacy SSL
    return None;
  }
  let payload_len = ((buf[3] as usize) << 8) + buf[4] as usize;
  if buf.len() < TLS_RECORD_HEADER_LEN + payload_len {
    debug!("Peek buffer for TLS handshake detection is not enough");
    return None;
  }
  debug!("TLS Payload length: {}", payload_len);

  probe_tls_client_hello(&buf[TLS_RECORD_HEADER_LEN..], tls_version_major, tls_version_minor)
}

/// Check if the buffer is a TLS ClientHello, called from TLS and QUIC
pub(crate) fn probe_tls_client_hello(buf: &[u8], tls_version_major: u8, tls_version_minor: u8) -> Option<TlsClientHelloInfo> {
  let mut pos = 0;

  // Check if the buffer is a TLS handshake
  // https://datatracker.ietf.org/doc/html/rfc8446#page-24
  // https://tools.ietf.org/html/rfc5246#section-7.4
  // let mut pos = TLS_RECORD_HEADER_LEN;
  if buf[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
    return None;
  }
  // Skip past fixed length records:
  // -- Handshake --
  //  - 1 Handshake Type msg_type
  //  - 3 Length
  // -- if msg_type == Client Hello --
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
  let mut cnt = 0;
  while cnt < extensions_len {
    if buf.len() < pos + 4 {
      return None;
    }
    let extension_type = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
    debug!("TLS extension_type: {:2x}", extension_type);
    // TODO: parse extension for the routing with SNI and ALPN
    pos += 2;
    cnt += 2;
    let extension_len = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
    // debug!("TLS extension_len: {}", extension_len);
    pos += 2;
    cnt += 2;
    // let extension_payload = &buf[pos..pos + extension_len];
    // debug!("TLS extension_payload: {:?}", extension_payload);
    if extension_type.eq(&0x00) {
      debug!("Found Server Name Indication extension");
      let extension_payload = &buf[pos..pos + extension_len];
      let sni = parse_sni(extension_payload);
      println!("SNI: {:?}", sni);
    }
    pos += extension_len;
    cnt += extension_len;
  }

  // Check the remaining buffer is all zero, consistent as a TLS ClientHello
  if !buf[pos..].iter().all(|v| v.eq(&0)) {
    return None;
  }

  debug!("TLS ClientHello detected");
  // TODO: TODO: TODO: TODO:
  Some(TlsClientHelloInfo {
    server_name: String::new(),
    alpn: String::new(),
  })
}

/// Parse server name from the SNI extension
pub(crate) fn parse_sni(buf: &[u8]) -> Result<Vec<String>, anyhow::Error> {
  let mut pos = 0;

  // byte length of the server name list payload
  let server_name_list_len = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
  pos += 2;

  let mut sni_list = Vec::new();
  while pos + 3 < buf.len() {
    let name_type = buf[pos];
    let len = ((buf[pos + 1] as usize) << 8) + buf[pos + 2] as usize;
    if buf.len() < pos + 3 + len {
      return Err(anyhow::anyhow!("Invalid SNI extension"));
    }
    match name_type {
      0x00 => {
        // Hostname
        let name_payload = &buf[pos + 3..pos + 3 + len];
        let name = String::from_utf8_lossy(name_payload).to_string().to_ascii_lowercase();
        sni_list.push(name);
      }
      _ => {
        debug!("Unknown SNI name type: {:x}", name_type);
      }
    }

    pos += 3 + len;
  }

  if sni_list.is_empty() {
    return Err(anyhow::anyhow!("No SNI found"));
  }

  if pos != server_name_list_len + 2 {
    return Err(anyhow::anyhow!("Invalid SNI extension"));
  }

  Ok(sni_list)
}
