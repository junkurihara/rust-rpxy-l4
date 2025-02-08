use crate::log::debug;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// Check if the buffer is a TLS handshake
/// This is inspired by https://github.com/yrutschle/sslh/blob/master/tls.c
pub(crate) fn is_tls_handshake(buf: &[u8]) -> bool {
  // TLS record header is 5 bytes
  if buf.len() < TLS_RECORD_HEADER_LEN {
    return false;
  }
  // TLS record header: https://tools.ietf.org/html/rfc5246#section-6.2 , https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
  // - content type: 1 byte
  // - version: 2 bytes
  // - length: 2 bytes
  // content type should be 0x16 (handshake)
  if !buf[0].eq(&TLS_HANDSHAKE_CONTENT_TYPE) {
    return false;
  }
  // Initial client hello possibly has the legacy versions for interoperability, like 0x03 0x01 = TLS 1.0
  let tls_version_major = buf[1];
  let tls_version_minor = buf[2];
  if tls_version_major < 3 {
    // Omit the legacy SSL
    return false;
  }
  let payload_len = ((buf[3] as usize) << 8) + buf[4] as usize;
  debug!("TLS Payload length: {}", payload_len);

  // Check if the buffer is a TLS handshake
  // https://datatracker.ietf.org/doc/html/rfc8446#page-24
  // https://tools.ietf.org/html/rfc5246#section-7.4
  let mut pos = TLS_RECORD_HEADER_LEN;
  if buf[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
    return false;
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

  // Session ID
  let session_id_len = buf[pos] as usize;
  pos += 1 + session_id_len;

  // Cipher Suites
  let cipher_suites_len = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
  if cipher_suites_len < 2 || cipher_suites_len % 2 != 0 {
    return false;
  }
  pos += 2 + cipher_suites_len;

  // Compression Methods
  let compression_methods_len = buf[pos] as usize;
  if compression_methods_len < 1 {
    return false;
  }
  pos += 1 + compression_methods_len;

  // Now we are at the end of the Client Hello message.
  // If no extensions are present, the next 2 bytes, extension_type, should be 0.
  // Then, if major version == 3 and minor version == 0, it is SSL 3.0, not TLS 1.0, and we should reject it.
  let extensions_len = ((buf[pos] as usize) << 8) + buf[pos + 1] as usize;
  if tls_version_major == 3 && tls_version_minor == 0 && extensions_len == 0 {
    return false;
  }
  pos += 2;
  debug!("TLS extensions_len: {}", extensions_len);
  // Check extensions
  // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
  let mut cnt = 0;
  while cnt < extensions_len {
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
    pos += extension_len;
    cnt += extension_len;
  }

  // Check the remaining buffer is all zero, consistent as a TLS ClientHello
  if !buf[pos..].iter().all(|v| v.eq(&0)) {
    return false;
  }

  debug!("TLS ClientHello detected");
  true
}
