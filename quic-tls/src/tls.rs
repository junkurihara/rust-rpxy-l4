use crate::{
  client_hello::{probe_tls_client_hello_body, probe_tls_client_hello_header, TlsClientHelloInfo},
  error::TlsProbeFailure,
  trace::*,
};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_MESSAGE_HEADER_LEN: usize = 4;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;

/* ---------------------------------------------------------- */

/// Check if the buffer is a TLS handshake
/// This is inspired by https://github.com/yrutschle/sslh/blob/master/tls.c
pub fn probe_tls_handshake(buf: &[u8]) -> Result<TlsClientHelloInfo, TlsProbeFailure> {
  // TLS record header (5) + handshake type (1) + body length (3)
  if buf.len() < TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_MESSAGE_HEADER_LEN {
    return Err(TlsProbeFailure::Failure);
  }
  // TLS record header: https://tools.ietf.org/html/rfc5246#section-6.2 , https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
  // - content type: 1 byte
  // - version: 2 bytes
  // - length: 2 bytes
  // content type should be 0x16 (handshake)
  if !buf[0].eq(&TLS_HANDSHAKE_CONTENT_TYPE) {
    return Err(TlsProbeFailure::Failure);
  }
  // Initial client hello possibly has the legacy versions for interoperability, like 0x03 0x01 = TLS 1.0
  let tls_version_major = buf[1];
  let tls_version_minor = buf[2];
  if tls_version_major < 3 {
    // Omit the legacy SSL
    return Err(TlsProbeFailure::Failure);
  }
  let payload_len = ((buf[3] as usize) << 8) + buf[4] as usize;
  if buf.len() < TLS_RECORD_HEADER_LEN + payload_len {
    debug!("Read buffer for TLS handshake detection is not enough");
    return Err(TlsProbeFailure::PollNext);
  }
  debug!("TLS Payload length: {}", payload_len);

  // Check if the buffer is a TLS handshake
  // https://datatracker.ietf.org/doc/html/rfc8446#page-24
  // https://tools.ietf.org/html/rfc5246#section-7.4
  // -- Handshake message header --
  //  - 1 Handshake Type msg_type
  //  - 3 Length
  let pos = TLS_RECORD_HEADER_LEN;
  probe_tls_client_hello_header(buf, pos)?;

  match probe_tls_client_hello_body(&buf[TLS_RECORD_HEADER_LEN..], tls_version_major, tls_version_minor) {
    Some(client_hello_info) => Ok(client_hello_info),
    None => Err(TlsProbeFailure::Failure),
  }
}
