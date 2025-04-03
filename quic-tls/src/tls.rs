use crate::{
  SUPPORTED_TLS_VERSIONS,
  client_hello::{TlsClientHello, probe_tls_client_hello, probe_tls_handshake_message},
  error::TlsProbeFailure,
  trace::*,
};
use bytes::{Buf, BytesMut};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;

/* ---------------------------------------------------------- */

/// Check if the buffer is a TLSPlaintext record
/// This is inspired by https://github.com/yrutschle/sslh/blob/master/tls.c
/// Support TLS Record layer fragmentation https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
pub fn probe_tls_handshake<B: Buf>(buf: &mut B) -> Result<TlsClientHello, TlsProbeFailure> {
  let mut tls_plaintext = BytesMut::new();

  while buf.remaining() > 0 {
    // TLS record header (5)
    if buf.remaining() < TLS_RECORD_HEADER_LEN {
      return Err(TlsProbeFailure::PollNext);
    }
    // TLS record header: https://tools.ietf.org/html/rfc5246#section-6.2 , https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
    // - content type: 1 byte
    // - version: 2 bytes
    // - length: 2 bytes
    // content type should be 0x16 (handshake)
    let content_type = buf.get_u8();
    if !content_type.eq(&TLS_HANDSHAKE_CONTENT_TYPE) {
      return Err(TlsProbeFailure::Failure);
    }

    // Initial client hello possibly has the legacy versions for interoperability, like 0x03 0x01 = TLS 1.0
    let tls_version = buf.get_u16();
    if !SUPPORTED_TLS_VERSIONS.contains(&tls_version) {
      // Omit the legacy SSL and unknown versions
      return Err(TlsProbeFailure::Failure);
    }
    let payload_len = buf.get_u16() as usize;
    if buf.remaining() < payload_len {
      debug!("Read buffer for TLS handshake detection is not enough");
      return Err(TlsProbeFailure::PollNext);
    }
    debug!("TLS Payload length: {}", payload_len);

    let b = buf.copy_to_bytes(payload_len);
    tls_plaintext.extend_from_slice(&b);
  }

  // Check if the buffer is a TLS handshake
  probe_tls_handshake_message(&mut tls_plaintext)?;

  // Check if the buffer is a TLS ClientHello
  match probe_tls_client_hello(&mut tls_plaintext) {
    Some(client_hello) => {
      // TODO: remove later, checking ech
      if client_hello.is_ech_outer() {
        crate::ech::decrypt_ech(&client_hello);
      }
      Ok(client_hello)
    }
    None => Err(TlsProbeFailure::Failure),
  }
}
