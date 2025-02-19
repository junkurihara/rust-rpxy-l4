use crate::trace::*;

const QUIC_VERSION: &[u8] = &[0x00, 0x00, 0x00, 0x01];

/// Check if the buffer contains a QUIC handshake packet.
/// https://www.rfc-editor.org/rfc/rfc9000.html
/// https://www.rfc-editor.org/rfc/rfc9001.html
/// https://quic.xargs.org
/// - First checks if the buffer is consistent with a QUIC initial handshake packet.
/// - Then derive the header protection key and decrypt the packet.
/// - Finally, check if the decrypted packet is consistent with a QUIC TLS ClientHello.
pub(crate) fn is_quic_handshake(buf: &[u8]) -> bool {
  // header(1), version(4), DCID length(1), SCID length(1)
  if buf.len() < 7 {
    return false;
  }
  // Packet header byte
  // 0b1100_[0000] - Long header with protected packet number field length ([0000])
  // omitting the protected part.
  if buf[0] & 0xf0 != 0xc0 {
    return false;
  }
  // Version
  if !buf[1..5].eq(QUIC_VERSION) {
    return false;
  }
  let mut ptr = 5;
  // DCID length
  let dcid_len = buf[ptr] as usize;
  ptr += 1 + dcid_len;
  if ptr >= buf.len() {
    return false;
  }
  debug!("DCID: {:x?}", &buf[ptr - dcid_len..ptr]);
  // SCID length
  let scid_len = buf[ptr] as usize;
  ptr += 1 + scid_len;
  if ptr >= buf.len() {
    return false;
  }
  debug!("SCID: {:x?}", &buf[ptr - scid_len..ptr]);

  debug!("{:x?}", buf);
  false
}
