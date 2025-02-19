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
  // Token length
  // let token_len =
  // let token_len = buf[ptr] as usize;
  // ptr += 1 + token_len;
  // if ptr >= buf.len() {
  //   return false;
  // }
  // debug!("Token: {:x?}", &buf[ptr - token_len..ptr]);
  // Payload length

  debug!("{:x?}", buf);
  false
}

/// Variable-length integer encoding
/// https://www.rfc-editor.org/rfc/rfc9000.html#integer-encoding
#[inline]
fn variable_length_int(buf: &[u8], mut pos: usize) -> (usize, usize) {
  // let mut val = buf[pos] as usize;
  // if val & 0x80 == 0 {
  //   return (val, pos + 1);
  // }
  // val &= 0x7f;
  // let mut shift = 7;
  // loop {
  //   pos += 1;
  //   val += (buf[pos] as usize) << shift;
  //   if buf[pos] & 0x80 == 0 {
  //     break;
  //   }
  //   shift += 7;
  // }
  // (val, pos + 1)
  todo!()
}
