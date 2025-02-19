use crate::trace::*;

const QUIC_VERSION: &[u8] = &[0x00, 0x00, 0x00, 0x01];

/// Check if the buffer contains a QUIC initial packet with TLS ClientHello.
/// https://www.rfc-editor.org/rfc/rfc9000.html
/// https://www.rfc-editor.org/rfc/rfc9001.html
/// https://quic.xargs.org
/// - First checks if the buffer is consistent with a QUIC initial packet.
/// - Then derive the header protection key and decrypt the packet.
/// - Finally, check if the decrypted packet is consistent with a QUIC TLS ClientHello.
pub(crate) fn is_quic_initial_packet(buf: &[u8]) -> bool {
  // header(1), version(4), DCID length(1), SCID length(1)
  if buf.len() < 7 {
    return false;
  }
  // Packet header byte
  // 0b1100_[0000] - Long header for initial packet type
  // with protected packet number field length ([0000])
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
  let Ok(token_len) = variable_length_int(buf, &mut ptr) else {
    return false;
  };
  ptr += token_len;
  if ptr >= buf.len() {
    return false;
  }
  debug!("Token: {:x?}", &buf[ptr - token_len..ptr]);
  // Payload length
  let Ok(payload_len) = variable_length_int(buf, &mut ptr) else {
    return false;
  };
  ptr += payload_len;
  if ptr >= buf.len() {
    return false;
  }
  debug!("Payload: {:x?}", &buf[ptr - payload_len..ptr]);
  // The remaining part should be padded frames
  if buf[ptr..].iter().any(|&b| b != 0) {
    return false;
  }

  // So far, the buffer is consistent with a QUIC initial packet.

  debug!("{:x?}", buf);
  false
}

/// Variable-length integer encoding
/// https://www.rfc-editor.org/rfc/rfc9000.html#integer-encoding
#[inline]
fn variable_length_int(buf: &[u8], pos: &mut usize) -> Result<usize, anyhow::Error> {
  let two_msb = buf[*pos] >> 6;
  let len = 1 << two_msb;
  if *pos + len > buf.len() {
    debug!("buffer too short as variable-length integer");
    return Err(anyhow::anyhow!("Buffer too short"));
  }
  let mut val = (buf[*pos] as usize) & 0x3f;
  *pos += 1;
  for _ in 1..len {
    val = (val << 8) + (buf[*pos] as usize);
    *pos += 1;
  }

  Ok(val)
}

/* ---------------------------------------------------- */

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_variable_length_int() {
    let buf = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
    let mut pos = 0;
    let val = variable_length_int(&buf, &mut pos).unwrap();
    assert_eq!(val, 151_288_809_941_952_652);
    assert_eq!(pos, 8);

    let buf = [0x9d, 0x7f, 0x3e, 0x7d];
    let mut pos = 0;
    let val = variable_length_int(&buf, &mut pos).unwrap();
    assert_eq!(val, 494_878_333);

    let buf = [0x7b, 0xbd];
    let mut pos = 0;
    let val = variable_length_int(&buf, &mut pos).unwrap();
    assert_eq!(val, 15_293);

    let buf = [0x25];
    let mut pos = 0;
    let val = variable_length_int(&buf, &mut pos).unwrap();
    assert_eq!(val, 37);
  }
}
