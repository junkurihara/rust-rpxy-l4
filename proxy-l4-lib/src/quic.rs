use crate::trace::*;

/// Check if the buffer contains a QUIC handshake packet.
/// https://www.rfc-editor.org/rfc/rfc9000.html
/// https://www.rfc-editor.org/rfc/rfc9001.html
pub(crate) fn is_quic_handshake(buf: &[u8]) -> bool {
  debug!("{:x?}", buf);
  false
}
