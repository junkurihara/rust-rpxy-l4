use bytes::{Buf, BufMut, Bytes, BytesMut};

// Define distinct deserialize/serialize error for objects
#[derive(Debug, thiserror::Error)]
pub(crate) enum SerDeserError {
  #[error("Short input")]
  ShortInput,
  #[error("Invalid input length")]
  InvalidInputLength,
}

/* ------------------------------------------- */
// Imported from odoh-rs crate

/// Serialize to IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub(crate) trait Serialize {
  type Error;
  /// Serialize the provided struct into the buf.
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error>;
}

/// Deserialize from IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub(crate) trait Deserialize {
  type Error;
  /// Deserialize a struct from the buf.
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized;
}

/// Convenient function to deserialize a structure from Bytes.
pub(super) fn parse<D: Deserialize, B: Buf>(buf: &mut B) -> Result<D, D::Error> {
  D::deserialize(buf)
}

#[allow(unused)]
/// Convenient function to serialize a structure into a new BytesMut.
pub(super) fn compose<S: Serialize>(s: S) -> Result<BytesMut, S::Error> {
  let mut buf = BytesMut::new();
  s.serialize(&mut buf)?;
  Ok(buf)
}

/// Reads a length-prefixed value from the buffer, where the length is defined as `len_prefix` bytes
pub(super) fn read_lengthed<B: Buf>(b: &mut B, len_prefix: usize) -> Result<Bytes, SerDeserError> {
  if b.remaining() < len_prefix {
    return Err(SerDeserError::ShortInput);
  }
  // byte length of usize::MAX
  let max_len_prefix = std::mem::size_of::<usize>();
  if len_prefix > max_len_prefix {
    return Err(SerDeserError::InvalidInputLength);
  }

  let mut len = 0;
  for _ in 0..len_prefix {
    len <<= 8;
    len += b.get_u8() as usize;
  }

  if len > b.remaining() {
    return Err(SerDeserError::InvalidInputLength);
  }

  Ok(b.copy_to_bytes(len))
}
