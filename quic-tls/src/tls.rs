use crate::{
  SUPPORTED_TLS_VERSIONS,
  client_hello::{
    TLS_HANDSHAKE_MESSAGE_HEADER_LEN, TlsClientHello, TlsHandshakeMessageHeader, probe_tls_client_hello,
    probe_tls_handshake_message,
  },
  error::{TlsClientHelloError, TlsProbeFailure, TlsProbeRejection},
  serialize::{Deserialize, SerDeserError, Serialize, compose},
  trace::*,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_PLAINTEXT_MAX_LEN: usize = 1 << 14;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_ALERT_CONTENT_TYPE: u8 = 0x15;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq)]
/// TLS Record Layer
pub struct TlsRecordHeader {
  /// Content type
  pub(crate) content_type: u8,
  /// Version
  pub(crate) version: u16,
  /// Length
  pub(crate) length: u16,
}
impl Default for TlsRecordHeader {
  fn default() -> Self {
    TlsRecordHeader {
      content_type: TLS_HANDSHAKE_CONTENT_TYPE,
      version: SUPPORTED_TLS_VERSIONS[0],
      length: 0,
    }
  }
}
impl Serialize for TlsRecordHeader {
  type Error = SerDeserError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    buf.put_u8(self.content_type);
    buf.put_u16(self.version);
    buf.put_u16(self.length);
    Ok(())
  }
}

impl Deserialize for TlsRecordHeader {
  type Error = SerDeserError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    if buf.remaining() < TLS_RECORD_HEADER_LEN {
      return Err(SerDeserError::ShortInput);
    }
    let content_type = buf.get_u8();
    let version = buf.get_u16();
    let length = buf.get_u16();
    Ok(TlsRecordHeader {
      content_type,
      version,
      length,
    })
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsClientHelloBuffer {
  /// Tls record header
  pub record_header: TlsRecordHeader,
  /// Tls handshake message
  pub handshake_message_header: TlsHandshakeMessageHeader,
  /// Tls client hello
  pub client_hello: TlsClientHello,
}
impl TlsClientHelloBuffer {
  /// Is Ech Outer
  pub fn is_ech_outer(&self) -> bool {
    self.client_hello.is_ech_outer()
  }
  /// to Bytes
  pub fn try_to_bytes(&self) -> Result<Bytes, TlsClientHelloError> {
    compose(self.clone()).map(|b| b.freeze())
  }
}

impl Serialize for TlsClientHelloBuffer {
  type Error = TlsClientHelloError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    let client_hello_bytes = compose(self.client_hello)?;

    // Make length fields consistent
    let client_hello_len = client_hello_bytes.len();
    let mut handshake_msg_len_field = [0u8; 3];
    handshake_msg_len_field[0] = (client_hello_len >> 16) as u8;
    handshake_msg_len_field[1] = (client_hello_len >> 8) as u8;
    handshake_msg_len_field[2] = client_hello_len as u8;
    let mut handshake_message_header = self.handshake_message_header.clone();
    handshake_message_header.length = handshake_msg_len_field;
    let handshake_message_header_bytes = compose(handshake_message_header)?;

    let record_layer_len_field = client_hello_len + handshake_message_header_bytes.len();
    let mut record_header = self.record_header.clone();
    record_header.length = record_layer_len_field as u16;
    let record_header_bytes = compose(record_header)?;

    buf.put_slice(&record_header_bytes);
    buf.put_slice(&handshake_message_header_bytes);
    buf.put_slice(&client_hello_bytes);
    Ok(())
  }
}

impl Deserialize for TlsClientHelloBuffer {
  type Error = TlsClientHelloError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    let record_header = TlsRecordHeader::deserialize(buf)?;
    let handshake_message_header = TlsHandshakeMessageHeader::deserialize(buf)?;
    let client_hello = TlsClientHello::deserialize(buf)?;

    Ok(TlsClientHelloBuffer {
      record_header,
      handshake_message_header,
      client_hello,
    })
  }
}

/// Check if the buffer is a TLSPlaintext record
/// This is inspired by https://github.com/yrutschle/sslh/blob/master/tls.c
/// Support TLS Record layer fragmentation https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
///
/// This entry point enforces TLS record limits but does not apply a caller-specific
/// cumulative wire-byte budget. TCP protocol detection must use
/// [`probe_tls_handshake_with_max_probe_bytes`].
pub fn probe_tls_handshake<B: Buf>(buf: &mut B) -> Result<TlsClientHelloBuffer, TlsProbeFailure> {
  probe_tls_handshake_inner(buf, None)
}

/// Probe a TLS ClientHello while rejecting declarations that cannot fit within
/// `max_probe_bytes` of TLS records on the wire.
pub fn probe_tls_handshake_with_max_probe_bytes<B: Buf>(
  buf: &mut B,
  max_probe_bytes: usize,
) -> Result<TlsClientHelloBuffer, TlsProbeFailure> {
  probe_tls_handshake_inner(buf, Some(max_probe_bytes))
}

fn probe_tls_handshake_inner<B: Buf>(
  buf: &mut B,
  max_probe_bytes: Option<usize>,
) -> Result<TlsClientHelloBuffer, TlsProbeFailure> {
  let mut tls_plaintext = BytesMut::new();
  let mut record_headers = Vec::new();

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
    if payload_len > TLS_PLAINTEXT_MAX_LEN {
      debug!("TLSPlaintext payload exceeds the protocol length limit");
      return Err(TlsProbeFailure::Rejected(TlsProbeRejection::RecordOverflow));
    }
    if buf.remaining() < payload_len {
      debug!("Read buffer for TLS handshake detection is not enough");
      return Err(TlsProbeFailure::PollNext);
    }
    debug!("TLS Payload length: {}", payload_len);

    let b = buf.copy_to_bytes(payload_len);
    tls_plaintext.extend_from_slice(&b);

    record_headers.push(TlsRecordHeader {
      content_type,
      version: tls_version,
      length: payload_len as u16,
    });
  }

  // Check if all the TLS record headers are the same
  if record_headers.len() > 1 {
    let first_header = &record_headers[0];
    for header in &record_headers[1..] {
      if header != first_header {
        debug!("TLS record headers are not the same");
        return Err(TlsProbeFailure::Failure);
      }
    }
  }

  // Check if the buffer is a TLS handshake
  let max_client_hello_body_len = max_probe_bytes.map(max_client_hello_body_len_for_wire_budget);
  let handshake_message_header = probe_tls_handshake_message(&mut tls_plaintext, max_client_hello_body_len)?;

  // Check if the buffer is a TLS ClientHello
  match probe_tls_client_hello(&mut tls_plaintext) {
    Some(client_hello) => Ok(TlsClientHelloBuffer {
      record_header: record_headers[0].clone(),
      handshake_message_header,
      client_hello,
    }),
    None => Err(TlsProbeFailure::Failure),
  }
}

fn max_client_hello_body_len_for_wire_budget(max_probe_bytes: usize) -> usize {
  const MAX_RECORD_WIRE_LEN: usize = TLS_RECORD_HEADER_LEN + TLS_PLAINTEXT_MAX_LEN;

  let full_records = max_probe_bytes / MAX_RECORD_WIRE_LEN;
  let remaining_wire_bytes = max_probe_bytes % MAX_RECORD_WIRE_LEN;
  let final_record_payload = remaining_wire_bytes
    .saturating_sub(TLS_RECORD_HEADER_LEN)
    .min(TLS_PLAINTEXT_MAX_LEN);
  let max_plaintext = full_records * TLS_PLAINTEXT_MAX_LEN + final_record_payload;

  max_plaintext.saturating_sub(TLS_HANDSHAKE_MESSAGE_HEADER_LEN)
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq)]
/// https://datatracker.ietf.org/doc/html/rfc8446#section-6
pub struct TlsAlertBuffer {
  /// Tls record header
  pub record_header: TlsRecordHeader,
  /// alert level
  pub alert_level: TlsAlertLevel,
  /// alert description
  pub alert_description: TlsAlertDescription,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// TLS Alert Level
/// https://datatracker.ietf.org/doc/html/rfc8446#section-6
#[allow(unused)]
pub enum TlsAlertLevel {
  /// Warning
  Warning = 1,
  /// Fatal
  Fatal = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// TLS Alert Description
/// https://datatracker.ietf.org/doc/html/rfc8446#section-6
/// Define only some of the alert descriptions used for ECH
#[allow(unused)]
pub enum TlsAlertDescription {
  /// Illegal parameter
  IllegalParameter = 47,
  /// Decrypt error
  DecryptError = 21,
}

impl Default for TlsAlertBuffer {
  fn default() -> Self {
    Self::new(TlsAlertLevel::Fatal, TlsAlertDescription::IllegalParameter)
  }
}

impl TlsAlertBuffer {
  /// Create a new instance
  pub fn new(level: TlsAlertLevel, description: TlsAlertDescription) -> Self {
    Self {
      record_header: TlsRecordHeader {
        content_type: TLS_ALERT_CONTENT_TYPE,
        version: SUPPORTED_TLS_VERSIONS[0],
        length: 2,
      },
      alert_level: level,
      alert_description: description,
    }
  }

  /// to Bytes
  pub fn to_bytes(&self) -> Bytes {
    compose(self.clone())
      .expect("TlsAlertBuffer serialization should not fail")
      .freeze()
  }
}

impl Serialize for TlsAlertBuffer {
  type Error = SerDeserError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    let record_header_bytes = compose(self.record_header)?;
    buf.put_slice(&record_header_bytes);
    buf.put_u8(self.alert_level as u8);
    buf.put_u8(self.alert_description as u8);
    Ok(())
  }
}

impl Deserialize for TlsAlertBuffer {
  type Error = SerDeserError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    let record_header = TlsRecordHeader::deserialize(buf)?;
    if buf.remaining() < 2 {
      return Err(SerDeserError::ShortInput);
    }
    let alert_level = match buf.get_u8() {
      1 => TlsAlertLevel::Warning,
      2 => TlsAlertLevel::Fatal,
      _ => return Err(SerDeserError::InvalidInput),
    };
    let alert_description = match buf.get_u8() {
      21 => TlsAlertDescription::DecryptError,
      47 => TlsAlertDescription::IllegalParameter,
      _ => return Err(SerDeserError::InvalidInput),
    };
    Ok(TlsAlertBuffer {
      record_header,
      alert_level,
      alert_description,
    })
  }
}

/* ---------------------------------------------------------- */
#[cfg(test)]
mod tests {
  use super::*;
  use crate::serialize::parse;

  fn tls_record_header(payload_len: usize) -> Vec<u8> {
    vec![
      TLS_HANDSHAKE_CONTENT_TYPE,
      (SUPPORTED_TLS_VERSIONS[0] >> 8) as u8,
      SUPPORTED_TLS_VERSIONS[0] as u8,
      (payload_len >> 8) as u8,
      payload_len as u8,
    ]
  }

  fn client_hello_header(body_len: usize) -> [u8; TLS_HANDSHAKE_MESSAGE_HEADER_LEN] {
    [0x01, (body_len >> 16) as u8, (body_len >> 8) as u8, body_len as u8]
  }

  fn valid_client_hello_record() -> Vec<u8> {
    let mut sni_extension = Vec::new();
    sni_extension.extend_from_slice(&0x0000u16.to_be_bytes());
    sni_extension.extend_from_slice(&16u16.to_be_bytes());
    sni_extension.extend_from_slice(&14u16.to_be_bytes());
    sni_extension.push(0);
    sni_extension.extend_from_slice(&11u16.to_be_bytes());
    sni_extension.extend_from_slice(b"example.com");

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0xc02fu16.to_be_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
    body.extend_from_slice(&sni_extension);

    let mut handshake = client_hello_header(body.len()).to_vec();
    handshake.extend_from_slice(&body);
    let mut record = tls_record_header(handshake.len());
    record.extend_from_slice(&handshake);
    record
  }

  #[test]
  fn test_tls_record_header_serdeser() {
    let header = TlsRecordHeader {
      content_type: TLS_HANDSHAKE_CONTENT_TYPE,
      version: SUPPORTED_TLS_VERSIONS[0],
      length: 1234,
    };

    let mut serialized = compose(header.clone()).unwrap();
    let deserialized: TlsRecordHeader = parse(&mut serialized).unwrap();
    assert_eq!(header, deserialized);
  }

  #[test]
  fn test_tls_alert_buffer_serdeser() {
    let alert = TlsAlertBuffer::new(TlsAlertLevel::Fatal, TlsAlertDescription::IllegalParameter);

    let mut serialized = compose(alert.clone()).unwrap();
    let deserialized: TlsAlertBuffer = parse(&mut serialized).unwrap();
    assert_eq!(alert, deserialized);
  }

  #[test]
  fn maximum_tls_plaintext_length_is_not_rejected_for_length() {
    let input = tls_record_header(TLS_PLAINTEXT_MAX_LEN);
    let mut input = input.as_slice();

    assert_eq!(probe_tls_handshake(&mut input), Err(TlsProbeFailure::PollNext));
  }

  #[test]
  fn oversized_tls_plaintext_length_is_rejected_before_payload() {
    let input = tls_record_header(TLS_PLAINTEXT_MAX_LEN + 1);
    let mut input = input.as_slice();

    assert_eq!(
      probe_tls_handshake(&mut input),
      Err(TlsProbeFailure::Rejected(TlsProbeRejection::RecordOverflow))
    );
  }

  #[test]
  fn client_hello_declared_length_respects_probe_wire_budget() {
    const PROBE_BUDGET: usize = 128 * 1024;
    let max_body_len = max_client_hello_body_len_for_wire_budget(PROBE_BUDGET);
    assert_eq!(max_body_len, 131_028);

    let mut at_limit = tls_record_header(TLS_HANDSHAKE_MESSAGE_HEADER_LEN);
    at_limit.extend_from_slice(&client_hello_header(max_body_len));
    let mut at_limit = at_limit.as_slice();
    assert_eq!(
      probe_tls_handshake_with_max_probe_bytes(&mut at_limit, PROBE_BUDGET),
      Err(TlsProbeFailure::PollNext)
    );

    let mut over_limit = tls_record_header(TLS_HANDSHAKE_MESSAGE_HEADER_LEN);
    over_limit.extend_from_slice(&client_hello_header(max_body_len + 1));
    let mut over_limit = over_limit.as_slice();
    assert_eq!(
      probe_tls_handshake_with_max_probe_bytes(&mut over_limit, PROBE_BUDGET),
      Err(TlsProbeFailure::Rejected(TlsProbeRejection::ClientHelloTooLarge))
    );
  }

  #[test]
  fn structurally_valid_client_hello_is_probeable() {
    let encoded = valid_client_hello_record();
    let mut encoded = encoded.as_ref();

    assert!(probe_tls_handshake(&mut encoded).is_ok());
  }
}
