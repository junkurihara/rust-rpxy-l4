use crate::{
  SUPPORTED_TLS_VERSIONS,
  client_hello::{TlsClientHello, TlsHandshakeMessageHeader, probe_tls_client_hello, probe_tls_handshake_message},
  error::{TlsClientHelloError, TlsProbeFailure},
  serialize::{Deserialize, SerDeserError, Serialize, compose},
  trace::*,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

const TLS_RECORD_HEADER_LEN: usize = 5;
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
pub fn probe_tls_handshake<B: Buf>(buf: &mut B) -> Result<TlsClientHelloBuffer, TlsProbeFailure> {
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
  let handshake_message_header = probe_tls_handshake_message(&mut tls_plaintext)?;

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
      _ => return Err(SerDeserError::InvalidInputLength),
    };
    let alert_description = match buf.get_u8() {
      21 => TlsAlertDescription::DecryptError,
      47 => TlsAlertDescription::IllegalParameter,
      _ => return Err(SerDeserError::InvalidInputLength),
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

  #[test]
  fn test_tls_record_header_serdeser() {
    let header = TlsRecordHeader {
      content_type: TLS_HANDSHAKE_CONTENT_TYPE,
      version: SUPPORTED_TLS_VERSIONS[0],
      length: 1234,
    };

    let serialized = compose(header.clone()).unwrap();
    let deserialized: TlsRecordHeader = parse(&mut serialized.clone()).unwrap();
    assert_eq!(header, deserialized);
  }

  #[test]
  fn test_tls_alert_buffer_serdeser() {
    let alert = TlsAlertBuffer::new(TlsAlertLevel::Fatal, TlsAlertDescription::IllegalParameter);

    let serialized = compose(alert.clone()).unwrap();
    let deserialized: TlsAlertBuffer = parse(&mut serialized.clone()).unwrap();
    assert_eq!(alert, deserialized);
  }
}
