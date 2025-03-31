use crate::{
  SUPPORTED_TLS_VERSIONS,
  error::{TlsClientHelloError, TlsProbeFailure},
  serialize::{Deserialize, read_lengthed},
  trace::*,
};
use bytes::{Buf, Bytes};

const TLS_HANDSHAKE_MESSAGE_HEADER_LEN: usize = 4;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
/// Probed TLS ClientHello information
pub struct TlsClientHelloInfo {
  /// SNI
  pub sni: Vec<String>,
  /// ALPN
  #[allow(unused)]
  pub alpn: Vec<String>,
  //TODO: /// ECH info
}

impl From<TlsClientHello> for TlsClientHelloInfo {
  fn from(client_hello: TlsClientHello) -> Self {
    let mut sni = Vec::new();
    let mut alpn = Vec::new();
    for ext in client_hello.extensions {
      match ext {
        TlsClientHelloExtension::Sni(sni_ext) => {
          for server_name in sni_ext.server_name_list {
            sni.push(server_name.name);
          }
        }
        TlsClientHelloExtension::Alpn(alpn_ext) => {
          for protocol_name in alpn_ext.protocol_name_list {
            alpn.push(protocol_name.inner);
          }
        }
        _ => {}
      }
    }
    TlsClientHelloInfo { sni, alpn }
  }
}

/* ---------------------------------------------------------- */
/// Check if the buffer has a valid handshake message containing a TLS ClientHello
/// https://datatracker.ietf.org/doc/html/rfc8446#section-4
/// https://tools.ietf.org/html/rfc5246#section-7.4
/// -- Handshake message header --
///  - 1 Handshake Type msg_type
///  - 3 Length
///  - <var> Handshake message body
pub(crate) fn probe_tls_handshake_message<B: Buf>(buf: &mut B) -> Result<(), TlsProbeFailure> {
  if buf.remaining() < TLS_HANDSHAKE_MESSAGE_HEADER_LEN {
    debug!("TLS ClientHello header is not fully received");
    return Err(TlsProbeFailure::PollNext);
  }
  let msg_type = buf.get_u8();
  if msg_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
    return Err(TlsProbeFailure::Failure);
  }
  let length = ((buf.get_u16() as usize) << 8) + buf.get_u8() as usize;
  debug!("TLS ClientHello body length: {}", length);

  if buf.remaining() < length {
    debug!("TLS ClientHello body is not fully received");
    return Err(TlsProbeFailure::PollNext);
  }
  Ok(())
}

/* ---------------------------------------------------------- */
/// Check if the buffer is a TLS ClientHello
pub(crate) fn probe_tls_client_hello<B: Buf>(buf: &mut B) -> Option<TlsClientHello> {
  let Ok(client_hello) = TlsClientHello::deserialize(buf) else {
    return None;
  };

  if !SUPPORTED_TLS_VERSIONS.contains(&client_hello.protocol_version) {
    // Omit the legacy SSL and unknown versions
    return None;
  }

  // Check the remaining buffer is all zero, consistent as a TLS ClientHello
  if !buf.chunk().iter().all(|v| v.eq(&0)) {
    return None;
  }

  debug!("TLS ClientHello detected: {:?}", client_hello);
  Some(client_hello)
}

/* ---------------------------------------------------------- */
#[allow(unused)]
#[derive(Debug)]
/// TLS ClientHello
/// https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
pub struct TlsClientHello {
  /// TLS version
  protocol_version: u16,
  /// Random bytes
  random: [u8; 32],
  /// Session ID
  legacy_session_id: Bytes,
  /// Cipher suites (list)
  cipher_suites: Bytes,
  /// Compression methods (list)
  legacy_compression_methods: Bytes,
  /// Extensions (list)
  extensions: Vec<TlsClientHelloExtension>,
}

#[derive(Debug)]
/// TLS ClientHello Extension
pub enum TlsClientHelloExtension {
  /// Server Name Indication
  Sni(ServerNameIndication),
  /// Application-Layer Protocol Negotiation
  Alpn(ApplicationLayerProtocolNegotiation),
  /// Other
  Other(OtherTlsClientHelloExtension),
}

impl std::fmt::Display for TlsClientHelloExtension {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      TlsClientHelloExtension::Sni(sni) => write!(f, "{}", sni),
      TlsClientHelloExtension::Alpn(alpn) => write!(f, "{}", alpn),
      TlsClientHelloExtension::Other(other) => write!(f, "{}", other),
    }
  }
}

#[derive(Debug)]
/// TLS ClientHello SNI Extension
pub struct ServerNameIndication {
  /// Server name list
  server_name_list: Vec<ServerName>,
}

impl std::fmt::Display for ServerNameIndication {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let names = self
      .server_name_list
      .iter()
      .map(|s| s.to_string())
      .collect::<Vec<String>>()
      .join(", ");
    write!(f, "ServerNameIndication (0x00): {names}")
  }
}

#[allow(unused)]
#[derive(Debug)]
/// TLS ClientHello SNI Extension Server Name
pub struct ServerName {
  /// Server name Type, 0x00 = Hostname is the only type
  name_type: u8,
  /// Server name
  name: String,
}

impl std::fmt::Display for ServerName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.name)
  }
}

#[derive(Debug)]
/// TLS ClientHello ALPN Extension
pub struct ApplicationLayerProtocolNegotiation {
  /// Protocol name list
  protocol_name_list: Vec<ProtocolName>,
}

impl std::fmt::Display for ApplicationLayerProtocolNegotiation {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let names = self
      .protocol_name_list
      .iter()
      .map(|s| s.to_string())
      .collect::<Vec<String>>()
      .join(", ");
    write!(f, "ApplicationLayerProtocolNegotiation (0x10): {names}")
  }
}

#[derive(Debug)]
/// TLS ClientHello ALPN Extension Protocol Name
pub struct ProtocolName {
  /// Protocol name
  inner: String,
}

impl std::fmt::Display for ProtocolName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.inner)
  }
}

#[derive(Debug)]
/// Other (Unsupported) TLS ClientHello Extension
pub struct OtherTlsClientHelloExtension {
  /// Extension Type
  extension_type: u16,
  /// Extension Payload
  extension_payload: Bytes,
}

impl std::fmt::Display for OtherTlsClientHelloExtension {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "OtherTlsClientHelloExtension (0x{:02x}): {:?}",
      self.extension_type, self.extension_payload
    )
  }
}
/* ---------------------------------------------------------- */

impl Deserialize for TlsClientHello {
  type Error = TlsClientHelloError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    // Handshake message body if msg_type == Client Hello
    // - 2: Version (again)
    // - 32: Random
    // - 1: Session ID Length
    // - <var>: Session ID
    // - 2: Cipher Suites Length
    // - <var>: Cipher Suites
    // - 1: Compression Methods Length
    // - <var>: Compression Methods
    // - 2: Extensions Length
    // - <var>: Extensions
    // Total: 40 + Session ID + Cipher Suites + Compression Methods + Extensions
    if buf.remaining() < 40 {
      return Err(TlsClientHelloError::ShortInput);
    }
    let protocol_version = buf.get_u16();
    let mut random = [0u8; 32];
    buf.copy_to_slice(&mut random);
    let legacy_session_id = read_lengthed(buf, 1)?;
    let cipher_suites = read_lengthed(buf, 2)?;
    let legacy_compression_methods = read_lengthed(buf, 1)?;
    let extensions_len = buf.get_u16() as usize;
    if extensions_len < 8 {
      return Err(TlsClientHelloError::ShortInput);
    }
    let mut extensions = Vec::new();
    while buf.remaining() > 0 {
      if let Ok(ext) = TlsClientHelloExtension::deserialize(buf) {
        extensions.push(ext);
      } else {
        error!("Failed to parse TLS ClientHello extension");
        return Err(TlsClientHelloError::InvalidTlsClientHello);
      }
    }

    Ok(TlsClientHello {
      protocol_version,
      random,
      legacy_session_id,
      cipher_suites,
      legacy_compression_methods,
      extensions,
    })
  }
}

/* ---------------------------------------------------------- */

impl Deserialize for TlsClientHelloExtension {
  type Error = TlsClientHelloError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    if buf.remaining() < 2 {
      return Err(TlsClientHelloError::ShortInput);
    }
    let extension_type = buf.get_u16();
    let mut extension_payload = read_lengthed(buf, 2)?;

    let extension = match extension_type {
      0x00 => {
        // Server Name Indication
        let sni = ServerNameIndication::deserialize(&mut extension_payload)?;
        TlsClientHelloExtension::Sni(sni)
      }
      0x10 => {
        // Application-Layer Protocol Negotiation
        let alpn = ApplicationLayerProtocolNegotiation::deserialize(&mut extension_payload)?;
        TlsClientHelloExtension::Alpn(alpn)
      }
      _ => {
        // Other
        TlsClientHelloExtension::Other(OtherTlsClientHelloExtension {
          extension_type,
          extension_payload,
        })
      }
    };
    Ok(extension)
  }
}

/* ---------------------------------------------------------- */
impl Deserialize for ServerNameIndication {
  type Error = TlsClientHelloError;
  /// Parse server name list from the SNI extension
  /// https://datatracker.ietf.org/doc/html/rfc6066#section-3
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    if buf.remaining() < 2 {
      return Err(TlsClientHelloError::ShortInput);
    }
    let mut server_name_list_bytes = read_lengthed(buf, 2)?;
    let mut server_name_list = Vec::new();
    while server_name_list_bytes.remaining() > 0 {
      let sni = ServerName::deserialize(&mut server_name_list_bytes)?;
      server_name_list.push(sni);
    }

    if server_name_list.is_empty() {
      error!("No SNI found");
      return Err(TlsClientHelloError::InvalidSniExtension);
    }

    if server_name_list_bytes.remaining() != 0 {
      error!("Invalid SNI extension");
      return Err(TlsClientHelloError::InvalidSniExtension);
    }

    Ok(ServerNameIndication { server_name_list })
  }
}

/* ---------------------------------------------------------- */
impl Deserialize for ServerName {
  type Error = TlsClientHelloError;
  /// Parse server name
  /// https://datatracker.ietf.org/doc/html/rfc6066#section-3
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    if buf.remaining() < 3 {
      return Err(TlsClientHelloError::InvalidSniExtension);
    }
    let name_type = buf.get_u8();

    if name_type != 0x00 {
      error!("Unknown SNI name type: {:x}", name_type);
      return Err(TlsClientHelloError::InvalidSniExtension);
    }

    let name = read_lengthed(buf, 2)?;
    let name = String::from_utf8_lossy(&name).to_ascii_lowercase();
    Ok(ServerName { name_type, name })
  }
}

/* ---------------------------------------------------------- */

impl Deserialize for ApplicationLayerProtocolNegotiation {
  /// Parse ALPN extension
  /// https://datatracker.ietf.org/doc/html/rfc7301
  type Error = TlsClientHelloError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    if buf.remaining() < 2 {
      return Err(TlsClientHelloError::ShortInput);
    }
    let mut protocol_name_list_bytes = read_lengthed(buf, 2)?;
    let mut protocol_name_list = Vec::new();
    while protocol_name_list_bytes.remaining() > 0 {
      let protocol_name = ProtocolName::deserialize(&mut protocol_name_list_bytes)?;
      protocol_name_list.push(protocol_name);
    }

    if protocol_name_list.is_empty() {
      error!("No ALPN found");
      return Err(TlsClientHelloError::InvalidAlpnExtension);
    }

    if protocol_name_list_bytes.remaining() != 0 {
      error!("Invalid ALPN extension");
      return Err(TlsClientHelloError::InvalidSniExtension);
    }

    Ok(ApplicationLayerProtocolNegotiation { protocol_name_list })
  }
}

/* ---------------------------------------------------------- */

impl Deserialize for ProtocolName {
  type Error = TlsClientHelloError;
  /// Parse protocol name
  /// https://datatracker.ietf.org/doc/html/rfc7301
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    if buf.remaining() < 1 {
      return Err(TlsClientHelloError::InvalidAlpnExtension);
    }
    let protocol_name = read_lengthed(buf, 1)?;
    let protocol_name = String::from_utf8_lossy(&protocol_name).to_ascii_lowercase();
    Ok(ProtocolName { inner: protocol_name })
  }
}

/* ---------------------------------------------------------- */
