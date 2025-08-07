use crate::{
  SUPPORTED_TLS_VERSIONS,
  ech_extension::{ClientHelloOuter, EncryptedClientHello, OuterExtensions},
  error::{TlsClientHelloError, TlsProbeFailure},
  serialize::{Deserialize, SerDeserError, Serialize, compose, read_lengthed},
  trace::*,
};
use bytes::{Buf, BufMut, Bytes};

/* ---------------------------------------------------------- */
const TLS_HANDSHAKE_MESSAGE_HEADER_LEN: usize = 4;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// Supported TLS ClientHello extension types
struct ExtensionType;
impl ExtensionType {
  /// Server Name Indication
  const SNI: u16 = 0x0000;
  /// Application-Layer Protocol Negotiation
  const ALPN: u16 = 0x0010;
  /// Encrypted ClientHello
  const ECH: u16 = 0xfe0d;
  /// OuterExtensions
  const OUTER_EXTENSIONS: u16 = 0xfd00;
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq)]
/// TLS Handshake message header
pub struct TlsHandshakeMessageHeader {
  /// handshake type (msg_type)
  pub(crate) msg_type: u8,
  /// length
  pub(crate) length: [u8; 3],
}
impl Default for TlsHandshakeMessageHeader {
  fn default() -> Self {
    TlsHandshakeMessageHeader {
      msg_type: TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
      length: [0u8; 3],
    }
  }
}
impl Serialize for TlsHandshakeMessageHeader {
  type Error = TlsClientHelloError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    buf.put_u8(self.msg_type);
    buf.put_slice(&self.length);
    Ok(())
  }
}

impl Deserialize for TlsHandshakeMessageHeader {
  type Error = TlsClientHelloError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    if buf.remaining() < TLS_HANDSHAKE_MESSAGE_HEADER_LEN {
      return Err(SerDeserError::ShortInput.into());
    }
    let msg_type = buf.get_u8();
    let mut length = [0u8; 3];
    buf.copy_to_slice(&mut length);
    Ok(TlsHandshakeMessageHeader { msg_type, length })
  }
}

/// Check if the buffer has a valid handshake message containing a TLS ClientHello
/// https://datatracker.ietf.org/doc/html/rfc8446#section-4
/// https://tools.ietf.org/html/rfc5246#section-7.4
/// -- Handshake message header --
///  - 1 Handshake Type msg_type
///  - 3 Length
///  - <var> Handshake message body
pub(crate) fn probe_tls_handshake_message<B: Buf>(buf: &mut B) -> Result<TlsHandshakeMessageHeader, TlsProbeFailure> {
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
  let mut length_bytes = [0u8; 3];
  length_bytes[0] = (length >> 16) as u8;
  length_bytes[1] = (length >> 8) as u8;
  length_bytes[2] = length as u8;
  let tls_handshake_message_header = TlsHandshakeMessageHeader {
    msg_type,
    length: length_bytes,
  };
  Ok(tls_handshake_message_header)
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

  debug!("TLS ClientHello detected: {:#?}", client_hello);
  Some(client_hello)
}

/* ---------------------------------------------------------- */
#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

impl Default for TlsClientHello {
  fn default() -> Self {
    TlsClientHello {
      protocol_version: 0x0303,
      random: [0u8; 32],
      legacy_session_id: Bytes::new(),
      cipher_suites: Bytes::new(),
      legacy_compression_methods: Bytes::new(),
      extensions: Vec::new(),
    }
  }
}

impl TlsClientHello {
  /// to Bytes
  pub fn try_to_bytes(&self) -> Result<Bytes, TlsClientHelloError> {
    compose(self.clone()).map(|b| b.freeze())
  }
  // Get SNIs
  pub fn sni(&self) -> Vec<String> {
    self
      .extensions
      .iter()
      .find_map(|ext| {
        if let TlsClientHelloExtension::Sni(sni) = ext {
          let snis = sni
            .server_name_list
            .iter()
            .map(|sever_name| String::from_utf8_lossy(&sever_name.name).to_string())
            .collect::<Vec<String>>();
          Some(snis)
        } else {
          None
        }
      })
      .unwrap_or_default()
  }
  /// Add or replace SNI extension
  pub fn add_replace_sni(&mut self, server_name: &ServerNameIndication) {
    if let Some(pos) = self
      .extensions
      .iter()
      .position(|ext| matches!(ext, TlsClientHelloExtension::Sni(_)))
    {
      self.extensions.remove(pos);
    }
    self.extensions.push(TlsClientHelloExtension::Sni(server_name.clone()));
  }
  // Get ALPNs
  pub fn alpn(&self) -> Vec<String> {
    self
      .extensions
      .iter()
      .find_map(|ext| {
        if let TlsClientHelloExtension::Alpn(alpn) = ext {
          let alpn = alpn
            .protocol_name_list
            .iter()
            .map(|protocol_name| String::from_utf8_lossy(&protocol_name.inner).to_string())
            .collect::<Vec<String>>();
          Some(alpn)
        } else {
          None
        }
      })
      .unwrap_or_default()
  }
  /// Add or replace ALPN extension
  pub fn add_replace_alpn(&mut self, protocol_name: &ApplicationLayerProtocolNegotiation) {
    if let Some(pos) = self
      .extensions
      .iter()
      .position(|ext| matches!(ext, TlsClientHelloExtension::Alpn(_)))
    {
      self.extensions.remove(pos);
    }
    self.extensions.push(TlsClientHelloExtension::Alpn(protocol_name.clone()));
  }

  /// Get extensions
  pub(crate) fn extensions(&self) -> Vec<TlsClientHelloExtension> {
    self.extensions.clone()
  }
  /// Add or replace all extensions
  pub(crate) fn add_replace_extensions(&mut self, extensions: &[TlsClientHelloExtension]) {
    self.extensions = extensions.to_vec();
  }

  /// Is ech outer?
  pub(crate) fn is_ech_outer(&self) -> bool {
    self
      .extensions
      .iter()
      .any(|ext| matches!(ext, TlsClientHelloExtension::Ech(EncryptedClientHello::Outer(_))))
  }
  /// Is decrypted ech inner
  pub(crate) fn is_ech_inner(&self) -> bool {
    self
      .extensions
      .iter()
      .any(|ext| matches!(ext, TlsClientHelloExtension::Ech(EncryptedClientHello::Inner)))
  }
  /// If extensions contains ECH Outer, fill its payload with zeros,
  /// Used for AAD calculation
  pub(crate) fn fill_ech_payload_with_zeros(&mut self) {
    for ext in &mut self.extensions {
      if let TlsClientHelloExtension::Ech(EncryptedClientHello::Outer(ech_outer)) = ext {
        ech_outer.fill_payload_with_zeros();
      }
    }
  }
  /// Get ECH extension if the ClientHello contains ECH Outer
  pub(crate) fn get_ech_outer(&self) -> Option<ClientHelloOuter> {
    self.extensions.iter().find_map(|ext| {
      if let TlsClientHelloExtension::Ech(EncryptedClientHello::Outer(ech_outer)) = ext {
        Some(ech_outer.clone())
      } else {
        None
      }
    })
  }
  /// Update session ID when ECH inner is recomposed
  pub(crate) fn update_session_id(&mut self, session_id: Bytes) {
    self.legacy_session_id = session_id;
  }
  pub(crate) fn legacy_session_id(&self) -> Bytes {
    self.legacy_session_id.clone()
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// TLS ClientHello Extension
pub enum TlsClientHelloExtension {
  /// Server Name Indication
  Sni(ServerNameIndication),
  /// Application-Layer Protocol Negotiation
  Alpn(ApplicationLayerProtocolNegotiation),
  /// Encrypted ClientHello
  Ech(EncryptedClientHello),
  /// Ech Outer Extensions
  OuterExtensions(OuterExtensions),
  /// Other
  Other(OtherTlsClientHelloExtension),
}

impl TlsClientHelloExtension {
  /// Get extension type
  pub fn extension_type(&self) -> u16 {
    match self {
      TlsClientHelloExtension::Sni(_) => ExtensionType::SNI,
      TlsClientHelloExtension::Alpn(_) => ExtensionType::ALPN,
      TlsClientHelloExtension::Ech(_) => ExtensionType::ECH,
      TlsClientHelloExtension::OuterExtensions(_) => ExtensionType::OUTER_EXTENSIONS,
      TlsClientHelloExtension::Other(other) => other.extension_type,
    }
  }
}

impl std::fmt::Display for TlsClientHelloExtension {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      TlsClientHelloExtension::Sni(sni) => write!(f, "{}", sni),
      TlsClientHelloExtension::Alpn(alpn) => write!(f, "{}", alpn),
      TlsClientHelloExtension::Ech(ech) => write!(f, "{}", ech),
      TlsClientHelloExtension::OuterExtensions(outer_ext) => write!(f, "{}", outer_ext),
      TlsClientHelloExtension::Other(other) => write!(f, "{}", other),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
/// TLS ClientHello SNI Extension
pub struct ServerNameIndication {
  /// Server name list
  server_name_list: Vec<ServerName>,
}
impl ServerNameIndication {
  /// add a server name
  pub fn add_server_name(&mut self, server_name: &str) {
    let server_name = server_name.to_string();
    if !self.server_name_list.iter().any(|s| s.to_string() == server_name) {
      self.server_name_list.push(ServerName::new(server_name.into()));
    }
  }
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// TLS ClientHello SNI Extension Server Name
pub(crate) struct ServerName {
  /// Server name Type, 0x00 = Hostname is the only type
  name_type: u8,
  /// Server name
  name: Bytes,
}

impl ServerName {
  /// Instantiate a new ServerName
  pub fn new(name: Bytes) -> Self {
    ServerName { name_type: 0x00, name }
  }
}

impl std::fmt::Display for ServerName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", String::from_utf8_lossy(&self.name))
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
/// TLS ClientHello ALPN Extension
pub struct ApplicationLayerProtocolNegotiation {
  /// Protocol name list
  protocol_name_list: Vec<ProtocolName>,
}

impl ApplicationLayerProtocolNegotiation {
  /// add a protocol name
  pub fn add_protocol_name(&mut self, protocol_name: &str) {
    let protocol_name = protocol_name.to_string();
    if !self.protocol_name_list.iter().any(|s| s.to_string() == protocol_name) {
      self.protocol_name_list.push(ProtocolName {
        inner: protocol_name.into(),
      });
    }
  }
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// TLS ClientHello ALPN Extension Protocol Name
pub(crate) struct ProtocolName {
  /// Protocol name
  inner: Bytes,
}

impl std::fmt::Display for ProtocolName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", String::from_utf8_lossy(&self.inner))
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
      error!("Not enough data as TLS ClientHello");
      return Err(SerDeserError::ShortInput.into());
    }
    let protocol_version = buf.get_u16();
    let mut random = [0u8; 32];
    buf.copy_to_slice(&mut random);
    let legacy_session_id = read_lengthed(buf, 1)?;
    let cipher_suites = read_lengthed(buf, 2)?;
    let legacy_compression_methods = read_lengthed(buf, 1)?;
    if buf.remaining() < 2 {
      error!("Not enough data as TLS ClientHello extensions");
      return Err(SerDeserError::ShortInput.into());
    }
    let extensions_len = buf.get_u16() as usize;
    if extensions_len < 8 {
      error!("Invalid extensions length: {}", extensions_len);
      return Err(TlsClientHelloError::InvalidExtensionLength);
    }
    let mut extensions = Vec::new();

    let expected_padding_len = buf.remaining() - extensions_len;
    while buf.remaining() > expected_padding_len {
      match TlsClientHelloExtension::deserialize(buf) {
        Ok(ext) => {
          extensions.push(ext);
        }
        Err(e) => {
          error!("Failed to parse TLS ClientHello extension: {e}");
          return Err(TlsClientHelloError::InvalidTlsClientHello);
        }
      }
    }

    // OuterExtensions and ECHOuter must not be simultaneously present
    if extensions
      .iter()
      .any(|ext| matches!(ext, TlsClientHelloExtension::OuterExtensions(_)))
      && extensions
        .iter()
        .any(|ext| matches!(ext, TlsClientHelloExtension::Ech(EncryptedClientHello::Outer(_))))
    {
      error!("OuterExtensions and ECHOuter must not be simultaneously present on the same level");
      return Err(TlsClientHelloError::InvalidOuterExtensionsExtension);
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

impl Serialize for TlsClientHello {
  type Error = TlsClientHelloError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    // Serialize the ClientHello
    buf.put_u16(self.protocol_version);
    buf.put_slice(&self.random);
    buf.put_u8(self.legacy_session_id.len() as u8);
    buf.put_slice(&self.legacy_session_id);
    buf.put_u16(self.cipher_suites.len() as u16);
    buf.put_slice(&self.cipher_suites);
    buf.put_u8(self.legacy_compression_methods.len() as u8);
    buf.put_slice(&self.legacy_compression_methods);

    // Serialize the extensions
    let mut ext_buf = bytes::BytesMut::new();
    for ext in self.extensions {
      ext.serialize(&mut ext_buf)?;
    }
    let ext_len = ext_buf.len();
    if !(8..=0xFFFF).contains(&ext_len) {
      error!("Invalid extensions length: {}", ext_len);
      return Err(TlsClientHelloError::InvalidExtensionLength);
    }
    buf.put_u16(ext_len as u16);
    buf.put_slice(&ext_buf);

    Ok(())
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
      error!("Not enough data as TLS ClientHello extension");
      return Err(SerDeserError::ShortInput.into());
    }
    let extension_type = buf.get_u16();
    let mut extension_payload = read_lengthed(buf, 2)?;

    let extension = match extension_type {
      ExtensionType::SNI => {
        // Server Name Indication
        let sni = ServerNameIndication::deserialize(&mut extension_payload)?;
        TlsClientHelloExtension::Sni(sni)
      }
      ExtensionType::ALPN => {
        // Application-Layer Protocol Negotiation
        let alpn = ApplicationLayerProtocolNegotiation::deserialize(&mut extension_payload)?;
        TlsClientHelloExtension::Alpn(alpn)
      }
      ExtensionType::ECH => {
        // Encrypted ClientHello
        let ech = EncryptedClientHello::deserialize(&mut extension_payload)?;
        TlsClientHelloExtension::Ech(ech)
      }
      ExtensionType::OUTER_EXTENSIONS => {
        // OuterExtensions
        let outer_ext = OuterExtensions::deserialize(&mut extension_payload)?;
        TlsClientHelloExtension::OuterExtensions(outer_ext)
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

impl Serialize for TlsClientHelloExtension {
  type Error = TlsClientHelloError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    match self {
      TlsClientHelloExtension::Sni(sni) => {
        buf.put_u16(ExtensionType::SNI);
        let ser_sni = compose(sni)?;
        buf.put_u16(ser_sni.len() as u16);
        buf.put_slice(&ser_sni);
      }
      TlsClientHelloExtension::Alpn(alpn) => {
        buf.put_u16(ExtensionType::ALPN);
        let ser_alpn = compose(alpn)?;
        buf.put_u16(ser_alpn.len() as u16);
        buf.put_slice(&ser_alpn);
      }
      TlsClientHelloExtension::Ech(ech) => {
        buf.put_u16(ExtensionType::ECH);
        let ser_ech = compose(ech)?;
        buf.put_u16(ser_ech.len() as u16);
        buf.put_slice(&ser_ech);
      }
      TlsClientHelloExtension::OuterExtensions(outer_ext) => {
        buf.put_u16(ExtensionType::OUTER_EXTENSIONS);
        let ser_outer_ext = compose(outer_ext)?;
        buf.put_u16(ser_outer_ext.len() as u16);
        buf.put_slice(&ser_outer_ext);
      }
      TlsClientHelloExtension::Other(other) => {
        buf.put_u16(other.extension_type);
        buf.put_u16(other.extension_payload.len() as u16);
        buf.put_slice(&other.extension_payload);
      }
    }
    Ok(())
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
      error!("Not enough data as SNI extension");
      return Err(SerDeserError::ShortInput.into());
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

impl Serialize for ServerNameIndication {
  type Error = TlsClientHelloError;
  /// Serialize the server name list
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    let server_name_list = self.server_name_list;
    let len = server_name_list
      .iter()
      .fold(0, |acc, server_name| acc + server_name.name.len() + 3);
    buf.put_u16(len as u16);
    for server_name in server_name_list {
      server_name.serialize(buf)?;
    }
    Ok(())
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
    Ok(ServerName { name_type, name })
  }
}

impl Serialize for ServerName {
  type Error = TlsClientHelloError;
  /// Serialize the server name
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    buf.put_u8(self.name_type);
    buf.put_u16(self.name.len() as u16);
    buf.put_slice(&self.name);
    Ok(())
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
      error!("Not enough data as ALPN extension");
      return Err(SerDeserError::ShortInput.into());
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

impl Serialize for ApplicationLayerProtocolNegotiation {
  type Error = TlsClientHelloError;
  /// Serialize the ALPN extension
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    let protocol_name_list = self.protocol_name_list;
    let len = protocol_name_list
      .iter()
      .fold(0, |acc, protocol_name| acc + protocol_name.inner.len() + 1);
    buf.put_u16(len as u16);
    for protocol_name in protocol_name_list {
      protocol_name.serialize(buf)?;
    }
    Ok(())
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
    Ok(ProtocolName { inner: protocol_name })
  }
}

impl Serialize for ProtocolName {
  type Error = TlsClientHelloError;
  /// Serialize the protocol name
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error> {
    buf.put_u8(self.inner.len() as u8);
    buf.put_slice(&self.inner);
    Ok(())
  }
}

/* ---------------------------------------------------------- */

#[cfg(test)]
mod tests {
  use super::*;
  use crate::serialize::parse;

  #[test]
  fn test_serdeser() {
    let sn = ServerName {
      name_type: 0x00,
      name: Bytes::from_static(b"my-public-name.example.com"),
    };
    let ser_sn = compose(sn.clone()).unwrap();
    let deser_sn: ServerName = parse(&mut ser_sn.clone()).unwrap();
    assert_eq!(sn, deser_sn);

    let sni = ServerNameIndication {
      server_name_list: vec![sn],
    };
    let ser_sni = compose(sni.clone()).unwrap();
    let deser_sni: ServerNameIndication = parse(&mut ser_sni.clone()).unwrap();
    assert_eq!(sni, deser_sni);

    let alpn = ProtocolName {
      inner: Bytes::from(b"h2".as_slice()),
    };
    let ser_alpn = compose(alpn.clone()).unwrap();
    let deser_alpn: ProtocolName = parse(&mut ser_alpn.clone()).unwrap();
    assert_eq!(alpn, deser_alpn);

    let alpn_ext = ApplicationLayerProtocolNegotiation {
      protocol_name_list: vec![alpn],
    };
    let ser_alpn_ext = compose(alpn_ext.clone()).unwrap();
    let deser_alpn_ext: ApplicationLayerProtocolNegotiation = parse(&mut ser_alpn_ext.clone()).unwrap();
    assert_eq!(alpn_ext, deser_alpn_ext);

    let extensions = [
      TlsClientHelloExtension::Sni(sni),
      TlsClientHelloExtension::Alpn(alpn_ext),
      TlsClientHelloExtension::Other(OtherTlsClientHelloExtension {
        extension_type: 0x1234,
        extension_payload: Bytes::from_static(b"hello world"),
      }),
    ];

    let tls_client_hello = TlsClientHello {
      protocol_version: 0x0303,
      random: [0u8; 32],
      legacy_session_id: Bytes::from_static(b"session_id"),
      cipher_suites: Bytes::from_static(b"cipher_suites"),
      legacy_compression_methods: Bytes::from_static(b"compression_methods"),
      extensions: extensions.to_vec(),
    };
    let ser_tls_client_hello = compose(tls_client_hello.clone()).unwrap();
    let deser_tls_client_hello: TlsClientHello = parse(&mut ser_tls_client_hello.clone()).unwrap();
    assert_eq!(tls_client_hello, deser_tls_client_hello);
  }

  #[test]
  fn test_tls_handshake_message_header_serdeser() {
    let header = TlsHandshakeMessageHeader {
      msg_type: TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
      length: [0x00, 0x01, 0x23], // Example length
    };
    
    let serialized = compose(header.clone()).unwrap();
    let deserialized: TlsHandshakeMessageHeader = parse(&mut serialized.clone()).unwrap();
    assert_eq!(header, deserialized);
  }
}
