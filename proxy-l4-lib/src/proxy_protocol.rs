//! Proxy Protocol v1 and v2 support for preserving client IP addresses
//!
//! This module implements PROXY protocol support as defined in:
//! - v1: http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
//! - v2: https://www.haproxy.org/download/1.8/doc/proxy-protocol-v2.txt

use crate::error::ProxyError;
use bytes::BytesMut;
use ppp::{v1, v2};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Proxy Protocol version configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocolVersion {
  /// PROXY protocol version 1 (text-based)
  V1,
  /// PROXY protocol version 2 (binary) - default
  #[default]
  V2,
}

impl std::fmt::Display for ProxyProtocolVersion {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::V1 => write!(f, "v1"),
      Self::V2 => write!(f, "v2"),
    }
  }
}

impl std::str::FromStr for ProxyProtocolVersion {
  type Err = ProxyError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s.to_lowercase().as_str() {
      "v1" | "1" => Ok(Self::V1),
      "v2" | "2" => Ok(Self::V2),
      _ => Err(ProxyError::InvalidProxyProtocolVersion(s.to_string())),
    }
  }
}

/// Parsed PROXY protocol header information
#[derive(Debug, Clone)]
pub struct ProxyProtocolHeader {
  /// Source address (real client address)
  pub source: SocketAddr,
  /// Destination address (proxy's listening address)
  pub destination: SocketAddr,
  /// Protocol version that was parsed
  pub version: ProxyProtocolVersion,
}

impl ProxyProtocolHeader {
  /// Create a new PROXY protocol header
  pub fn new(source: SocketAddr, destination: SocketAddr, version: ProxyProtocolVersion) -> Self {
    Self {
      source,
      destination,
      version,
    }
  }
}

/// Maximum size of PROXY protocol header
/// v1: max 108 bytes, v2: max 536 bytes (including TLVs)
const MAX_PROXY_PROTOCOL_HEADER_SIZE: usize = 536;

/// Parse PROXY protocol header from a TCP stream
///
/// This function reads the PROXY protocol header from the stream and returns
/// the parsed header along with any remaining data that was read but not consumed.
///
/// Returns:
/// - Ok((header, remaining_data)) on successful parse
/// - Err(ProxyError) on parse failure or invalid header
pub async fn parse_proxy_protocol_header<R: AsyncRead + Unpin>(
  stream: &mut R,
) -> Result<Option<(ProxyProtocolHeader, BytesMut)>, ProxyError> {
  let mut buf = BytesMut::with_capacity(MAX_PROXY_PROTOCOL_HEADER_SIZE);

  // Read data until we have enough to determine the header type
  // v2 signature is 12 bytes, v1 signature starts with "PROXY"
  let mut found = false;

  while buf.len() < MAX_PROXY_PROTOCOL_HEADER_SIZE {
    let mut temp_buf = [0u8; 64];
    let n = stream
      .read(&mut temp_buf)
      .await
      .map_err(|e| ProxyError::ProxyProtocolParseError(format!("Failed to read from stream: {}", e)))?;

    if n == 0 {
      // Connection closed
      break;
    }

    buf.extend_from_slice(&temp_buf[..n]);

    // Try to parse v2 first (binary format with signature)
    if buf.len() >= 16 {
      // v2 header minimum: 12-byte signature + 4-byte header
      if let Ok(header) = try_parse_v2_header(&buf) {
        found = true;
        return Ok(Some(header));
      }
    }

    // Try to parse v1 (text format ending with \r\n)
    if buf.len() >= 6 && &buf[..6] == b"PROXY" {
      // Look for CRLF terminator
      if let Some(crlf_pos) = buf.iter().position(|&b| b == b'\n') {
        if crlf_pos > 0 && buf[crlf_pos - 1] == b'\r' {
          if let Ok(header) = try_parse_v1_header(&buf) {
            found = true;
            return Ok(Some(header));
          }
        }
      }
    }

    // If we've read enough data without finding a valid header, it's not a proxy protocol
    if buf.len() >= MAX_PROXY_PROTOCOL_HEADER_SIZE {
      break;
    }
  }

  // No valid PROXY protocol header found
  // Return None to indicate the stream doesn't have a proxy protocol header
  // The caller should handle the buffered data appropriately
  if !found {
    return Ok(None);
  }

  unreachable!()
}

/// Try to parse a v2 PROXY protocol header from the buffer
fn try_parse_v2_header(buf: &BytesMut) -> Result<(ProxyProtocolHeader, BytesMut), ProxyError> {
  let data = buf.as_ref();

  // Parse v2 header using ppp crate
  let header = match v2::Header::try_from(data) {
    Ok(result) => result,
    Err(e) => {
      // Not a valid v2 header
      return Err(ProxyError::ProxyProtocolParseError(format!(
        "Failed to parse v2 header: {:?}",
        e
      )));
    }
  };

  // Calculate consumed bytes (header length)
  let consumed = header.header.len();

  // Extract source and destination addresses
  let (source, destination) = match header.addresses {
    v2::Addresses::IPv4(ipv4) => {
      let source = SocketAddr::new(
        std::net::IpAddr::V4(ipv4.source_ip),
        ipv4.source_port,
      );
      let destination = SocketAddr::new(
        std::net::IpAddr::V4(ipv4.destination_ip),
        ipv4.destination_port,
      );
      (source, destination)
    }
    v2::Addresses::IPv6(ipv6) => {
      let source = SocketAddr::new(
        std::net::IpAddr::V6(ipv6.source_ip),
        ipv6.source_port,
      );
      let destination = SocketAddr::new(
        std::net::IpAddr::V6(ipv6.destination_ip),
        ipv6.destination_port,
      );
      (source, destination)
    }
    v2::Addresses::Unix(_) => {
      // Unix sockets not supported for proxying
      return Err(ProxyError::ProxyProtocolParseError(
        "Unix socket addresses not supported".to_string(),
      ));
    }
    v2::Addresses::Unspecified => {
      // UNSPEC - use proxy's address
      return Err(ProxyError::ProxyProtocolParseError(
        "Unspecified address family in PROXY protocol header".to_string(),
      ));
    }
  };

  let remaining = buf.split_off(consumed);
  let header = ProxyProtocolHeader::new(source, destination, ProxyProtocolVersion::V2);

  Ok((header, remaining))
}

/// Try to parse a v1 PROXY protocol header from the buffer
fn try_parse_v1_header(buf: &BytesMut) -> Result<(ProxyProtocolHeader, BytesMut), ProxyError> {
  let data = std::str::from_utf8(buf.as_ref())
    .map_err(|e| ProxyError::ProxyProtocolParseError(format!("Invalid UTF-8 in v1 header: {}", e)))?;

  // Parse v1 header using ppp crate
  let header = match v1::Header::try_from(data) {
    Ok(result) => result,
    Err(e) => {
      return Err(ProxyError::ProxyProtocolParseError(format!(
        "Failed to parse v1 header: {:?}",
        e
      )));
    }
  };

  // Extract source and destination addresses
  let source = header
    .source
    .parse::<SocketAddr>()
    .map_err(|e| ProxyError::ProxyProtocolParseError(format!("Invalid source address: {}", e)))?;
  let destination = header
    .destination
    .parse::<SocketAddr>()
    .map_err(|e| ProxyError::ProxyProtocolParseError(format!("Invalid destination address: {}", e)))?;

  // Calculate consumed bytes from the header string representation
  let header_str = header.to_string();
  let consumed_bytes = header_str.len();
  let remaining = buf.split_off(consumed_bytes);
  let header = ProxyProtocolHeader::new(source, destination, ProxyProtocolVersion::V1);

  Ok((header, remaining))
}

/// Generate a PROXY protocol v1 header
///
/// Returns the header as a byte vector ready to be sent to the backend.
pub fn generate_v1_header(source: SocketAddr, destination: SocketAddr) -> Result<Vec<u8>, ProxyError> {
  let (source_ip, source_port) = extract_ip_port(source);
  let (dest_ip, dest_port) = extract_ip_port(destination);

  let protocol = match source {
    SocketAddr::V4(_) => "TCP4",
    SocketAddr::V6(_) => "TCP6",
  };

  let header = format!(
    "PROXY {} {} {} {} {}\r\n",
    protocol, source_ip, dest_ip, source_port, dest_port
  );

  Ok(header.into_bytes())
}

/// Generate a PROXY protocol v2 header
///
/// Returns the header as a byte vector ready to be sent to the backend.
pub fn generate_v2_header(source: SocketAddr, destination: SocketAddr) -> Result<Vec<u8>, ProxyError> {
  use ppp::v2::{Builder, Version, Command, Protocol};

  // Build version_command byte: Version::Two (0x02) | Command::Proxy (0x01)
  let version_command = (Version::Two as u8) << 4 | (Command::Proxy as u8);

  let header = match (source, destination) {
    (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
      let addresses = v2::IPv4::new(src.ip(), src.port(), dst.ip(), dst.port());
      // Build protocol byte: AddressFamily::IPv4 (0x01) | Protocol::Stream (0x01)
      let protocol = Protocol::Stream;
      Builder::with_addresses(version_command, protocol, v2::Addresses::IPv4(addresses))
        .build()
        .map_err(|e| ProxyError::ProxyProtocolGenerateError(format!("Failed to build v2 header: {:?}", e)))?
    }
    (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
      let addresses = v2::IPv6::new(src.ip(), src.port(), dst.ip(), dst.port());
      // Build protocol byte: AddressFamily::IPv6 (0x02) | Protocol::Stream (0x01)
      let protocol = Protocol::Stream;
      Builder::with_addresses(version_command, protocol, v2::Addresses::IPv6(addresses))
        .build()
        .map_err(|e| ProxyError::ProxyProtocolGenerateError(format!("Failed to build v2 header: {:?}", e)))?
    }
    _ => {
      return Err(ProxyError::ProxyProtocolGenerateError(
        "Source and destination address families must match".to_string(),
      ));
    }
  };

  Ok(header.to_vec())
}

/// Generate a PROXY protocol header for the specified version
pub fn generate_proxy_protocol_header(
  version: ProxyProtocolVersion,
  source: SocketAddr,
  destination: SocketAddr,
) -> Result<Vec<u8>, ProxyError> {
  match version {
    ProxyProtocolVersion::V1 => generate_v1_header(source, destination),
    ProxyProtocolVersion::V2 => generate_v2_header(source, destination),
  }
}

/// Extract IP address and port from a SocketAddr as strings
fn extract_ip_port(addr: SocketAddr) -> (String, u16) {
  match addr {
    SocketAddr::V4(v4) => (v4.ip().to_string(), v4.port()),
    SocketAddr::V6(v6) => (v6.ip().to_string(), v6.port()),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

  #[test]
  fn test_proxy_protocol_version_parse() {
    assert_eq!(ProxyProtocolVersion::from_str("v1").unwrap(), ProxyProtocolVersion::V1);
    assert_eq!(ProxyProtocolVersion::from_str("v2").unwrap(), ProxyProtocolVersion::V2);
    assert_eq!(ProxyProtocolVersion::from_str("1").unwrap(), ProxyProtocolVersion::V1);
    assert_eq!(ProxyProtocolVersion::from_str("2").unwrap(), ProxyProtocolVersion::V2);
    assert!(ProxyProtocolVersion::from_str("invalid").is_err());
  }

  #[test]
  fn test_generate_v1_header_ipv4() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);

    let header = generate_v1_header(source, dest).unwrap();
    let header_str = String::from_utf8(header).unwrap();

    assert!(header_str.starts_with("PROXY TCP4 "));
    assert!(header_str.contains("192.168.1.1"));
    assert!(header_str.contains("10.0.0.1"));
    assert!(header_str.contains("12345"));
    assert!(header_str.contains("443"));
    assert!(header_str.ends_with("\r\n"));
  }

  #[test]
  fn test_generate_v1_header_ipv6() {
    let source = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 12345);
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)), 443);

    let header = generate_v1_header(source, dest).unwrap();
    let header_str = String::from_utf8(header).unwrap();

    assert!(header_str.starts_with("PROXY TCP6 "));
    assert!(header_str.ends_with("\r\n"));
  }

  #[test]
  fn test_generate_v2_header_ipv4() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);

    let header = generate_v2_header(source, dest).unwrap();

    // v2 header starts with signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
    assert!(header.starts_with(b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"));
  }

  #[test]
  fn test_generate_v2_header_ipv6() {
    let source = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 12345);
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)), 443);

    let header = generate_v2_header(source, dest).unwrap();

    // v2 header starts with signature
    assert!(header.starts_with(b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"));
  }

  #[test]
  fn test_mixed_address_families_error() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 443);

    assert!(generate_v2_header(source, dest).is_err());
  }
}
