use crate::config::ProxyProtocolVersion;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::{io::AsyncReadExt, net::TcpStream};
use tracing::debug;

/// Encode a PROXY protocol header for the given source and destination addresses.
///
/// Returns the encoded header bytes ready to be written to the outbound stream.
pub(crate) fn encode_proxy_header(
  version: ProxyProtocolVersion,
  src: SocketAddr,
  dst: SocketAddr,
) -> Result<Vec<u8>, std::io::Error> {
  // Normalize addresses to ensure consistent address family
  let (src, dst) = normalize_address_pair(src, dst);

  match version {
    ProxyProtocolVersion::V1 => encode_v1(src, dst),
    ProxyProtocolVersion::V2 => encode_v2(src, dst),
  }
}

/// Encode a PROXY protocol v1 (text) header.
fn encode_v1(src: SocketAddr, dst: SocketAddr) -> Result<Vec<u8>, std::io::Error> {
  let proto = match src.ip() {
    IpAddr::V4(_) => "TCP4",
    IpAddr::V6(_) => "TCP6",
  };
  let header = format!("PROXY {} {} {} {} {}\r\n", proto, src.ip(), dst.ip(), src.port(), dst.port());
  Ok(header.into_bytes())
}

/// Encode a PROXY protocol v2 (binary) header.
fn encode_v2(src: SocketAddr, dst: SocketAddr) -> Result<Vec<u8>, std::io::Error> {
  let addresses: ppp::v2::Addresses = match (src.ip(), dst.ip()) {
    (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => ppp::v2::IPv4::new(src_ip, dst_ip, src.port(), dst.port()).into(),
    (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => ppp::v2::IPv6::new(src_ip, dst_ip, src.port(), dst.port()).into(),
    _ => {
      // Address families should be normalized before calling this function
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "PROXY protocol requires source and destination to have the same address family",
      ));
    }
  };

  let version_command = ppp::v2::Version::Two | ppp::v2::Command::Proxy;
  ppp::v2::Builder::with_addresses(version_command, ppp::v2::Protocol::Stream, addresses)
    .build()
    .map_err(|e| {
      std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("Failed to build PROXY v2 header: {e}"),
      )
    })
}

/// Resolve the destination address for the PROXY header.
///
/// If the listen address is a wildcard (0.0.0.0 or [::]),
/// use the actual local address from the accepted connection instead.
pub(crate) fn resolve_dst_addr(listen_on: SocketAddr, local_addr: SocketAddr) -> SocketAddr {
  if listen_on.ip().is_unspecified() {
    SocketAddr::new(local_addr.ip(), listen_on.port())
  } else {
    listen_on
  }
}

/// Normalize an IPv4-mapped IPv6 address to plain IPv4.
///
/// When a dual-stack listener binds to [::] and accepts an IPv4 connection,
/// the local_addr may return an IPv4-mapped IPv6 address (e.g., ::ffff:192.168.1.10).
/// The PROXY protocol requires src/dst to use the same address family.
pub(crate) fn normalize_mapped_ipv4(addr: IpAddr) -> IpAddr {
  match addr {
    IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
      Some(v4) => IpAddr::V4(v4),
      None => IpAddr::V6(v6),
    },
    other => other,
  }
}

/// Normalize a pair of addresses to ensure they share the same address family.
///
/// Both addresses are first normalized from IPv4-mapped IPv6 to plain IPv4.
/// If they still differ in family after normalization, the IPv4 address is
/// mapped to IPv6 (::ffff:x.x.x.x) to ensure consistency.
fn normalize_address_pair(src: SocketAddr, dst: SocketAddr) -> (SocketAddr, SocketAddr) {
  let src_ip = normalize_mapped_ipv4(src.ip());
  let dst_ip = normalize_mapped_ipv4(dst.ip());

  match (src_ip, dst_ip) {
    (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
      (SocketAddr::new(src_ip, src.port()), SocketAddr::new(dst_ip, dst.port()))
    }
    // Mixed families after normalization: promote IPv4 to IPv6
    (IpAddr::V4(v4), IpAddr::V6(_)) => {
      let mapped = IpAddr::V6(v4.to_ipv6_mapped());
      (SocketAddr::new(mapped, src.port()), SocketAddr::new(dst_ip, dst.port()))
    }
    (IpAddr::V6(_), IpAddr::V4(v4)) => {
      let mapped = IpAddr::V6(v4.to_ipv6_mapped());
      (SocketAddr::new(src_ip, src.port()), SocketAddr::new(mapped, dst.port()))
    }
  }
}

/* ---------------------------------------------------------- */
// Inbound PROXY protocol parsing
/* ---------------------------------------------------------- */

/// Configuration for inbound PROXY protocol parsing
#[derive(Debug, Clone)]
pub(crate) struct InboundProxyProtocolConfig {
  /// Trusted source IPs/CIDRs allowed to send PROXY headers.
  /// Must not be empty (enforced at config validation).
  pub trusted_proxies: Vec<IpNet>,
}

/// v2 signature: 12-byte magic sequence
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
/// v2 fixed header size (signature + version/command + family/protocol + addr_len)
const V2_HEADER_FIXED_SIZE: usize = 16;
/// v1 prefix "PROXY "
const V1_PREFIX: &[u8; 6] = b"PROXY ";
/// v1 maximum header length per spec (including \r\n)
const V1_MAX_LENGTH: usize = 107;

/// Parse an inbound PROXY protocol header from the stream.
///
/// **I/O contract**: This function consumes exactly the PROXY header bytes
/// from the stream and nothing more. After this function returns, the stream
/// is positioned at the first byte of application data.
///
/// Returns:
/// - `Ok(Some(src_addr))` if a PROXY command header was parsed (replace src_addr)
/// - `Ok(None)` if a LOCAL/UNKNOWN command was parsed (keep original src_addr)
/// - `Err(...)` on untrusted source, malformed header, or I/O error
pub(crate) async fn parse_inbound_proxy_header(
  stream: &mut TcpStream,
  peer_addr: &SocketAddr,
  config: &InboundProxyProtocolConfig,
) -> Result<Option<SocketAddr>, std::io::Error> {
  // 1. Validate peer_addr against trusted_proxies
  let normalized_peer_ip = normalize_mapped_ipv4(peer_addr.ip());
  if !config.trusted_proxies.iter().any(|net| net.contains(&normalized_peer_ip)) {
    return Err(std::io::Error::new(
      std::io::ErrorKind::PermissionDenied,
      format!("PROXY header from untrusted source: {peer_addr}"),
    ));
  }

  // 2. Peek first 16 bytes to determine version
  let mut peek_buf = [0u8; V2_HEADER_FIXED_SIZE];
  let peeked = stream.peek(&mut peek_buf).await?;
  if peeked < 6 {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "Too few bytes to detect PROXY header version",
    ));
  }

  // 3. Determine version and parse
  if peeked >= 12 && peek_buf[..12] == *V2_SIGNATURE {
    parse_v2_inbound(stream, &peek_buf, peeked).await
  } else if peek_buf[..6] == *V1_PREFIX {
    parse_v1_inbound(stream).await
  } else {
    Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "No valid PROXY protocol signature detected",
    ))
  }
}

/// Parse a v2 (binary) PROXY protocol header.
async fn parse_v2_inbound(
  stream: &mut TcpStream,
  peek_buf: &[u8; V2_HEADER_FIXED_SIZE],
  peeked: usize,
) -> Result<Option<SocketAddr>, std::io::Error> {
  if peeked < V2_HEADER_FIXED_SIZE {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "Incomplete v2 PROXY header (need at least 16 bytes)",
    ));
  }

  // Extract addr_len from bytes 14-15
  let addr_len = u16::from_be_bytes([peek_buf[14], peek_buf[15]]) as usize;
  let total_len = V2_HEADER_FIXED_SIZE + addr_len;

  // Read exactly the full header
  let mut header_buf = vec![0u8; total_len];
  stream.read_exact(&mut header_buf).await?;

  // Parse with ppp crate
  let header = ppp::v2::Header::try_from(header_buf.as_slice()).map_err(|e| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      format!("Failed to parse PROXY v2 header: {e:?}"),
    )
  })?;

  // Check command type
  if header.command == ppp::v2::Command::Local {
    debug!("PROXY v2 LOCAL command received");
    return Ok(None);
  }

  // PROXY command - extract source address
  match header.addresses {
    ppp::v2::Addresses::IPv4(ipv4) => {
      let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ipv4.source_address)), ipv4.source_port);
      Ok(Some(src))
    }
    ppp::v2::Addresses::IPv6(ipv6) => {
      let src = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ipv6.source_address)), ipv6.source_port);
      Ok(Some(src))
    }
    ppp::v2::Addresses::Unix(_) => Err(std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "Unix socket addresses not supported in PROXY protocol",
    )),
    ppp::v2::Addresses::Unspecified => {
      debug!("PROXY v2 unspecified addresses");
      Ok(None)
    }
  }
}

/// Parse a v1 (text) PROXY protocol header.
/// Reads byte-by-byte until \r\n to avoid over-consuming application data.
async fn parse_v1_inbound(stream: &mut TcpStream) -> Result<Option<SocketAddr>, std::io::Error> {
  let mut header_bytes = Vec::with_capacity(V1_MAX_LENGTH);
  let mut byte = [0u8; 1];
  let mut found_cr = false;

  loop {
    stream.read_exact(&mut byte).await?;
    header_bytes.push(byte[0]);

    if found_cr && byte[0] == b'\n' {
      break;
    }
    found_cr = byte[0] == b'\r';

    if header_bytes.len() >= V1_MAX_LENGTH {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "PROXY v1 header exceeds maximum length",
      ));
    }
  }

  let header = ppp::v1::Header::try_from(header_bytes.as_slice()).map_err(|e| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      format!("Failed to parse PROXY v1 header: {e:?}"),
    )
  })?;

  match header.addresses {
    ppp::v1::Addresses::Tcp4(tcp4) => {
      let src = SocketAddr::new(IpAddr::V4(tcp4.source_address), tcp4.source_port);
      Ok(Some(src))
    }
    ppp::v1::Addresses::Tcp6(tcp6) => {
      let src = SocketAddr::new(IpAddr::V6(tcp6.source_address), tcp6.source_port);
      Ok(Some(src))
    }
    ppp::v1::Addresses::Unknown => {
      debug!("PROXY v1 UNKNOWN command received");
      Ok(None)
    }
  }
}

/* ---------------------------------------------------------- */

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::Ipv4Addr;

  #[test]
  fn test_encode_v1_ipv4() {
    let src: SocketAddr = "192.168.1.100:45000".parse().unwrap();
    let dst: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let header = encode_proxy_header(ProxyProtocolVersion::V1, src, dst).unwrap();
    let header_str = String::from_utf8(header).unwrap();
    assert_eq!(header_str, "PROXY TCP4 192.168.1.100 10.0.0.1 45000 443\r\n");
  }

  #[test]
  fn test_encode_v1_ipv6() {
    let src: SocketAddr = "[2001:db8::1]:45000".parse().unwrap();
    let dst: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
    let header = encode_proxy_header(ProxyProtocolVersion::V1, src, dst).unwrap();
    let header_str = String::from_utf8(header).unwrap();
    assert_eq!(header_str, "PROXY TCP6 2001:db8::1 2001:db8::2 45000 443\r\n");
  }

  #[test]
  fn test_encode_v2_ipv4() {
    let src: SocketAddr = "192.168.1.100:45000".parse().unwrap();
    let dst: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let header = encode_proxy_header(ProxyProtocolVersion::V2, src, dst).unwrap();

    // v2 header starts with the 12-byte signature
    let signature = b"\r\n\r\n\x00\r\nQUIT\n";
    assert_eq!(&header[..12], signature);
    // 13th byte: version (0x2) | command (0x1) = 0x21
    assert_eq!(header[12], 0x21);
    // 14th byte: address family (AF_INET=0x1) | protocol (STREAM=0x1) = 0x11
    assert_eq!(header[13], 0x11);
    // Total length for IPv4: 12 (src_ip + dst_ip + src_port + dst_port)
    let addr_len = u16::from_be_bytes([header[14], header[15]]);
    assert_eq!(addr_len, 12);
  }

  #[test]
  fn test_encode_v2_ipv6() {
    let src: SocketAddr = "[2001:db8::1]:45000".parse().unwrap();
    let dst: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
    let header = encode_proxy_header(ProxyProtocolVersion::V2, src, dst).unwrap();

    let signature = b"\r\n\r\n\x00\r\nQUIT\n";
    assert_eq!(&header[..12], signature);
    assert_eq!(header[12], 0x21);
    // AF_INET6=0x2, STREAM=0x1 => 0x21
    assert_eq!(header[13], 0x21);
    // Total length for IPv6: 36 (src_ip + dst_ip + src_port + dst_port)
    let addr_len = u16::from_be_bytes([header[14], header[15]]);
    assert_eq!(addr_len, 36);
  }

  #[test]
  fn test_resolve_dst_addr_specific_bind() {
    let listen_on: SocketAddr = "192.168.1.10:443".parse().unwrap();
    let local_addr: SocketAddr = "192.168.1.10:443".parse().unwrap();
    assert_eq!(resolve_dst_addr(listen_on, local_addr), listen_on);
  }

  #[test]
  fn test_resolve_dst_addr_wildcard_ipv4() {
    let listen_on: SocketAddr = "0.0.0.0:443".parse().unwrap();
    let local_addr: SocketAddr = "192.168.1.10:443".parse().unwrap();
    let result = resolve_dst_addr(listen_on, local_addr);
    assert_eq!(result, "192.168.1.10:443".parse::<SocketAddr>().unwrap());
  }

  #[test]
  fn test_resolve_dst_addr_wildcard_ipv6() {
    let listen_on: SocketAddr = "[::]:443".parse().unwrap();
    let local_addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let result = resolve_dst_addr(listen_on, local_addr);
    assert_eq!(result, "[2001:db8::1]:443".parse::<SocketAddr>().unwrap());
  }

  #[test]
  fn test_normalize_mapped_ipv4() {
    // IPv4-mapped IPv6 → plain IPv4
    let mapped = IpAddr::V6(Ipv4Addr::new(192, 168, 1, 10).to_ipv6_mapped());
    assert_eq!(normalize_mapped_ipv4(mapped), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));

    // Plain IPv4 → unchanged
    let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(normalize_mapped_ipv4(v4), v4);

    // Regular IPv6 → unchanged
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(normalize_mapped_ipv4(v6), v6);
  }

  #[test]
  fn test_normalize_address_pair_both_ipv4() {
    let src: SocketAddr = "192.168.1.100:45000".parse().unwrap();
    let dst: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let (s, d) = normalize_address_pair(src, dst);
    assert_eq!(s, src);
    assert_eq!(d, dst);
  }

  #[test]
  fn test_normalize_address_pair_mapped_ipv6() {
    // IPv4-mapped IPv6 src + plain IPv4 dst → both plain IPv4
    let mapped_src = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(192, 168, 1, 100).to_ipv6_mapped()), 45000);
    let dst: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let (s, d) = normalize_address_pair(mapped_src, dst);
    assert!(s.ip().is_ipv4());
    assert!(d.ip().is_ipv4());
  }

  #[test]
  fn test_normalize_address_pair_mixed_families() {
    // IPv4 src + IPv6 dst → both IPv6 (IPv4 promoted)
    let src: SocketAddr = "192.168.1.100:45000".parse().unwrap();
    let dst: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let (s, d) = normalize_address_pair(src, dst);
    assert!(s.ip().is_ipv6());
    assert!(d.ip().is_ipv6());
  }

  /* ---------------------------------------------------------- */
  // Inbound PROXY protocol parsing tests
  /* ---------------------------------------------------------- */

  use tokio::io::AsyncWriteExt;
  use tokio::net::TcpListener;

  /// Helper: create a connected TcpStream pair with given data written from the "client" side.
  /// Returns the server-side stream (for parsing) and the client-side stream.
  async fn setup_stream_with_data(data: &[u8]) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    client.write_all(data).await.unwrap();
    (server, client)
  }

  fn trusted_config(cidrs: &[&str]) -> InboundProxyProtocolConfig {
    InboundProxyProtocolConfig {
      trusted_proxies: cidrs.iter().map(|c| c.parse::<IpNet>().unwrap()).collect(),
    }
  }

  // --- Trusted proxy validation tests ---

  #[tokio::test]
  async fn test_inbound_reject_untrusted_source() {
    let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n";
    let (mut server, _client) = setup_stream_with_data(data).await;
    let peer: SocketAddr = "99.99.99.99:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
  }

  #[tokio::test]
  async fn test_inbound_accept_trusted_source_cidr() {
    let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n";
    let (mut server, _client) = setup_stream_with_data(data).await;
    let peer: SocketAddr = "10.1.2.3:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    assert!(result.is_ok());
    let src = result.unwrap().unwrap();
    assert_eq!(src, "1.2.3.4:1234".parse::<SocketAddr>().unwrap());
  }

  #[tokio::test]
  async fn test_inbound_trusted_proxy_ipv4_mapped_ipv6() {
    // Peer address is ::ffff:10.0.0.1 (IPv4-mapped), trusted CIDR is 10.0.0.0/8
    let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n";
    let (mut server, _client) = setup_stream_with_data(data).await;
    let mapped_ip = Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped();
    let peer = SocketAddr::new(IpAddr::V6(mapped_ip), 9999);
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap(), "1.2.3.4:1234".parse::<SocketAddr>().unwrap());
  }

  // --- v1 parsing tests ---

  #[tokio::test]
  async fn test_inbound_v1_tcp4() {
    let data = b"PROXY TCP4 192.168.1.100 10.0.0.1 45000 443\r\nGET / HTTP/1.1\r\n";
    let (mut server, _client) = setup_stream_with_data(data).await;
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    let src = result.unwrap().unwrap();
    assert_eq!(src, "192.168.1.100:45000".parse::<SocketAddr>().unwrap());
  }

  #[tokio::test]
  async fn test_inbound_v1_tcp6() {
    let data = b"PROXY TCP6 2001:db8::1 2001:db8::2 45000 443\r\n";
    let (mut server, _client) = setup_stream_with_data(data).await;
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    let src = result.unwrap().unwrap();
    assert_eq!(src, "[2001:db8::1]:45000".parse::<SocketAddr>().unwrap());
  }

  #[tokio::test]
  async fn test_inbound_v1_unknown_returns_none() {
    let data = b"PROXY UNKNOWN\r\n";
    let (mut server, _client) = setup_stream_with_data(data).await;
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    assert_eq!(result.unwrap(), None);
  }

  #[tokio::test]
  async fn test_inbound_v1_exact_byte_consumption() {
    let app_data = b"GET / HTTP/1.1\r\n";
    let mut full_data = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n".to_vec();
    full_data.extend_from_slice(app_data);

    let (mut server, _client) = setup_stream_with_data(&full_data).await;
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    // Parse header
    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    assert!(result.is_ok());

    // Read remaining application data - must match exactly
    let mut remaining = vec![0u8; app_data.len()];
    server.read_exact(&mut remaining).await.unwrap();
    assert_eq!(&remaining, app_data);
  }

  // --- v2 parsing tests ---

  /// Build a v2 PROXY header with given addresses
  fn build_v2_proxy_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    encode_proxy_header(ProxyProtocolVersion::V2, src, dst).unwrap()
  }

  /// Build a v2 LOCAL header (no addresses)
  fn build_v2_local_header() -> Vec<u8> {
    let version_command = ppp::v2::Version::Two | ppp::v2::Command::Local;
    ppp::v2::Builder::with_addresses(
      version_command,
      ppp::v2::Protocol::Stream,
      ppp::v2::Addresses::Unspecified,
    )
    .build()
    .unwrap()
  }

  #[tokio::test]
  async fn test_inbound_v2_proxy_ipv4() {
    let header = build_v2_proxy_header(
      "192.168.1.100:45000".parse().unwrap(),
      "10.0.0.1:443".parse().unwrap(),
    );
    let (mut server, _client) = setup_stream_with_data(&header).await;
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    let src = result.unwrap().unwrap();
    assert_eq!(src, "192.168.1.100:45000".parse::<SocketAddr>().unwrap());
  }

  #[tokio::test]
  async fn test_inbound_v2_proxy_ipv6() {
    let header = build_v2_proxy_header(
      "[2001:db8::1]:45000".parse().unwrap(),
      "[2001:db8::2]:443".parse().unwrap(),
    );
    let (mut server, _client) = setup_stream_with_data(&header).await;
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    let src = result.unwrap().unwrap();
    assert_eq!(src, "[2001:db8::1]:45000".parse::<SocketAddr>().unwrap());
  }

  #[tokio::test]
  async fn test_inbound_v2_local_returns_none() {
    let header = build_v2_local_header();
    let (mut server, _client) = setup_stream_with_data(&header).await;
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    assert_eq!(result.unwrap(), None);
  }

  #[tokio::test]
  async fn test_inbound_v2_exact_byte_consumption() {
    let app_data = b"\x16\x03\x01\x00\x05hello";
    let mut header = build_v2_proxy_header(
      "192.168.1.100:45000".parse().unwrap(),
      "10.0.0.1:443".parse().unwrap(),
    );
    header.extend_from_slice(app_data);

    let (mut server, _client) = setup_stream_with_data(&header).await;
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    // Parse header
    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    assert!(result.is_ok());

    // Read remaining application data - must match exactly
    let mut remaining = vec![0u8; app_data.len()];
    server.read_exact(&mut remaining).await.unwrap();
    assert_eq!(&remaining, app_data);
  }

  // --- Error cases ---

  #[tokio::test]
  async fn test_inbound_malformed_header() {
    let data = b"NOT_A_PROXY_HEADER\r\n";
    let (mut server, _client) = setup_stream_with_data(data).await;
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
  }

  #[tokio::test]
  async fn test_inbound_too_few_bytes() {
    let data = b"PRO";
    let (mut server, mut client) = setup_stream_with_data(data).await;
    // Close client so peek returns only 3 bytes
    client.shutdown().await.unwrap();
    let peer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
    let config = trusted_config(&["10.0.0.0/8"]);

    let result = parse_inbound_proxy_header(&mut server, &peer, &config).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
  }
}
