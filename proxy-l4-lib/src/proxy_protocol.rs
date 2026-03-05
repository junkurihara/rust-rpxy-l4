use crate::config::ProxyProtocolVersion;
use std::net::{IpAddr, SocketAddr};

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
    ProxyProtocolVersion::None => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "PROXY protocol is disabled")),
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
fn normalize_mapped_ipv4(addr: IpAddr) -> IpAddr {
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
}
