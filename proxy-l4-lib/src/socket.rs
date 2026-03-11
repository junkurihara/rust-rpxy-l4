use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};
use tokio::net::TcpSocket;

/// Bind TCP socket to the given `SocketAddr`, and returns the TCP socket with `SO_REUSEADDR` and `SO_REUSEPORT` options.
/// This option is required to re-bind the socket address when the proxy instance is reconstructed.
/// For IPv6 sockets, `IPV6_V6ONLY` is set to avoid dual-stack interference.
pub(super) fn bind_tcp_socket(listening_on: &SocketAddr) -> Result<TcpSocket, std::io::Error> {
  let domain = if listening_on.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
  let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

  if listening_on.is_ipv6() {
    socket.set_only_v6(true)?;
  }
  socket.set_reuse_address(true)?;

  #[cfg(not(target_os = "windows"))]
  socket.set_reuse_port(true)?;

  socket.set_nonblocking(true)?;
  socket.bind(&(*listening_on).into())?;

  Ok(TcpSocket::from_std_stream(socket.into()))
}

/// Bind UDP socket to the given `SocketAddr`, and returns the UDP socket with `SO_REUSEADDR` and `SO_REUSEPORT` options.
/// This option is required to re-bind the socket address when the proxy instance is reconstructed.
/// For IPv6 sockets, `IPV6_V6ONLY` is set to avoid dual-stack interference.
pub(super) fn bind_udp_socket(listening_on: &SocketAddr) -> Result<UdpSocket, std::io::Error> {
  let domain = if listening_on.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
  let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

  if listening_on.is_ipv6() {
    socket.set_only_v6(true)?;
  }
  socket.set_reuse_address(true)?;

  #[cfg(not(target_os = "windows"))]
  socket.set_reuse_port(true)?;

  socket.set_nonblocking(true)?;
  socket.bind(&(*listening_on).into())?;

  Ok(socket.into())
}
