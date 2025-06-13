use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};
use tokio::net::TcpSocket;

/// Bind TCP socket to the given `SocketAddr`, and returns the TCP socket with `SO_REUSEADDR` and `SO_REUSEPORT` options.
/// This option is required to re-bind the socket address when the proxy instance is reconstructed.
pub(super) fn bind_tcp_socket(listening_on: &SocketAddr) -> Result<TcpSocket, std::io::Error> {
  let tcp_socket = if listening_on.is_ipv6() {
    TcpSocket::new_v6()
  } else {
    TcpSocket::new_v4()
  }?;
  tcp_socket.set_reuseaddr(true)?;

  #[cfg(not(target_os = "windows"))]
  tcp_socket.set_reuseport(true)?;

  tcp_socket.bind(*listening_on)?;
  Ok(tcp_socket)
}

/// Bind UDP socket to the given `SocketAddr`, and returns the UDP socket with `SO_REUSEADDR` and `SO_REUSEPORT` options.
/// This option is required to re-bind the socket address when the proxy instance is reconstructed.
pub(super) fn bind_udp_socket(listening_on: &SocketAddr) -> Result<UdpSocket, std::io::Error> {
  let socket = if listening_on.is_ipv6() {
    Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
  } else {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
  }?;
  socket.set_reuse_address(true)?;

  #[cfg(not(target_os = "windows"))]
  socket.set_reuse_port(true)?;

  socket.set_nonblocking(true)?; // This is important to use `recv_from` in the UDP listener

  socket.bind(&(*listening_on).into())?;
  Ok(socket.into())
}
