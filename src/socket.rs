// use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
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

  // if let Err(e) = tcp_socket.bind(*listening_on) {
  //   error!("Failed to bind TCP socket: {}", e);
  //   return Err(e);
  // };
  tcp_socket.bind(*listening_on)?;
  Ok(tcp_socket)
}
