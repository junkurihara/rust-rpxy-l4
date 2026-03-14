//! Socket creation utilities and downstream UDP abstraction.
//!
//! This module provides:
//! - TCP/UDP socket creation with common options (`SO_REUSEADDR`, `SO_REUSEPORT`, etc.)
//! - [`DownstreamUdpSocket`]: a platform-aware UDP socket that preserves the local
//!   destination IP on multi-homed servers, so responses are sent from the same IP
//!   the client originally addressed.
//!
//! Platform-specific details (`recvmsg`/`sendmsg`, `IP_PKTINFO`) are confined to
//! this module; upper layers only interact through the [`DownstreamUdpSocket`] API.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};
use tokio::net::TcpSocket;

mod udp_downstream;
#[cfg(not(unix))]
mod udp_downstream_fallback;
#[cfg(unix)]
mod udp_downstream_unix;

pub(crate) use udp_downstream::{DownstreamRecvInfo, DownstreamUdpSocket};

/// Bind TCP socket to the given `SocketAddr`, and returns the TCP socket with `SO_REUSEADDR` and `SO_REUSEPORT` options.
/// This option is required to re-bind the socket address when the proxy instance is reconstructed.
/// For IPv6 sockets, `IPV6_V6ONLY` is set to avoid dual-stack interference.
pub(super) fn bind_tcp_socket(listening_on: &SocketAddr) -> Result<TcpSocket, std::io::Error> {
  let socket = build_raw_socket(listening_on, Protocol::TCP)?;
  socket.bind(&(*listening_on).into())?;
  Ok(TcpSocket::from_std_stream(socket.into()))
}

/// Bind UDP socket to the given `SocketAddr`, and returns the UDP socket with `SO_REUSEADDR` and `SO_REUSEPORT` options.
/// This option is required to re-bind the socket address when the proxy instance is reconstructed.
/// For IPv6 sockets, `IPV6_V6ONLY` is set to avoid dual-stack interference.
pub(super) fn bind_udp_socket(listening_on: &SocketAddr) -> Result<UdpSocket, std::io::Error> {
  let socket = build_raw_socket(listening_on, Protocol::UDP)?;
  socket.bind(&(*listening_on).into())?;
  Ok(socket.into())
}

/// Create an unbound socket with `SO_REUSEADDR` and `SO_REUSEPORT` options, and `IPV6_V6ONLY` if it's an IPv6 socket.
pub(super) fn build_raw_socket(listening_on: &SocketAddr, protocol: Protocol) -> Result<Socket, std::io::Error> {
  let ipv6 = listening_on.is_ipv6();
  let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
  let ty = match protocol {
    Protocol::UDP => Type::DGRAM,
    Protocol::TCP => Type::STREAM,
    _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unsupported protocol")),
  };
  let socket = Socket::new(domain, ty, Some(protocol))?;

  if ipv6 {
    socket.set_only_v6(true)?;
  }
  socket.set_reuse_address(true)?;

  #[cfg(not(target_os = "windows"))]
  socket.set_reuse_port(true)?;

  socket.set_nonblocking(true)?;

  Ok(socket)
}
