//! Non-Unix fallback implementation of [`DownstreamUdpSocket`](super::DownstreamUdpSocket).
//!
//! Without `recvmsg`/`IP_PKTINFO` support, this implementation uses standard
//! `recv_from`/`send_to` and therefore cannot discover the per-datagram local
//! destination IP.  It works correctly when the socket is bound to a specific
//! (non-wildcard) address, returning the bound IP as `local_ip`.
//!
//! Wildcard binds (`0.0.0.0` / `[::]`) are rejected at `bind()` time because
//! the platform cannot preserve the response source IP.

use super::{DownstreamRecvInfo, bind_udp_socket};
use std::{
  io,
  net::{IpAddr, SocketAddr},
};
use tokio::net::UdpSocket;

/// Fallback downstream UDP socket using standard `recv_from`/`send_to`.
///
/// Only supports non-wildcard bind addresses since the local destination IP
/// cannot be determined per-datagram on this platform.
#[derive(Debug)]
pub(super) struct DownstreamUdpSocketImpl {
  listening_on: SocketAddr,
  socket: UdpSocket,
}

impl DownstreamUdpSocketImpl {
  /// Bind to a specific (non-wildcard) address.
  ///
  /// Returns `io::ErrorKind::Unsupported` if `listening_on` is a wildcard address.
  pub(super) fn bind(listening_on: &SocketAddr) -> Result<Self, io::Error> {
    if listening_on.ip().is_unspecified() {
      return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Wildcard UDP listen with preserved downstream source IP is not supported on this platform",
      ));
    }

    Ok(Self {
      listening_on: *listening_on,
      socket: UdpSocket::from_std(bind_udp_socket(listening_on)?)?,
    })
  }

  pub(super) async fn recv(&self, buf: &mut [u8]) -> Result<DownstreamRecvInfo, io::Error> {
    let (bytes_read, src_addr) = self.socket.recv_from(buf).await?;
    Ok(DownstreamRecvInfo {
      bytes_read,
      src_addr,
      local_ip: self.listening_on.ip(),
    })
  }

  pub(super) async fn send_to(&self, buf: &[u8], dst_addr: &SocketAddr, local_ip: IpAddr) -> Result<usize, io::Error> {
    if local_ip != self.listening_on.ip() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
          "Local IP {local_ip} does not match bound downstream socket {}",
          self.listening_on.ip()
        ),
      ));
    }
    self.socket.send_to(buf, dst_addr).await
  }
}
