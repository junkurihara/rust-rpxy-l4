//! Platform-independent public API for the downstream UDP socket.
//!
//! [`DownstreamUdpSocket`] wraps a platform-specific implementation that is
//! selected at compile time:
//! - Unix: uses `recvmsg`/`sendmsg` with `IP_PKTINFO` to capture and control the local IP.
//! - Non-Unix: falls back to standard `recv_from`/`send_to` (only supports non-wildcard bind).

use std::{
  io,
  net::{IpAddr, SocketAddr},
};

#[cfg(not(unix))]
use super::udp_downstream_fallback as imp;
#[cfg(unix)]
use super::udp_downstream_unix as imp;

/// Metadata returned by [`DownstreamUdpSocket::recv`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DownstreamRecvInfo {
  /// Number of bytes read into the buffer.
  pub bytes_read: usize,
  /// Source (client) address of the received datagram.
  pub src_addr: SocketAddr,
  /// Local destination IP that the client addressed.
  /// On Unix this is extracted from `IP_PKTINFO`; on non-Unix it equals the bound address.
  pub local_ip: IpAddr,
}

/// A UDP socket for the downstream (client-facing) side of the proxy.
///
/// This abstraction hides platform differences around preserving the local
/// destination IP so that responses are always sent from the IP the client
/// originally addressed -- critical for correct behaviour on multi-homed servers.
#[derive(Debug)]
pub(crate) struct DownstreamUdpSocket {
  inner: imp::DownstreamUdpSocketImpl,
}

impl DownstreamUdpSocket {
  /// Bind a new downstream UDP socket to `listening_on`.
  ///
  /// On non-Unix platforms, wildcard addresses (`0.0.0.0` / `[::]`) are
  /// rejected because the platform cannot preserve the per-datagram local IP.
  pub(crate) fn bind(listening_on: &SocketAddr) -> Result<Self, io::Error> {
    Ok(Self {
      inner: imp::DownstreamUdpSocketImpl::bind(listening_on)?,
    })
  }

  /// Receive a datagram, returning the payload length, client address, and
  /// the local IP the datagram was addressed to.
  pub(crate) async fn recv(&self, buf: &mut [u8]) -> Result<DownstreamRecvInfo, io::Error> {
    self.inner.recv(buf).await
  }

  /// Send a datagram to `dst_addr`, ensuring the packet leaves from `local_ip`.
  pub(crate) async fn send_to(&self, buf: &[u8], dst_addr: &SocketAddr, local_ip: IpAddr) -> Result<usize, io::Error> {
    self.inner.send_to(buf, dst_addr, local_ip).await
  }
}
