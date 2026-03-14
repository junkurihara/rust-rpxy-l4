//! Unix implementation of [`DownstreamUdpSocket`](super::DownstreamUdpSocket).
//!
//! Uses `recvmsg(2)` with `IP_PKTINFO` / `IPV6_RECVPKTINFO` to capture the
//! local destination IP of each incoming datagram, and `sendmsg(2)` with the
//! same control message to set the source IP on outgoing responses.
//!
//! This ensures correct behaviour on multi-homed servers where the listening
//! socket is bound to a wildcard address.

use super::{DownstreamRecvInfo, build_raw_socket};
use socket2::Protocol;
use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
  os::unix::io::{AsFd, AsRawFd},
};
use tokio::{io::Interest, net::UdpSocket};

/// Unix-specific downstream UDP socket backed by `recvmsg`/`sendmsg` + `IP_PKTINFO`.
#[derive(Debug)]
pub(super) struct DownstreamUdpSocketImpl {
  socket: UdpSocket,
}

impl DownstreamUdpSocketImpl {
  /// Bind a UDP socket with `IP_PKTINFO` enabled.
  pub(super) fn bind(listening_on: &SocketAddr) -> Result<Self, io::Error> {
    let socket = build_raw_socket(listening_on, Protocol::UDP)?;
    enable_pktinfo(&socket, listening_on.is_ipv6())?;
    socket.bind(&(*listening_on).into())?;
    Ok(Self {
      socket: UdpSocket::from_std(socket.into())?,
    })
  }

  /// Receive a datagram via `recvmsg`, extracting the local destination IP from `IP_PKTINFO`.
  pub(super) async fn recv(&self, buf: &mut [u8]) -> Result<DownstreamRecvInfo, io::Error> {
    loop {
      self.socket.readable().await?;

      match self.socket.try_io(Interest::READABLE, || recv_sync(&self.socket, buf)) {
        Ok(result) => return Ok(result),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
        Err(e) => return Err(e),
      }
    }
  }

  /// Send a datagram via `sendmsg`, setting the source IP through `IP_PKTINFO`.
  pub(super) async fn send_to(&self, buf: &[u8], dst_addr: &SocketAddr, local_ip: IpAddr) -> Result<usize, io::Error> {
    loop {
      self.socket.writable().await?;

      match self
        .socket
        .try_io(Interest::WRITABLE, || send_sync(&self.socket, buf, dst_addr, local_ip))
      {
        Ok(n) => return Ok(n),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
        Err(e) => return Err(e),
      }
    }
  }
}

/// Enable `IP_PKTINFO` (IPv4) or `IPV6_RECVPKTINFO` (IPv6) on the socket.
fn enable_pktinfo(socket: &socket2::Socket, ipv6: bool) -> Result<(), io::Error> {
  let fd = socket.as_raw_fd();
  let enabled: libc::c_int = 1;
  let res = if ipv6 {
    // SAFETY: fd is a valid socket file descriptor obtained from socket2::Socket.
    // `enabled` is a valid c_int with correct size passed via size_of.
    unsafe {
      libc::setsockopt(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_RECVPKTINFO,
        &enabled as *const _ as *const libc::c_void,
        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
      )
    }
  } else {
    // SAFETY: same as above, for IPv4 IP_PKTINFO.
    unsafe {
      libc::setsockopt(
        fd,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        &enabled as *const _ as *const libc::c_void,
        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
      )
    }
  };

  if res < 0 {
    return Err(io::Error::last_os_error());
  }
  Ok(())
}

/// Synchronous `recvmsg(2)` wrapper that extracts source address and local IP from control messages.
fn recv_sync(socket: &UdpSocket, buf: &mut [u8]) -> Result<DownstreamRecvInfo, io::Error> {
  let fd = socket.as_fd().as_raw_fd();

  let mut iov = libc::iovec {
    iov_base: buf.as_mut_ptr() as *mut libc::c_void,
    iov_len: buf.len(),
  };
  // SAFETY: zeroed sockaddr_storage is a valid initial state for recvmsg to populate.
  let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
  let mut control_buf = [0u8; 256];

  let mut msghdr = libc::msghdr {
    msg_name: &mut src_storage as *mut _ as *mut libc::c_void,
    msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
    msg_iov: &mut iov,
    msg_iovlen: 1,
    msg_control: control_buf.as_mut_ptr() as *mut libc::c_void,
    msg_controllen: control_buf.len() as _,
    msg_flags: 0,
  };

  // SAFETY: fd is a valid socket descriptor; msghdr and its referenced buffers
  // (iov, src_storage, control_buf) are all valid and live for the duration of the call.
  let n = unsafe { libc::recvmsg(fd, &mut msghdr, 0) };
  if n < 0 {
    return Err(io::Error::last_os_error());
  }

  Ok(DownstreamRecvInfo {
    bytes_read: n as usize,
    src_addr: sockaddr_storage_to_socket_addr(&src_storage)?,
    local_ip: extract_local_ip_from_cmsg(&msghdr)?,
  })
}

/// Synchronous `sendmsg(2)` wrapper that sets the source IP via `IP_PKTINFO` control message.
fn send_sync(socket: &UdpSocket, buf: &[u8], dst_addr: &SocketAddr, local_ip: IpAddr) -> Result<usize, io::Error> {
  let fd = socket.as_fd().as_raw_fd();
  let iov = libc::iovec {
    iov_base: buf.as_ptr() as *mut libc::c_void,
    iov_len: buf.len(),
  };
  let (dst_storage, dst_len) = socket_addr_to_sockaddr_storage(dst_addr);
  let mut control_buf = [0u8; 256];
  let control_len = build_pktinfo_cmsg(&mut control_buf, local_ip)?;

  let msghdr = libc::msghdr {
    msg_name: &dst_storage as *const _ as *mut libc::c_void,
    msg_namelen: dst_len,
    msg_iov: &iov as *const _ as *mut libc::iovec,
    msg_iovlen: 1,
    msg_control: control_buf.as_ptr() as *mut libc::c_void,
    msg_controllen: control_len as _,
    msg_flags: 0,
  };

  // SAFETY: fd is a valid socket descriptor; msghdr and its referenced buffers
  // (iov, dst_storage, control_buf) are all valid and live for the duration of the call.
  let n = unsafe { libc::sendmsg(fd, &msghdr, 0) };
  if n < 0 {
    return Err(io::Error::last_os_error());
  }
  Ok(n as usize)
}

/// Convert a C `sockaddr_storage` populated by `recvmsg` into a Rust `SocketAddr`.
fn sockaddr_storage_to_socket_addr(storage: &libc::sockaddr_storage) -> Result<SocketAddr, io::Error> {
  match storage.ss_family as libc::c_int {
    libc::AF_INET => {
      let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
      let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
      let port = u16::from_be(addr.sin_port);
      Ok(SocketAddr::new(IpAddr::V4(ip), port))
    }
    libc::AF_INET6 => {
      let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
      let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
      let port = u16::from_be(addr.sin6_port);
      Ok(SocketAddr::new(IpAddr::V6(ip), port))
    }
    _ => Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "Invalid address family from recvmsg",
    )),
  }
}

/// Walk the control messages in `msghdr` and extract the local destination IP
/// from `IP_PKTINFO` (IPv4) or `IPV6_PKTINFO` (IPv6).
fn extract_local_ip_from_cmsg(msghdr: &libc::msghdr) -> Result<IpAddr, io::Error> {
  // SAFETY: msghdr was populated by a successful recvmsg call; CMSG_FIRSTHDR/NXTHDR
  // are safe to call on a valid msghdr and return null when no more messages exist.
  let mut cmsg_ptr = unsafe { libc::CMSG_FIRSTHDR(msghdr) };

  while !cmsg_ptr.is_null() {
    let cmsg = unsafe { &*cmsg_ptr };

    if cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == libc::IP_PKTINFO {
      let pktinfo = unsafe { &*(libc::CMSG_DATA(cmsg_ptr) as *const libc::in_pktinfo) };
      let ip = Ipv4Addr::from(u32::from_be(
        #[cfg(target_os = "linux")]
        pktinfo.ipi_spec_dst.s_addr,
        #[cfg(not(target_os = "linux"))]
        pktinfo.ipi_addr.s_addr,
      ));
      return Ok(IpAddr::V4(ip));
    }

    if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == libc::IPV6_PKTINFO {
      let pktinfo = unsafe { &*(libc::CMSG_DATA(cmsg_ptr) as *const libc::in6_pktinfo) };
      return Ok(IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)));
    }

    cmsg_ptr = unsafe { libc::CMSG_NXTHDR(msghdr, cmsg_ptr) };
  }

  Err(io::Error::new(
    io::ErrorKind::InvalidData,
    "No IP_PKTINFO/IPV6_PKTINFO found in control message",
  ))
}

/// Convert a Rust `SocketAddr` into a C `sockaddr_storage` for use with `sendmsg`.
fn socket_addr_to_sockaddr_storage(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
  // SAFETY: zeroed sockaddr_storage is a valid initial state before we populate the fields.
  let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
  match addr {
    SocketAddr::V4(v4) => {
      let sockaddr = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
      sockaddr.sin_family = libc::AF_INET as libc::sa_family_t;
      sockaddr.sin_port = v4.port().to_be();
      sockaddr.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
      (storage, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
    }
    SocketAddr::V6(v6) => {
      let sockaddr = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
      sockaddr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
      sockaddr.sin6_port = v6.port().to_be();
      sockaddr.sin6_addr.s6_addr = v6.ip().octets();
      sockaddr.sin6_scope_id = v6.scope_id();
      (storage, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
    }
  }
}

/// Build a control-message buffer containing `IP_PKTINFO` or `IPV6_PKTINFO` for the given local IP.
fn build_pktinfo_cmsg(control_buf: &mut [u8; 256], local_ip: IpAddr) -> Result<usize, io::Error> {
  match local_ip {
    IpAddr::V4(ipv4) => {
      let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
          s_addr: u32::from(ipv4).to_be(),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
      };
      build_cmsg_buffer(
        control_buf,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        &pktinfo,
        std::mem::size_of::<libc::in_pktinfo>(),
      )
    }
    IpAddr::V6(ipv6) => {
      let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr { s6_addr: ipv6.octets() },
        ipi6_ifindex: 0,
      };
      build_cmsg_buffer(
        control_buf,
        libc::IPPROTO_IPV6,
        libc::IPV6_PKTINFO,
        &pktinfo,
        std::mem::size_of::<libc::in6_pktinfo>(),
      )
    }
  }
}

/// Generic helper to write a single control message (cmsghdr + payload) into a raw byte buffer.
fn build_cmsg_buffer(
  control_buf: &mut [u8; 256],
  level: libc::c_int,
  msg_type: libc::c_int,
  data: *const impl Sized,
  data_len: usize,
) -> Result<usize, io::Error> {
  // SAFETY: CMSG_LEN/CMSG_SPACE are pure arithmetic macros operating on the data length.
  let cmsg_len = unsafe { libc::CMSG_LEN(data_len as _) } as usize;
  let cmsg_space = unsafe { libc::CMSG_SPACE(data_len as _) } as usize;

  if cmsg_space > control_buf.len() {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "Control buffer too small for cmsg",
    ));
  }

  control_buf[..cmsg_space].fill(0);
  let cmsg = control_buf.as_mut_ptr() as *mut libc::cmsghdr;
  // SAFETY: control_buf is large enough (checked above). We write the cmsghdr
  // fields and then copy data_len bytes of pktinfo data right after the header
  // at the offset returned by CMSG_DATA.
  unsafe {
    (*cmsg).cmsg_len = cmsg_len as _;
    (*cmsg).cmsg_level = level;
    (*cmsg).cmsg_type = msg_type;
    let data_ptr = libc::CMSG_DATA(cmsg);
    std::ptr::copy_nonoverlapping(data as *const _ as *const u8, data_ptr, data_len);
  }

  Ok(cmsg_space)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_pktinfo_recv_and_send() {
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listen_socket = DownstreamUdpSocketImpl::bind(&listen_addr).unwrap();
    let actual_addr = listen_socket.socket.local_addr().unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();

    client.send_to(b"hello", actual_addr).await.unwrap();

    let mut buf = [0u8; 64];
    let result = listen_socket.recv(&mut buf).await.unwrap();

    assert_eq!(result.bytes_read, 5);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(result.src_addr, client_addr);
    assert_eq!(result.local_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));

    let sent = listen_socket.send_to(b"world", &client_addr, result.local_ip).await.unwrap();
    assert_eq!(sent, 5);

    let mut recv_buf = [0u8; 64];
    let (recv_len, from_addr) = client.recv_from(&mut recv_buf).await.unwrap();
    assert_eq!(recv_len, 5);
    assert_eq!(&recv_buf[..5], b"world");
    assert_eq!(from_addr, actual_addr);
  }
}
