use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};
use tokio::net::TcpSocket;

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
/// Helper function for both binding and pktinfo sockets, since the options are mostly the same.
fn build_raw_socket(listening_on: &SocketAddr, protocol: Protocol) -> Result<Socket, std::io::Error> {
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

/// UDP socket with `IP_PKTINFO` support for receiving destination address information.
#[cfg(unix)]
pub(super) mod udp_pktinfo {
  use super::*;
  use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::io::{AsFd, AsRawFd},
  };
  use tokio::{io::Interest, net::UdpSocket as TokioUdpSocket};

  /// Enable `IP_PKTINFO` (IPv4) or `IPV6_RECVPKTINFO` (IPv6) on the given socket.
  /// This allows `recvmsg` to return the local destination address of received datagrams.
  pub(crate) fn enable_pktinfo(socket: &Socket, ipv6: bool) -> Result<(), io::Error> {
    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    let res = if ipv6 {
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

  /// Bind a UDP socket with `IP_PKTINFO` enabled for receiving destination address information.
  pub(crate) fn bind_udp_socket_with_pktinfo(listening_on: &SocketAddr) -> Result<UdpSocket, io::Error> {
    let socket = build_raw_socket(listening_on, Protocol::UDP)?;
    enable_pktinfo(&socket, listening_on.is_ipv6())?;
    socket.bind(&(*listening_on).into())?;
    Ok(socket.into())
  }

  /// Result of a `recvmsg` call, including source address and local destination IP.
  pub(crate) struct RecvMsgResult {
    /// Number of bytes received
    pub bytes_read: usize,
    /// Source address (client)
    pub src_addr: SocketAddr,
    /// Local destination IP address (the IP the client sent to)
    pub local_ip: IpAddr,
  }

  /// Receive a UDP datagram using `recvmsg` with `IP_PKTINFO`, extracting the destination IP.
  /// This must be called within a tokio async context using `try_io`.
  pub(crate) async fn recv_msg(socket: &TokioUdpSocket, buf: &mut [u8]) -> Result<RecvMsgResult, io::Error> {
    loop {
      socket.readable().await?;

      match socket.try_io(Interest::READABLE, || recv_msg_sync(socket, buf)) {
        Ok(result) => return Ok(result),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
        Err(e) => return Err(e),
      }
    }
  }

  /// Synchronous `recvmsg` implementation using raw libc calls.
  fn recv_msg_sync(socket: &TokioUdpSocket, buf: &mut [u8]) -> Result<RecvMsgResult, io::Error> {
    let fd = socket.as_fd().as_raw_fd();

    let mut iov = libc::iovec {
      iov_base: buf.as_mut_ptr() as *mut libc::c_void,
      iov_len: buf.len(),
    };

    // Allocate storage for source address
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    // Control buffer for cmsg (large enough for IP_PKTINFO or IPV6_PKTINFO)
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

    let n = unsafe { libc::recvmsg(fd, &mut msghdr, 0) };
    if n < 0 {
      return Err(io::Error::last_os_error());
    }
    let bytes_read = n as usize;

    // Parse source address
    let src_addr = sockaddr_storage_to_socket_addr(&src_storage, msghdr.msg_namelen)?;

    // Parse control messages to extract local destination IP
    let local_ip = extract_local_ip_from_cmsg(&msghdr)?;

    Ok(RecvMsgResult {
      bytes_read,
      src_addr,
      local_ip,
    })
  }

  /// Convert `sockaddr_storage` to `SocketAddr`
  fn sockaddr_storage_to_socket_addr(storage: &libc::sockaddr_storage, _len: libc::socklen_t) -> Result<SocketAddr, io::Error> {
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

  /// Extract local destination IP from cmsg control data.
  fn extract_local_ip_from_cmsg(msghdr: &libc::msghdr) -> Result<IpAddr, io::Error> {
    let mut cmsg_ptr = unsafe { libc::CMSG_FIRSTHDR(msghdr) };

    while !cmsg_ptr.is_null() {
      let cmsg = unsafe { &*cmsg_ptr };

      // IPv4: IP_PKTINFO
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

      // IPv6: IPV6_PKTINFO
      if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == libc::IPV6_PKTINFO {
        let pktinfo = unsafe { &*(libc::CMSG_DATA(cmsg_ptr) as *const libc::in6_pktinfo) };
        let ip = Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr);
        return Ok(IpAddr::V6(ip));
      }

      cmsg_ptr = unsafe { libc::CMSG_NXTHDR(msghdr, cmsg_ptr) };
    }

    Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "No IP_PKTINFO/IPV6_PKTINFO found in control message",
    ))
  }

  /// Send a UDP datagram using `sendmsg` with `IP_PKTINFO` to control the source IP address.
  /// This allows responding from the correct local IP on multi-homed servers.
  pub(crate) async fn send_msg(
    socket: &TokioUdpSocket,
    buf: &[u8],
    dst_addr: &SocketAddr,
    local_ip: IpAddr,
  ) -> Result<usize, io::Error> {
    loop {
      socket.writable().await?;

      match socket.try_io(Interest::WRITABLE, || send_msg_sync(socket, buf, dst_addr, local_ip)) {
        Ok(n) => return Ok(n),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
        Err(e) => return Err(e),
      }
    }
  }

  /// Synchronous `sendmsg` implementation using raw libc calls with `IP_PKTINFO`.
  fn send_msg_sync(socket: &TokioUdpSocket, buf: &[u8], dst_addr: &SocketAddr, local_ip: IpAddr) -> Result<usize, io::Error> {
    let fd = socket.as_fd().as_raw_fd();

    let iov = libc::iovec {
      iov_base: buf.as_ptr() as *mut libc::c_void,
      iov_len: buf.len(),
    };

    // Build destination sockaddr
    let (dst_storage, dst_len) = socket_addr_to_sockaddr_storage(dst_addr);

    // Build control message with IP_PKTINFO
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

    let n = unsafe { libc::sendmsg(fd, &msghdr, 0) };
    if n < 0 {
      return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
  }

  /// Convert `SocketAddr` to `sockaddr_storage` for use with `sendmsg`.
  fn socket_addr_to_sockaddr_storage(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
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

  /// Build a cmsg control buffer containing `IP_PKTINFO` or `IPV6_PKTINFO`.
  fn build_pktinfo_cmsg(control_buf: &mut [u8; 256], local_ip: IpAddr) -> Result<usize, io::Error> {
    match local_ip {
      IpAddr::V4(ipv4) => {
        let pktinfo = libc::in_pktinfo {
          ipi_ifindex: 0, // let the kernel choose the interface
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
          ipi6_ifindex: 0, // let the kernel choose the interface
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

  /// Build a raw cmsg buffer for sendmsg.
  fn build_cmsg_buffer(
    control_buf: &mut [u8; 256],
    level: libc::c_int,
    msg_type: libc::c_int,
    data: *const impl Sized,
    data_len: usize,
  ) -> Result<usize, io::Error> {
    let cmsg_len = unsafe { libc::CMSG_LEN(data_len as _) } as usize;
    let cmsg_space = unsafe { libc::CMSG_SPACE(data_len as _) } as usize;

    if cmsg_space > control_buf.len() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "Control buffer too small for cmsg",
      ));
    }

    // Zero the buffer
    control_buf[..cmsg_space].fill(0);

    // Set up the cmsghdr
    let cmsg = control_buf.as_mut_ptr() as *mut libc::cmsghdr;
    unsafe {
      (*cmsg).cmsg_len = cmsg_len as _;
      (*cmsg).cmsg_level = level;
      (*cmsg).cmsg_type = msg_type;

      // Copy pktinfo data after the header
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
      // Bind a listening socket with pktinfo enabled
      let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
      let std_socket = bind_udp_socket_with_pktinfo(&listen_addr).unwrap();
      let actual_addr = std_socket.local_addr().unwrap();
      let listen_socket = TokioUdpSocket::from_std(std_socket).unwrap();

      // Bind a client socket
      let client = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
      let client_addr = client.local_addr().unwrap();

      // Client sends a datagram to the listening socket
      client.send_to(b"hello", actual_addr).await.unwrap();

      // Receive with pktinfo
      let mut buf = [0u8; 64];
      let result = recv_msg(&listen_socket, &mut buf).await.unwrap();

      assert_eq!(result.bytes_read, 5);
      assert_eq!(&buf[..5], b"hello");
      assert_eq!(result.src_addr, client_addr);
      assert_eq!(result.local_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));

      // Send response back using sendmsg with IP_PKTINFO (same listening socket)
      let response = b"world";
      let sent = send_msg(&listen_socket, response, &client_addr, result.local_ip)
        .await
        .unwrap();
      assert_eq!(sent, 5);

      // Client receives the response
      let mut recv_buf = [0u8; 64];
      let (recv_len, from_addr) = client.recv_from(&mut recv_buf).await.unwrap();
      assert_eq!(recv_len, 5);
      assert_eq!(&recv_buf[..5], b"world");
      // Response should come from the listening socket's address
      assert_eq!(from_addr, actual_addr);
    }
  }
}
