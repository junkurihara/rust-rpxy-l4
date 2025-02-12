use super::{
  constants::{BASE_ANY_SOCKET_V4, BASE_ANY_SOCKET_V6},
  error::ProxyError,
  socket::bind_udp_socket,
};
use crate::log::warn;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

/// DashMap type alias, uses ahash::RandomState as hashbuilder
type DashMap<K, V> = dashmap::DashMap<K, V, ahash::RandomState>;

/* ---------------------------------------------------------- */
/// Udp connection manager
pub struct UdpConnectionPool {
  /// inner hashmap
  inner: DashMap<SocketAddr, Arc<UdpConnection>>,
  // TODO: Manage the connection lifetime
}

impl UdpConnectionPool {
  /// Create a new UdpConnectionManager
  pub fn new() -> Self {
    let inner: DashMap<SocketAddr, Arc<UdpConnection>> = DashMap::default();
    Self { inner }
  }
  /// Get Arc<UdpConnection> by the source address + port
  pub fn get(&self, src_addr: &SocketAddr) -> Option<Arc<UdpConnection>> {
    // TODO: make the connection active
    self.inner.get(src_addr).map(|arc| arc.value().clone())
  }
  /// Create and insert a new UdpConnection, and return the Arc<UdpConnection>
  /// If the source address + port already exists, update the value.
  pub fn create_insert(&self, src_addr: &SocketAddr, dst_addr: &SocketAddr) -> Result<Arc<UdpConnection>, ProxyError> {
    let udp_connection = UdpConnection::try_new(*src_addr, *dst_addr)?;
    if self.inner.insert(*src_addr, Arc::new(udp_connection)).is_some() {
      warn!("UdpConnection already exists, updating the value. Should not call create_insert() for existing keys.");
    }
    Ok(self.inner.get(src_addr).unwrap().value().clone())
  }
  fn remove(&self, src_addr: &SocketAddr) -> Option<Arc<UdpConnection>> {
    // TODO: make the connection inactive (prune)
    self.inner.remove(src_addr).map(|arc| arc.1)
  }
}

/* ---------------------------------------------------------- */
/// Udp connection
pub struct UdpConnection {
  /// Remote socket address of the client
  src_addr: SocketAddr,

  /// Remote socket address of the upstream server
  dst_addr: SocketAddr,

  /// Local UdpSocket for the upstream server
  udp_socket_to_upstream: Arc<UdpSocket>,
  // TODO: Connection liveness, expiration date that are updated when the connection is used
}

impl UdpConnection {
  /// Create a new UdpConnection
  pub fn try_new(src_addr: SocketAddr, dst_addr: SocketAddr) -> Result<Self, ProxyError> {
    let udp_socket_to_upstream = match dst_addr {
      SocketAddr::V4(_) => UdpSocket::from_std(bind_udp_socket(BASE_ANY_SOCKET_V4.get().unwrap())?),
      SocketAddr::V6(_) => UdpSocket::from_std(bind_udp_socket(BASE_ANY_SOCKET_V6.get().unwrap())?),
    }
    .map(Arc::new)?;

    Ok(Self {
      src_addr,
      dst_addr,
      udp_socket_to_upstream,
    })
  }
}
