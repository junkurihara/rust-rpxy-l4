use crate::{
  access_log::{AccessLogProtocolType, access_log_finish, access_log_start},
  constants::{UDP_BUFFER_SIZE, UDP_CHANNEL_CAPACITY},
  count::ConnectionPermit,
  error::ProxyError,
  proto::UdpProtocolType,
  socket::{DownstreamUdpSocket, bind_udp_socket},
  time_util::get_monotonic_seconds,
  trace::*,
  udp_proxy::UdpDestinationInner,
};
use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
  sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
  },
};
use tokio::{net::UdpSocket, runtime::Handle, sync::mpsc};
use tokio_util::sync::CancellationToken;

/// Any socket address for IPv4 for auto-binding
pub static BASE_ANY_SOCKET_V4: OnceLock<SocketAddr> = OnceLock::new();
/// Any socket address for IPv6 for auto-binding
pub static BASE_ANY_SOCKET_V6: OnceLock<SocketAddr> = OnceLock::new();

fn base_any_socket_v4() -> &'static SocketAddr {
  BASE_ANY_SOCKET_V4.get_or_init(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

fn base_any_socket_v6() -> &'static SocketAddr {
  BASE_ANY_SOCKET_V6.get_or_init(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
}

/// DashMap type alias, uses ahash::RandomState as hashbuilder
type DashMap<K, V> = dashmap::DashMap<K, V, ahash::RandomState>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
/// Key for UDP pseudo-connections scoped by downstream source socket and local destination IP.
pub(crate) struct UdpFlowKey {
  pub src_addr: SocketAddr,
  pub local_ip: IpAddr,
}

impl UdpFlowKey {
  pub(crate) fn new(src_addr: SocketAddr, local_ip: IpAddr) -> Self {
    Self { src_addr, local_ip }
  }
}

/* ---------------------------------------------------------- */
/// Udp connection pool
pub(crate) struct UdpConnectionPool {
  /// inner hashmap
  inner: DashMap<UdpFlowKey, UdpConnection>,
  /// parent cancel token to cancel all connections
  parent_cancel_token: CancellationToken,
  /// runtime handle
  runtime_handle: Handle,
}

impl UdpConnectionPool {
  /// Create a new UdpConnectionManager
  pub(crate) fn new(runtime_handle: Handle, parent_cancel_token: CancellationToken) -> Self {
    let inner: DashMap<UdpFlowKey, UdpConnection> = DashMap::default();
    Self {
      inner,
      runtime_handle,
      parent_cancel_token,
    }
  }

  /// Get Arc<UdpConnection> by the downstream flow key.
  pub(crate) fn get(&self, flow_key: &UdpFlowKey) -> Option<UdpConnection> {
    self.inner.get(flow_key).map(|arc| arc.value().clone())
  }

  /// Get current connection count for this pool
  pub(crate) fn local_pool_size(&self) -> usize {
    self.inner.len()
  }

  /// Create and insert a new UdpConnection, and return the
  /// If the source address + port already exists, update the value.
  pub(crate) async fn create_new_connection(
    self: &Arc<Self>,
    src_addr: &SocketAddr,
    udp_dst: &UdpDestinationInner,
    protocol: &UdpProtocolType,
    udp_socket_to_downstream: Arc<DownstreamUdpSocket>,
    local_ip: IpAddr,
    connection_permit: ConnectionPermit,
  ) -> Result<UdpConnection, ProxyError> {
    // Connection limit is handled by the caller

    let conn = Arc::new(
      UdpConnectionInner::try_new(
        protocol,
        src_addr,
        udp_dst,
        udp_socket_to_downstream,
        local_ip,
        self.parent_cancel_token.child_token(),
        connection_permit,
      )
      .await?,
    );
    let (tx, rx) = mpsc::channel::<Vec<u8>>(UDP_CHANNEL_CAPACITY);
    let new_conn = UdpConnection { tx, inner: conn.clone() };
    let flow_key = UdpFlowKey::new(*src_addr, local_ip);

    if let Some(old_conn) = self.inner.insert(flow_key, new_conn.clone()) {
      warn!("UdpConnection was already existed but overwritten. Should not call create_new_connection() for existing keys.");
      old_conn.inner.cancel_token.cancel(); // cancel the old connection
    }
    // spawn the connection service
    let pool = Arc::clone(self);
    self.runtime_handle.spawn(async move {
      // Here we are establishing a udp connection. Logging info for the connection as an access log.
      udp_access_log_start(&conn);
      conn.serve(rx, pool.runtime_handle.clone()).await;
      // clean up if the connection service is closed, here the connection service was already closed
      pool.remove_if_same(&flow_key, &conn);
      // finish log
      udp_access_log_finish(&conn);
    });

    //   Ok(udp_connection)
    Ok(new_conn)
  }

  /// Remove the entry by the downstream flow key.
  fn remove_if_same(&self, flow_key: &UdpFlowKey, connection: &Arc<UdpConnectionInner>) {
    self
      .inner
      .remove_if(flow_key, |_, current| Arc::ptr_eq(&current.inner, connection));
  }

  /// Prune inactive connections
  /// This must be called when a new UDP datagram is received.
  pub(crate) fn prune_inactive_connections(&self) {
    self.inner.retain(|_, conn| {
      let last_active = conn.inner.last_active.load(Ordering::Acquire);
      let current = get_monotonic_seconds();
      let elapsed = current - last_active;
      debug!(
        "UdpConnection from {} to {} is active for {} seconds",
        conn.inner.src_addr, conn.inner.dst_addr, elapsed
      );
      if elapsed < conn.inner.idle_lifetime {
        return true;
      }
      debug!("UdpConnection from {} is pruned due to inactivity", conn.inner.src_addr);
      conn.inner.cancel_token.cancel();
      false
    });
  }
}

/* ---------------------------------------------------------- */
#[derive(Clone, Debug)]
/// Connection pool value
pub(crate) struct UdpConnection {
  /// Sender to the UdpConnection
  tx: mpsc::Sender<Vec<u8>>,
  /// UdpConnection
  inner: Arc<UdpConnectionInner>,
}

impl UdpConnection {
  /// Send a datagram to the UdpConnection
  pub(crate) async fn send(&self, datagram: &[u8]) -> Result<(), ProxyError> {
    self.tx.send(datagram.to_owned()).await.map_err(|e| {
      error!("Error sending datagram to UdpConnection: {e}");
      error!(
        "Stopping UdpConnection from {} to {}",
        self.inner.src_addr, self.inner.dst_addr
      );
      self.inner.cancel_token.cancel(); // cancellation will remove the connection from the pool
      ProxyError::BrokenUdpConnection(String::new())
    })
  }
  /// Send multiple datagrams to the UdpConnection
  pub(crate) async fn send_many(&self, datagrams: &[Vec<u8>]) -> Result<(), ProxyError> {
    for dg in datagrams.iter() {
      self.send(dg).await?;
    }
    Ok(())
  }
}
/* ---------------------------------------------------------- */
#[derive(Debug)]
/// Udp connection
struct UdpConnectionInner {
  /// Permit for one global UDP connection slot
  _connection_permit: ConnectionPermit,

  /// Udp protocol type
  protocol: UdpProtocolType,

  /// Remote socket address of the client
  src_addr: SocketAddr,

  /// Remote socket address of the upstream server
  dst_addr: SocketAddr,

  /// Local UdpSocket for the upstream server
  udp_socket_to_upstream: Arc<UdpSocket>,

  /// Local UdpSocket to send data back to the downstream client
  udp_socket_to_downstream: Arc<DownstreamUdpSocket>,

  /// Local IP address that the client originally sent to.
  /// Used by the downstream socket abstraction to preserve the response source IP.
  local_ip: IpAddr,

  /// Cancel token to cancel the connection service
  cancel_token: CancellationToken,

  /// Connection idle lifetime
  /// If set to 0, no limit is applied.
  idle_lifetime: u64,

  /// Last active time
  last_active: Arc<AtomicU64>,
}

impl UdpConnectionInner {
  /// Create a new UdpConnection
  async fn try_new(
    protocol: &UdpProtocolType,
    src_addr: &SocketAddr,
    udp_dst: &UdpDestinationInner,
    udp_socket_to_downstream: Arc<DownstreamUdpSocket>,
    local_ip: IpAddr,
    cancel_token: CancellationToken,
    connection_permit: ConnectionPermit,
  ) -> Result<Self, ProxyError> {
    let dst_addr = udp_dst.get_destination(src_addr).await?;
    let idle_lifetime = udp_dst.get_connection_idle_lifetime() as u64;
    let udp_socket_to_upstream = match dst_addr {
      SocketAddr::V4(_) => UdpSocket::from_std(bind_udp_socket(base_any_socket_v4())?),
      SocketAddr::V6(_) => UdpSocket::from_std(bind_udp_socket(base_any_socket_v6())?),
    }
    .map(Arc::new)?;

    udp_socket_to_upstream.connect(dst_addr).await?;
    debug!("Connected to the upstream server: {dst_addr}");

    let last_active = Arc::new(AtomicU64::new(get_monotonic_seconds()));

    Ok(Self {
      _connection_permit: connection_permit,
      protocol: protocol.clone(),
      src_addr: *src_addr,
      dst_addr,
      udp_socket_to_upstream,
      udp_socket_to_downstream,
      local_ip,
      cancel_token,
      idle_lifetime,
      last_active,
    })
  }

  /// Update the last active time
  fn update_last_active(&self) {
    self.last_active.store(get_monotonic_seconds(), Ordering::Release);
  }

  /// Serve the UdpConnection
  async fn serve(self: &Arc<Self>, channel_rx: mpsc::Receiver<Vec<u8>>, runtime_handle: Handle) {
    debug!("UdpConnection from {} to {} started", self.src_addr, self.dst_addr);
    let udp_socket_to_upstream_tx = self.udp_socket_to_upstream.clone();
    let udp_socket_to_upstream_rx = self.udp_socket_to_upstream.clone();

    /* ---------------------------------------------------------- */
    let downstream_jh = runtime_handle.clone().spawn({
      let connection = Arc::clone(self);
      async move { connection.service_forward_downstream(udp_socket_to_upstream_rx).await }
    });

    /* ---------------------------------------------------------- */
    let upstream_jh = runtime_handle.clone().spawn({
      let connection = Arc::clone(self);
      async move {
        connection
          .service_forward_upstream(channel_rx, udp_socket_to_upstream_tx)
          .await
      }
    });

    /* ---------------------------------------------------------- */
    match tokio::join!(downstream_jh, upstream_jh) {
      (Err(e), _) | (_, Err(e)) => {
        error!("Error serving UdpConnection: {e}");
      }
      _ => {}
    }
  }

  /// Service to forward datagrams to the upstream
  async fn service_forward_upstream(
    &self,
    mut channel_rx: mpsc::Receiver<Vec<u8>>,
    udp_socket_to_upstream_tx: Arc<UdpSocket>,
  ) -> Result<(), ProxyError> {
    let service = async move {
      // Handle multiple datagrams from the same source
      loop {
        let Some(datagram) = channel_rx.recv().await else {
          error!("Error receiving datagram from channel");
          return Err(ProxyError::BrokenUdpConnection(String::new()));
        };
        trace!(
          "[{} -> {}] received {} bytes from downstream",
          self.src_addr,
          self.dst_addr,
          datagram.len()
        );
        self.update_last_active();

        if let Err(e) = udp_socket_to_upstream_tx.send(datagram.as_slice()).await {
          error!("Error sending datagram to upstream: {e}");
          return Err(ProxyError::BrokenUdpConnection(String::new()));
        };
      }
    };

    tokio::select! {
      res = service => res,
      _ = self.cancel_token.cancelled() => {
        debug!("UdpConnection cancelled [{} -> {}]", self.src_addr, self.dst_addr);
        Ok(())
      }
    }
  }

  /// Service to forward datagrams to the downstream
  async fn service_forward_downstream(&self, udp_socket_to_upstream_rx: Arc<UdpSocket>) -> Result<(), ProxyError> {
    // Handle multiple datagrams sent back from the upstream as responses
    let service = async {
      loop {
        let mut udp_buf = vec![0u8; UDP_BUFFER_SIZE];
        let buf_size = match udp_socket_to_upstream_rx.recv(&mut udp_buf).await {
          Err(e) => {
            error!("Error in UDP listener for upstream: {e}");
            return Err(ProxyError::BrokenUdpConnection(String::new()));
          }
          Ok(res) => res,
        };

        trace!(
          "[{} <- {}] received {} bytes from upstream",
          self.src_addr, self.dst_addr, buf_size
        );
        self.update_last_active();

        let response = &udp_buf[..buf_size];

        if let Err(e) = self
          .udp_socket_to_downstream
          .send_to(response, &self.src_addr, self.local_ip)
          .await
        {
          error!("Error sending datagram to downstream: {e}");
          return Err(ProxyError::BrokenUdpConnection(String::new()));
        };
      }
    };

    tokio::select! {
      res = service => res,
      _ = self.cancel_token.cancelled() => {
        debug!("UdpConnection cancelled: [{} <- {}]", self.src_addr, self.dst_addr);
        Ok(())
      }
    }
  }

  /// Get the source address of the UdpConnection
  fn src_addr(&self) -> &SocketAddr {
    &self.src_addr
  }
  /// Get the destination address of the UdpConnection
  fn dst_addr(&self) -> &SocketAddr {
    &self.dst_addr
  }
  /// Get the protocol of the UdpConnection
  fn protocol(&self) -> &UdpProtocolType {
    &self.protocol
  }
}

/* ---------------------------------------------------------- */
/// Handle UDP access log when establishing a new connection
fn udp_access_log_start(conn: &UdpConnectionInner) {
  let protocol = AccessLogProtocolType::Udp(conn.protocol().to_owned());
  access_log_start(&protocol, conn.src_addr(), conn.dst_addr());
}
/// Handle UDP access log when closing a connection
fn udp_access_log_finish(conn: &UdpConnectionInner) {
  let protocol = AccessLogProtocolType::Udp(conn.protocol().to_owned());
  access_log_finish(&protocol, conn.src_addr(), conn.dst_addr());
}

/* ---------------------------------------------------------- */
#[cfg(test)]
mod tests {
  use crate::{
    count::ConnectionCount,
    target::{DnsCache, TargetAddr},
  };

  use super::*;
  use std::str::FromStr;
  use tracing_subscriber::{fmt, prelude::*};

  fn init_logger() {
    let level = tracing::Level::from_str("debug").unwrap();
    let passed_pkg_names = [env!("CARGO_PKG_NAME").replace('-', "_")];
    let stdio_layer = fmt::layer()
      .with_line_number(true)
      .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
        (passed_pkg_names
          .iter()
          .any(|pkg_name| metadata.target().starts_with(pkg_name))
          && metadata.level() <= &level)
          || metadata.level() <= &tracing::Level::INFO.min(level)
      }));

    tracing_subscriber::registry().with(stdio_layer).init();
  }

  async fn wait_for_connection_count(count: &ConnectionCount, expected: usize) {
    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
      while count.current() != expected {
        tokio::task::yield_now().await;
      }
    })
    .await
    .unwrap();
  }

  #[tokio::test]
  async fn test_udp_connection_pool() {
    init_logger();
    let runtime_handle = tokio::runtime::Handle::current();

    let cancel_token = CancellationToken::new();
    let udp_connection_pool = Arc::new(UdpConnectionPool::new(runtime_handle.clone(), cancel_token.clone()));

    let src_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let dns_cache = Arc::new(DnsCache::default());
    let udp_dst = UdpDestinationInner::try_from((
      ["127.0.0.1:54321".parse::<TargetAddr>().unwrap()].as_slice(),
      None,
      &dns_cache,
      Some(10),
    ))
    .unwrap();

    let socket: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    let udp_socket_to_downstream = Arc::new(DownstreamUdpSocket::bind(&socket).unwrap());
    let protocol = UdpProtocolType::Any;
    let admission_count = ConnectionCount::default();

    let udp_connection = udp_connection_pool
      .create_new_connection(
        &src_addr,
        &udp_dst,
        &protocol,
        udp_socket_to_downstream,
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        admission_count.try_acquire(1).unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(admission_count.current(), 1);

    drop(udp_connection);
    cancel_token.cancel();
    wait_for_connection_count(&admission_count, 0).await;
    assert_eq!(admission_count.current(), 0);
  }

  #[test]
  fn test_udp_flow_key_distinguishes_local_ip() {
    // Same client (src_addr) connecting to two different VIPs must produce distinct flow keys.
    let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let vip_a: IpAddr = "192.168.1.1".parse().unwrap();
    let vip_b: IpAddr = "192.168.1.2".parse().unwrap();

    let key_a = UdpFlowKey::new(src, vip_a);
    let key_b = UdpFlowKey::new(src, vip_b);

    assert_ne!(
      key_a, key_b,
      "same src_addr with different local_ip must be distinct flow keys"
    );

    // Same local_ip but different src_addr must also be distinct.
    let src2: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    let key_c = UdpFlowKey::new(src2, vip_a);
    assert_ne!(key_a, key_c);

    // Identical (src_addr, local_ip) must be equal.
    let key_a2 = UdpFlowKey::new(src, vip_a);
    assert_eq!(key_a, key_a2);
  }

  #[test]
  fn test_udp_flow_key_hash_consistency() {
    use std::collections::HashMap;

    let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let vip_a: IpAddr = "192.168.1.1".parse().unwrap();
    let vip_b: IpAddr = "192.168.1.2".parse().unwrap();

    let mut map = HashMap::new();
    map.insert(UdpFlowKey::new(src, vip_a), "conn_a");
    map.insert(UdpFlowKey::new(src, vip_b), "conn_b");

    // Two distinct entries must coexist, not overwrite each other.
    assert_eq!(map.len(), 2);
    assert_eq!(map[&UdpFlowKey::new(src, vip_a)], "conn_a");
    assert_eq!(map[&UdpFlowKey::new(src, vip_b)], "conn_b");
  }

  #[tokio::test]
  async fn test_udp_connection_pool_multi_vip() {
    // Verify that the connection pool creates separate entries for the same client
    // connecting via different local IPs (multi-VIP scenario).
    //
    // We use the same downstream socket (bound to 127.0.0.1) but pass different
    // local_ip values to simulate the multi-VIP scenario at the pool level,
    // because not all CI environments have multiple loopback addresses available.
    let runtime_handle = tokio::runtime::Handle::current();
    let cancel_token = CancellationToken::new();
    let pool = Arc::new(UdpConnectionPool::new(runtime_handle, cancel_token.clone()));

    let src_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let dns_cache = Arc::new(DnsCache::default());
    let udp_dst = UdpDestinationInner::try_from((
      ["127.0.0.1:54321".parse::<TargetAddr>().unwrap()].as_slice(),
      None,
      &dns_cache,
      Some(10),
    ))
    .unwrap();

    // Simulate two VIPs: the pool keys differ by local_ip.
    let vip_a: IpAddr = "192.168.1.1".parse().unwrap();
    let vip_b: IpAddr = "192.168.1.2".parse().unwrap();

    // Both connections share the same downstream socket (bind to loopback).
    let socket_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let ds = Arc::new(DownstreamUdpSocket::bind(&socket_addr).unwrap());
    let admission_count = ConnectionCount::default();

    let conn_a = pool
      .create_new_connection(
        &src_addr,
        &udp_dst,
        &UdpProtocolType::Any,
        ds.clone(),
        vip_a,
        admission_count.try_acquire(2).unwrap(),
      )
      .await
      .unwrap();
    let conn_b = pool
      .create_new_connection(
        &src_addr,
        &udp_dst,
        &UdpProtocolType::Any,
        ds,
        vip_b,
        admission_count.try_acquire(2).unwrap(),
      )
      .await
      .unwrap();

    // Both connections must coexist in the pool.
    assert_eq!(pool.local_pool_size(), 2);
    assert_eq!(admission_count.current(), 2);
    assert!(pool.get(&UdpFlowKey::new(src_addr, vip_a)).is_some());
    assert!(pool.get(&UdpFlowKey::new(src_addr, vip_b)).is_some());

    drop((conn_a, conn_b));
    cancel_token.cancel();
    wait_for_connection_count(&admission_count, 0).await;
    assert_eq!(admission_count.current(), 0);
  }

  #[tokio::test]
  async fn test_udp_connection_replacement_releases_only_replaced_permit() {
    let runtime_handle = tokio::runtime::Handle::current();
    let cancel_token = CancellationToken::new();
    let pool = Arc::new(UdpConnectionPool::new(runtime_handle, cancel_token.clone()));
    let src_addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
    let local_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let dns_cache = Arc::new(DnsCache::default());
    let udp_dst = UdpDestinationInner::try_from((
      ["127.0.0.1:54322".parse::<TargetAddr>().unwrap()].as_slice(),
      None,
      &dns_cache,
      Some(10),
    ))
    .unwrap();
    let downstream = Arc::new(DownstreamUdpSocket::bind(&"127.0.0.1:0".parse().unwrap()).unwrap());
    let admission_count = ConnectionCount::default();

    let replaced = pool
      .create_new_connection(
        &src_addr,
        &udp_dst,
        &UdpProtocolType::Any,
        downstream.clone(),
        local_ip,
        admission_count.try_acquire(2).unwrap(),
      )
      .await
      .unwrap();
    let replacement = pool
      .create_new_connection(
        &src_addr,
        &udp_dst,
        &UdpProtocolType::Any,
        downstream,
        local_ip,
        admission_count.try_acquire(2).unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(admission_count.current(), 2);

    drop(replaced);
    wait_for_connection_count(&admission_count, 1).await;
    assert!(pool.get(&UdpFlowKey::new(src_addr, local_ip)).is_some());

    drop(replacement);
    cancel_token.cancel();
    wait_for_connection_count(&admission_count, 0).await;
  }
}
