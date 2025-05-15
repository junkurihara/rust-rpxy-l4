use crate::{
  access_log::{AccessLogProtocolType, access_log_finish, access_log_start},
  constants::{UDP_BUFFER_SIZE, UDP_CHANNEL_CAPACITY},
  error::ProxyError,
  proto::UdpProtocolType,
  socket::bind_udp_socket,
  time_util::get_since_the_epoch,
  trace::*,
  udp_proxy::UdpDestinationInner,
};
use std::{
  net::SocketAddr,
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

/// Initialize once lock values
fn init_once_lock() {
  let _ = BASE_ANY_SOCKET_V4.get_or_init(|| "0.0.0.0:0".parse().unwrap());
  let _ = BASE_ANY_SOCKET_V6.get_or_init(|| "[::]:0".parse().unwrap());
}

/// DashMap type alias, uses ahash::RandomState as hashbuilder
type DashMap<K, V> = dashmap::DashMap<K, V, ahash::RandomState>;

/* ---------------------------------------------------------- */
#[derive(Clone)]
/// Udp connection pool
pub(crate) struct UdpConnectionPool {
  /// inner hashmap
  inner: DashMap<SocketAddr, UdpConnection>,
  /// parent cancel token to cancel all connections
  parent_cancel_token: CancellationToken,
  /// runtime handle
  runtime_handle: Handle,
}

impl UdpConnectionPool {
  /// Create a new UdpConnectionManager
  pub(crate) fn new(runtime_handle: Handle, parent_cancel_token: CancellationToken) -> Self {
    init_once_lock();

    let inner: DashMap<SocketAddr, UdpConnection> = DashMap::default();
    Self {
      inner,
      runtime_handle,
      parent_cancel_token,
    }
  }

  /// Get Arc<UdpConnection> by the source address + port
  pub(crate) fn get(&self, src_addr: &SocketAddr) -> Option<UdpConnection> {
    self.inner.get(src_addr).map(|arc| arc.value().clone())
  }

  /// Get current connection count for this pool
  pub(crate) fn local_pool_size(&self) -> usize {
    self.inner.len()
  }

  /// Create and insert a new UdpConnection, and return the
  /// If the source address + port already exists, update the value.
  pub(crate) async fn create_new_connection(
    &self,
    src_addr: &SocketAddr,
    udp_dst: &UdpDestinationInner,
    protocol: &UdpProtocolType,
    udp_socket_to_downstream: Arc<UdpSocket>,
  ) -> Result<UdpConnection, ProxyError> {
    // Connection limit is handled by the caller

    let conn = Arc::new(
      UdpConnectionInner::try_new(
        protocol,
        src_addr,
        udp_dst,
        udp_socket_to_downstream,
        self.parent_cancel_token.child_token(),
      )
      .await?,
    );
    let (tx, rx) = mpsc::channel::<Vec<u8>>(UDP_CHANNEL_CAPACITY);
    let new_conn = UdpConnection { tx, inner: conn.clone() };

    if let Some(old_conn) = self.inner.insert(*src_addr, new_conn.clone()) {
      warn!("UdpConnection was already existed but overwritten. Should not call create_new_connection() for existing keys.");
      old_conn.inner.cancel_token.cancel(); // cancel the old connection
    }
    // spawn the connection service
    let self_clone = self.clone();
    let src_addr = *src_addr;
    self.runtime_handle.spawn(async move {
      // Here we are establishing a udp connection. Logging info for the connection as an access log.
      udp_access_log_start(&conn);
      conn.serve(rx, self_clone.runtime_handle.clone()).await;
      // clean up if the connection service is closed, here the connection service was already closed
      self_clone.remove(&src_addr);
      // finish log
      udp_access_log_finish(&conn);
    });

    //   Ok(udp_connection)
    Ok(new_conn)
  }

  /// Remove the entry by the source address + port
  fn remove(&self, src_addr: &SocketAddr) {
    self.inner.remove(src_addr);
  }

  /// Prune inactive connections
  /// This must be called when a new UDP datagram is received.
  pub(crate) fn prune_inactive_connections(&self) {
    self.inner.retain(|_, conn| {
      let last_active = conn.inner.last_active.load(Ordering::Acquire);
      let current = get_since_the_epoch();
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
    if let Err(e) = self.tx.send(datagram.to_owned()).await {
      error!("Error sending datagram to UdpConnection: {e}");
      error!(
        "Stopping UdpConnection from {} to {}",
        self.inner.src_addr, self.inner.dst_addr
      );
      self.inner.cancel_token.cancel(); // cancellation will remove the connection from the pool
      return Err(ProxyError::BrokenUdpConnection);
    }
    Ok(())
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
#[derive(Clone, Debug)]
/// Udp connection
struct UdpConnectionInner {
  /// Udp protocol type
  protocol: UdpProtocolType,

  /// Remote socket address of the client
  src_addr: SocketAddr,

  /// Remote socket address of the upstream server
  dst_addr: SocketAddr,

  /// Local UdpSocket for the upstream server
  udp_socket_to_upstream: Arc<UdpSocket>,

  /// Local UdpSocket to send data back to the downstream client
  udp_socket_to_downstream: Arc<UdpSocket>,

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
    udp_socket_to_downstream: Arc<UdpSocket>,
    cancel_token: CancellationToken,
  ) -> Result<Self, ProxyError> {
    let dst_addr = udp_dst.get_destination(src_addr)?;
    let idle_lifetime = udp_dst.get_connection_idle_lifetime() as u64;
    let udp_socket_to_upstream = match dst_addr {
      SocketAddr::V4(_) => UdpSocket::from_std(bind_udp_socket(BASE_ANY_SOCKET_V4.get().unwrap())?),
      SocketAddr::V6(_) => UdpSocket::from_std(bind_udp_socket(BASE_ANY_SOCKET_V6.get().unwrap())?),
    }
    .map(Arc::new)?;

    udp_socket_to_upstream.connect(dst_addr).await?;
    debug!("Connected to the upstream server: {dst_addr}");

    let last_active = Arc::new(AtomicU64::new(get_since_the_epoch()));

    Ok(Self {
      protocol: protocol.clone(),
      src_addr: *src_addr,
      dst_addr: *dst_addr,
      udp_socket_to_upstream,
      udp_socket_to_downstream,
      cancel_token,
      idle_lifetime,
      last_active,
    })
  }

  /// Update the last active time
  fn update_last_active(&self) {
    self.last_active.store(get_since_the_epoch(), Ordering::Release);
  }

  /// Serve the UdpConnection
  async fn serve(&self, channel_rx: mpsc::Receiver<Vec<u8>>, runtime_handle: Handle) {
    debug!("UdpConnection from {} to {} started", self.src_addr, self.dst_addr);
    let udp_socket_to_upstream_tx = self.udp_socket_to_upstream.clone();
    let udp_socket_to_upstream_rx = self.udp_socket_to_upstream.clone();

    /* ---------------------------------------------------------- */
    let downstream_jh = runtime_handle.clone().spawn({
      let self_clone = self.clone();
      async move { self_clone.service_forward_downstream(udp_socket_to_upstream_rx).await }
    });

    /* ---------------------------------------------------------- */
    let upstream_jh = runtime_handle.clone().spawn({
      let self_clone = self.clone();
      async move {
        self_clone
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
          return Err(ProxyError::BrokenUdpConnection) as Result<(), ProxyError>;
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
          return Err(ProxyError::BrokenUdpConnection) as Result<(), ProxyError>;
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
            return Err(ProxyError::BrokenUdpConnection) as Result<(), ProxyError>;
          }
          Ok(res) => res,
        };

        trace!(
          "[{} <- {}] received {} bytes from upstream",
          self.src_addr, self.dst_addr, buf_size
        );
        self.update_last_active();

        let response = udp_buf[..buf_size].to_vec();

        if let Err(e) = self
          .udp_socket_to_downstream
          .send_to(response.as_slice(), self.src_addr)
          .await
        {
          error!("Error sending datagram to downstream: {e}");
          return Err(ProxyError::BrokenUdpConnection) as Result<(), ProxyError>;
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

  #[tokio::test]
  async fn test_udp_connection_pool() {
    init_logger();
    let runtime_handle = tokio::runtime::Handle::current();

    let cancel_token = CancellationToken::new();
    let udp_connection_pool = UdpConnectionPool::new(runtime_handle.clone(), cancel_token.clone());

    let src_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let udp_dst =
      UdpDestinationInner::try_from((["127.0.0.1:54321".parse::<SocketAddr>().unwrap()].as_slice(), None, Some(10))).unwrap();

    let socket: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    let udp_socket_to_downstream = Arc::new(UdpSocket::from_std(bind_udp_socket(&socket).unwrap()).unwrap());
    let protocol = UdpProtocolType::Any;

    let _udp_connection = udp_connection_pool
      .create_new_connection(&src_addr, &udp_dst, &protocol, udp_socket_to_downstream)
      .await
      .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    udp_connection_pool.prune_inactive_connections();
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
  }
}
