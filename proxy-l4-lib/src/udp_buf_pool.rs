use crate::udp_conn::UdpConnectionPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;

/// DashMap type alias, uses ahash::RandomState as hashbuilder
type DashMap<K, V> = dashmap::DashMap<K, V, ahash::RandomState>;

#[derive(Clone)]
struct UdpInitialPackets {
  /// inner buffer of multiple UDP packet payloads
  inner: Vec<Vec<u8>>,
}

/* ---------------------------------------------------------- */
#[derive(Clone)]
/// Temporary buffer pool of initial packets dispatched from each clients.
/// This is used to buffer the initial packets of each client, probe the destination, and then establish a UDP connection.
pub(crate) struct UdpInitialPacketsPool {
  /// inner hashmap
  inner: DashMap<SocketAddr, UdpInitialPackets>,
  /// pointer to udp connection pool
  udp_conn_pool: Arc<UdpConnectionPool>,
  /// runtime handle
  runtime_handle: Handle,
}
