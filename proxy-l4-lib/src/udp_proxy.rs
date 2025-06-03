use crate::{
  config::EchProtocolConfig,
  constants::UDP_BUFFER_SIZE,
  count::ConnectionCountSum,
  destination::{LoadBalance, integration::ModernTlsDestinations, tls::TlsDestinationItem},
  error::{ProxyBuildError, ProxyError},
  probe::ProbeResult,
  proto::UdpProtocolType,
  protocol::{registry::UdpProtocolRegistry, udp::UdpProtocol},
  socket::bind_udp_socket,
  target::{DnsCache, TargetAddr},
  time_util::get_since_the_epoch,
  trace::*,
  udp_conn::UdpConnectionPool,
};
use std::{
  net::SocketAddr,
  sync::{Arc, atomic::AtomicU64},
};
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;

/// Type alias for QUIC destinations - now using modern implementation
type QuicDestinations = ModernTlsDestinations<UdpDestinationInner>;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
enum UdpDestination {
  /// Udp destination
  Udp(UdpDestinationInner),
  /// Udp destinations specific for QUIC
  Quic(QuicDestinations),
}

#[derive(Debug, Clone)]
/// Udp destination struct - now using modern target destination
pub(crate) struct UdpDestinationInner {
  /// Modern destination inner
  inner: crate::destination::integration::ModernTargetDestination,
  /// Connection idle lifetime in seconds
  /// If set to 0, no limit is applied for the destination
  connection_idle_lifetime: u32,
}

#[derive(Debug, Clone)]
/// Destination struct found in the multiplexer from UdpProbedProtocol
enum FoundUdpDestination {
  /// Udp destination
  Udp(UdpDestinationInner),
  /// Tls destination
  Quic(TlsDestinationItem<UdpDestinationInner>),
}

impl TryFrom<(&[TargetAddr], Option<&LoadBalance>, &Arc<DnsCache>, Option<u32>)> for UdpDestinationInner {
  type Error = ProxyBuildError;
  fn try_from(
    (dst_addrs, load_balance, dns_cache, connection_idle_lifetime): (
      &[TargetAddr],
      Option<&LoadBalance>,
      &Arc<DnsCache>,
      Option<u32>,
    ),
  ) -> Result<Self, Self::Error> {
    let inner = crate::destination::integration::ModernTargetDestination::try_from((dst_addrs, load_balance, dns_cache.clone()))?;
    let connection_idle_lifetime = connection_idle_lifetime.unwrap_or(crate::constants::UDP_CONNECTION_IDLE_LIFETIME);

    Ok(Self {
      inner,
      connection_idle_lifetime,
    })
  }
}

impl UdpDestinationInner {
  /// Get the destination socket address
  pub(crate) async fn get_destination(&self, src_addr: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    self.inner.get_destination(src_addr).await
  }
  /// Get the connection idle lifetime
  pub(crate) fn get_connection_idle_lifetime(&self) -> u32 {
    self.connection_idle_lifetime
  }
}

#[allow(unused)]
impl FoundUdpDestination {
  /// Get the destination socket address
  pub(crate) async fn get_destination(&self, src_addr: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    match self {
      Self::Udp(dst) => dst.get_destination(src_addr).await,
      Self::Quic(dst) => dst.destination().get_destination(src_addr).await,
    }
  }
  /// Get the connection idle lifetime
  pub(crate) fn get_connection_idle_lifetime(&self) -> u32 {
    match self {
      Self::Udp(dst) => dst.get_connection_idle_lifetime(),
      Self::Quic(dst) => dst.destination().get_connection_idle_lifetime(),
    }
  }
}

/* ---------------------------------------------------------- */
/// Udp destination multiplexer
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct UdpDestinationMux {
  /// Multiplexed UDP destinations
  #[builder(default = "ahash::HashMap::default()")]
  inner: ahash::HashMap<UdpProtocolType, UdpDestination>,
}

impl UdpDestinationMuxBuilder {
  /// Create a new Udp destination multiplexer builder
  pub(crate) fn set_base(
    &mut self,
    proto_type: UdpProtocolType,
    addrs: &[TargetAddr],
    dns_cache: &Arc<DnsCache>,
    load_balance: Option<&LoadBalance>,
    lifetime: Option<u32>,
  ) -> &mut Self {
    let udp_dest = UdpDestinationInner::try_from((addrs, load_balance, dns_cache, lifetime));
    if udp_dest.is_err() {
      return self;
    }
    let udp_dest_inner = udp_dest.unwrap();

    let mut inner = self.inner.clone().unwrap_or_default();
    match proto_type {
      UdpProtocolType::Quic => {
        let mut current_quic = if let Some(UdpDestination::Quic(current)) = inner.get(&proto_type).cloned() {
          current
        } else {
          QuicDestinations::new()
        };
        current_quic.add(&[], &[], udp_dest_inner, None, dns_cache);
        inner.insert(proto_type, UdpDestination::Quic(current_quic));
      }
      _ => {
        inner.insert(proto_type, UdpDestination::Udp(udp_dest_inner));
      }
    }
    self.inner = Some(inner);
    self
  }

  /// Set Quic destinations, use this if alpn and server names are needed for protocol detection or ech is need to be configured
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn set_quic(
    &mut self,
    addrs: &[TargetAddr],
    dns_cache: &Arc<DnsCache>,
    load_balance: Option<&LoadBalance>,
    lifetime: Option<u32>,
    server_names: Option<&[&str]>,
    alpn: Option<&[&str]>,
    _ech: Option<&EchProtocolConfig>, // TODO: Consider how to handle TLS ClientHello for QUIC + ECH, especially reassembling the datagram for TLS ClientHello Inner
  ) -> &mut Self {
    let udp_dest = UdpDestinationInner::try_from((addrs, load_balance, dns_cache, lifetime));
    if udp_dest.is_err() {
      return self;
    }
    let udp_dest_inner = udp_dest.unwrap();
    let mut inner = self.inner.clone().unwrap_or_default();

    let mut current_quic = match inner.get(&UdpProtocolType::Quic).cloned() {
      Some(UdpDestination::Quic(current)) => current,
      _ => QuicDestinations::new(), // If not found, create a new one
    };
    current_quic.add(
      server_names.unwrap_or_default(),
      alpn.unwrap_or_default(),
      udp_dest_inner,
      None, // TODO: currently NONE for ech
      dns_cache,
    );

    inner.insert(UdpProtocolType::Quic, UdpDestination::Quic(current_quic));
    self.inner = Some(inner);
    self
  }
}

impl UdpDestinationMux {
  /// Check if the destination mux is empty
  pub fn is_empty(&self) -> bool {
    self.inner.is_empty()
  }
  /// Get the destination socket address for the given protocol
  fn find_destination(&self, probed_protocol: &UdpProbedProtocol) -> Result<FoundUdpDestination, ProxyError> {
    let proto_type = probed_protocol.proto_type();
    match self.inner.get(&proto_type) {
      // Found non-Quic protocol
      Some(UdpDestination::Udp(udp_destination)) => {
        debug!("Setting up dest addr for {proto_type}");
        return Ok(FoundUdpDestination::Udp(udp_destination.clone()));
      }
      // Found Quic protocol
      Some(UdpDestination::Quic(quic_destinations)) => {
        let UdpProbedProtocol::Quic(client_hello) = probed_protocol else {
          return Err(ProxyError::no_destination_address_for_protocol());
        };
        return quic_destinations
          .find(client_hello)
          .ok_or(ProxyError::no_destination_address_for_protocol())
          .map(|found| {
            debug!("Setting up dest addr for {proto_type}");
            FoundUdpDestination::Quic(found.clone())
          });
      }
      _ => {}
    };

    // if nothing is found, check for the default destination
    if proto_type == UdpProtocolType::Any {
      return Err(ProxyError::no_destination_address_for_protocol());
    }
    // Check for the default destination
    let destination_any = self
      .inner
      .get(&UdpProtocolType::Any)
      .cloned()
      .ok_or(ProxyError::no_destination_address_for_protocol())?;
    let UdpDestination::Udp(dst) = destination_any else {
      return Err(ProxyError::no_destination_address_for_protocol());
    };
    debug!("Setting up dest addr for unspecified proto");
    Ok(FoundUdpDestination::Udp(dst.clone()))
  }
}

/* ---------------------------------------------------------- */
// Re-export UdpProtocol as UdpProbedProtocol for backward compatibility
pub use crate::protocol::udp::UdpProtocol as UdpProbedProtocol;

impl UdpProtocol {
  fn proto_type(&self) -> UdpProtocolType {
    match self {
      Self::Any => UdpProtocolType::Any,
      Self::Wireguard => UdpProtocolType::Wireguard,
      Self::Quic(_) => UdpProtocolType::Quic,
    }
  }
}

impl UdpProtocol {
  /// Detect the protocol from the first few bytes of the incoming datagram using the registry
  async fn detect_protocol(initial_datagrams: &mut UdpInitialDatagrams) -> Result<ProbeResult<Self>, ProxyError> {
    use bytes::BytesMut;

    let registry = UdpProtocolRegistry::default();

    // Convert the UDP datagrams to a BytesMut for the registry
    let first_datagram = match initial_datagrams.first() {
      Some(datagram) => datagram,
      None => return Ok(ProbeResult::Success(Self::Any)),
    };

    let mut buffer = BytesMut::from(first_datagram);

    // Try detection with the registry
    match registry.detect_protocol(&mut buffer).await? {
      ProbeResult::Success(protocol) => Ok(ProbeResult::Success(protocol)),
      ProbeResult::Failure => {
        debug!("Untyped UDP connection detected");
        Ok(ProbeResult::Success(Self::Any))
      }
      ProbeResult::PollNext => {
        // For UDP, we usually have all the data we need in the first packet
        // If we need more, return PollNext to indicate we need more datagrams

        // Store the protocol that requested more data (for compatibility)
        initial_datagrams.probed_as_pollnext.insert(Self::Any);
        Ok(ProbeResult::PollNext)
      }
    }
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, derive_builder::Builder)]
/// Single Udp proxy struct
pub struct UdpProxy {
  /// Bound socket address to listen on, exposed to the client
  listen_on: SocketAddr,

  /// Socket address to write on, the actual destination routed for protocol types
  destination_mux: Arc<UdpDestinationMux>,

  /// Tokio runtime handle
  runtime_handle: tokio::runtime::Handle,

  /// Connection counter, set shared counter if #connections of all UDP proxies are needed
  #[builder(default = "ConnectionCountSum::default()")]
  connection_count: ConnectionCountSum<SocketAddr>,

  /// Max UDP concurrent connections
  #[builder(default = "crate::constants::MAX_UDP_CONCURRENT_CONNECTIONS")]
  max_connections: usize,
}

impl UdpProxy {
  pub async fn start(&self, cancel_token: CancellationToken) -> Result<(), ProxyError> {
    info!("Starting UDP proxy on {}", self.listen_on);

    // bind the socket to listen on the given address
    let udp_socket = UdpSocket::from_std(bind_udp_socket(&self.listen_on)?)?;

    // Channel to receive incoming datagram from the source
    let udp_socket_rx = Arc::new(udp_socket);

    // clone for sending back upstream responses to the original source by each individual spawned task
    let udp_socket_tx = Arc::clone(&udp_socket_rx);

    // Build the UDP connection pool
    let udp_connection_pool = Arc::new(UdpConnectionPool::new(self.runtime_handle.clone(), cancel_token.clone()));

    // Set the initial connection count
    self.connection_count.set(self.listen_on, 0);

    // Setup buffer
    let mut udp_buf = vec![0u8; UDP_BUFFER_SIZE];

    /* ----------------- */
    // Start the initial datagram buffer pool service for source socket address to handle multiple datagrams for detection
    let udp_initial_datagrams_buffer_pool = UdpInitialDatagramsBufferPool::new((self, &udp_socket_tx, &udp_connection_pool));
    let udp_initial_datagrams_tx = udp_initial_datagrams_buffer_pool.spawn_service(cancel_token.clone());

    /* ----------------- */
    // Prune inactive connections periodically
    self.runtime_handle.spawn({
      let udp_connection_pool = udp_connection_pool.clone();
      let cancel_token = cancel_token.clone();
      let connection_count = self.connection_count.clone();
      connection_pruner_service(self.listen_on, connection_count, udp_connection_pool, cancel_token)
    });

    /* ----------------- */
    let listener_service = async {
      loop {
        let (buf_size, src_addr) = match udp_socket_rx.recv_from(&mut udp_buf).await {
          Err(e) => {
            error!("Error in UDP listener for downstream: {e}");
            break;
          }
          Ok(res) => res,
        };
        trace!("received {} bytes from {} [source]", buf_size, src_addr);

        // Prune inactive connections first
        udp_connection_pool.prune_inactive_connections();

        if let Some(conn) = udp_connection_pool.get(&src_addr) {
          // Handle case there is an existing connection
          debug!("Found existing connection for {}", src_addr);
          let _ = conn.send(&udp_buf[..buf_size]).await;
          // here we ignore the error, as the connection might be closed
          continue;
        }

        // Handle case there is no existing connection
        debug!("No existing connection for {}", src_addr);

        // Buffer the initial datagram
        if let Err(e) = udp_initial_datagrams_tx.send((src_addr, udp_buf[..buf_size].to_vec())).await {
          error!("Failed to buffer the initial UDP datagram: {e}");
          continue;
        }
      }
      Ok(()) as Result<(), ProxyError>
    };

    tokio::select! {
      _ = listener_service => {
        error!("UDP proxy stopped");
      }
      _ = cancel_token.cancelled() => {
        warn!("UDP proxy cancelled");
      }
    }
    Ok(())
  }
}

/* ---------------------------------------------------------- */
/// Connection pruner service to prune inactive connections periodically
async fn connection_pruner_service(
  listen_on: SocketAddr,
  connection_count: ConnectionCountSum<SocketAddr>,
  udp_connection_pool: Arc<UdpConnectionPool>,
  cancel_token: CancellationToken,
) {
  let service = async {
    loop {
      tokio::time::sleep(tokio::time::Duration::from_secs(
        crate::constants::UDP_CONNECTION_PRUNE_INTERVAL,
      ))
      .await;
      udp_connection_pool.prune_inactive_connections();
      connection_count.set(listen_on, udp_connection_pool.local_pool_size());
      debug!(
        "Current connection: (local: {}, global: {}) @{}",
        udp_connection_pool.local_pool_size(),
        connection_count.current(),
        listen_on,
      );
    }
  };
  tokio::select! {
    _ = service => (),
    _ = cancel_token.cancelled() => {
      warn!("UDP connection pruner cancelled");
    }
  }
}

/* ---------------------------------------------------------- */
/// DashMap type alias, uses ahash::RandomState as hashbuilder
type DashMap<K, V> = dashmap::DashMap<K, V, ahash::RandomState>;

#[derive(Clone)]
struct UdpInitialDatagrams {
  /// inner buffer of multiple UDP datagram payloads
  inner: Vec<Vec<u8>>,
  /// created at
  created_at: Arc<AtomicU64>,
  /// Protocols that were detected as 'poll_next'
  probed_as_pollnext: std::collections::HashSet<UdpProbedProtocol>,
}

impl UdpInitialDatagrams {
  /// Get the first datagram
  fn first(&self) -> Option<&[u8]> {
    self.inner.first().map(|v| v.as_slice())
  }
}

/* ---------------------------------------------------------- */
#[derive(Clone)]
/// Temporary buffer pool of initial UDP datagrams dispatched from each clients.
/// This is used to buffer the initial datagrams of each client, probe the destination, and then establish a UDP connection.
struct UdpInitialDatagramsBufferPool {
  /// listening socket address
  listen_on: SocketAddr,

  /// inner hashmap of mapping from client socket address to initial datagrams buffer
  inner: DashMap<SocketAddr, UdpInitialDatagrams>,

  /// UDP socket to write on back to the client
  udp_socket_tx: Arc<UdpSocket>,

  /// pointer to udp connection pool
  udp_connection_pool: Arc<UdpConnectionPool>,

  /// Socket address to write on, the actual destination routed for protocol types
  destination_mux: Arc<UdpDestinationMux>,

  /// Tokio runtime handle
  runtime_handle: tokio::runtime::Handle,

  /// Connection counter, set shared counter if #connections of all UDP proxies are needed
  connection_count: ConnectionCountSum<SocketAddr>,

  /// Max UDP concurrent connections
  max_connections: usize,
}

impl UdpInitialDatagramsBufferPool {
  /// Create a new UdpInitialDatagramsBufferPool
  fn new((udp_proxy, udp_socket_tx, udp_conn_pool): (&UdpProxy, &Arc<UdpSocket>, &Arc<UdpConnectionPool>)) -> Self {
    Self {
      listen_on: udp_proxy.listen_on,
      inner: DashMap::with_hasher(ahash::RandomState::default()),
      udp_socket_tx: udp_socket_tx.clone(),
      udp_connection_pool: udp_conn_pool.clone(),
      destination_mux: udp_proxy.destination_mux.clone(),
      runtime_handle: udp_proxy.runtime_handle.clone(),
      connection_count: udp_proxy.connection_count.clone(),
      max_connections: udp_proxy.max_connections,
    }
  }
  /// Start the UdpInitialDatagramsBufferPool
  fn spawn_service(&self, cancel_token: CancellationToken) -> mpsc::Sender<(SocketAddr, Vec<u8>)> {
    let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(UDP_BUFFER_SIZE);

    let self_clone = self.clone();
    let service = async move {
      loop {
        let Some((src_addr, udp_datagram)) = rx.recv().await else {
          warn!("UDP buffering channel closed");
          break;
        };
        // Prune expired datagram buffers
        self_clone.inner.retain(|_, v| {
          let elapsed = get_since_the_epoch() - v.created_at.load(std::sync::atomic::Ordering::Relaxed);
          if elapsed < crate::constants::UDP_INITIAL_BUFFER_LIFETIME {
            debug!("Pruning expired datagram buffer for {}", src_addr);
          }
          elapsed < crate::constants::UDP_INITIAL_BUFFER_LIFETIME
        });

        // Check the initial datagram buffer
        let mut initial_datagrams = match self_clone.inner.get(&src_addr) {
          Some(datagrams) => {
            debug!("Found existing UDP datagram buffer for {}", src_addr);
            let mut datagrams = datagrams.clone();
            datagrams.inner.push(udp_datagram);
            datagrams
          }
          None => {
            // Check the connection limit
            if self_clone.max_connections > 0 && self_clone.connection_count.current() >= self_clone.max_connections {
              warn!("UDP connection limit reached: {}", self_clone.max_connections);
              continue;
            }
            debug!("No existing initial datagram buffer for {}", src_addr);
            UdpInitialDatagrams {
              inner: vec![udp_datagram],
              created_at: Arc::new(AtomicU64::new(get_since_the_epoch())),
              probed_as_pollnext: Default::default(),
            }
          }
        };

        // Handle with probe result
        let Ok(probe_result) = UdpProbedProtocol::detect_protocol(&mut initial_datagrams).await else {
          error!("Failed to probe protocol from the incoming datagram");
          continue;
        };
        let probed_protocol = match probe_result {
          ProbeResult::Success(protocol) => protocol,
          ProbeResult::PollNext => {
            // add the datagram buffer back to the buffer pool
            self_clone.inner.insert(src_addr, initial_datagrams);
            continue;
          }
          ProbeResult::Failure => unreachable!(),
        };

        // Delete entry from the buffer pool
        debug!("Release the datagram buffer for {}", src_addr);
        self_clone.inner.remove(&src_addr);

        let Ok(found_dst) = self_clone.destination_mux.find_destination(&probed_protocol) else {
          error!("No destination address found for protocol: {}", probed_protocol);
          continue;
        };
        let udp_dst_inner = match &found_dst {
          FoundUdpDestination::Udp(dst) => dst,
          FoundUdpDestination::Quic(dst) => dst.destination(),
        };
        let Ok(conn) = self_clone
          .udp_connection_pool
          .create_new_connection(
            &src_addr,
            udp_dst_inner,
            &probed_protocol.proto_type(),
            self_clone.udp_socket_tx.clone(),
          )
          .await
        else {
          continue;
        };

        let _ = conn.send_many(&initial_datagrams.inner).await;
        // here we ignore the error, as the connection might be closed
        self_clone
          .connection_count
          .set(self_clone.listen_on, self_clone.udp_connection_pool.local_pool_size());
        debug!(
          "Current connection: (local: {}, global: {}) @{}",
          self_clone.udp_connection_pool.local_pool_size(),
          self_clone.connection_count.current(),
          self_clone.listen_on,
        );
      }
    };

    self.runtime_handle.spawn({
      let child_token = cancel_token.child_token();
      async move {
        tokio::select! {
          _ = service => {
            warn!("UDP initial datagram buffer pool stopped");
            cancel_token.cancel();
          },
          _ = child_token.cancelled() => {
            info!("UDP initial datagram buffer pool cancelled");
          }
        }
      }
    });

    tx
  }
}
