use crate::{
  config::EchProtocolConfig,
  constants::UDP_BUFFER_SIZE,
  count::ConnectionCountSum,
  destination::{Destination, DestinationBuilder, LoadBalance, TlsDestinationItem},
  error::{ProxyBuildError, ProxyError},
  probe::ProbeResult,
  proto::UdpProtocolType,
  socket::bind_udp_socket,
  time_util::get_since_the_epoch,
  trace::{debug, error, info, warn},
  udp_conn::UdpConnectionPool,
};
use quic_tls::{TlsClientHello, TlsProbeFailure, probe_quic_initial_packets};
use std::{
  net::SocketAddr,
  sync::{Arc, atomic::AtomicU64},
};
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;

/// Type alias for QUIC destinations
type QuicDestinations = crate::destination::TlsDestinations<UdpDestinationInner>;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
enum UdpDestination {
  /// Udp destination
  Udp(UdpDestinationInner),
  /// Udp destinations specific for QUIC
  Quic(QuicDestinations),
}
#[derive(Debug, Clone)]
/// Udp destination struct
pub(crate) struct UdpDestinationInner {
  /// Destination socket address
  inner: Destination,
  /// Connection idle lifetime in seconds
  /// If set to 0, no limit is applied for the destination
  connection_idle_lifetime: u32,
}

#[derive(Debug, Clone)]
/// Destination struct found in the multiplexer from TcpProbedProtocol
enum FoundUdpDestination {
  /// Udp destination
  Udp(UdpDestinationInner),
  /// Tls destination
  Quic(TlsDestinationItem<UdpDestinationInner>),
}

impl TryFrom<(&[SocketAddr], Option<&LoadBalance>, Option<u32>)> for UdpDestinationInner {
  type Error = ProxyBuildError;
  fn try_from(
    (dst_addrs, load_balance, connection_idle_lifetime): (&[SocketAddr], Option<&LoadBalance>, Option<u32>),
  ) -> Result<Self, Self::Error> {
    let binding = LoadBalance::default();
    let load_balance = load_balance.unwrap_or(&binding);
    let connection_idle_lifetime = connection_idle_lifetime.unwrap_or(crate::constants::UDP_CONNECTION_IDLE_LIFETIME);

    let inner = DestinationBuilder::default()
      .dst_addrs(dst_addrs.to_vec())
      .load_balance(*load_balance)
      .build()?;
    Ok(Self {
      inner,
      connection_idle_lifetime,
    })
  }
}

impl UdpDestinationInner {
  /// Get the destination socket address
  pub(crate) fn get_destination(&self, src_addr: &SocketAddr) -> Result<&SocketAddr, ProxyError> {
    self.inner.get_destination(src_addr)
  }
  /// Get the connection idle lifetime
  pub(crate) fn get_connection_idle_lifetime(&self) -> u32 {
    self.connection_idle_lifetime
  }
}

#[allow(unused)]
impl FoundUdpDestination {
  /// Get the destination socket address
  pub(crate) fn get_destination(&self, src_addr: &SocketAddr) -> Result<&SocketAddr, ProxyError> {
    match self {
      Self::Udp(dst) => dst.get_destination(src_addr),
      Self::Quic(dst) => dst.destination().get_destination(src_addr),
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
  /// Multiplexed TCP destinations
  #[builder(default = "ahash::HashMap::default()")]
  inner: ahash::HashMap<UdpProtocolType, UdpDestination>,
}

impl UdpDestinationMuxBuilder {
  /// Create a new Udp destination multiplexer builder
  pub(crate) fn set_base(
    &mut self,
    proto_type: UdpProtocolType,
    addrs: &[SocketAddr],
    load_balance: Option<&LoadBalance>,
    lifetime: Option<u32>,
  ) -> &mut Self {
    let udp_dest = UdpDestinationInner::try_from((addrs, load_balance, lifetime));
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
        current_quic.add(&[], &[], udp_dest_inner, None);
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
  pub(crate) fn set_quic(
    &mut self,
    addrs: &[SocketAddr],
    load_balance: Option<&LoadBalance>,
    lifetime: Option<u32>,
    server_names: Option<&[&str]>,
    alpn: Option<&[&str]>,
    _ech: Option<&EchProtocolConfig>, // TODO: Consider how to handle TLS ClientHello for QUIC + ECH, especially reassembling the datagram for TLS ClientHello Inner
  ) -> &mut Self {
    let udp_dest = UdpDestinationInner::try_from((addrs, load_balance, lifetime));
    if udp_dest.is_err() {
      return self;
    }
    let udp_dest_inner = udp_dest.unwrap();
    let mut inner = self.inner.clone().unwrap_or_default();

    let mut current_quic = if let Some(UdpDestination::Quic(current)) = inner.get(&UdpProtocolType::Quic).cloned() {
      current
    } else {
      QuicDestinations::new()
    };
    current_quic.add(
      server_names.unwrap_or_default(),
      alpn.unwrap_or_default(),
      udp_dest_inner,
      None, // TODO: currently NONE for ech
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
          return Err(ProxyError::NoDestinationAddressForProtocol);
        };
        if let Some(found) = quic_destinations.find(client_hello) {
          debug!("Setting up dest addr for {proto_type}");
          return Ok(FoundUdpDestination::Quic(found.clone()));
        } else {
          return Err(ProxyError::NoDestinationAddressForProtocol);
        }
      }
      _ => {}
    };

    // if nothing is found, check for the default destination
    if proto_type == UdpProtocolType::Any {
      return Err(ProxyError::NoDestinationAddressForProtocol);
    }
    // Check for the default destination
    let destination_any = self
      .inner
      .get(&UdpProtocolType::Any)
      .cloned()
      .ok_or(ProxyError::NoDestinationAddressForProtocol)?;
    let UdpDestination::Udp(dst) = destination_any else {
      return Err(ProxyError::NoDestinationAddressForProtocol);
    };
    debug!("Setting up dest addr for unspecified proto");
    Ok(FoundUdpDestination::Udp(dst.clone()))
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// UDP probed protocol, specific protocols like SSH, and default is "any".
pub(crate) enum UdpProbedProtocol {
  /// any, default
  Any,
  /// wireguard
  Wireguard,
  /// quic
  Quic(TlsClientHello),
  // TODO: and more ...
}

impl UdpProbedProtocol {
  fn proto_type(&self) -> UdpProtocolType {
    match self {
      Self::Any => UdpProtocolType::Any,
      Self::Wireguard => UdpProtocolType::Wireguard,
      Self::Quic(_) => UdpProtocolType::Quic,
    }
  }
}

impl std::fmt::Display for UdpProbedProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Any => write!(f, "Any"),
      Self::Wireguard => write!(f, "Wireguard"),
      Self::Quic(_) => write!(f, "QUIC"),
      // TODO: and more...
    }
  }
}

/* ------ */
/// Is Wireguard protocol?
fn is_wireguard(initial_datagrams: &mut UdpInitialDatagrams) -> ProbeResult<UdpProbedProtocol> {
  // Wireguard protocol 'initiation' detection [only Handshake]
  // Thus this may not be a reliable way to detect Wireguard protocol
  // since UDP connection will be lost if the handshake interval is set to be longer than the connection timeout.
  // https://www.wireguard.com/protocol/
  let Some(first) = initial_datagrams.first() else {
    return ProbeResult::Failure; // unreachable. just in case.
  };

  if first.len() == 148 && first[0] == 0x01 && first[1] == 0x00 && first[2] == 0x00 && first[3] == 0x00 {
    debug!("Wireguard protocol (initiator to responder first message) detected");
    ProbeResult::Success(UdpProbedProtocol::Wireguard)
  } else {
    ProbeResult::Failure
  }
}

/// Is QUIC protocol?
fn is_quic_initial(initial_dagatgrams: &mut UdpInitialDatagrams) -> ProbeResult<UdpProbedProtocol> {
  let initial_datagrams_inner = initial_dagatgrams.inner.as_slice();

  match probe_quic_initial_packets(initial_datagrams_inner) {
    Err(TlsProbeFailure::Failure) => ProbeResult::Failure,
    Err(TlsProbeFailure::PollNext) => {
      initial_dagatgrams
        .probed_as_pollnext
        .insert(UdpProbedProtocol::Quic(Default::default()));
      ProbeResult::PollNext
    }
    Ok(client_hello_info) => ProbeResult::Success(UdpProbedProtocol::Quic(client_hello_info)),
  }
}

impl UdpProbedProtocol {
  /// Detect the protocol from the first few bytes of the incoming datagram
  async fn detect_protocol(initial_datagrams: &mut UdpInitialDatagrams) -> Result<ProbeResult<Self>, ProxyError> {
    // TODO: Add more protocol detection patterns

    // Probe functions
    let probe_functions = if initial_datagrams.probed_as_pollnext.is_empty() {
      // No candidate probed as PollNext, i.e., Round 1
      vec![is_wireguard, is_quic_initial]
    } else {
      // Round 2 or later
      initial_datagrams
        .probed_as_pollnext
        .iter()
        .map(|p| match p {
          UdpProbedProtocol::Wireguard => is_wireguard,
          UdpProbedProtocol::Quic(_) => is_quic_initial,
          _ => unreachable!(),
        })
        .collect()
    };

    let probe_res = probe_functions.into_iter().map(|f| f(initial_datagrams)).collect::<Vec<_>>();

    // In case any of the probe results is a success, return it
    if let Some(probe_success) = probe_res.iter().find(|r| matches!(r, ProbeResult::Success(_))) {
      return Ok(probe_success.clone());
    };

    // In case any of the probe results is PollNext, return it
    if let Some(probe_pollnext) = probe_res.iter().find(|r| matches!(r, ProbeResult::PollNext)) {
      return Ok(probe_pollnext.to_owned());
    };

    // All detection finished as failure
    debug!("Untyped UDP connection detected");
    Ok(ProbeResult::Success(Self::Any))
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

  /// Connection counter, set shared counter if #connections of all TCP proxies are needed
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
        debug!("received {} bytes from {} [source]", buf_size, src_addr);

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

  /// Connection counter, set shared counter if #connections of all TCP proxies are needed
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
            &&probed_protocol.proto_type(),
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
