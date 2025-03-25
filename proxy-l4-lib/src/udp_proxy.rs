use crate::{
  constants::UDP_BUFFER_SIZE,
  count::ConnectionCountSum,
  destination::{Destination, DestinationBuilder, LoadBalance},
  error::ProxyError,
  probe::ProbeResult,
  quic::probe_quic_packet,
  socket::bind_udp_socket,
  time_util::get_since_the_epoch,
  tls::{TlsClientHelloInfo, TlsDestinations},
  trace::{debug, error, info, warn},
  udp_conn::UdpConnectionPool,
};
use std::{
  net::SocketAddr,
  sync::{atomic::AtomicU64, Arc},
};
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;

/// Type alias for QUIC destinations
type QuicDestinations = TlsDestinations<UdpDestination>;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
/// Udp destination struct
pub(crate) struct UdpDestination {
  /// Destination socket address
  inner: Destination,
  /// Connection idle lifetime in seconds
  /// If set to 0, no limit is applied for the destination
  connection_idle_lifetime: u32,
}

impl TryFrom<(&[SocketAddr], Option<&LoadBalance>, Option<u32>)> for UdpDestination {
  type Error = ProxyError;
  fn try_from(
    (dst_addrs, load_balance, connection_idle_lifetime): (&[SocketAddr], Option<&LoadBalance>, Option<u32>),
  ) -> Result<Self, Self::Error> {
    let binding = LoadBalance::default();
    let load_balance = load_balance.unwrap_or(&binding);
    let connection_idle_lifetime = connection_idle_lifetime.unwrap_or(crate::constants::UDP_CONNECTION_IDLE_LIFETIME);

    let inner = DestinationBuilder::default()
      .dst_addrs(dst_addrs.to_vec())
      .load_balance(*load_balance)
      .build()
      .map_err(|e| ProxyError::DestinationBuilderError(e.into()))?;
    Ok(Self {
      inner,
      connection_idle_lifetime,
    })
  }
}

impl UdpDestination {
  /// Get the destination socket address
  pub(crate) fn get_destination(&self, src_addr: &SocketAddr) -> Result<&SocketAddr, ProxyError> {
    self
      .inner
      .get_destination(src_addr)
      .map_err(ProxyError::DestinationBuilderError)
  }
  /// Get the connection idle lifetime
  pub(crate) fn get_connection_idle_lifetime(&self) -> u32 {
    self.connection_idle_lifetime
  }
}
/* ---------------------------------------------------------- */
/// Udp destination multiplexer
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct UdpDestinationMux {
  /// destination socket address for any protocol
  /// If this is set, it will be used for all protocols except the specific (non-None) protocols.
  #[builder(setter(custom), default = "None")]
  dst_any: Option<UdpDestination>,
  /// destination socket address for Wireguard protocol
  #[builder(setter(custom), default = "None")]
  dst_wireguard: Option<UdpDestination>,
  /// destination socket address for IETF QUIC protocol
  #[builder(setter(custom), default = "None")]
  dst_quic: Option<QuicDestinations>,
  // TODO: Add more protocols
}

impl UdpDestinationMuxBuilder {
  /* --------------------- */
  pub fn dst_any(&mut self, addrs: &[SocketAddr], load_balance: Option<&LoadBalance>, lifetime: Option<u32>) -> &mut Self {
    let udp_dest = UdpDestination::try_from((addrs, load_balance, lifetime));
    if udp_dest.is_err() {
      return self;
    }
    self.dst_any = Some(udp_dest.ok());
    self
  }
  /* --------------------- */
  pub fn dst_wireguard(&mut self, addrs: &[SocketAddr], load_balance: Option<&LoadBalance>, lifetime: Option<u32>) -> &mut Self {
    let udp_dest = UdpDestination::try_from((addrs, load_balance, lifetime));
    if udp_dest.is_err() {
      return self;
    }
    self.dst_wireguard = Some(udp_dest.ok());
    self
  }
  /* --------------------- */
  pub fn dst_quic(
    &mut self,
    addrs: &[SocketAddr],
    load_balance: Option<&LoadBalance>,
    lifetime: Option<u32>,
    server_names: Option<&[&str]>,
    alpn: Option<&[&str]>,
  ) -> &mut Self {
    let udp_dest = UdpDestination::try_from((addrs, load_balance, lifetime));
    if udp_dest.is_err() {
      return self;
    }

    let udp_dest = udp_dest.unwrap();
    let mut current = if self.dst_quic.as_ref().is_none_or(|d| d.is_none()) {
      TlsDestinations::<UdpDestination>::new()
    } else {
      self.dst_quic.as_ref().unwrap().as_ref().unwrap().clone()
    };

    let server_names = server_names.unwrap_or_default();
    let alpn = alpn.unwrap_or_default();
    current.add(server_names, alpn, udp_dest);

    self.dst_quic = Some(Some(current));
    self
  }
}

impl UdpDestinationMux {
  /// Check if the destination mux is empty
  pub fn is_empty(&self) -> bool {
    self.dst_any.is_none() && self.dst_wireguard.is_none() && self.dst_quic.is_none()
  }
  /// Get the destination socket address for the given protocol
  pub(crate) fn get_destination(&self, protocol: &UdpProxyProtocol) -> Result<UdpDestination, ProxyError> {
    match protocol {
      // No matched protocol found from the pattern
      UdpProxyProtocol::Any => {
        if let Some(dst) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(dst.clone())
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
      UdpProxyProtocol::Wireguard => {
        if let Some(dst) = &self.dst_wireguard {
          debug!("Setting up dest addr for Wireguard proto");
          Ok(dst.clone())
        } else if let Some(dst) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(dst.clone())
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
      UdpProxyProtocol::Quic(client_hello_info) => {
        if let Some(dst) = &self.dst_quic {
          debug!("Setting up dest addr for QUIC proto");
          if let Some(found) = dst.find(client_hello_info) {
            Ok(found.clone())
          } else {
            Err(ProxyError::NoDestinationAddressForProtocol)
          }
        } else if let Some(dst) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(dst.clone())
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
    }
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
/// TCP proxy protocol, specific protocols like SSH, and default is "any".
pub(crate) enum UdpProxyProtocol {
  /// any, default
  Any,
  /// wireguard
  Wireguard,
  /// quic
  Quic(TlsClientHelloInfo),
  // TODO: and more ...
}

impl std::fmt::Display for UdpProxyProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Any => write!(f, "Any"),
      Self::Wireguard => write!(f, "Wireguard"),
      Self::Quic(_) => write!(f, "QUIC"),
      // TODO: and more...
    }
  }
}

impl UdpProxyProtocol {
  /// Detect the protocol from the first few bytes of the incoming packet
  async fn detect_protocol(initial_packets: &UdpInitialPackets) -> Result<ProbeResult<Self>, ProxyError> {
    let initial_packets = &initial_packets.inner[0]; //TODO: FIX ME

    /* ------ */
    // Wireguard protocol 'initiation' detection [only Handshake]
    // Thus this may not be a reliable way to detect Wireguard protocol
    // since UDP connection will be lost if the handshake interval is set to be longer than the connection timeout.
    // https://www.wireguard.com/protocol/
    if initial_packets.len() == 148
      && initial_packets[0] == 0x01
      && initial_packets[1] == 0x00
      && initial_packets[2] == 0x00
      && initial_packets[3] == 0x00
    {
      debug!("Wireguard protocol (initiator to responder first message) detected");
      return Ok(ProbeResult::Success(Self::Wireguard));
    }
    /* ------ */
    // IETF QUIC handshake protocol detection
    if let Some(info) = probe_quic_packet(initial_packets) {
      debug!("IETF QUIC protocol detected");
      return Ok(ProbeResult::Success(Self::Quic(info)));
    }

    // TODO: Add more protocol detection patterns
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

    // Channel to receive incoming packets from the source
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
    // Start the initial packets buffer pool service for source socket address to handle multiple packets for detection
    let udp_initial_packets_buffer_pool = UdpInitialPacketsBufferPool::new((self, &udp_socket_tx, &udp_connection_pool));
    let udp_initial_packets_tx = udp_initial_packets_buffer_pool.spawn_service(cancel_token.clone());

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

        // Buffer the initial packet
        if let Err(e) = udp_initial_packets_tx.send((src_addr, udp_buf[..buf_size].to_vec())).await {
          error!("Failed to buffer the initial packet: {e}");
          continue;
        }

        // // Check the connection limit
        // if self.max_connections > 0 && self.connection_count.current() >= self.max_connections {
        //   warn!("UDP connection limit reached: {}", self.max_connections);
        //   continue;
        // }
        // let protocol = UdpProxyProtocol::detect_protocol(&udp_buf[..buf_size]).await?;
        // let Ok(udp_dst) = self.destination_mux.get_destination(&protocol) else {
        //   error!("No destination address found for protocol: {}", protocol);
        //   continue;
        // };
        // let Ok(conn) = udp_connection_pool
        //   .create_new_connection(&src_addr, &udp_dst, udp_socket_tx.clone())
        //   .await
        // else {
        //   continue;
        // };
        // let _ = conn.send(udp_buf[..buf_size].to_vec()).await;
        // // here we ignore the error, as the connection might be closed
        // self
        //   .connection_count
        //   .set(self.listen_on, udp_connection_pool.local_pool_size());
        // debug!(
        //   "Current connection: (local: {}, global: {}) @{}",
        //   udp_connection_pool.local_pool_size(),
        //   self.connection_count.current(),
        //   self.listen_on,
        // );
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
struct UdpInitialPackets {
  /// inner buffer of multiple UDP packet payloads
  inner: Vec<Vec<u8>>,
  /// created at
  created_at: Arc<AtomicU64>,
}

/* ---------------------------------------------------------- */
#[derive(Clone)]
/// Temporary buffer pool of initial packets dispatched from each clients.
/// This is used to buffer the initial packets of each client, probe the destination, and then establish a UDP connection.
struct UdpInitialPacketsBufferPool {
  /// listening socket address
  listen_on: SocketAddr,

  /// inner hashmap of mapping from client socket address to initial packets buffer
  inner: DashMap<SocketAddr, UdpInitialPackets>,

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

impl UdpInitialPacketsBufferPool {
  /// Create a new UdpInitialPacketsBufferPool
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
  /// Start the UdpInitialPacketsBufferPool
  fn spawn_service(&self, cancel_token: CancellationToken) -> mpsc::Sender<(SocketAddr, Vec<u8>)> {
    let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(UDP_BUFFER_SIZE);

    let self_clone = self.clone();
    let service = async move {
      loop {
        let Some((src_addr, udp_packet)) = rx.recv().await else {
          warn!("UDP buffering channel closed");
          break;
        };
        // Prune expired packet buffers
        self_clone.inner.retain(|_, v| {
          let elapsed = get_since_the_epoch() - v.created_at.load(std::sync::atomic::Ordering::Relaxed);
          if elapsed < crate::constants::UDP_INITIAL_BUFFER_LIFETIME {
            debug!("Pruning expired packet buffer for {}", src_addr);
          }
          elapsed < crate::constants::UDP_INITIAL_BUFFER_LIFETIME
        });

        // Check the initial packet buffer
        let initial_packets = match self_clone.inner.get(&src_addr) {
          Some(packets) => {
            debug!("Found existing packet buffer for {}", src_addr);
            let mut packets = packets.clone();
            packets.inner.push(udp_packet);
            packets
          }
          None => {
            // Check the connection limit
            if self_clone.max_connections > 0 && self_clone.connection_count.current() >= self_clone.max_connections {
              warn!("UDP connection limit reached: {}", self_clone.max_connections);
              continue;
            }
            debug!("No existing initial packet buffer for {}", src_addr);
            UdpInitialPackets {
              inner: vec![udp_packet],
              created_at: Arc::new(AtomicU64::new(get_since_the_epoch())),
            }
          }
        };

        // Handle with probe result
        let Ok(probe_result) = UdpProxyProtocol::detect_protocol(&initial_packets).await else {
          error!("Failed to probe protocol from the incoming packet");
          continue;
        };
        let protocol = match probe_result {
          ProbeResult::Success(protocol) => protocol,
          ProbeResult::PollNext => {
            // add the packet buffer back to the buffer pool
            self_clone.inner.insert(src_addr, initial_packets);
            continue;
          }
          ProbeResult::Failure => unreachable!(),
        };

        // Delete entry from the buffer pool
        debug!("Release the packet buffer for {}", src_addr);
        self_clone.inner.remove(&src_addr);

        let Ok(udp_dst) = self_clone.destination_mux.get_destination(&protocol) else {
          error!("No destination address found for protocol: {}", protocol);
          continue;
        };
        let Ok(conn) = self_clone
          .udp_connection_pool
          .create_new_connection(&src_addr, &udp_dst, self_clone.udp_socket_tx.clone())
          .await
        else {
          continue;
        };

        let _ = conn.send_many(&initial_packets.inner).await;
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
      // let udp_initial_packets_buffer_pool = self.clone();
      let child_token = cancel_token.child_token();
      async move {
        tokio::select! {
          _ = service => {
            warn!("UDP initial packets buffer pool stopped");
            cancel_token.cancel();
          },
          _ = child_token.cancelled() => {
            info!("UDP initial packets buffer pool cancelled");
          }
        }
      }
    });

    tx
  }
}
