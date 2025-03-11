use crate::{
  constants::UDP_BUFFER_SIZE,
  count::ConnectionCountSum,
  destination::{Destination, DestinationBuilder},
  error::ProxyError,
  quic::probe_quic_packet,
  socket::bind_udp_socket,
  tls::{TlsClientHelloInfo, TlsDestinations},
  trace::{debug, error, info, warn},
  udp_conn::UdpConnectionPool,
  LoadBalance,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
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
    self.dst_any = Some(udp_dest.ok());
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
  pub(crate) async fn detect_protocol(incoming_buf: &[u8]) -> Result<Self, ProxyError> {
    /* ------ */
    // Wireguard protocol 'initiation' detection [only Handshake]
    // Thus this may not be a reliable way to detect Wireguard protocol
    // since UDP connection will be lost if the handshake interval is set to be longer than the connection timeout.
    // https://www.wireguard.com/protocol/
    if incoming_buf.len() == 148
      && incoming_buf[0] == 0x01
      && incoming_buf[1] == 0x00
      && incoming_buf[2] == 0x00
      && incoming_buf[3] == 0x00
    {
      debug!("Wireguard protocol (initiator to responder first message) detected");
      return Ok(Self::Wireguard);
    }
    /* ------ */
    // IETF QUIC handshake protocol detection
    if let Some(info) = probe_quic_packet(incoming_buf) {
      debug!("IETF QUIC protocol detected");
      return Ok(Self::Quic(info));
    }

    // TODO: Add more protocol detection patterns
    debug!("Untyped UDP connection detected");
    Ok(Self::Any)
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
  max_connections: u32,
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
          let _ = conn.send(udp_buf[..buf_size].to_vec()).await;
          // here we ignore the error, as the connection might be closed
          continue;
        }

        // Handle case there is no existing connection
        debug!("No existing connection for {}", src_addr);
        // Check the connection limit
        if self.max_connections > 0 && self.connection_count.current() >= self.max_connections as usize {
          warn!("UDP connection limit reached: {}", self.max_connections);
          continue;
        }
        let protocol = UdpProxyProtocol::detect_protocol(&udp_buf[..buf_size]).await?;
        let udp_dst = self.destination_mux.get_destination(&protocol)?;
        let Ok(conn) = udp_connection_pool
          .create_new_connection(&src_addr, &udp_dst, udp_socket_tx.clone())
          .await
        else {
          continue;
        };
        let _ = conn.send(udp_buf[..buf_size].to_vec()).await;
        // here we ignore the error, as the connection might be closed
        self
          .connection_count
          .set(self.listen_on, udp_connection_pool.local_pool_size());
        debug!(
          "Current connection: (local: {}, global: {}) @{}",
          udp_connection_pool.local_pool_size(),
          self.connection_count.current(),
          self.listen_on,
        );
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
