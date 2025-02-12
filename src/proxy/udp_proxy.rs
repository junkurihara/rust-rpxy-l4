use super::{constants::UDP_BUFFER_SIZE, error::ProxyError, socket::bind_udp_socket};
use crate::{
  log::{debug, error, info, warn},
  proxy::{constants::UDP_CONNECTION_IDLE_LIFETIME, udp_conn::UdpConnectionPool},
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/* ---------------------------------------------------------- */
/// Udp destination multiplexer
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct UdpDestinationMux {
  /// destination socket address for any protocol
  /// If this is set, it will be used for all protocols except the specific (non-None) protocols.
  #[builder(setter(custom), default = "None")]
  dst_any: Option<SocketAddr>,
  // TODO: Add more protocols
}

impl UdpDestinationMuxBuilder {
  pub fn dst_any(&mut self, addr: SocketAddr) -> &mut Self {
    self.dst_any = Some(Some(addr));
    self
  }
}

impl UdpDestinationMux {
  /// Get the destination socket address for the given protocol
  pub fn get_destination(&self, protocol: &UdpProxyProtocol) -> Result<SocketAddr, ProxyError> {
    match protocol {
      // No matched protocol found from the pattern
      UdpProxyProtocol::Any => {
        if let Some(addr) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(*addr)
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
pub enum UdpProxyProtocol {
  /// any, default
  Any,
  // TODO: and more ...
}

impl std::fmt::Display for UdpProxyProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Any => write!(f, "Any"),
      // TODO: and more...
    }
  }
}

impl UdpProxyProtocol {
  /// Detect the protocol from the first few bytes of the incoming packet
  pub async fn detect_protocol(_incoming_buf: &[u8]) -> Result<Self, ProxyError> {
    // TODO: Implement protocol detection
    debug!("Untyped UDP connection");
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

    let udp_connection_pool = UdpConnectionPool::new(
      UDP_CONNECTION_IDLE_LIFETIME, // TODO:
      0,                            // TODO: max_connection, currently no limit
      self.runtime_handle.clone(),
      cancel_token.clone(),
    );

    // Setup buffer
    let mut udp_buf = vec![0u8; UDP_BUFFER_SIZE];

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
        // debug!("UDP packet: {:x?}", &udp_buf[..buf_size]);

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
        let protocol = UdpProxyProtocol::detect_protocol(&udp_buf[..buf_size]).await?;
        let dst_addr = self.destination_mux.get_destination(&protocol)?;
        let Ok(conn) = udp_connection_pool.create_new_connection(&src_addr, &dst_addr, udp_socket_tx.clone()) else {
          continue;
        };
        let _ = conn.send(udp_buf[..buf_size].to_vec()).await;
        // here we ignore the error, as the connection might be closed
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
