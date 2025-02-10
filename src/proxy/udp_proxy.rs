use super::{
  constants::{UDP_BUFFER_SIZE, UDP_CHANNEL_CAPACITY},
  error::ProxyError,
  socket::bind_udp_socket,
};
use crate::log::{debug, error, info, warn};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::mpsc};
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
  // /// Detect the protocol from the first few bytes of the incoming stream
  // pub async fn detect_protocol(incoming_stream: &TcpStream) -> Result<Self, ProxyError> {
  //   debug!("Untyped UDP connection");
  //   Ok(Self::Any)
  // }
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

    let base_any_socket_v4: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let base_any_socket_v6: SocketAddr = "[::]:0".parse().unwrap();

    // bind the socket to listen on the given address
    let udp_socket = UdpSocket::from_std(bind_udp_socket(&self.listen_on)?)?;

    // Channel to receive incoming packets from the source
    let udp_socket_rx = Arc::new(udp_socket);

    // clone for sending back upstream responses to the original source by each individual spawned task
    let udp_socket_tx = Arc::clone(&udp_socket_rx);

    //   let incoming_listen_on = "127.0.0.1:50553".parse().unwrap();
    //   let outgoing_listen_on = "127.0.0.1:50054".parse().unwrap();
    //   let write_on: SocketAddr = "127.0.0.1:50053".parse().unwrap();
    //   let incoming_udp_socket = UdpSocket::from_std(bind_udp_socket(&incoming_listen_on).unwrap()).unwrap();
    //   let incoming_socket_tx = Arc::new(incoming_udp_socket);
    //   let incoming_socket_rx = incoming_socket_tx.clone();
    //   let outgoing_udp_socket = UdpSocket::from_std(bind_udp_socket(&outgoing_listen_on).unwrap()).unwrap();
    //   let outgoing_socket_tx = Arc::new(outgoing_udp_socket);
    //   let outgoing_socket_rx = outgoing_socket_tx.clone();

    // Setup buffer
    let mut udp_buf = vec![0u8; UDP_BUFFER_SIZE];

    let listener_service = async {
      loop {
        let (buf_size, src_addr) = match udp_socket_rx.recv_from(&mut udp_buf).await {
          Err(e) => {
            println!("Error in UDP listener for downstream: {e}");
            continue;
          }
          Ok(res) => res,
        };
        debug!("received {} bytes from {} [source]", buf_size, src_addr);

        let rx_packet_buf = udp_buf[..buf_size].to_vec();

        // TODO: poc
        // TODO: manage for each connection context (by the source address + port)
        // setup a channel to forward upstream response to the spawned responder task
        // このチャネルはconnectionごとに作成
        // - key: [src_socket_addr, dst_socket_addr]
        // - value: [channel_tx]
        let (channel_tx, mut channel_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(UDP_CHANNEL_CAPACITY);
        let upd_socket_tx_clone = udp_socket_tx.clone();
        let dst = self.destination_mux.get_destination(&UdpProxyProtocol::Any).unwrap();
        let runtime_handle_clone = self.runtime_handle.clone();

        self.runtime_handle.spawn(async move {
          let udp_socket_to_upstream = match dst {
            SocketAddr::V4(_) => UdpSocket::from_std(bind_udp_socket(&base_any_socket_v4)?)?,
            SocketAddr::V6(_) => UdpSocket::from_std(bind_udp_socket(&base_any_socket_v6)?)?,
          };
          debug!(
            "Bound UDP socket for upstream on {}",
            udp_socket_to_upstream
              .local_addr()
              .map(|v| v.to_string())
              .unwrap_or("unknown".to_string())
          );
          let upd_socket_to_upstream_tx = Arc::new(udp_socket_to_upstream);
          let udp_socket_to_upstream_rx = upd_socket_to_upstream_tx.clone();

          runtime_handle_clone.spawn(async move {
            let mut udp_buf = vec![0u8; UDP_BUFFER_SIZE];
            // This should be loop to handle multiple packets from the same source
            let (buf_size, _) = match udp_socket_to_upstream_rx.recv_from(&mut udp_buf).await {
              Err(e) => {
                error!("Error in UDP listener for upstream: {e}");
                return Ok(());
              }
              Ok(res) => res,
            };
            debug!("received {} bytes from {} [upstream]", buf_size, dst);
            let response = udp_buf[..buf_size].to_vec();
            if let Err(e) = upd_socket_tx_clone.send_to(response.as_slice(), src_addr).await {
              error!("Error sending packet to upstream: {e}");
            };

            Ok(()) as Result<(), ProxyError>
          });

          // This should be loop to handle multiple packets from the same source
          let Some((packet, _)) = channel_rx.recv().await else {
            error!("Error receiving packet from channel");
            return Ok(());
          };
          if let Err(e) = upd_socket_to_upstream_tx.send_to(packet.as_slice(), dst).await {
            error!("Error sending packet to upstream: {e}");
          };
          Ok(()) as Result<(), ProxyError>
        });
        if let Err(e) = channel_tx.send((rx_packet_buf, src_addr)).await {
          error!("Error sending packet to channel: {e}");
        }
      }
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
