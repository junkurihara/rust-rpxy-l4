use super::{
  constants::{TCP_PROTOCOL_DETECTION_BUFFER_SIZE, TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC},
  error::ProxyError,
  socket::bind_tcp_socket,
  tls::is_tls_handshake,
  trace::*,
};

use std::{net::SocketAddr, sync::Arc};
use tokio::{
  io::copy_bidirectional,
  net::TcpStream,
  time::{timeout, Duration},
};
use tokio_util::sync::CancellationToken;

/* ---------------------------------------------------------- */
/// TCP destination multiplexer
/// TODO: Load balance with multiple addresses
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct TcpDestinationMux {
  /// destination socket address for any protocol
  /// If this is set, it will be used for all protocols except the specific (non-None) protocols.
  #[builder(setter(custom), default = "None")]
  dst_any: Option<SocketAddr>,
  /// destination socket address for SSH protocol
  #[builder(setter(custom), default = "None")]
  dst_ssh: Option<SocketAddr>,
  #[builder(setter(custom), default = "None")]
  dst_tls: Option<SocketAddr>,
  #[builder(setter(custom), default = "None")]
  dst_http: Option<SocketAddr>,
  // TODO: Add more protocols
}

impl TcpDestinationMuxBuilder {
  pub fn dst_any(&mut self, addr: SocketAddr) -> &mut Self {
    self.dst_any = Some(Some(addr));
    self
  }
  pub fn dst_ssh(&mut self, addr: SocketAddr) -> &mut Self {
    self.dst_ssh = Some(Some(addr));
    self
  }
  pub fn dst_tls(&mut self, addr: SocketAddr) -> &mut Self {
    self.dst_tls = Some(Some(addr));
    self
  }
  pub fn dst_http(&mut self, addr: SocketAddr) -> &mut Self {
    self.dst_http = Some(Some(addr));
    self
  }
}

impl TcpDestinationMux {
  /// Get the destination socket address for the given protocol
  pub fn get_destination(&self, protocol: &TcpProxyProtocol) -> Result<SocketAddr, ProxyError> {
    match protocol {
      // No matched protocol found from the pattern
      TcpProxyProtocol::Any => {
        if let Some(addr) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(*addr)
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
      // Found SSH protocol
      TcpProxyProtocol::Ssh => {
        if let Some(addr) = &self.dst_ssh {
          debug!("Setting up dest addr specific to SSH");
          Ok(*addr)
        } else if let Some(addr) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(*addr)
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
      // Found TLS protocol
      TcpProxyProtocol::Tls => {
        if let Some(addr) = &self.dst_tls {
          debug!("Setting up dest addr specific to TLS");
          Ok(*addr)
        } else if let Some(addr) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(*addr)
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
      // Found HTTP protocol
      TcpProxyProtocol::Http => {
        if let Some(addr) = &self.dst_http {
          debug!("Setting up dest addr specific to HTTP");
          Ok(*addr)
        } else if let Some(addr) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(*addr)
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      } // TODO: Add more protocols
    }
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
/// TCP proxy protocol, specific protocols like SSH, and default is "any".
pub enum TcpProxyProtocol {
  /// any, default
  Any,
  /// SSH
  Ssh,
  /// TLS
  Tls,
  /// Plaintext HTTP
  Http,
  // TODO: and more ...
}

impl std::fmt::Display for TcpProxyProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Any => write!(f, "Any"),
      Self::Ssh => write!(f, "SSH"),
      Self::Tls => write!(f, "TLS"),
      Self::Http => write!(f, "HTTP"),
      // TODO: and more...
    }
  }
}

impl TcpProxyProtocol {
  /// Detect the protocol from the first few bytes of the incoming stream
  pub async fn detect_protocol(incoming_stream: &TcpStream) -> Result<Self, ProxyError> {
    let mut buf = vec![0u8; TCP_PROTOCOL_DETECTION_BUFFER_SIZE];
    let Ok(res) = timeout(
      Duration::from_millis(TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC),
      incoming_stream.peek(&mut buf),
    )
    .await
    else {
      error!("Failed to detect protocol: timeout");
      return Err(ProxyError::TimeOutToReadTcpStream);
    };
    let read_len = res?;
    if read_len == 0 {
      error!("No data received");
      return Err(ProxyError::NoDataReceivedTcpStream);
    }

    // TODO: Add more protocol detection
    if buf.starts_with(b"SSH-") {
      debug!("SSH connection detected");
      return Ok(Self::Ssh);
    }

    if is_tls_handshake(buf.as_slice()) {
      debug!("TLS connection detected");
      return Ok(Self::Tls);
    }

    if buf.windows(4).any(|w| w.eq(b"HTTP")) {
      debug!("HTTP connection detected");
      return Ok(Self::Http);
    }

    debug!("Untyped TCP connection");
    Ok(Self::Any)
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, derive_builder::Builder)]
/// Single TCP proxy struct
pub struct TcpProxy {
  /// Bound socket address to listen on, exposed to the client
  listen_on: SocketAddr,
  /// Multiplexed socket addresses, the actual destination routed for protocol types
  destination_mux: Arc<TcpDestinationMux>,
  #[builder(default = "super::constants::TCP_BACKLOG")]
  /// TCP backlog size
  backlog: u32,
  /// Tokio runtime handle
  runtime_handle: tokio::runtime::Handle,
}

impl TcpProxy {
  /// Start the TCP proxy
  pub async fn start(&self, cancel_token: CancellationToken) -> Result<(), ProxyError> {
    info!("Starting TCP proxy on {}", self.listen_on);
    let tcp_socket = bind_tcp_socket(&self.listen_on)?;
    let tcp_listener = tcp_socket.listen(self.backlog)?;

    let listener_service = async {
      loop {
        let (mut incoming_stream, src_addr) = match tcp_listener.accept().await {
          Err(e) => {
            error!("Error in TCP listener: {e}");
            continue;
          }
          Ok(res) => res,
        };
        // TODO: Connection limit
        debug!("Accepted TCP connection from: {src_addr}");

        self.runtime_handle.spawn({
          let dst_mux = Arc::clone(&self.destination_mux);
          async move {
            let protocol = match TcpProxyProtocol::detect_protocol(&incoming_stream).await {
              Ok(p) => p,
              Err(e) => {
                error!("Failed to detect protocol: {e}");
                return;
              }
            };
            let dst = match dst_mux.get_destination(&protocol) {
              Ok(addr) => addr,
              Err(e) => {
                error!("No route for {protocol}: {e}");
                return;
              }
            };

            let Ok(mut outgoing_stream) = TcpStream::connect(dst).await else {
              error!("Failed to connect to the destination: {dst}");
              return;
            };
            if let Err(e) = copy_bidirectional(&mut incoming_stream, &mut outgoing_stream).await {
              warn!("Failed to copy bidirectional TCP stream (maybe the timing on disconnect): {e}");
            }
            debug!("TCP proxy connection closed");
          }
        });
      }
    };
    tokio::select! {
      _ = listener_service => {
        error!("TCP proxy stopped");
      }
      _ = cancel_token.cancelled() => {
        warn!("TCP proxy cancelled");
      }
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_tcp_proxy() {
    let handle = tokio::runtime::Handle::current();
    let dst_any = "127.0.0.1:50053".parse().unwrap();
    let dst_ssh = "127.0.0.1:50022".parse().unwrap();
    let dst_tls = "127.0.0.1:50443".parse().unwrap();
    let dst_mux = Arc::new(
      TcpDestinationMuxBuilder::default()
        .dst_any(dst_any)
        .dst_ssh(dst_ssh)
        .dst_tls(dst_tls)
        .build()
        .unwrap(),
    );
    let listen_on: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    let tcp_proxy = TcpProxyBuilder::default()
      .listen_on(listen_on)
      .destination_mux(dst_mux)
      .runtime_handle(handle.clone())
      .build()
      .unwrap();
    assert_eq!(tcp_proxy.backlog, super::super::constants::TCP_BACKLOG);
  }
}
