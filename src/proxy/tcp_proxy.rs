use super::{constants::TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC, error::ProxyError, socket::bind_tcp_socket};
use crate::log::{debug, error, warn};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
  io::copy_bidirectional,
  net::TcpStream,
  time::{timeout, Duration},
};
use tokio_util::sync::CancellationToken;

/* ---------------------------------------------------------- */
/// TCP proxy multiplexer
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct TcpProxyMux {
  /// destination socket address for any protocol
  /// If this is set, it will be used for all protocols except the specific (non-None) protocols.
  #[builder(setter(custom), default = "None")]
  write_on_any: Option<SocketAddr>,
  /// destination socket address for SSH protocol
  #[builder(setter(custom), default = "None")]
  write_on_ssh: Option<SocketAddr>,
  // TODO: Add more protocols
}

impl TcpProxyMuxBuilder {
  pub fn write_on_any(&mut self, addr: SocketAddr) -> &mut Self {
    self.write_on_any = Some(Some(addr));
    self
  }
  pub fn write_on_ssh(&mut self, addr: SocketAddr) -> &mut Self {
    self.write_on_ssh = Some(Some(addr));
    self
  }
}

impl TcpProxyMux {
  /// Get the destination socket address for the given protocol
  pub fn get_write_on(&self, protocol: &TcpProxyProtocol) -> Result<SocketAddr, ProxyError> {
    match protocol {
      // No matched protocol found from the pattern
      TcpProxyProtocol::Any => {
        if let Some(addr) = &self.write_on_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(*addr)
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
      // Found SSH protocol
      TcpProxyProtocol::Ssh => {
        if let Some(addr) = &self.write_on_ssh {
          debug!("Setting up dest addr specific to SSH");
          Ok(*addr)
        } else if let Some(addr) = &self.write_on_any {
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
  // TODO: and more ...
}

impl std::fmt::Display for TcpProxyProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Any => write!(f, "Any"),
      Self::Ssh => write!(f, "SSH"),
      // TODO: and more...
    }
  }
}

impl TcpProxyProtocol {
  /// Detect the protocol from the first few bytes of the incoming stream
  pub async fn detect_protocol(incoming_stream: &TcpStream) -> Result<Self, ProxyError> {
    let mut buf = vec![0u8; 4]; // TODO: This length, 4, is possibly insufficient for other protocols
    let Ok(res) = timeout(
      Duration::from_millis(TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC),
      incoming_stream.peek(&mut buf),
    )
    .await
    else {
      error!("Failed to detect protocol: timeout");
      return Err(ProxyError::FailedToReadFirstFewBytesTcpStream);
    };
    let read_len = res?;
    if read_len == 0 {
      println!("No data received");
      return Err(ProxyError::NoDataReceivedTcpStream);
    }
    // TODO: Add more protocol detection
    if buf.eq(b"SSH-") {
      debug!("SSH connection detected");
      Ok(Self::Ssh)
    } else {
      debug!("Untyped TCP connection");
      Ok(Self::Any)
    }
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, derive_builder::Builder)]
/// Single TCP proxy struct
pub struct TcpProxy {
  /// Bound socket address to listen on, exposed to the client
  listen_on: SocketAddr,
  /// Socket address to write on, the actual destination routed for protocol types
  write_on_mux: Arc<TcpProxyMux>,
  #[builder(default = "super::constants::TCP_BACKLOG")]
  /// TCP backlog size
  backlog: u32,
  /// Tokio runtime handle
  runtime_handle: tokio::runtime::Handle,
}

impl TcpProxy {
  /// Start the TCP proxy
  pub async fn start(&self, cancel_token: CancellationToken) -> Result<(), ProxyError> {
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
        debug!("Accepted TCP connection from: {src_addr}");

        self.runtime_handle.spawn({
          let write_on_mux = Arc::clone(&self.write_on_mux);
          async move {
            let protocol = match TcpProxyProtocol::detect_protocol(&incoming_stream).await {
              Ok(p) => p,
              Err(e) => {
                error!("Failed to detect protocol: {e}");
                return;
              }
            };
            let write_on = match write_on_mux.get_write_on(&protocol) {
              Ok(addr) => addr,
              Err(e) => {
                error!("No route for {protocol}: {e}");
                return;
              }
            };

            let Ok(mut outgoing_stream) = TcpStream::connect(write_on).await else {
              error!("Failed to connect to the destination: {write_on}");
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
    let write_on_any = "127.0.0.1:50053".parse().unwrap();
    let write_on_ssh = "127.0.0.1:50022".parse().unwrap();
    let write_on_mux = Arc::new(
      TcpProxyMuxBuilder::default()
        .write_on_any(write_on_any)
        .write_on_ssh(write_on_ssh)
        .build()
        .unwrap(),
    );
    let listen_on: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    let tcp_proxy = TcpProxyBuilder::default()
      .listen_on(listen_on)
      .write_on_mux(write_on_mux)
      .runtime_handle(handle.clone())
      .build()
      .unwrap();
    assert_eq!(tcp_proxy.backlog, super::super::constants::TCP_BACKLOG);
  }
}
