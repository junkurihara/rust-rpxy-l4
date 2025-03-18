use crate::{
  constants::{TCP_PROTOCOL_DETECTION_BUFFER_SIZE, TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC},
  count::ConnectionCount,
  destination::{Destination, DestinationBuilder, LoadBalance},
  error::ProxyError,
  socket::bind_tcp_socket,
  tls::{probe_tls_handshake, TlsClientHelloInfo, TlsProbeResult},
  trace::*,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
  io::copy_bidirectional,
  net::TcpStream,
  time::{timeout, Duration},
};
use tokio_util::sync::CancellationToken;

/// Type alias for TLS destinations
type TlsDestinations = crate::tls::TlsDestinations<TcpDestination>;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
/// Tcp destination struct
pub(crate) struct TcpDestination {
  /// Destination inner
  inner: Destination,
}

impl TryFrom<(&[SocketAddr], Option<&LoadBalance>)> for TcpDestination {
  type Error = ProxyError;
  fn try_from((dst_addrs, load_balance): (&[SocketAddr], Option<&LoadBalance>)) -> Result<Self, Self::Error> {
    let binding = LoadBalance::default();
    let load_balance = load_balance.unwrap_or(&binding);
    let inner = DestinationBuilder::default()
      .dst_addrs(dst_addrs.to_vec())
      .load_balance(*load_balance)
      .build()
      .map_err(|e| ProxyError::DestinationBuilderError(e.into()))?;
    Ok(Self { inner })
  }
}

impl TcpDestination {
  /// Get the destination socket address
  pub(crate) fn get_destination(&self, src_addr: &SocketAddr) -> Result<&SocketAddr, ProxyError> {
    self
      .inner
      .get_destination(src_addr)
      .map_err(ProxyError::DestinationBuilderError)
  }
}

/* ---------------------------------------------------------- */
/// TCP destination multiplexer
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct TcpDestinationMux {
  /// destination socket address for any protocol
  /// If this is set, it will be used for all protocols except the specific (non-None) protocols.
  #[builder(setter(custom), default = "None")]
  dst_any: Option<TcpDestination>,
  /// destination socket address for SSH protocol
  #[builder(setter(custom), default = "None")]
  dst_ssh: Option<TcpDestination>,
  #[builder(setter(custom), default = "None")]
  dst_http: Option<TcpDestination>,
  #[builder(setter(custom), default = "None")]
  dst_tls: Option<TlsDestinations>,
  // TODO: Add more protocols
}

impl TcpDestinationMuxBuilder {
  pub fn dst_any(&mut self, addrs: &[SocketAddr], load_balance: Option<&LoadBalance>) -> &mut Self {
    let tcp_dest = TcpDestination::try_from((addrs, load_balance));
    if tcp_dest.is_err() {
      return self;
    }
    self.dst_any = Some(tcp_dest.ok());
    self
  }

  pub fn dst_ssh(&mut self, addrs: &[SocketAddr], load_balance: Option<&LoadBalance>) -> &mut Self {
    let tcp_dest = TcpDestination::try_from((addrs, load_balance));
    if tcp_dest.is_err() {
      return self;
    }
    self.dst_ssh = Some(tcp_dest.ok());
    self
  }

  pub fn dst_http(&mut self, addrs: &[SocketAddr], load_balance: Option<&LoadBalance>) -> &mut Self {
    let tcp_dest = TcpDestination::try_from((addrs, load_balance));
    if tcp_dest.is_err() {
      return self;
    }
    self.dst_http = Some(tcp_dest.ok());
    self
  }

  pub fn dst_tls(
    &mut self,
    addrs: &[SocketAddr],
    load_balance: Option<&LoadBalance>,
    server_names: Option<&[&str]>,
    alpn: Option<&[&str]>,
  ) -> &mut Self {
    let tcp_dest = TcpDestination::try_from((addrs, load_balance));
    if tcp_dest.is_err() {
      return self;
    }

    let tcp_dest = tcp_dest.unwrap();
    let mut current = if self.dst_tls.as_ref().is_none_or(|d| d.is_none()) {
      TlsDestinations::new()
    } else {
      self.dst_tls.as_ref().unwrap().as_ref().unwrap().clone()
    };

    let server_names = server_names.unwrap_or_default();
    let alpn = alpn.unwrap_or_default();
    current.add(server_names, alpn, tcp_dest);

    self.dst_tls = Some(Some(current));
    self
  }
}

impl TcpDestinationMux {
  /// Check if the destination mux is empty
  pub fn is_empty(&self) -> bool {
    self.dst_any.is_none() && self.dst_ssh.is_none() && self.dst_http.is_none() && self.dst_tls.is_none()
  }
  /// Get the destination socket address for the given protocol
  pub(crate) fn get_destination(&self, protocol: &TcpProxyProtocol) -> Result<TcpDestination, ProxyError> {
    match protocol {
      // No matched protocol found from the pattern
      TcpProxyProtocol::Any => {
        if let Some(dst) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(dst.clone())
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
      // Found SSH protocol
      TcpProxyProtocol::Ssh => {
        if let Some(dst) = &self.dst_ssh {
          debug!("Setting up dest addr specific to SSH");
          Ok(dst.clone())
        } else if let Some(dst) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(dst.clone())
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
      // Found HTTP protocol
      TcpProxyProtocol::Http => {
        if let Some(dst) = &self.dst_http {
          debug!("Setting up dest addr specific to HTTP");
          Ok(dst.clone())
        } else if let Some(dst) = &self.dst_any {
          debug!("Setting up dest addr for unspecified proto");
          Ok(dst.clone())
        } else {
          Err(ProxyError::NoDestinationAddressForProtocol)
        }
      }
      // Found TLS protocol
      TcpProxyProtocol::Tls(client_hello_info) => {
        if let Some(dst) = &self.dst_tls {
          debug!("Setting up dest addr specific to TLS");
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
      } // TODO: Add more protocols
    }
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
/// TCP proxy protocol, specific protocols like SSH, and default is "any".
pub(crate) enum TcpProxyProtocol {
  /// any, default
  Any,
  /// SSH
  Ssh,
  /// Plaintext HTTP
  Http,
  /// TLS
  Tls(TlsClientHelloInfo),
  // TODO: and more ...
}

impl std::fmt::Display for TcpProxyProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Any => write!(f, "Any"),
      Self::Ssh => write!(f, "SSH"),
      Self::Http => write!(f, "HTTP"),
      Self::Tls(_) => write!(f, "TLS"),
      // TODO: and more...
    }
  }
}

/// Peek the incoming TCP stream to detect the protocol
async fn peek_tcp_stream(incoming_stream: &TcpStream, buf: &mut [u8]) -> Result<usize, ProxyError> {
  let Ok(res) = timeout(
    Duration::from_millis(TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC),
    incoming_stream.peek(buf),
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
  Ok(read_len)
}

impl TcpProxyProtocol {
  /// Detect the protocol from the first few bytes of the incoming stream
  pub(crate) async fn detect_protocol(incoming_stream: &TcpStream) -> Result<Self, ProxyError> {
    let mut buf = vec![0u8; TCP_PROTOCOL_DETECTION_BUFFER_SIZE];
    let read_len = peek_tcp_stream(incoming_stream, &mut buf).await?;

    // TODO: Add more protocol detection
    if buf.starts_with(b"SSH-") {
      debug!("SSH connection detected");
      return Ok(Self::Ssh);
    }

    if let Some(res) = probe_tls_handshake(&buf.as_slice()[..read_len]) {
      let read_again_len = match res {
        TlsProbeResult::Success(info) => {
          debug!("TLS connection detected");
          return Ok(Self::Tls(info));
        }
        TlsProbeResult::PeekMore => {
          debug!("TLS connection detected, but need more data");
          peek_tcp_stream(incoming_stream, &mut buf).await?
        }
      };
      let res = probe_tls_handshake(&buf.as_slice()[..read_again_len]);
      if let Some(TlsProbeResult::Success(info)) = res {
        debug!("TLS connection detected");
        return Ok(Self::Tls(info));
      }
      debug!("Peeked again, but failed to get enough data of TLS Client Hello");
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

  #[builder(default = "ConnectionCount::default()")]
  /// Connection counter, set shared counter if #connections of all TCP proxies are needed
  connection_count: ConnectionCount,

  #[builder(default = "crate::constants::MAX_TCP_CONCURRENT_CONNECTIONS")]
  /// Maximum number of concurrent connections
  /// If `cnt` is shared with other spawned TCP proxies, this value is evaluated for the total number of connections
  max_connections: usize,

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
        // Connection limit
        if self.connection_count.current() >= self.max_connections {
          warn!("TCP connection limit reached: {}", self.max_connections);
          continue;
        }
        self.connection_count.increment();
        debug!(
          "Accepted TCP connection from: {src_addr} (total: {})",
          self.connection_count.current()
        );

        self.runtime_handle.spawn({
          let dst_mux = Arc::clone(&self.destination_mux);
          let connection_count = self.connection_count.clone();
          async move {
            let protocol = match TcpProxyProtocol::detect_protocol(&incoming_stream).await {
              Ok(p) => p,
              Err(e) => {
                error!("Failed to detect protocol: {e}");
                connection_count.decrement();
                return;
              }
            };
            let dst = match dst_mux.get_destination(&protocol) {
              Ok(addr) => addr,
              Err(e) => {
                error!("No route for {protocol}: {e}");
                connection_count.decrement();
                return;
              }
            };

            let Ok(dst_addr) = dst.get_destination(&src_addr) else {
              error!("Failed to get destination address for {src_addr}");
              connection_count.decrement();
              return;
            };
            let Ok(mut outgoing_stream) = TcpStream::connect(dst_addr).await else {
              error!("Failed to connect to the destination: {dst_addr}");
              connection_count.decrement();
              return;
            };
            if let Err(e) = copy_bidirectional(&mut incoming_stream, &mut outgoing_stream).await {
              warn!("Failed to copy bidirectional TCP stream (maybe the timing on disconnect): {e}");
            }
            connection_count.decrement();
            debug!("TCP proxy connection closed (total: {})", connection_count.current());
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
    let dst_any = &["127.0.0.1:50053".parse().unwrap()];
    let dst_ssh = &["127.0.0.1:50022".parse().unwrap()];
    let dst_tls_1 = &["127.0.0.1:50443".parse().unwrap()];
    let dst_tls_2 = &["127.0.0.1:50444".parse().unwrap()];
    let dst_mux = Arc::new(
      TcpDestinationMuxBuilder::default()
        .dst_any(dst_any, None)
        .dst_ssh(dst_ssh, None)
        .dst_tls(dst_tls_1, None, None, None)
        .dst_tls(dst_tls_2, None, Some(&["example.com"]), None)
        .build()
        .unwrap(),
    );
    // check for example.com tls
    let chi = TlsClientHelloInfo {
      sni: vec!["example.com".to_string()],
      alpn: vec!["".to_string()],
    };
    let found = dst_mux.get_destination(&TcpProxyProtocol::Tls(chi)).unwrap();
    let destination = found.inner.get_destination(&"127.0.0.1:60000".parse().unwrap()).unwrap();
    assert_eq!(destination, &"127.0.0.1:50444".parse().unwrap());

    // check for unspecified tls
    let chi = TlsClientHelloInfo {
      sni: vec!["any.com".to_string()],
      alpn: vec!["".to_string()],
    };
    let found = dst_mux.get_destination(&TcpProxyProtocol::Tls(chi)).unwrap();
    let destination = found.inner.get_destination(&"127.0.0.1:60000".parse().unwrap()).unwrap();
    assert_eq!(destination, &"127.0.0.1:50443".parse().unwrap());

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
