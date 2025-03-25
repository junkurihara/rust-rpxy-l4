use crate::{
  constants::{TCP_PROTOCOL_DETECTION_BUFFER_SIZE, TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC},
  count::ConnectionCount,
  destination::{Destination, DestinationBuilder, LoadBalance},
  error::ProxyError,
  probe::ProbeResult,
  socket::bind_tcp_socket,
  tls::{probe_tls_handshake, TlsClientHelloInfo},
  trace::*,
};
use bytes::BytesMut;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
  io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
async fn read_tcp_stream(incoming_stream: &mut TcpStream, buf: &mut BytesMut) -> Result<usize, ProxyError> {
  let read_len = incoming_stream.read_buf(buf).await?;
  if read_len == 0 {
    error!("No data received");
    return Err(ProxyError::NoDataReceivedTcpStream);
  }
  Ok(read_len)
}

/// Is SSH
fn is_ssh(buf: &BytesMut) -> ProbeResult<TcpProxyProtocol> {
  if buf.len() < 4 {
    return ProbeResult::PollNext;
  }
  if buf.starts_with(b"SSH-") {
    debug!("SSH connection detected");
    ProbeResult::Success(TcpProxyProtocol::Ssh)
  } else {
    ProbeResult::Failure
  }
}

/// Is HTTP
fn is_http(buf: &BytesMut) -> ProbeResult<TcpProxyProtocol> {
  if buf.len() < 4 {
    return ProbeResult::PollNext;
  }
  if buf.windows(4).any(|w| w.eq(b"HTTP")) {
    debug!("HTTP connection detected");
    ProbeResult::Success(TcpProxyProtocol::Http)
  } else {
    ProbeResult::Failure
  }
}

impl TcpProxyProtocol {
  /// Detect the protocol from the first few bytes of the incoming stream
  async fn detect_protocol(incoming_stream: &mut TcpStream, buf: &mut BytesMut) -> Result<ProbeResult<Self>, ProxyError> {
    let mut probe_fns = vec![is_ssh, is_http, probe_tls_handshake];

    while !probe_fns.is_empty() {
      // Read the first several bytes to probe. at the first loop, the buffer is empty.
      let mut next_buf = BytesMut::with_capacity(TCP_PROTOCOL_DETECTION_BUFFER_SIZE);
      let _read_len = read_tcp_stream(incoming_stream, &mut next_buf).await?;
      buf.extend_from_slice(&next_buf[..]);

      // Check probe functions
      #[allow(clippy::type_complexity)]
      let (new_probe_fns, probe_res): (Vec<fn(&BytesMut) -> ProbeResult<_>>, Vec<_>) = probe_fns
        .into_iter()
        .filter_map(|f| {
          let res = f(buf);
          match res {
            ProbeResult::Success(_) | ProbeResult::PollNext => Some((f, res)),
            _ => None,
          }
        })
        .unzip();

      // If any of them returns Success, return the protocol.
      if let Some(probe_success) = probe_res.into_iter().find(|r| matches!(r, ProbeResult::Success(_))) {
        return Ok(probe_success);
      };

      // If the rest returned PollNext, fetch more data
      probe_fns = new_probe_fns;
    }

    // loop {
    //   let mut found = false;
    //   for prob_fn in prob_fns.iter() {
    //     match prob_fn(&buf) {
    //       ProbeResult::Failure => {
    //         continue;
    //       }
    //       ProbeResult::Success(_) => {
    //         found = true;
    //         break;
    //       }
    //       ProbeResult::PollNext => {
    //         return Ok(Self::Any);
    //       }
    //     }
    //   }
    //   if found {
    //     break;
    //   }
    // }
    // TODO: Add more protocol detection
    // // SSH
    // if buf.starts_with(b"SSH-") {
    //   debug!("SSH connection detected");
    //   return Ok(Self::Ssh);
    // }

    // // HTTP
    // if buf.windows(4).any(|w| w.eq(b"HTTP")) {
    //   debug!("HTTP connection detected");
    //   return Ok(Self::Http);
    // }

    // // TLS
    // loop {
    //   match probe_tls_handshake(buf) {
    //     ProbeResult::Failure => {
    //       break;
    //     }
    //     ProbeResult::Success(info) => {
    //       debug!("TLS connection detected");
    //       return Ok(info);
    //     }
    //     ProbeResult::PollNext => {
    //       debug!("TLS connection detected, but need more data. Polling next.");
    //       let mut next_buf = BytesMut::with_capacity(TCP_PROTOCOL_DETECTION_BUFFER_SIZE);
    //       let _read_len = read_tcp_stream(incoming_stream, &mut next_buf).await?;

    //       buf.extend_from_slice(&next_buf[..]);
    //     }
    //   }
    // }

    debug!("Untyped TCP connection");
    Ok(ProbeResult::Success(Self::Any))
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
            let mut initial_buf = BytesMut::with_capacity(TCP_PROTOCOL_DETECTION_BUFFER_SIZE);
            let Ok(probe_result) = timeout(
              Duration::from_millis(TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC),
              TcpProxyProtocol::detect_protocol(&mut incoming_stream, &mut initial_buf),
            )
            .await
            else {
              error!("Timeout to probe the incoming TCP stream");
              return;
            };
            let protocol = match probe_result {
              Ok(ProbeResult::Success(p)) => p,
              Ok(_) => {
                // Unreachable!
                connection_count.decrement();
                return;
              }
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
            // Write the initial buffer to the outgoing stream
            if let Err(e) = outgoing_stream.write_all(&initial_buf).await {
              error!("Failed to write the initial buffer to the outgoing stream: {e}");
              connection_count.decrement();
              return;
            }
            // Then, copy bidirectional
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
