use crate::{
  access_log::{AccessLogProtocolType, access_log_start},
  config::EchProtocolConfig,
  constants::{TCP_PROTOCOL_DETECTION_BUFFER_SIZE, TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC},
  count::ConnectionCount,
  destination::{LoadBalance, TargetDestination, TlsDestinationItem},
  error::{ProxyBuildError, ProxyError},
  probe::ProbeResult,
  proto::TcpProtocolType,
  socket::bind_tcp_socket,
  target::{DnsCache, TargetAddr},
  trace::*,
};
use bytes::BytesMut;
use quic_tls::{TlsAlertBuffer, TlsClientHelloBuffer, TlsProbeFailure, probe_tls_handshake};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
  net::TcpStream,
  time::{Duration, timeout},
};
use tokio_util::sync::CancellationToken;

/// Type alias for TLS destinations
type TlsDestinations = crate::destination::TlsDestinations<TcpDestinationInner>;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
/// Tcp destination enum
enum TcpDestination {
  /// Tcp destination
  Tcp(TcpDestinationInner),
  /// Tcp destinations specific to Tls
  Tls(TlsDestinations),
}

#[derive(Debug, Clone)]
/// Tcp destination struct
struct TcpDestinationInner {
  /// Destination inner
  inner: TargetDestination,
}

#[derive(Debug, Clone)]
/// Destination struct found in the multiplexer from TcpProbedProtocol
enum FoundTcpDestination {
  /// Tcp destination
  Tcp(TcpDestinationInner),
  /// Tls destination
  Tls(TlsDestinationItem<TcpDestinationInner>),
}

impl TryFrom<(&[TargetAddr], Option<&LoadBalance>, &Arc<DnsCache>)> for TcpDestinationInner {
  type Error = ProxyBuildError;
  fn try_from(
    (dst_addrs, load_balance, dns_cache): (&[TargetAddr], Option<&LoadBalance>, &Arc<DnsCache>),
  ) -> Result<Self, Self::Error> {
    let inner = TargetDestination::try_from((dst_addrs, load_balance, dns_cache.clone()))?;
    Ok(Self { inner })
  }
}

impl TcpDestinationInner {
  /// Get the destination socket address
  pub(crate) async fn get_destination(&self, src_addr: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    self.inner.get_destination(src_addr).await
  }
}

impl FoundTcpDestination {
  /// Get the destination socket address
  async fn get_destination(&self, src_addr: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    match self {
      Self::Tcp(tcp_destination) => tcp_destination.get_destination(src_addr).await,
      Self::Tls(tls_destination) => tls_destination.destination().get_destination(src_addr).await,
    }
  }
}

/* ---------------------------------------------------------- */
/// TCP destination multiplexer
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct TcpDestinationMux {
  /// Multiplexed TCP destinations
  #[builder(default = "ahash::HashMap::default()")]
  inner: ahash::HashMap<TcpProtocolType, TcpDestination>,
}

impl TcpDestinationMuxBuilder {
  /// Create a new TCP destination multiplexer builder
  pub(crate) fn set_base(
    &mut self,
    proto_type: TcpProtocolType,
    addrs: &[TargetAddr],
    dns_cache: &Arc<DnsCache>,
    load_balance: Option<&LoadBalance>,
  ) -> &mut Self {
    let tcp_dest = TcpDestinationInner::try_from((addrs, load_balance, dns_cache));
    if tcp_dest.is_err() {
      return self;
    }
    let tcp_dest_inner = tcp_dest.unwrap();

    let mut inner = self.inner.clone().unwrap_or_default();
    match proto_type {
      TcpProtocolType::Tls => {
        let mut current_tls = if let Some(TcpDestination::Tls(current)) = inner.get(&proto_type).cloned() {
          current
        } else {
          TlsDestinations::new()
        };
        current_tls.add(&[], &[], tcp_dest_inner, None);
        inner.insert(proto_type, TcpDestination::Tls(current_tls));
      }
      _ => {
        inner.insert(proto_type, TcpDestination::Tcp(tcp_dest_inner));
      }
    }
    self.inner = Some(inner);
    self
  }

  /// Set TLS destinations, use this if alpn and server names are needed for protocol detection or ech is need to be configured
  pub(crate) fn set_tls(
    &mut self,
    addrs: &[TargetAddr],
    dns_cache: &Arc<DnsCache>,
    load_balance: Option<&LoadBalance>,
    server_names: Option<&[&str]>,
    alpn: Option<&[&str]>,
    ech: Option<&EchProtocolConfig>,
  ) -> &mut Self {
    let tcp_dest = TcpDestinationInner::try_from((addrs, load_balance, dns_cache));
    if tcp_dest.is_err() {
      return self;
    }
    let tcp_dest_inner = tcp_dest.unwrap();
    let mut inner = self.inner.clone().unwrap_or_default();

    let mut current_tls = if let Some(TcpDestination::Tls(current)) = inner.get(&TcpProtocolType::Tls).cloned() {
      current
    } else {
      TlsDestinations::new()
    };
    current_tls.add(
      server_names.unwrap_or_default(),
      alpn.unwrap_or_default(),
      tcp_dest_inner,
      ech.cloned(),
    );

    inner.insert(TcpProtocolType::Tls, TcpDestination::Tls(current_tls));
    self.inner = Some(inner);
    self
  }
}

impl TcpDestinationMux {
  /// Check if the destination mux is empty
  pub fn is_empty(&self) -> bool {
    self.inner.is_empty()
  }
  /// Get the destination socket address for the given protocol
  fn find_destination(&self, probed_protocol: &TcpProbedProtocol) -> Result<FoundTcpDestination, ProxyError> {
    let proto_type = probed_protocol.proto_type();
    match self.inner.get(&proto_type) {
      // Found non-TLS protocol
      Some(TcpDestination::Tcp(tcp_destination)) => {
        debug!("Setting up dest addr for {proto_type}");
        return Ok(FoundTcpDestination::Tcp(tcp_destination.clone()));
      }
      // Found TLS protocol
      Some(TcpDestination::Tls(tls_destinations)) => {
        let TcpProbedProtocol::Tls(client_hello_buf) = probed_protocol else {
          return Err(ProxyError::NoDestinationAddressForProtocol);
        };
        return tls_destinations
          .find(&client_hello_buf.client_hello)
          .ok_or(ProxyError::NoDestinationAddressForProtocol)
          .map(|found| {
            debug!("Setting up dest addr for {proto_type}");
            FoundTcpDestination::Tls(found.clone())
          });
      }
      _ => {}
    };

    // if nothing is found, check for the default destination
    if proto_type == TcpProtocolType::Any {
      return Err(ProxyError::NoDestinationAddressForProtocol);
    }
    // Check for the default destination
    let destination_any = self
      .inner
      .get(&TcpProtocolType::Any)
      .cloned()
      .ok_or(ProxyError::NoDestinationAddressForProtocol)?;
    let TcpDestination::Tcp(dst) = destination_any else {
      return Err(ProxyError::NoDestinationAddressForProtocol);
    };
    debug!("Setting up dest addr for unspecified proto");
    Ok(FoundTcpDestination::Tcp(dst.clone()))
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq)]
/// Probed TCP proxy protocol, specific protocols like SSH, and default is "any".
enum TcpProbedProtocol {
  /// any, default
  Any,
  /// SSH
  Ssh,
  /// Plaintext HTTP
  Http,
  /// TLS
  Tls(TlsClientHelloBuffer),
  // TODO: and more ...
}

impl TcpProbedProtocol {
  fn proto_type(&self) -> TcpProtocolType {
    match self {
      Self::Any => TcpProtocolType::Any,
      Self::Ssh => TcpProtocolType::Ssh,
      Self::Http => TcpProtocolType::Http,
      Self::Tls(_) => TcpProtocolType::Tls,
    }
  }
}

impl std::fmt::Display for TcpProbedProtocol {
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

/// Poll the incoming TCP stream to detect the protocol
async fn read_tcp_stream(incoming_stream: &mut TcpStream, buf: &mut BytesMut) -> Result<usize, ProxyError> {
  let read_len = incoming_stream.read_buf(buf).await?;
  if read_len == 0 {
    error!("No data received");
    return Err(ProxyError::NoDataReceivedTcpStream);
  }
  Ok(read_len)
}

/// Is SSH
fn is_ssh(buf: &[u8]) -> ProbeResult<TcpProbedProtocol> {
  if buf.len() < 4 {
    return ProbeResult::PollNext;
  }
  if buf.starts_with(b"SSH-") {
    debug!("SSH connection detected");
    ProbeResult::Success(TcpProbedProtocol::Ssh)
  } else {
    ProbeResult::Failure
  }
}

/// Is HTTP
fn is_http(buf: &[u8]) -> ProbeResult<TcpProbedProtocol> {
  if buf.len() < 4 {
    return ProbeResult::PollNext;
  }
  if buf.windows(4).any(|w| w.eq(b"HTTP")) {
    debug!("HTTP connection detected");
    ProbeResult::Success(TcpProbedProtocol::Http)
  } else {
    ProbeResult::Failure
  }
}

/// Is TLS handshake
fn is_tls_handshake(buf: &[u8]) -> ProbeResult<TcpProbedProtocol> {
  let mut buf = BytesMut::from(buf);
  match probe_tls_handshake(&mut buf) {
    Err(TlsProbeFailure::Failure) => ProbeResult::Failure,
    Err(TlsProbeFailure::PollNext) => ProbeResult::PollNext,
    Ok(chi) => ProbeResult::Success(TcpProbedProtocol::Tls(chi)),
  }
}

impl TcpProbedProtocol {
  /// Detect the protocol from the first few bytes of the incoming stream
  async fn detect_protocol(incoming_stream: &mut TcpStream, buf: &mut BytesMut) -> Result<ProbeResult<Self>, ProxyError> {
    let mut probe_functions = vec![is_ssh, is_http, is_tls_handshake];

    while !probe_functions.is_empty() {
      // Read the first several bytes to probe. at the first loop, the buffer is empty.
      let mut next_buf = BytesMut::with_capacity(TCP_PROTOCOL_DETECTION_BUFFER_SIZE);
      let _read_len = read_tcp_stream(incoming_stream, &mut next_buf).await?;
      buf.extend_from_slice(&next_buf[..]);

      // Check probe functions
      #[allow(clippy::type_complexity)]
      let (new_probe_fns, probe_res): (Vec<fn(&[u8]) -> ProbeResult<_>>, Vec<_>) = probe_functions
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
      probe_functions = new_probe_fns;
    }

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
        let (incoming_stream, src_addr) = match tcp_listener.accept().await {
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
          handle_tcp_connection(dst_mux, connection_count, incoming_stream, src_addr)
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

/* ---------------------------------------------------------- */
/// Handle TCP connection
async fn handle_tcp_connection(
  dst_mux: Arc<TcpDestinationMux>,
  connection_count: ConnectionCount,
  mut incoming_stream: TcpStream,
  src_addr: SocketAddr,
) {
  let mut initial_buf = BytesMut::with_capacity(TCP_PROTOCOL_DETECTION_BUFFER_SIZE);
  let Ok(probe_result) = timeout(
    Duration::from_millis(TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC),
    TcpProbedProtocol::detect_protocol(&mut incoming_stream, &mut initial_buf),
  )
  .await
  else {
    error!("Timeout to probe the incoming TCP stream");
    return;
  };
  let probed_protocol = match probe_result {
    Ok(ProbeResult::Success(p)) => p,
    Ok(_) => unreachable!(), // unreachable since PollNext is processed in detect_protocol
    Err(e) => {
      error!("Failed to detect protocol: {e}");
      connection_count.decrement();
      return;
    }
  };
  // found_dst contains not only TcpDestinationInner address but also ECH config for TLS
  let found_dst = match dst_mux.find_destination(&probed_protocol) {
    Ok(addr) => addr,
    Err(e) => {
      error!("No route for {probed_protocol}: {e}");
      connection_count.decrement();
      return;
    }
  };

  let Ok(dst_addr) = found_dst.get_destination(&src_addr).await else {
    error!("Failed to get destination address for {src_addr}");
    connection_count.decrement();
    return;
  };
  let Ok(mut outgoing_stream) = TcpStream::connect(dst_addr).await else {
    error!("Failed to connect to the destination: {dst_addr}");
    connection_count.decrement();
    return;
  };

  let to_be_written = match (&found_dst, &probed_protocol) {
    (FoundTcpDestination::Tls(tls_destination), TcpProbedProtocol::Tls(client_hello_buf)) => {
      // Handle tls, especially ECH
      let Ok(client_hello_bytes) = handle_tls_client_hello(&client_hello_buf, &tls_destination) else {
        // Error means that illegal parameter must be sent back when error
        error!("Failed to handle TLS client hello, sending illegal_parameter alert back to the client");
        let illegal_parameter_alert = TlsAlertBuffer::default();
        if let Err(e) = send_back_tls_alert(&mut incoming_stream, &illegal_parameter_alert).await {
          error!("Failed to send TLS alert: {e}");
        }
        connection_count.decrement();
        return;
      };
      client_hello_bytes
    }
    _ => {
      // handle non-tls
      initial_buf.freeze()
    }
  };

  if let Err(e) = outgoing_stream.write_all(&to_be_written).await {
    error!("Failed to write the initial buffer to the outgoing stream: {e}");
    connection_count.decrement();
    return;
  }
  // Here we are establishing a bidirectional connection. Logging the connection.
  tcp_access_log_start(&src_addr, &dst_addr, &probed_protocol);
  // Then, copy bidirectional
  if let Err(e) = copy_bidirectional(&mut incoming_stream, &mut outgoing_stream).await {
    warn!("Failed to copy bidirectional TCP stream (maybe the timing on disconnect): {e}");
  }
  // finish log
  tcp_access_log_finish(&src_addr, &dst_addr, &probed_protocol);
  connection_count.decrement();
  debug!("TCP proxy connection closed (total: {})", connection_count.current());
}

/// handle tls, especially ECH
/// This returns as is (Ok(...)) in Bytes when no matching config_id is found (case of GREASE), otherwise returns decrypted ClientHello record in Bytes
/// If this returns Err(...), it means that it failed to be decrypted or that the decrypted result is illegal. Then we must send some error back to the client.
fn handle_tls_client_hello<T>(
  orig_ch_buf: &TlsClientHelloBuffer,
  tls_destination: &TlsDestinationItem<T>,
) -> Result<bytes::Bytes, ProxyError> {
  if orig_ch_buf.is_ech_outer() && tls_destination.ech().is_some() {
    trace!("Handling ECH ClientHello Outer");
    let ech = tls_destination.ech().unwrap();
    let Some(decrypted_ch) = orig_ch_buf.client_hello.decrypt_ech(&ech.private_keys, false)? else {
      return Ok(orig_ch_buf.try_to_bytes()?);
    };

    let new_ch_buf = TlsClientHelloBuffer {
      client_hello: decrypted_ch,
      record_header: orig_ch_buf.record_header.clone(),
      handshake_message_header: orig_ch_buf.handshake_message_header.clone(),
    };

    return Ok(new_ch_buf.try_to_bytes()?);
  };

  Ok(orig_ch_buf.try_to_bytes()?)
}

/// Handle TLS alert, writing TLS alert to the incoming stream back to the client
async fn send_back_tls_alert(incoming_stream: &mut TcpStream, alert_buf: &TlsAlertBuffer) -> Result<(), ProxyError> {
  let alert_bytes = alert_buf.to_bytes();
  match timeout(
    Duration::from_millis(TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC),
    incoming_stream.write_all(&alert_bytes),
  )
  .await
  {
    Ok(Ok(_)) => {
      debug!("TLS alert sent to the incoming stream");
    }
    _ => {
      error!("Failed to write TLS alert to the incoming stream");
      return Err(ProxyError::TlsAlertWriteError);
    }
  }

  Ok(())
}
/* ---------------------------------------------------------- */

#[cfg(test)]
mod tests {
  use super::*;
  use quic_tls::extension::ServerNameIndication;

  #[tokio::test]
  async fn test_tcp_proxy() {
    let handle = tokio::runtime::Handle::current();
    let dns_cache = Arc::new(DnsCache::default());
    let dst_any = &["127.0.0.1:50053".parse().unwrap()];
    let dst_ssh = &["127.0.0.1:50022".parse().unwrap()];
    let dst_tls_1 = &["127.0.0.1:50443".parse().unwrap()];
    let dst_tls_2 = &["127.0.0.1:50444".parse().unwrap()];
    let dst_mux = Arc::new(
      TcpDestinationMuxBuilder::default()
        .set_base(TcpProtocolType::Any, dst_any, &dns_cache, None)
        .set_base(TcpProtocolType::Ssh, dst_ssh, &dns_cache, None)
        .set_base(TcpProtocolType::Tls, dst_tls_1, &dns_cache, None)
        .set_tls(dst_tls_2, &dns_cache, None, Some(&["example.com"]), None, None)
        .build()
        .unwrap(),
      // .dst_http(dst_http, None)
      //     .dst_any(dst_any, None)
      //     .dst_ssh(dst_ssh, None)
      //     .dst_tls(dst_tls_1, None, None, None, None)
      //     .dst_tls(dst_tls_2, None, Some(&["example.com"]), None, None)
      //     .build()
      //     .unwrap(),
    );
    // check for example.com tls
    let mut sni = ServerNameIndication::default();
    sni.add_server_name("example.com");
    let mut chb = TlsClientHelloBuffer::default();
    chb.client_hello.add_replace_sni(&sni);

    let found = dst_mux.find_destination(&TcpProbedProtocol::Tls(chb)).unwrap();
    let destination = found.get_destination(&"127.0.0.1:60000".parse().unwrap()).await.unwrap();
    assert_eq!(destination, "127.0.0.1:50444".parse().unwrap());

    // check for unspecified tls
    let mut sni = ServerNameIndication::default();
    sni.add_server_name("any.com");
    let mut chb = TlsClientHelloBuffer::default();
    chb.client_hello.add_replace_sni(&sni);

    let found = dst_mux.find_destination(&TcpProbedProtocol::Tls(chb)).unwrap();
    let destination = found.get_destination(&"127.0.0.1:60000".parse().unwrap()).await.unwrap();
    assert_eq!(destination, "127.0.0.1:50443".parse().unwrap());

    let listen_on: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    let tcp_proxy = TcpProxyBuilder::default()
      .listen_on(listen_on)
      .destination_mux(dst_mux)
      .runtime_handle(handle.clone())
      .build()
      .unwrap();
    assert_eq!(tcp_proxy.backlog, super::super::constants::TCP_BACKLOG);
  }

  #[tokio::test]
  async fn test_tcp_proxy_with_domain_name_one_one_one_one() {
    let dns_cache = Arc::new(DnsCache::default());
    let dst_any = &["one.one.one.one:53".parse().unwrap()];
    let dst_mux = Arc::new(
      TcpDestinationMuxBuilder::default()
        .set_base(TcpProtocolType::Any, dst_any, &dns_cache, None)
        .build()
        .unwrap(),
    );

    let found = dst_mux.find_destination(&TcpProbedProtocol::Any).unwrap();
    let destination = found.get_destination(&"127.0.0.1:60000".parse().unwrap()).await.unwrap();
    assert!(["1.1.1.1:53".parse().unwrap(), "1.0.0.1:53".parse().unwrap()].contains(&destination));
  }
}

/* ---------------------------------------------------------- */
/// Handle TCP access log, when establishing a connection
fn tcp_access_log_start(src_addr: &SocketAddr, dst_addr: &SocketAddr, probed_protocol: &TcpProbedProtocol) {
  let proto = AccessLogProtocolType::Tcp(probed_protocol.proto_type());
  access_log_start(&proto, src_addr, dst_addr);
}
/// Handle TCP access log, when closing a connection
fn tcp_access_log_finish(src_addr: &SocketAddr, dst_addr: &SocketAddr, probed_protocol: &TcpProbedProtocol) {
  let proto = AccessLogProtocolType::Tcp(probed_protocol.proto_type());
  crate::access_log::access_log_finish(&proto, src_addr, dst_addr);
}
