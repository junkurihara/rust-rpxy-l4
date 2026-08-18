#[cfg(feature = "proxy-protocol")]
use crate::config::ProxyProtocolVersion;
#[cfg(feature = "proxy-protocol")]
use crate::proxy_protocol;
#[cfg(feature = "proxy-protocol")]
use crate::proxy_protocol::InboundProxyProtocolConfig;
use crate::{
  access_log::{AccessLogProtocolType, access_log_start},
  config::EchProtocolConfig,
  constants::{TCP_BACKEND_CONNECT_TIMEOUT_MSEC, TCP_PROTOCOL_DETECTION_READ_CHUNK_SIZE, TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC},
  count::{ConnectionCount, ConnectionPermit},
  destination::{LoadBalance, TargetDestination, TlsDestinationItem},
  error::{ProxyBuildError, ProxyError},
  probe::{ProbeResult, TcpProbedProtocol},
  proto::TcpProtocolType,
  socket::bind_tcp_socket,
  target::{DnsCache, TargetAddr},
  trace::*,
};
use bytes::BytesMut;
use quic_tls::{TlsAlertBuffer, TlsClientHelloBuffer};
use std::{future::Future, net::SocketAddr, sync::Arc};
use tokio::{
  io::{AsyncWriteExt, copy_bidirectional},
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
pub(crate) struct TcpDestinationInner {
  /// Destination inner
  inner: TargetDestination,
  /// PROXY protocol version to send for this destination
  #[cfg(feature = "proxy-protocol")]
  send_proxy_protocol: Option<ProxyProtocolVersion>,
}

#[derive(Debug, Clone)]
/// Destination struct found in the multiplexer from TcpProbedProtocol
pub(crate) enum FoundTcpDestination {
  /// Tcp destination
  Tcp(TcpDestinationInner),
  /// Tls destination
  Tls(TlsDestinationItem<TcpDestinationInner>),
}

#[cfg(feature = "proxy-protocol")]
impl
  TryFrom<(
    &[TargetAddr],
    Option<&LoadBalance>,
    &Arc<DnsCache>,
    Option<ProxyProtocolVersion>,
  )> for TcpDestinationInner
{
  type Error = ProxyBuildError;
  fn try_from(
    (dst_addrs, load_balance, dns_cache, send_proxy_protocol): (
      &[TargetAddr],
      Option<&LoadBalance>,
      &Arc<DnsCache>,
      Option<ProxyProtocolVersion>,
    ),
  ) -> Result<Self, Self::Error> {
    let inner = TargetDestination::try_from((dst_addrs, load_balance, dns_cache.clone()))?;
    Ok(Self {
      inner,
      send_proxy_protocol,
    })
  }
}

#[cfg(not(feature = "proxy-protocol"))]
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

  /// Get the PROXY protocol version for this destination
  #[cfg(feature = "proxy-protocol")]
  pub(crate) fn proxy_protocol_version(&self) -> Option<ProxyProtocolVersion> {
    self.send_proxy_protocol
  }
}

impl FoundTcpDestination {
  /// Get the destination socket address
  pub(crate) async fn get_destination(&self, src_addr: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    match self {
      Self::Tcp(tcp_destination) => tcp_destination.get_destination(src_addr).await,
      Self::Tls(tls_destination) => tls_destination.destination().get_destination(src_addr).await,
    }
  }

  /// Get the PROXY protocol version for this destination
  #[cfg(feature = "proxy-protocol")]
  pub(crate) fn proxy_protocol_version(&self) -> Option<ProxyProtocolVersion> {
    match self {
      Self::Tcp(tcp_destination) => tcp_destination.proxy_protocol_version(),
      Self::Tls(tls_destination) => tls_destination.destination().proxy_protocol_version(),
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
    #[cfg(feature = "proxy-protocol")] send_proxy_protocol: Option<ProxyProtocolVersion>,
  ) -> &mut Self {
    #[cfg(feature = "proxy-protocol")]
    let tcp_dest = TcpDestinationInner::try_from((addrs, load_balance, dns_cache, send_proxy_protocol));
    #[cfg(not(feature = "proxy-protocol"))]
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
        current_tls.add(&[], &[], tcp_dest_inner, None, dns_cache);
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
  #[allow(
    clippy::too_many_arguments,
    reason = "The builder method mirrors the existing TLS route configuration fields"
  )]
  pub(crate) fn set_tls(
    &mut self,
    addrs: &[TargetAddr],
    dns_cache: &Arc<DnsCache>,
    load_balance: Option<&LoadBalance>,
    server_names: Option<&[&str]>,
    alpn: Option<&[&str]>,
    ech: Option<&EchProtocolConfig>,
    #[cfg(feature = "proxy-protocol")] send_proxy_protocol: Option<ProxyProtocolVersion>,
  ) -> &mut Self {
    #[cfg(feature = "proxy-protocol")]
    let tcp_dest = TcpDestinationInner::try_from((addrs, load_balance, dns_cache, send_proxy_protocol));
    #[cfg(not(feature = "proxy-protocol"))]
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
      dns_cache,
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
  pub(crate) fn find_destination(&self, probed_protocol: &TcpProbedProtocol) -> Result<FoundTcpDestination, ProxyError> {
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
          return Err(ProxyError::NoDestinationAddressForProtocol(String::new()));
        };
        return tls_destinations
          .find(&client_hello_buf.client_hello)
          .ok_or(ProxyError::NoDestinationAddressForProtocol(String::new()))
          .map(|found| {
            debug!("Setting up dest addr for {proto_type}");
            FoundTcpDestination::Tls(found.clone())
          });
      }
      _ => {}
    };

    // if nothing is found, check for the default destination
    if proto_type == TcpProtocolType::Any {
      return Err(ProxyError::NoDestinationAddressForProtocol(String::new()));
    }
    // Check for the default destination
    let destination_any = self
      .inner
      .get(&TcpProtocolType::Any)
      .cloned()
      .ok_or(ProxyError::NoDestinationAddressForProtocol(String::new()))?;
    let TcpDestination::Tcp(dst) = destination_any else {
      return Err(ProxyError::NoDestinationAddressForProtocol(String::new()));
    };
    debug!("Setting up dest addr for unspecified proto");
    Ok(FoundTcpDestination::Tcp(dst.clone()))
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

  #[cfg(feature = "proxy-protocol")]
  #[builder(default = "None", setter(custom))]
  /// Configuration for receiving inbound PROXY protocol header, if None, the proxy will not attempt to parse the PROXY header
  /// If Some, the proxy will expect the PROXY header and parse it for all incoming TCP connections. If the parsing fails, the connection will be dropped.
  recv_proxy_protocol_config: Option<Arc<InboundProxyProtocolConfig>>,

  /// Tokio runtime handle
  runtime_handle: tokio::runtime::Handle,
}

#[cfg(feature = "proxy-protocol")]
impl TcpProxyBuilder {
  /// Custom setter for recv_proxy_config to allow setting from Config
  pub fn recv_proxy_protocol_config(
    &mut self,
    recv_proxy_protocol: &bool,
    trusted_proxies: Option<&Vec<ipnet::IpNet>>,
  ) -> &mut Self {
    // Determine whether to parse inbound PROXY protocol header based on configuration, and prepare the config if needed
    let recv_proxy_protocol = recv_proxy_protocol
      .then(|| {
        trusted_proxies.as_ref().map(|&proxies| {
          Arc::new(InboundProxyProtocolConfig {
            trusted_proxies: proxies.clone(),
          })
        })
      })
      .flatten();
    self.recv_proxy_protocol_config = Some(recv_proxy_protocol);
    self
  }
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
        let Some(connection_permit) = self.connection_count.try_acquire(self.max_connections) else {
          debug!("TCP connection limit reached: {}", self.max_connections);
          continue;
        };
        debug!(
          "Accepted TCP connection from: {src_addr} (total: {})",
          self.connection_count.current()
        );
        // Enable keepalive so a dead/half-open downstream peer is eventually reclaimed by the kernel.
        enable_tcp_keepalive(&incoming_stream, "downstream");

        self.runtime_handle.spawn({
          let dst_mux = Arc::clone(&self.destination_mux);
          #[cfg(feature = "proxy-protocol")]
          let recv_proxy_protocol_config = self.recv_proxy_protocol_config.clone();

          handle_tcp_connection(
            dst_mux,
            connection_permit,
            incoming_stream,
            src_addr,
            #[cfg(feature = "proxy-protocol")]
            self.listen_on,
            #[cfg(feature = "proxy-protocol")]
            recv_proxy_protocol_config,
          )
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnexpectedTcpProbeState {
  PollNext,
  Failure,
  Rejected,
}

fn completed_tcp_probe(probe_result: ProbeResult<TcpProbedProtocol>) -> Result<TcpProbedProtocol, UnexpectedTcpProbeState> {
  match probe_result {
    ProbeResult::Success(protocol) => Ok(protocol),
    ProbeResult::PollNext => Err(UnexpectedTcpProbeState::PollNext),
    ProbeResult::Failure => Err(UnexpectedTcpProbeState::Failure),
    ProbeResult::Rejected => Err(UnexpectedTcpProbeState::Rejected),
  }
}

fn contextualize_destination_error(error: ProxyError, src_addr: SocketAddr, probed_protocol: &TcpProbedProtocol) -> ProxyError {
  error
    .with_source_context(src_addr)
    .with_protocol_context(&probed_protocol.to_string())
}

#[derive(Debug)]
enum TcpBackendConnectError {
  Io(std::io::Error),
  Timeout,
}

async fn connect_tcp_backend_with_timeout<F>(connect: F, duration: Duration) -> Result<TcpStream, TcpBackendConnectError>
where
  F: Future<Output = Result<TcpStream, std::io::Error>>,
{
  match timeout(duration, connect).await {
    Ok(Ok(stream)) => Ok(stream),
    Ok(Err(error)) => Err(TcpBackendConnectError::Io(error)),
    Err(_) => Err(TcpBackendConnectError::Timeout),
  }
}

/// Enable SO_KEEPALIVE (OS-default timing) on a TCP stream so the kernel can
/// reclaim a dead/half-open peer that vanished without a FIN/RST.
///
/// Best-effort: a failure is logged and the connection continues. Keepalive is a
/// hygiene safety-net; failing to set it must not drop an otherwise-healthy
/// proxied connection. It reclaims only unresponsive peers, not a live client
/// deliberately holding a connection.
fn enable_tcp_keepalive(stream: &TcpStream, leg: &str) {
  if let Err(e) = socket2::SockRef::from(stream).set_keepalive(true) {
    warn!("Failed to enable TCP keepalive on the {leg} stream: {e}");
  }
}

/* ---------------------------------------------------------- */
/// Handle TCP connection
async fn handle_tcp_connection(
  dst_mux: Arc<TcpDestinationMux>,
  _connection_permit: ConnectionPermit,
  mut incoming_stream: TcpStream,
  #[cfg(feature = "proxy-protocol")] mut src_addr: SocketAddr,
  #[cfg(not(feature = "proxy-protocol"))] src_addr: SocketAddr,
  #[cfg(feature = "proxy-protocol")] listen_on: SocketAddr,
  #[cfg(feature = "proxy-protocol")] recv_proxy_protocol: Option<Arc<InboundProxyProtocolConfig>>,
) {
  #[cfg(feature = "proxy-protocol")]
  if let Some(pp_config) = recv_proxy_protocol.as_ref() {
    match timeout(
      Duration::from_millis(crate::constants::TCP_PROXY_HEADER_READ_TIMEOUT_MSEC),
      proxy_protocol::parse_inbound_proxy_header(&mut incoming_stream, &src_addr, pp_config),
    )
    .await
    {
      Ok(Ok(Some(parsed_src))) => {
        debug!("PROXY header from {src_addr}: original client = {parsed_src}");
        src_addr = parsed_src;
      }
      Ok(Ok(None)) => {
        debug!("PROXY LOCAL/UNKNOWN from {src_addr}, keeping peer address");
      }
      Ok(Err(e)) => {
        error!("Failed to parse inbound PROXY header from {src_addr}: {e}");
        return;
      }
      Err(_) => {
        error!(
          "Timeout ({}ms) reading PROXY header from {src_addr}",
          crate::constants::TCP_PROXY_HEADER_READ_TIMEOUT_MSEC
        );
        return;
      }
    }
  }

  let mut initial_buf = BytesMut::with_capacity(TCP_PROTOCOL_DETECTION_READ_CHUNK_SIZE);
  let Ok(probe_result) = timeout(
    Duration::from_millis(TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC),
    TcpProbedProtocol::detect_protocol(&mut incoming_stream, &mut initial_buf),
  )
  .await
  else {
    error!("Timeout ({TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC}ms) while probing TCP stream from {src_addr}");
    return;
  };
  let probed_protocol = match probe_result {
    Ok(result) => match completed_tcp_probe(result) {
      Ok(protocol) => protocol,
      Err(unexpected_state) => {
        error!("TCP protocol detector returned unexpected {unexpected_state:?} state for {src_addr}; closing connection");
        return;
      }
    },
    Err(error @ (ProxyError::TcpProbeLimitExceeded | ProxyError::TcpProbeRejected | ProxyError::NoDataReceivedTcpStream(_))) => {
      debug!("TCP protocol probe ended for {src_addr}: {error}");
      return;
    }
    Err(e) => {
      let contextual_error = e.with_source_context(src_addr).with_protocol_context("TCP");
      error!("Failed to detect protocol from {src_addr}: {contextual_error}");
      return;
    }
  };
  // found_dst contains not only TcpDestinationInner address but also ECH config for TLS
  let found_dst = match dst_mux.find_destination(&probed_protocol) {
    Ok(addr) => addr,
    Err(e) => {
      let contextual_error = e
        .with_source_context(src_addr)
        .with_protocol_context(&probed_protocol.to_string());
      error!("No route for {probed_protocol} from {src_addr}: {contextual_error}");
      return;
    }
  };

  let Ok(mut dst_addr) = found_dst.get_destination(&src_addr).await.map_err(|e| {
    let contextual_error = contextualize_destination_error(e, src_addr, &probed_protocol);
    error!("Failed to resolve destination address for {probed_protocol} from {src_addr}: {contextual_error}");
    contextual_error
  }) else {
    return;
  };

  let to_be_written = match (&found_dst, &probed_protocol) {
    (FoundTcpDestination::Tls(tls_destination), TcpProbedProtocol::Tls(client_hello_buf)) => {
      // Handle tls, especially ECH
      let Ok(client_hello_bytes) = handle_tls_client_hello(client_hello_buf, tls_destination, &mut dst_addr).await else {
        // Error means that illegal parameter must be sent back when error
        error!("Failed to handle TLS client hello, sending illegal_parameter alert back to the client");
        let illegal_parameter_alert = TlsAlertBuffer::default();
        if let Err(e) = send_back_tls_alert(&mut incoming_stream, &illegal_parameter_alert).await {
          error!("Failed to send TLS alert: {e}");
        }
        return;
      };
      client_hello_bytes
    }
    _ => {
      // handle non-tls
      initial_buf.freeze()
    }
  };

  let mut outgoing_stream = match connect_tcp_backend_with_timeout(
    TcpStream::connect(dst_addr),
    Duration::from_millis(TCP_BACKEND_CONNECT_TIMEOUT_MSEC),
  )
  .await
  {
    Ok(stream) => stream,
    Err(TcpBackendConnectError::Io(error)) => {
      let contextual_error = ProxyError::IoError(error)
        .with_connection_context(src_addr, dst_addr)
        .with_protocol_context(&probed_protocol.to_string());
      error!("Failed to connect to destination {dst_addr} for {probed_protocol} from {src_addr}: {contextual_error}");
      return;
    }
    Err(TcpBackendConnectError::Timeout) => {
      error!(
        "Timeout ({TCP_BACKEND_CONNECT_TIMEOUT_MSEC}ms) connecting to destination {dst_addr} for {probed_protocol} from {src_addr}"
      );
      return;
    }
  };
  // Enable keepalive so a dead/half-open backend peer is eventually reclaimed by the kernel.
  enable_tcp_keepalive(&outgoing_stream, "upstream");

  #[cfg(feature = "proxy-protocol")]
  // Write PROXY protocol header before any application data
  if let Some(pp_version) = found_dst.proxy_protocol_version() {
    let local_addr = incoming_stream.local_addr().unwrap_or(listen_on);
    let pp_dst = proxy_protocol::resolve_dst_addr(listen_on, local_addr);
    match proxy_protocol::encode_proxy_header(pp_version, src_addr, pp_dst) {
      Ok(header_bytes) => {
        if let Err(e) = outgoing_stream.write_all(&header_bytes).await {
          let contextual_error = ProxyError::IoError(e)
            .with_connection_context(src_addr, dst_addr)
            .with_protocol_context(&probed_protocol.to_string());
          error!("Failed to write PROXY header to {dst_addr} for {probed_protocol} from {src_addr}: {contextual_error}");
          return;
        }
        debug!("Sent PROXY {pp_version:?} header to {dst_addr} for {probed_protocol} from {src_addr}");
      }
      Err(e) => {
        let contextual_error = ProxyError::IoError(e)
          .with_connection_context(src_addr, dst_addr)
          .with_protocol_context(&probed_protocol.to_string());
        error!("Failed to encode PROXY header for {probed_protocol} from {src_addr}: {contextual_error}");
        return;
      }
    }
  }

  if let Err(e) = outgoing_stream.write_all(&to_be_written).await {
    let contextual_error = ProxyError::IoError(e)
      .with_connection_context(src_addr, dst_addr)
      .with_protocol_context(&probed_protocol.to_string());
    error!("Failed to write initial buffer to {dst_addr} for {probed_protocol} from {src_addr}: {contextual_error}");
    return;
  }
  // Here we are establishing a bidirectional connection. Logging the connection.
  tcp_access_log_start(&src_addr, &dst_addr, &probed_protocol);
  // Then, copy bidirectional
  match copy_bidirectional(&mut incoming_stream, &mut outgoing_stream).await {
    Ok((bytes_to_server, bytes_to_client)) => {
      let total_bytes = bytes_to_server + bytes_to_client;
      debug!(
        "TCP proxy transferred {} bytes ({} to server, {} to client)",
        total_bytes, bytes_to_server, bytes_to_client
      );
    }
    Err(e) => {
      let contextual_error = ProxyError::IoError(e)
        .with_connection_context(src_addr, dst_addr)
        .with_protocol_context(&probed_protocol.to_string());
      warn!("Bidirectional TCP stream copy failed for {probed_protocol} {src_addr} <-> {dst_addr}: {contextual_error}");
    }
  }
  // finish log
  tcp_access_log_finish(&src_addr, &dst_addr, &probed_protocol);
  debug!("TCP proxy connection closed");
}

/// handle tls, especially ECH
/// This returns as is (Ok(...)) in Bytes when no matching config_id is found (case of GREASE), otherwise returns decrypted ClientHello record in Bytes
/// If this returns Err(...), it means that it failed to be decrypted or that the decrypted result is illegal. Then we must send some error back to the client.
async fn handle_tls_client_hello<T>(
  orig_ch_buf: &TlsClientHelloBuffer,
  tls_destination: &TlsDestinationItem<T>,
  dst_addr: &mut SocketAddr,
) -> Result<bytes::Bytes, ProxyError> {
  if orig_ch_buf.is_ech_outer() && tls_destination.ech().is_some() {
    trace!("Handling ECH ClientHello Outer");
    let ech = tls_destination.ech().unwrap();
    let Some(decrypted_ch) = orig_ch_buf.client_hello.decrypt_ech(&ech.private_keys, false)? else {
      return Ok(orig_ch_buf.try_to_bytes()?);
    };
    // Decryption succeeded, so we need to replace the destination address with the one in the decrypted ClientHello Inner
    trace!("Decrypted ClientHello Inner: {decrypted_ch:#?}");

    let sni = decrypted_ch.sni();
    let Some(private_server_name) = sni.first() else {
      error!("No SNI in decrypted ClientHello");
      return Err(ProxyError::TlsError(
        quic_tls::TlsClientHelloError::NoSniInDecryptedClientHello,
      ));
    };
    let Some(private_target_addr) = ech.private_server_names.get(private_server_name) else {
      error!("No matching private server name found in decrypted ClientHello");
      return Err(ProxyError::EchNoMatchingPrivateServerName(String::new()));
    };
    // Replace the destination address with the one in the decrypted ClientHello Inner
    let dns_cache = tls_destination.dns_cache();
    let resolved = private_target_addr.resolve_cached(dns_cache).await?;
    if resolved.is_empty() {
      error!("No destination address found for {private_server_name}");
      return Err(ProxyError::NoDestinationAddress(String::new()));
    }
    *dst_addr = resolved[0];
    debug!(
      "Decryption succeeded, replacing destination address with private server address {private_server_name}: {dst_addr} (ECH)"
    );

    // New client hello (i.e., reconstructed inner) that will be sent to the destination
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
      return Err(ProxyError::TlsAlertWriteError(String::new()));
    }
  }

  Ok(())
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

/* ---------------------------------------------------------- */

#[cfg(test)]
mod tests {
  use super::*;
  use quic_tls::extension::ServerNameIndication;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  #[test]
  fn test_unexpected_tcp_probe_states_are_rejected() {
    assert_eq!(
      completed_tcp_probe(ProbeResult::Success(TcpProbedProtocol::Any)),
      Ok(TcpProbedProtocol::Any)
    );
    assert_eq!(
      completed_tcp_probe(ProbeResult::PollNext),
      Err(UnexpectedTcpProbeState::PollNext)
    );
    assert_eq!(
      completed_tcp_probe(ProbeResult::Failure),
      Err(UnexpectedTcpProbeState::Failure)
    );
    assert_eq!(
      completed_tcp_probe(ProbeResult::Rejected),
      Err(UnexpectedTcpProbeState::Rejected)
    );
  }

  #[test]
  fn test_destination_resolution_error_uses_source_only_context() {
    let src_addr = "192.168.1.100:45000".parse().unwrap();
    let contextual_error = contextualize_destination_error(
      ProxyError::DnsResolutionError("resolver unavailable".to_string()),
      src_addr,
      &TcpProbedProtocol::Any,
    );
    let error_msg = contextual_error.to_string();

    assert!(error_msg.contains("192.168.1.100:45000"));
    assert!(error_msg.contains("Any protocol"));
    assert!(error_msg.contains("resolver unavailable"));
    assert!(!error_msg.contains("unknown"));
    assert!(!error_msg.contains("->"));
  }

  #[tokio::test]
  async fn test_backend_connect_timeout_is_distinct_from_io_failure() {
    let timeout_result = connect_tcp_backend_with_timeout(
      std::future::pending::<Result<TcpStream, std::io::Error>>(),
      Duration::from_millis(1),
    )
    .await;
    assert!(matches!(timeout_result, Err(TcpBackendConnectError::Timeout)));

    let io_result = connect_tcp_backend_with_timeout(
      std::future::ready(Err(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "connection refused",
      ))),
      Duration::from_secs(1),
    )
    .await;
    assert!(matches!(io_result, Err(TcpBackendConnectError::Io(_))));
  }

  #[tokio::test]
  async fn test_enable_tcp_keepalive_sets_option() {
    // A loopback listener + client yields an accepted (downstream-like) stream
    // and a connected (upstream-like) stream. Assert enable_tcp_keepalive turns
    // SO_KEEPALIVE on for each, verified by reading the socket option back
    // without waiting for any keepalive probe to fire. The two production call
    // sites (after accept, after backend connect) are covered by review and the
    // residual search, not by this helper-level test.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (accepted, _) = listener.accept().await.unwrap();

    enable_tcp_keepalive(&accepted, "downstream");
    enable_tcp_keepalive(&client, "upstream");

    assert!(socket2::SockRef::from(&accepted).keepalive().unwrap());
    assert!(socket2::SockRef::from(&client).keepalive().unwrap());
  }

  #[tokio::test]
  async fn test_rejected_tcp_probes_release_admission_permits() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_on = listener.local_addr().unwrap();
    let connection_count = ConnectionCount::default();
    let destination_mux = Arc::new(TcpDestinationMuxBuilder::default().build().unwrap());

    for _ in 0..3 {
      let mut client = TcpStream::connect(listen_on).await.unwrap();
      let (server, src_addr) = listener.accept().await.unwrap();
      client.write_all(&[0x16, 0x03, 0x01, 0xff, 0xff]).await.unwrap();

      let permit = connection_count.try_acquire(1).unwrap();
      assert_eq!(connection_count.current(), 1);

      #[cfg(feature = "proxy-protocol")]
      handle_tcp_connection(destination_mux.clone(), permit, server, src_addr, listen_on, None).await;
      #[cfg(not(feature = "proxy-protocol"))]
      handle_tcp_connection(destination_mux.clone(), permit, server, src_addr).await;

      assert_eq!(connection_count.current(), 0);
      let mut closed = [0u8; 1];
      assert_eq!(client.read(&mut closed).await.unwrap(), 0);
    }
  }

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
        .set_base(
          TcpProtocolType::Any,
          dst_any,
          &dns_cache,
          None,
          #[cfg(feature = "proxy-protocol")]
          None,
        )
        .set_base(
          TcpProtocolType::Ssh,
          dst_ssh,
          &dns_cache,
          None,
          #[cfg(feature = "proxy-protocol")]
          None,
        )
        .set_base(
          TcpProtocolType::Tls,
          dst_tls_1,
          &dns_cache,
          None,
          #[cfg(feature = "proxy-protocol")]
          None,
        )
        .set_tls(
          dst_tls_2,
          &dns_cache,
          None,
          Some(&["example.com"]),
          #[cfg(feature = "proxy-protocol")]
          None,
          None,
          None,
        )
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
        .set_base(
          TcpProtocolType::Any,
          dst_any,
          &dns_cache,
          None,
          #[cfg(feature = "proxy-protocol")]
          None,
        )
        .build()
        .unwrap(),
    );

    let found = dst_mux.find_destination(&TcpProbedProtocol::Any).unwrap();
    let destination = found.get_destination(&"127.0.0.1:60000".parse().unwrap()).await.unwrap();
    assert!(
      [
        "[2606:4700:4700::1111]:53".parse().unwrap(),
        "[2606:4700:4700::1001]:53".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
        "1.0.0.1:53".parse().unwrap()
      ]
      .contains(&destination)
    );
  }
}
