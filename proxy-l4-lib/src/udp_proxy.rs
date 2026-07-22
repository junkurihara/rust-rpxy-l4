use crate::{
  config::EchProtocolConfig,
  constants::{
    UDP_BUFFER_SIZE, UDP_INITIAL_BUFFER_LIFETIME, UDP_PROBE_CHANNEL_CAPACITY, UDP_PROBE_EXPIRY_INTERVAL_MILLIS,
    UDP_PROBE_MAX_BYTES_PER_FLOW, UDP_PROBE_MAX_BYTES_PER_IP, UDP_PROBE_MAX_BYTES_PER_IPV6_PREFIX,
    UDP_PROBE_MAX_DATAGRAMS_PER_FLOW, UDP_PROBE_MAX_DATAGRAMS_PER_IP, UDP_PROBE_MAX_DATAGRAMS_PER_IPV6_PREFIX,
    UDP_PROBE_MAX_ENTRIES, UDP_PROBE_MAX_ENTRIES_PER_IP, UDP_PROBE_MAX_ENTRIES_PER_IPV6_PREFIX, UDP_PROBE_MAX_PAYLOAD_BYTES,
    UDP_PROBE_OVERLOAD_WARNING_INTERVAL,
  },
  count::{ConnectionCount, ConnectionCountSum},
  destination::{LoadBalance, TargetDestination, TlsDestinationItem},
  error::{ProxyBuildError, ProxyError},
  probe::{ProbeResult, UdpInitialDatagrams, UdpProbedProtocol},
  proto::UdpProtocolType,
  socket::{DownstreamRecvInfo, DownstreamUdpSocket},
  target::{DnsCache, TargetAddr},
  time_util::get_monotonic_seconds,
  trace::*,
  udp_conn::{UdpConnectionPool, UdpFlowKey},
};
use std::{
  collections::{BTreeMap, HashSet},
  hash::Hash,
  net::{IpAddr, Ipv6Addr, SocketAddr},
  sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
  },
  time::Duration,
};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

/// Type alias for QUIC destinations
type QuicDestinations = crate::destination::TlsDestinations<UdpDestinationInner>;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone)]
enum UdpDestination {
  /// Udp destination
  Udp(UdpDestinationInner),
  /// Udp destinations specific for QUIC
  Quic(QuicDestinations),
}
#[derive(Debug, Clone)]
/// Udp destination struct
pub(crate) struct UdpDestinationInner {
  /// Destination socket address
  inner: TargetDestination,
  /// Connection idle lifetime in seconds
  /// If set to 0, no limit is applied for the destination
  connection_idle_lifetime: u32,
}

#[derive(Debug, Clone)]
/// Destination struct found in the multiplexer from TcpProbedProtocol
enum FoundUdpDestination {
  /// Udp destination
  Udp(UdpDestinationInner),
  /// Tls destination
  Quic(TlsDestinationItem<UdpDestinationInner>),
}

impl TryFrom<(&[TargetAddr], Option<&LoadBalance>, &Arc<DnsCache>, Option<u32>)> for UdpDestinationInner {
  type Error = ProxyBuildError;
  fn try_from(
    (dst_addrs, load_balance, dns_cache, connection_idle_lifetime): (
      &[TargetAddr],
      Option<&LoadBalance>,
      &Arc<DnsCache>,
      Option<u32>,
    ),
  ) -> Result<Self, Self::Error> {
    let inner = TargetDestination::try_from((dst_addrs, load_balance, dns_cache.clone()))?;
    let connection_idle_lifetime = connection_idle_lifetime.unwrap_or(crate::constants::UDP_CONNECTION_IDLE_LIFETIME);

    Ok(Self {
      inner,
      connection_idle_lifetime,
    })
  }
}

impl UdpDestinationInner {
  /// Get the destination socket address
  pub(crate) async fn get_destination(&self, src_addr: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    self.inner.get_destination(src_addr).await
  }
  /// Get the connection idle lifetime
  pub(crate) fn get_connection_idle_lifetime(&self) -> u32 {
    self.connection_idle_lifetime
  }
}

#[allow(unused)]
impl FoundUdpDestination {
  /// Get the destination socket address
  pub(crate) async fn get_destination(&self, src_addr: &SocketAddr) -> Result<SocketAddr, ProxyError> {
    match self {
      Self::Udp(dst) => dst.get_destination(src_addr).await,
      Self::Quic(dst) => dst.destination().get_destination(src_addr).await,
    }
  }
  /// Get the connection idle lifetime
  pub(crate) fn get_connection_idle_lifetime(&self) -> u32 {
    match self {
      Self::Udp(dst) => dst.get_connection_idle_lifetime(),
      Self::Quic(dst) => dst.destination().get_connection_idle_lifetime(),
    }
  }
}

/* ---------------------------------------------------------- */
/// Udp destination multiplexer
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct UdpDestinationMux {
  /// Multiplexed TCP destinations
  #[builder(default = "ahash::HashMap::default()")]
  inner: ahash::HashMap<UdpProtocolType, UdpDestination>,
}

impl UdpDestinationMuxBuilder {
  /// Create a new Udp destination multiplexer builder
  pub(crate) fn set_base(
    &mut self,
    proto_type: UdpProtocolType,
    addrs: &[TargetAddr],
    dns_cache: &Arc<DnsCache>,
    load_balance: Option<&LoadBalance>,
    lifetime: Option<u32>,
  ) -> &mut Self {
    let udp_dest = UdpDestinationInner::try_from((addrs, load_balance, dns_cache, lifetime));
    if udp_dest.is_err() {
      return self;
    }
    let udp_dest_inner = udp_dest.unwrap();

    let mut inner = self.inner.clone().unwrap_or_default();
    match proto_type {
      UdpProtocolType::Quic => {
        let mut current_quic = if let Some(UdpDestination::Quic(current)) = inner.get(&proto_type).cloned() {
          current
        } else {
          QuicDestinations::new()
        };
        current_quic.add(&[], &[], udp_dest_inner, None, dns_cache);
        inner.insert(proto_type, UdpDestination::Quic(current_quic));
      }
      _ => {
        inner.insert(proto_type, UdpDestination::Udp(udp_dest_inner));
      }
    }
    self.inner = Some(inner);
    self
  }

  /// Set Quic destinations, use this if alpn and server names are needed for protocol detection or ech is need to be configured
  #[allow(
    clippy::too_many_arguments,
    reason = "The builder method mirrors the existing QUIC route configuration fields"
  )]
  pub(crate) fn set_quic(
    &mut self,
    addrs: &[TargetAddr],
    dns_cache: &Arc<DnsCache>,
    load_balance: Option<&LoadBalance>,
    lifetime: Option<u32>,
    server_names: Option<&[&str]>,
    alpn: Option<&[&str]>,
    _ech: Option<&EchProtocolConfig>, // TODO: Consider how to handle TLS ClientHello for QUIC + ECH, especially reassembling the datagram for TLS ClientHello Inner
  ) -> &mut Self {
    let udp_dest = UdpDestinationInner::try_from((addrs, load_balance, dns_cache, lifetime));
    if udp_dest.is_err() {
      return self;
    }
    let udp_dest_inner = udp_dest.unwrap();
    let mut inner = self.inner.clone().unwrap_or_default();

    let mut current_quic = match inner.get(&UdpProtocolType::Quic).cloned() {
      Some(UdpDestination::Quic(current)) => current,
      _ => QuicDestinations::new(), // If not found, create a new one
    };
    current_quic.add(
      server_names.unwrap_or_default(),
      alpn.unwrap_or_default(),
      udp_dest_inner,
      None, // TODO: currently NONE for ech
      dns_cache,
    );

    inner.insert(UdpProtocolType::Quic, UdpDestination::Quic(current_quic));
    self.inner = Some(inner);
    self
  }
}

impl UdpDestinationMux {
  /// Check if the destination mux is empty
  pub fn is_empty(&self) -> bool {
    self.inner.is_empty()
  }
  /// Get the destination socket address for the given protocol
  fn find_destination(&self, probed_protocol: &UdpProbedProtocol) -> Result<FoundUdpDestination, ProxyError> {
    let proto_type = probed_protocol.proto_type();
    match self.inner.get(&proto_type) {
      // Found non-Quic protocol
      Some(UdpDestination::Udp(udp_destination)) => {
        debug!("Setting up dest addr for {proto_type}");
        return Ok(FoundUdpDestination::Udp(udp_destination.clone()));
      }
      // Found Quic protocol
      Some(UdpDestination::Quic(quic_destinations)) => {
        let UdpProbedProtocol::Quic(client_hello) = probed_protocol else {
          return Err(ProxyError::NoDestinationAddressForProtocol(String::new()));
        };
        return quic_destinations
          .find(client_hello)
          .ok_or(ProxyError::NoDestinationAddressForProtocol(String::new()))
          .map(|found| {
            debug!("Setting up dest addr for {proto_type}");
            FoundUdpDestination::Quic(found.clone())
          });
      }
      _ => {}
    };

    // if nothing is found, check for the default destination
    if proto_type == UdpProtocolType::Any {
      return Err(ProxyError::NoDestinationAddressForProtocol(String::new()));
    }
    // Check for the default destination
    let destination_any = self
      .inner
      .get(&UdpProtocolType::Any)
      .cloned()
      .ok_or(ProxyError::NoDestinationAddressForProtocol(String::new()))?;
    let UdpDestination::Udp(dst) = destination_any else {
      return Err(ProxyError::NoDestinationAddressForProtocol(String::new()));
    };
    debug!("Setting up dest addr for unspecified proto");
    Ok(FoundUdpDestination::Udp(dst.clone()))
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

  /// Authoritative connection admission counter shared across listeners and reload generations
  #[builder(default = "ConnectionCount::default()")]
  admission_count: ConnectionCount,

  /// Max UDP concurrent connections
  #[builder(default = "crate::constants::MAX_UDP_CONCURRENT_CONNECTIONS")]
  max_connections: usize,
}

impl UdpProxy {
  pub async fn start(&self, cancel_token: CancellationToken) -> Result<(), ProxyError> {
    info!("Starting UDP proxy on {}", self.listen_on);

    // Bind the downstream socket so we can preserve the local destination IP
    // that the client originally sent to when replying on multi-homed servers.
    let udp_socket = Arc::new(DownstreamUdpSocket::bind(&self.listen_on)?);

    // Channel to receive incoming datagram from the source
    let udp_socket_rx = udp_socket.clone();

    // Shared downstream socket for sending responses back to clients.
    let udp_socket_tx = udp_socket;

    // Build the UDP connection pool
    let udp_connection_pool = Arc::new(UdpConnectionPool::new(self.runtime_handle.clone(), cancel_token.clone()));

    // Set the initial connection count
    self.connection_count.set(self.listen_on, 0);

    // Setup buffer
    let mut udp_buf = vec![0u8; UDP_BUFFER_SIZE];

    /* ----------------- */
    // Start the initial datagram buffer pool service for source socket address to handle multiple datagrams for detection
    let udp_initial_datagrams_buffer_pool = UdpInitialDatagramsBufferPool::new((self, &udp_socket_tx, &udp_connection_pool));
    let udp_probe_ingress = udp_initial_datagrams_buffer_pool.spawn_service(cancel_token.clone());

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
        let (buf_size, src_addr, local_ip) = match udp_socket_rx.recv(&mut udp_buf).await {
          Err(e) => {
            let contextual_error = ProxyError::IoError(e)
              .with_source_context(self.listen_on)
              .with_protocol_context("UDP");
            error!("Error in UDP listener on {}: {contextual_error}", self.listen_on);
            return Err(contextual_error);
          }
          Ok(DownstreamRecvInfo {
            bytes_read,
            src_addr,
            local_ip,
          }) => (bytes_read, src_addr, local_ip),
        };
        trace!("received {} bytes from {} -> {} [source]", buf_size, src_addr, local_ip);

        // Prune inactive connections first
        udp_connection_pool.prune_inactive_connections();

        let flow_key = UdpFlowKey::new(src_addr, local_ip);

        if let Some(conn) = udp_connection_pool.get(&flow_key) {
          // Handle case there is an existing connection
          debug!("Found existing connection for {} -> {}", src_addr, local_ip);
          let _ = conn.send(&udp_buf[..buf_size]).await;
          // here we ignore the error, as the connection might be closed
          continue;
        }

        // Handle case there is no existing connection
        debug!(
          "No existing connection for {src_addr} -> {}:{}",
          if local_ip.is_ipv6() {
            format!("[{}]", local_ip)
          } else {
            local_ip.to_string()
          },
          self.listen_on.port()
        );

        // Reserve before copying, and never block established-flow receive on probe overload.
        if udp_probe_ingress.try_enqueue(flow_key, &udp_buf[..buf_size]) == ProbeEnqueueResult::Closed {
          error!("UDP initial datagram buffer service channel closed on {}", self.listen_on);
          cancel_token.cancel();
        }
      }
    };

    tokio::select! {
      result = listener_service => {
        if let Err(ref e) = result {
          error!("UDP proxy on {} stopped: {e}", self.listen_on);
        } else {
          error!("UDP proxy on {} stopped", self.listen_on);
        }
        result
      }
      _ = cancel_token.cancelled() => {
        warn!("UDP proxy cancelled");
        Ok(())
      }
    }
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
#[derive(Clone, Copy, Debug)]
struct ProbeLimits {
  channel_capacity: usize,
  max_entries: usize,
  max_payload_bytes: usize,
  max_datagrams_per_flow: usize,
  max_bytes_per_flow: usize,
  max_datagrams_per_ip: usize,
  max_bytes_per_ip: usize,
  max_entries_per_ip: usize,
  max_datagrams_per_prefix: usize,
  max_bytes_per_prefix: usize,
  max_entries_per_prefix: usize,
}

impl Default for ProbeLimits {
  fn default() -> Self {
    Self {
      channel_capacity: UDP_PROBE_CHANNEL_CAPACITY,
      max_entries: UDP_PROBE_MAX_ENTRIES,
      max_payload_bytes: UDP_PROBE_MAX_PAYLOAD_BYTES,
      max_datagrams_per_flow: UDP_PROBE_MAX_DATAGRAMS_PER_FLOW,
      max_bytes_per_flow: UDP_PROBE_MAX_BYTES_PER_FLOW,
      max_datagrams_per_ip: UDP_PROBE_MAX_DATAGRAMS_PER_IP,
      max_bytes_per_ip: UDP_PROBE_MAX_BYTES_PER_IP,
      max_entries_per_ip: UDP_PROBE_MAX_ENTRIES_PER_IP,
      max_datagrams_per_prefix: UDP_PROBE_MAX_DATAGRAMS_PER_IPV6_PREFIX,
      max_bytes_per_prefix: UDP_PROBE_MAX_BYTES_PER_IPV6_PREFIX,
      max_entries_per_prefix: UDP_PROBE_MAX_ENTRIES_PER_IPV6_PREFIX,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
enum ProbeDropReason {
  ChannelFull,
  GlobalPayloadBytes,
  PerFlowDatagrams,
  PerFlowBytes,
  PerIpDatagrams,
  PerIpBytes,
  PerPrefixDatagrams,
  PerPrefixBytes,
  GlobalEntries,
  PerIpEntries,
  PerPrefixEntries,
  ConnectionLimit,
  Expired,
  AccountingUnavailable,
}

impl ProbeDropReason {
  const COUNT: usize = 14;

  fn label(self) -> &'static str {
    match self {
      Self::ChannelFull => "channel_full",
      Self::GlobalPayloadBytes => "global_payload_bytes",
      Self::PerFlowDatagrams => "per_flow_datagrams",
      Self::PerFlowBytes => "per_flow_bytes",
      Self::PerIpDatagrams => "per_ip_datagrams",
      Self::PerIpBytes => "per_ip_bytes",
      Self::PerPrefixDatagrams => "per_prefix_datagrams",
      Self::PerPrefixBytes => "per_prefix_bytes",
      Self::GlobalEntries => "global_entries",
      Self::PerIpEntries => "per_ip_entries",
      Self::PerPrefixEntries => "per_prefix_entries",
      Self::ConnectionLimit => "connection_limit",
      Self::Expired => "expired",
      Self::AccountingUnavailable => "accounting_unavailable",
    }
  }

  fn all() -> [Self; Self::COUNT] {
    [
      Self::ChannelFull,
      Self::GlobalPayloadBytes,
      Self::PerFlowDatagrams,
      Self::PerFlowBytes,
      Self::PerIpDatagrams,
      Self::PerIpBytes,
      Self::PerPrefixDatagrams,
      Self::PerPrefixBytes,
      Self::GlobalEntries,
      Self::PerIpEntries,
      Self::PerPrefixEntries,
      Self::ConnectionLimit,
      Self::Expired,
      Self::AccountingUnavailable,
    ]
  }
}

#[derive(Debug)]
struct ProbeStats {
  counters: [AtomicU64; ProbeDropReason::COUNT],
  last_warning_at: AtomicU64,
}

impl ProbeStats {
  fn new() -> Self {
    Self {
      counters: std::array::from_fn(|_| AtomicU64::new(0)),
      last_warning_at: AtomicU64::new(u64::MAX),
    }
  }

  fn record(&self, reason: ProbeDropReason) {
    self.counters[reason as usize].fetch_add(1, Ordering::Relaxed);
  }

  fn count(&self, reason: ProbeDropReason) -> u64 {
    self.counters[reason as usize].load(Ordering::Relaxed)
  }

  fn nonzero_totals(&self) -> Vec<(&'static str, u64)> {
    ProbeDropReason::all()
      .into_iter()
      .filter_map(|reason| {
        let count = self.count(reason);
        (count > 0).then_some((reason.label(), count))
      })
      .collect()
  }

  fn maybe_warn(&self, now: u64, listen_on: SocketAddr, budget: &ProbeBudget) {
    let last = self.last_warning_at.load(Ordering::Relaxed);
    if last != u64::MAX && now.saturating_sub(last) < UDP_PROBE_OVERLOAD_WARNING_INTERVAL {
      return;
    }
    if self
      .last_warning_at
      .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
      .is_err()
    {
      return;
    }
    warn!(
      "UDP probe overload summary on {listen_on}: reasons={:?}, usage={:?}, limits={:?}",
      self.nonzero_totals(),
      budget.snapshot(),
      budget.limits
    );
  }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProbeUsage {
  datagrams: usize,
  bytes: usize,
  entries: usize,
}

impl ProbeUsage {
  fn is_zero(self) -> bool {
    self.datagrams == 0 && self.bytes == 0 && self.entries == 0
  }
}

#[derive(Debug)]
struct ProbeBudgetState {
  accounting_valid: bool,
  payload_bytes: usize,
  entries: usize,
  flow_usage: ahash::HashMap<UdpFlowKey, ProbeUsage>,
  ip_usage: ahash::HashMap<IpAddr, ProbeUsage>,
  prefix_usage: ahash::HashMap<Ipv6Addr, ProbeUsage>,
}

impl Default for ProbeBudgetState {
  fn default() -> Self {
    Self {
      accounting_valid: true,
      payload_bytes: 0,
      entries: 0,
      flow_usage: ahash::HashMap::default(),
      ip_usage: ahash::HashMap::default(),
      prefix_usage: ahash::HashMap::default(),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProbeBudgetSnapshot {
  accounting_valid: bool,
  payload_bytes: usize,
  entries: usize,
  flow_keys: usize,
  ip_keys: usize,
  prefix_keys: usize,
}

struct ProbeBudget {
  limits: ProbeLimits,
  state: Mutex<ProbeBudgetState>,
  stats: Arc<ProbeStats>,
}

impl ProbeBudget {
  fn new(limits: ProbeLimits, stats: Arc<ProbeStats>) -> Arc<Self> {
    Arc::new(Self {
      limits,
      state: Mutex::new(ProbeBudgetState::default()),
      stats,
    })
  }

  fn try_reserve_payload(
    self: &Arc<Self>,
    flow_key: UdpFlowKey,
    payload_bytes: usize,
  ) -> Result<ProbePayloadPermit, ProbeDropReason> {
    let (source_ip, source_prefix) = source_identities(flow_key.src_addr.ip());
    let mut state = match self.state.lock() {
      Ok(state) => state,
      Err(poisoned) => {
        let mut state = poisoned.into_inner();
        state.accounting_valid = false;
        return Err(ProbeDropReason::AccountingUnavailable);
      }
    };
    if !state.accounting_valid {
      return Err(ProbeDropReason::AccountingUnavailable);
    }

    let flow_usage = state.flow_usage.get(&flow_key).copied().unwrap_or_default();
    let ip_usage = state.ip_usage.get(&source_ip).copied().unwrap_or_default();
    let prefix_usage = source_prefix
      .and_then(|prefix| state.prefix_usage.get(&prefix).copied())
      .unwrap_or_default();

    if exceeds(state.payload_bytes, payload_bytes, self.limits.max_payload_bytes) {
      return Err(ProbeDropReason::GlobalPayloadBytes);
    }
    if exceeds(flow_usage.datagrams, 1, self.limits.max_datagrams_per_flow) {
      return Err(ProbeDropReason::PerFlowDatagrams);
    }
    if exceeds(flow_usage.bytes, payload_bytes, self.limits.max_bytes_per_flow) {
      return Err(ProbeDropReason::PerFlowBytes);
    }
    if exceeds(ip_usage.datagrams, 1, self.limits.max_datagrams_per_ip) {
      return Err(ProbeDropReason::PerIpDatagrams);
    }
    if exceeds(ip_usage.bytes, payload_bytes, self.limits.max_bytes_per_ip) {
      return Err(ProbeDropReason::PerIpBytes);
    }
    if source_prefix.is_some() && exceeds(prefix_usage.datagrams, 1, self.limits.max_datagrams_per_prefix) {
      return Err(ProbeDropReason::PerPrefixDatagrams);
    }
    if source_prefix.is_some() && exceeds(prefix_usage.bytes, payload_bytes, self.limits.max_bytes_per_prefix) {
      return Err(ProbeDropReason::PerPrefixBytes);
    }

    state.payload_bytes += payload_bytes;
    let flow_usage = state.flow_usage.entry(flow_key).or_default();
    flow_usage.datagrams += 1;
    flow_usage.bytes += payload_bytes;
    let ip_usage = state.ip_usage.entry(source_ip).or_default();
    ip_usage.datagrams += 1;
    ip_usage.bytes += payload_bytes;
    if let Some(prefix) = source_prefix {
      let prefix_usage = state.prefix_usage.entry(prefix).or_default();
      prefix_usage.datagrams += 1;
      prefix_usage.bytes += payload_bytes;
    }

    Ok(ProbePayloadPermit {
      budget: self.clone(),
      flow_key,
      source_ip,
      source_prefix,
      payload_bytes,
    })
  }

  fn try_reserve_entry(self: &Arc<Self>, flow_key: UdpFlowKey) -> Result<ProbeEntryPermit, ProbeDropReason> {
    let (source_ip, source_prefix) = source_identities(flow_key.src_addr.ip());
    let mut state = match self.state.lock() {
      Ok(state) => state,
      Err(poisoned) => {
        let mut state = poisoned.into_inner();
        state.accounting_valid = false;
        return Err(ProbeDropReason::AccountingUnavailable);
      }
    };
    if !state.accounting_valid {
      return Err(ProbeDropReason::AccountingUnavailable);
    }

    let ip_usage = state.ip_usage.get(&source_ip).copied().unwrap_or_default();
    let prefix_usage = source_prefix
      .and_then(|prefix| state.prefix_usage.get(&prefix).copied())
      .unwrap_or_default();
    if exceeds(state.entries, 1, self.limits.max_entries) {
      return Err(ProbeDropReason::GlobalEntries);
    }
    if exceeds(ip_usage.entries, 1, self.limits.max_entries_per_ip) {
      return Err(ProbeDropReason::PerIpEntries);
    }
    if source_prefix.is_some() && exceeds(prefix_usage.entries, 1, self.limits.max_entries_per_prefix) {
      return Err(ProbeDropReason::PerPrefixEntries);
    }

    state.entries += 1;
    state.ip_usage.entry(source_ip).or_default().entries += 1;
    if let Some(prefix) = source_prefix {
      state.prefix_usage.entry(prefix).or_default().entries += 1;
    }

    Ok(ProbeEntryPermit {
      budget: self.clone(),
      source_ip,
      source_prefix,
    })
  }

  fn release_payload(&self, permit: &ProbePayloadPermit) {
    let (mut state, poisoned) = match self.state.lock() {
      Ok(state) => (state, false),
      Err(poisoned) => (poisoned.into_inner(), true),
    };
    let global_ok = match state.payload_bytes.checked_sub(permit.payload_bytes) {
      Some(bytes) => {
        state.payload_bytes = bytes;
        true
      }
      None => false,
    };
    let flow_ok = release_usage(&mut state.flow_usage, permit.flow_key, 1, permit.payload_bytes, 0);
    let ip_ok = release_usage(&mut state.ip_usage, permit.source_ip, 1, permit.payload_bytes, 0);
    let prefix_ok = permit
      .source_prefix
      .map(|prefix| release_usage(&mut state.prefix_usage, prefix, 1, permit.payload_bytes, 0))
      .unwrap_or(true);
    let accounting_failed = poisoned || !(global_ok && flow_ok && ip_ok && prefix_ok);
    if accounting_failed {
      state.accounting_valid = false;
    }
    drop(state);
    if accounting_failed {
      self.stats.record(ProbeDropReason::AccountingUnavailable);
      error!("UDP probe payload accounting invariant failed; future probe admission is disabled");
    }
  }

  fn release_entry(&self, permit: &ProbeEntryPermit) {
    let (mut state, poisoned) = match self.state.lock() {
      Ok(state) => (state, false),
      Err(poisoned) => (poisoned.into_inner(), true),
    };
    let global_ok = match state.entries.checked_sub(1) {
      Some(entries) => {
        state.entries = entries;
        true
      }
      None => false,
    };
    let ip_ok = release_usage(&mut state.ip_usage, permit.source_ip, 0, 0, 1);
    let prefix_ok = permit
      .source_prefix
      .map(|prefix| release_usage(&mut state.prefix_usage, prefix, 0, 0, 1))
      .unwrap_or(true);
    let accounting_failed = poisoned || !(global_ok && ip_ok && prefix_ok);
    if accounting_failed {
      state.accounting_valid = false;
    }
    drop(state);
    if accounting_failed {
      self.stats.record(ProbeDropReason::AccountingUnavailable);
      error!("UDP probe entry accounting invariant failed; future probe admission is disabled");
    }
  }

  fn snapshot(&self) -> ProbeBudgetSnapshot {
    let state = match self.state.lock() {
      Ok(state) => state,
      Err(poisoned) => poisoned.into_inner(),
    };
    ProbeBudgetSnapshot {
      accounting_valid: state.accounting_valid,
      payload_bytes: state.payload_bytes,
      entries: state.entries,
      flow_keys: state.flow_usage.len(),
      ip_keys: state.ip_usage.len(),
      prefix_keys: state.prefix_usage.len(),
    }
  }
}

fn exceeds(current: usize, additional: usize, limit: usize) -> bool {
  current.checked_add(additional).is_none_or(|next| next > limit)
}

fn release_usage<K: Copy + Eq + Hash>(
  usage_map: &mut ahash::HashMap<K, ProbeUsage>,
  key: K,
  datagrams: usize,
  bytes: usize,
  entries: usize,
) -> bool {
  let Some(usage) = usage_map.get_mut(&key) else {
    return false;
  };
  let Some(next_datagrams) = usage.datagrams.checked_sub(datagrams) else {
    return false;
  };
  let Some(next_bytes) = usage.bytes.checked_sub(bytes) else {
    return false;
  };
  let Some(next_entries) = usage.entries.checked_sub(entries) else {
    return false;
  };
  usage.datagrams = next_datagrams;
  usage.bytes = next_bytes;
  usage.entries = next_entries;
  let remove = usage.is_zero();
  if remove {
    usage_map.remove(&key);
  }
  true
}

fn source_identities(source_ip: IpAddr) -> (IpAddr, Option<Ipv6Addr>) {
  match source_ip {
    IpAddr::V4(ipv4) => (IpAddr::V4(ipv4), None),
    IpAddr::V6(ipv6) => match ipv6.to_ipv4_mapped() {
      Some(ipv4) => (IpAddr::V4(ipv4), None),
      None => {
        let prefix = Ipv6Addr::from(u128::from(ipv6) & (u128::MAX << 64));
        (IpAddr::V6(ipv6), Some(prefix))
      }
    },
  }
}

struct ProbePayloadPermit {
  budget: Arc<ProbeBudget>,
  flow_key: UdpFlowKey,
  source_ip: IpAddr,
  source_prefix: Option<Ipv6Addr>,
  payload_bytes: usize,
}

impl Drop for ProbePayloadPermit {
  fn drop(&mut self) {
    self.budget.release_payload(self);
  }
}

struct ProbeEntryPermit {
  budget: Arc<ProbeBudget>,
  source_ip: IpAddr,
  source_prefix: Option<Ipv6Addr>,
}

impl Drop for ProbeEntryPermit {
  fn drop(&mut self) {
    self.budget.release_entry(self);
  }
}

#[derive(Debug, Eq, PartialEq)]
enum ProbeEnqueueResult {
  Enqueued,
  Dropped,
  Closed,
}

struct QueuedProbeDatagram {
  flow_key: UdpFlowKey,
  payload: Vec<u8>,
  _payload_permit: ProbePayloadPermit,
}

#[derive(Clone)]
struct UdpProbeIngress {
  listen_on: SocketAddr,
  tx: mpsc::Sender<QueuedProbeDatagram>,
  budget: Arc<ProbeBudget>,
  stats: Arc<ProbeStats>,
}

impl UdpProbeIngress {
  fn try_enqueue(&self, flow_key: UdpFlowKey, payload: &[u8]) -> ProbeEnqueueResult {
    let permit = match self.budget.try_reserve_payload(flow_key, payload.len()) {
      Ok(permit) => permit,
      Err(reason) => {
        self.record_drop(reason);
        return ProbeEnqueueResult::Dropped;
      }
    };
    let queued = QueuedProbeDatagram {
      flow_key,
      payload: payload.to_vec(),
      _payload_permit: permit,
    };
    match self.tx.try_send(queued) {
      Ok(()) => ProbeEnqueueResult::Enqueued,
      Err(mpsc::error::TrySendError::Full(queued)) => {
        drop(queued);
        self.record_drop(ProbeDropReason::ChannelFull);
        ProbeEnqueueResult::Dropped
      }
      Err(mpsc::error::TrySendError::Closed(queued)) => {
        drop(queued);
        ProbeEnqueueResult::Closed
      }
    }
  }

  fn record_drop(&self, reason: ProbeDropReason) {
    self.stats.record(reason);
    self
      .stats
      .maybe_warn(get_monotonic_seconds(), self.listen_on, self.budget.as_ref());
  }
}

struct ProbeFlowState {
  datagrams: UdpInitialDatagrams,
  _payload_permits: Vec<ProbePayloadPermit>,
  entry_permit: Option<ProbeEntryPermit>,
  expires_at: Option<u64>,
}

impl ProbeFlowState {
  fn new(queued: QueuedProbeDatagram) -> Self {
    let QueuedProbeDatagram {
      payload,
      _payload_permit,
      ..
    } = queued;
    Self {
      datagrams: UdpInitialDatagrams {
        inner: vec![payload],
        probed_as_pollnext: Default::default(),
      },
      _payload_permits: vec![_payload_permit],
      entry_permit: None,
      expires_at: None,
    }
  }

  fn push(&mut self, queued: QueuedProbeDatagram) {
    self.datagrams.inner.push(queued.payload);
    self._payload_permits.push(queued._payload_permit);
  }
}

type ProbeEntries = ahash::HashMap<UdpFlowKey, ProbeFlowState>;
type ProbeExpiryIndex = BTreeMap<u64, HashSet<UdpFlowKey>>;

fn remove_expiry(expiry_index: &mut ProbeExpiryIndex, flow_key: UdpFlowKey, expires_at: u64) {
  let remove_bucket = expiry_index.get_mut(&expires_at).is_some_and(|flows| {
    flows.remove(&flow_key);
    flows.is_empty()
  });
  if remove_bucket {
    expiry_index.remove(&expires_at);
  }
}

fn expire_due(entries: &mut ProbeEntries, expiry_index: &mut ProbeExpiryIndex, now: u64, stats: &ProbeStats) -> usize {
  let mut expired = 0;
  while let Some((&expires_at, _)) = expiry_index.first_key_value() {
    if expires_at > now {
      break;
    }
    let Some((_, flow_keys)) = expiry_index.pop_first() else {
      break;
    };
    for flow_key in flow_keys {
      if entries
        .get(&flow_key)
        .is_some_and(|entry| entry.expires_at == Some(expires_at))
      {
        entries.remove(&flow_key);
        stats.record(ProbeDropReason::Expired);
        expired += 1;
      }
    }
  }
  expired
}

#[derive(Clone)]
/// Temporary buffer pool of initial UDP datagrams dispatched from each clients.
/// This is used to buffer the initial datagrams of each client, probe the destination, and then establish a UDP connection.
struct UdpInitialDatagramsBufferPool {
  /// listening socket address
  listen_on: SocketAddr,

  /// Shared listening socket for sending responses back to clients
  udp_socket_tx: Arc<DownstreamUdpSocket>,

  /// pointer to udp connection pool
  udp_connection_pool: Arc<UdpConnectionPool>,

  /// Socket address to write on, the actual destination routed for protocol types
  destination_mux: Arc<UdpDestinationMux>,

  /// Tokio runtime handle
  runtime_handle: tokio::runtime::Handle,

  /// Connection counter, set shared counter if #connections of all TCP proxies are needed
  connection_count: ConnectionCountSum<SocketAddr>,

  /// Authoritative connection admission counter
  admission_count: ConnectionCount,

  /// Max UDP concurrent connections
  max_connections: usize,

  /// Shared probe resource accounting.
  budget: Arc<ProbeBudget>,

  /// Fixed-cardinality overload and expiry counters.
  stats: Arc<ProbeStats>,
}

impl UdpInitialDatagramsBufferPool {
  /// Create a new UdpInitialDatagramsBufferPool
  fn new((udp_proxy, udp_socket_tx, udp_conn_pool): (&UdpProxy, &Arc<DownstreamUdpSocket>, &Arc<UdpConnectionPool>)) -> Self {
    let stats = Arc::new(ProbeStats::new());
    let budget = ProbeBudget::new(ProbeLimits::default(), stats.clone());
    Self {
      listen_on: udp_proxy.listen_on,
      udp_socket_tx: udp_socket_tx.clone(),
      udp_connection_pool: udp_conn_pool.clone(),
      destination_mux: udp_proxy.destination_mux.clone(),
      runtime_handle: udp_proxy.runtime_handle.clone(),
      connection_count: udp_proxy.connection_count.clone(),
      admission_count: udp_proxy.admission_count.clone(),
      max_connections: udp_proxy.max_connections,
      budget,
      stats,
    }
  }

  async fn handle_datagram(&self, queued: QueuedProbeDatagram, entries: &mut ProbeEntries, expiry_index: &mut ProbeExpiryIndex) {
    let flow_key = queued.flow_key;
    let src_addr = flow_key.src_addr;

    // A connection may have completed while this datagram waited in the probe queue.
    if let Some(conn) = self.udp_connection_pool.get(&flow_key) {
      if let Err(error) = conn.send(&queued.payload).await {
        debug!("Failed to forward a queued datagram to an established UDP connection: {error}");
      }
      return;
    }

    let mut state = if let Some(mut state) = entries.remove(&flow_key) {
      state.push(queued);
      state
    } else {
      ProbeFlowState::new(queued)
    };

    let probe_result = match UdpProbedProtocol::detect_protocol(&mut state.datagrams).await {
      Ok(result) => result,
      Err(error) => {
        if let Some(expires_at) = state.expires_at {
          remove_expiry(expiry_index, flow_key, expires_at);
        }
        let contextual_error = error.with_source_context(src_addr).with_protocol_context("UDP");
        error!("Failed to detect UDP protocol: {contextual_error}");
        return;
      }
    };

    match probe_result {
      ProbeResult::PollNext => {
        if state.entry_permit.is_none() {
          let entry_permit = match self.budget.try_reserve_entry(flow_key) {
            Ok(permit) => permit,
            Err(reason) => {
              self.record_drop(reason);
              return;
            }
          };
          let expires_at = get_monotonic_seconds().saturating_add(UDP_INITIAL_BUFFER_LIFETIME);
          expiry_index.entry(expires_at).or_default().insert(flow_key);
          state.entry_permit = Some(entry_permit);
          state.expires_at = Some(expires_at);
        }
        entries.insert(flow_key, state);
      }
      ProbeResult::Success(probed_protocol) => {
        if let Some(expires_at) = state.expires_at {
          remove_expiry(expiry_index, flow_key, expires_at);
        }
        drop(state.entry_permit.take());
        self.forward_detected(flow_key, probed_protocol, state).await;
      }
      ProbeResult::Failure => {
        if let Some(expires_at) = state.expires_at {
          remove_expiry(expiry_index, flow_key, expires_at);
        }
        debug!("UDP protocol detector returned Failure; dropping buffered flow");
      }
    }
  }

  async fn forward_detected(&self, flow_key: UdpFlowKey, probed_protocol: UdpProbedProtocol, state: ProbeFlowState) {
    let src_addr = flow_key.src_addr;
    let local_ip = flow_key.local_ip;
    let found_dst = match self.destination_mux.find_destination(&probed_protocol) {
      Ok(destination) => destination,
      Err(error) => {
        let contextual_error = error
          .with_source_context(src_addr)
          .with_protocol_context(&probed_protocol.to_string());
        error!("No destination found for {probed_protocol}: {contextual_error}");
        return;
      }
    };
    let udp_dst_inner = match &found_dst {
      FoundUdpDestination::Udp(destination) => destination,
      FoundUdpDestination::Quic(destination) => destination.destination(),
    };

    // UdpConnectionPool deliberately relies on its caller to enforce this cap.
    let Some(connection_permit) = self.admission_count.try_acquire(self.max_connections) else {
      self.record_drop(ProbeDropReason::ConnectionLimit);
      return;
    };

    let connection = match self
      .udp_connection_pool
      .create_new_connection(
        &src_addr,
        udp_dst_inner,
        &probed_protocol.proto_type(),
        self.udp_socket_tx.clone(),
        local_ip,
        connection_permit,
      )
      .await
    {
      Ok(connection) => connection,
      Err(error) => {
        error!("Failed to create detected UDP connection: {error}");
        return;
      }
    };

    if let Err(error) = connection.send_many(&state.datagrams.inner).await {
      debug!("Failed to send initial datagrams to a detected UDP connection: {error}");
    }
    // state retains the payload permits until the initial send completes or fails.
    self
      .connection_count
      .set(self.listen_on, self.udp_connection_pool.local_pool_size());
    debug!(
      "Current connection: (local: {}, global: {}) @{}",
      self.udp_connection_pool.local_pool_size(),
      self.connection_count.current(),
      self.listen_on,
    );
  }

  fn record_drop(&self, reason: ProbeDropReason) {
    self.stats.record(reason);
    self
      .stats
      .maybe_warn(get_monotonic_seconds(), self.listen_on, self.budget.as_ref());
  }

  /// Start the UdpInitialDatagramsBufferPool
  fn spawn_service(&self, cancel_token: CancellationToken) -> UdpProbeIngress {
    let (tx, mut rx) = mpsc::channel::<QueuedProbeDatagram>(self.budget.limits.channel_capacity);

    let self_clone = self.clone();
    let service = async move {
      let mut entries = ProbeEntries::default();
      let mut expiry_index = ProbeExpiryIndex::default();
      let mut expiry_interval = tokio::time::interval(Duration::from_millis(UDP_PROBE_EXPIRY_INTERVAL_MILLIS));
      expiry_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
      loop {
        tokio::select! {
          _ = expiry_interval.tick() => {
            expire_due(
              &mut entries,
              &mut expiry_index,
              get_monotonic_seconds(),
              self_clone.stats.as_ref(),
            );
          }
          queued = rx.recv() => {
            let Some(queued) = queued else {
              warn!("UDP buffering channel closed");
              break;
            };
            self_clone
              .handle_datagram(queued, &mut entries, &mut expiry_index)
              .await;
          }
        }
      }
    };

    let ingress = UdpProbeIngress {
      listen_on: self.listen_on,
      tx,
      budget: self.budget.clone(),
      stats: self.stats.clone(),
    };
    self.runtime_handle.spawn({
      let child_token = cancel_token.child_token();
      let stats = self.stats.clone();
      let listen_on = self.listen_on;
      async move {
        tokio::select! {
          _ = service => {
            warn!("UDP initial datagram buffer pool stopped");
            cancel_token.cancel();
          },
          _ = child_token.cancelled() => {
            info!("UDP initial datagram buffer pool cancelled");
          }
        }
        let totals = stats.nonzero_totals();
        if !totals.is_empty() {
          info!("Final UDP probe drop summary on {listen_on}: {totals:?}");
        }
      }
    });

    ingress
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn generous_limits() -> ProbeLimits {
    ProbeLimits {
      channel_capacity: 8,
      max_entries: 1024,
      max_payload_bytes: 1024 * 1024,
      max_datagrams_per_flow: 1024,
      max_bytes_per_flow: 1024 * 1024,
      max_datagrams_per_ip: 1024,
      max_bytes_per_ip: 1024 * 1024,
      max_entries_per_ip: 1024,
      max_datagrams_per_prefix: 1024,
      max_bytes_per_prefix: 1024 * 1024,
      max_entries_per_prefix: 1024,
    }
  }

  fn test_budget(limits: ProbeLimits) -> (Arc<ProbeBudget>, Arc<ProbeStats>) {
    let stats = Arc::new(ProbeStats::new());
    (ProbeBudget::new(limits, stats.clone()), stats)
  }

  fn flow(source: &str, local_ip: &str) -> UdpFlowKey {
    UdpFlowKey::new(source.parse().unwrap(), local_ip.parse().unwrap())
  }

  fn assert_budget_empty(budget: &ProbeBudget) {
    assert_eq!(
      budget.snapshot(),
      ProbeBudgetSnapshot {
        accounting_valid: true,
        payload_bytes: 0,
        entries: 0,
        flow_keys: 0,
        ip_keys: 0,
        prefix_keys: 0,
      }
    );
  }

  #[test]
  fn test_production_limit_relationships_preserve_fairness() {
    let limits = ProbeLimits::default();
    assert!(limits.max_entries_per_ip < limits.max_entries);
    assert!(limits.max_bytes_per_ip < limits.max_payload_bytes);
    assert!(limits.max_datagrams_per_ip < limits.channel_capacity);
    assert!(limits.max_entries_per_prefix < limits.max_entries);
    assert!(limits.max_bytes_per_prefix < limits.max_payload_bytes);
    assert!(limits.max_datagrams_per_prefix < limits.channel_capacity);
  }

  #[test]
  fn test_payload_per_flow_datagram_limit_and_zero_key_eviction() {
    let mut limits = generous_limits();
    limits.max_datagrams_per_flow = 2;
    let (budget, _) = test_budget(limits);
    let key = flow("192.0.2.1:4000", "127.0.0.1");
    let first = budget.try_reserve_payload(key, 1).unwrap();
    let second = budget.try_reserve_payload(key, 1).unwrap();
    assert!(matches!(
      budget.try_reserve_payload(key, 1),
      Err(ProbeDropReason::PerFlowDatagrams)
    ));
    drop(first);
    drop(second);
    assert_budget_empty(budget.as_ref());
  }

  #[test]
  fn test_payload_per_flow_byte_limit() {
    let mut limits = generous_limits();
    limits.max_bytes_per_flow = 3;
    let (budget, _) = test_budget(limits);
    let key = flow("192.0.2.1:4000", "127.0.0.1");
    let permit = budget.try_reserve_payload(key, 3).unwrap();
    assert!(matches!(
      budget.try_reserve_payload(key, 1),
      Err(ProbeDropReason::PerFlowBytes)
    ));
    drop(permit);
    assert_budget_empty(budget.as_ref());
  }

  #[test]
  fn test_global_payload_byte_limit() {
    let mut limits = generous_limits();
    limits.max_payload_bytes = 2;
    let (budget, _) = test_budget(limits);
    let permit = budget.try_reserve_payload(flow("192.0.2.1:4000", "127.0.0.1"), 2).unwrap();
    assert!(matches!(
      budget.try_reserve_payload(flow("192.0.2.2:4000", "127.0.0.1"), 1),
      Err(ProbeDropReason::GlobalPayloadBytes)
    ));
    drop(permit);
    assert_budget_empty(budget.as_ref());
  }

  #[test]
  fn test_per_ip_datagram_and_byte_limits() {
    let mut datagram_limits = generous_limits();
    datagram_limits.max_datagrams_per_ip = 1;
    let (budget, _) = test_budget(datagram_limits);
    let permit = budget.try_reserve_payload(flow("192.0.2.1:4000", "127.0.0.1"), 1).unwrap();
    assert!(matches!(
      budget.try_reserve_payload(flow("192.0.2.1:4001", "127.0.0.1"), 1),
      Err(ProbeDropReason::PerIpDatagrams)
    ));
    assert!(budget.try_reserve_payload(flow("192.0.2.2:4000", "127.0.0.1"), 1).is_ok());
    drop(permit);
    assert_budget_empty(budget.as_ref());

    let mut byte_limits = generous_limits();
    byte_limits.max_bytes_per_ip = 2;
    let (budget, _) = test_budget(byte_limits);
    let permit = budget.try_reserve_payload(flow("192.0.2.1:4000", "127.0.0.1"), 2).unwrap();
    assert!(matches!(
      budget.try_reserve_payload(flow("192.0.2.1:4001", "127.0.0.1"), 1),
      Err(ProbeDropReason::PerIpBytes)
    ));
    drop(permit);
    assert_budget_empty(budget.as_ref());
  }

  #[test]
  fn test_ipv6_prefix_limits_and_identity_normalization() {
    let native_v4 = source_identities("192.0.2.1".parse().unwrap());
    let mapped_v4 = source_identities("::ffff:192.0.2.1".parse().unwrap());
    assert_eq!(native_v4, mapped_v4);
    assert_eq!(native_v4.1, None);

    let first = source_identities("2001:db8:1:2::1".parse().unwrap());
    let second = source_identities("2001:db8:1:2::ffff".parse().unwrap());
    let different = source_identities("2001:db8:1:3::1".parse().unwrap());
    assert_eq!(first.1, second.1);
    assert_ne!(first.1, different.1);
    assert_ne!(first.0, second.0);

    let mut limits = generous_limits();
    limits.max_datagrams_per_prefix = 1;
    let (budget, _) = test_budget(limits);
    let permit = budget.try_reserve_payload(flow("[2001:db8:1:2::1]:4000", "::1"), 1).unwrap();
    assert!(matches!(
      budget.try_reserve_payload(flow("[2001:db8:1:2::2]:4000", "::1"), 1),
      Err(ProbeDropReason::PerPrefixDatagrams)
    ));
    assert!(budget.try_reserve_payload(flow("[2001:db8:1:3::1]:4000", "::1"), 1).is_ok());
    drop(permit);
  }

  #[test]
  fn test_ipv6_prefix_byte_limit() {
    let mut limits = generous_limits();
    limits.max_bytes_per_prefix = 2;
    let (budget, _) = test_budget(limits);
    let permit = budget.try_reserve_payload(flow("[2001:db8:1:2::1]:4000", "::1"), 2).unwrap();
    assert!(matches!(
      budget.try_reserve_payload(flow("[2001:db8:1:2::2]:4000", "::1"), 1),
      Err(ProbeDropReason::PerPrefixBytes)
    ));
    drop(permit);
    assert_budget_empty(budget.as_ref());
  }

  #[test]
  fn test_entry_limits_and_release_key_absence() {
    let key = flow("[2001:db8:1:2::1]:4000", "::1");

    let mut limits = generous_limits();
    limits.max_entries = 1;
    let (budget, _) = test_budget(limits);
    let payload = budget.try_reserve_payload(key, 1).unwrap();
    let entry = budget.try_reserve_entry(key).unwrap();
    assert!(matches!(
      budget.try_reserve_entry(flow("[2001:db8:2:2::1]:4000", "::1")),
      Err(ProbeDropReason::GlobalEntries)
    ));
    drop(entry);
    drop(payload);
    assert_budget_empty(budget.as_ref());

    let mut limits = generous_limits();
    limits.max_entries_per_ip = 1;
    let (budget, _) = test_budget(limits);
    let entry = budget.try_reserve_entry(key).unwrap();
    assert!(matches!(budget.try_reserve_entry(key), Err(ProbeDropReason::PerIpEntries)));
    drop(entry);
    assert_budget_empty(budget.as_ref());

    let mut limits = generous_limits();
    limits.max_entries_per_prefix = 1;
    let (budget, _) = test_budget(limits);
    let entry = budget.try_reserve_entry(key).unwrap();
    assert!(matches!(
      budget.try_reserve_entry(flow("[2001:db8:1:2::2]:4000", "::1")),
      Err(ProbeDropReason::PerPrefixEntries)
    ));
    drop(entry);
    assert_budget_empty(budget.as_ref());
  }

  #[test]
  fn test_unique_identity_churn_removes_all_ledger_keys() {
    let (budget, _) = test_budget(generous_limits());
    for index in 0..1000_u16 {
      let source = SocketAddr::from(([10, (index >> 8) as u8, index as u8, 1], 4000));
      let key = UdpFlowKey::new(source, "127.0.0.1".parse().unwrap());
      let payload = budget.try_reserve_payload(key, 1).unwrap();
      let entry = budget.try_reserve_entry(key).unwrap();
      drop(entry);
      drop(payload);
    }
    assert_budget_empty(budget.as_ref());
  }

  #[test]
  fn test_channel_full_and_closed_release_payload_permits() {
    let limits = generous_limits();
    let (budget, stats) = test_budget(limits);
    let (tx, rx) = mpsc::channel(1);
    let ingress = UdpProbeIngress {
      listen_on: "127.0.0.1:443".parse().unwrap(),
      tx,
      budget: budget.clone(),
      stats: stats.clone(),
    };
    assert_eq!(
      ingress.try_enqueue(flow("192.0.2.1:4000", "127.0.0.1"), &[1]),
      ProbeEnqueueResult::Enqueued
    );
    assert_eq!(
      ingress.try_enqueue(flow("192.0.2.2:4000", "127.0.0.1"), &[2]),
      ProbeEnqueueResult::Dropped
    );
    assert_eq!(stats.count(ProbeDropReason::ChannelFull), 1);
    assert_eq!(budget.snapshot().payload_bytes, 1);
    assert_eq!(budget.snapshot().flow_keys, 1);
    assert_eq!(budget.snapshot().ip_keys, 1);
    drop(rx);
    assert_budget_empty(budget.as_ref());

    assert_eq!(
      ingress.try_enqueue(flow("192.0.2.3:4000", "127.0.0.1"), &[3]),
      ProbeEnqueueResult::Closed
    );
    assert_budget_empty(budget.as_ref());
  }

  fn empty_state(expires_at: u64) -> ProbeFlowState {
    ProbeFlowState {
      datagrams: UdpInitialDatagrams {
        inner: Vec::new(),
        probed_as_pollnext: Default::default(),
      },
      _payload_permits: Vec::new(),
      entry_permit: None,
      expires_at: Some(expires_at),
    }
  }

  fn reserved_state(budget: &Arc<ProbeBudget>, key: UdpFlowKey, expires_at: u64) -> ProbeFlowState {
    let payload_permit = budget.try_reserve_payload(key, 1).unwrap();
    let entry_permit = budget.try_reserve_entry(key).unwrap();
    ProbeFlowState {
      datagrams: UdpInitialDatagrams {
        inner: vec![vec![0]],
        probed_as_pollnext: Default::default(),
      },
      _payload_permits: vec![payload_permit],
      entry_permit: Some(entry_permit),
      expires_at: Some(expires_at),
    }
  }

  #[test]
  fn test_expiry_exact_deadline_and_work_scales_with_due_entries() {
    let stats = ProbeStats::new();
    let due = flow("192.0.2.1:4000", "127.0.0.1");
    let mut entries = ProbeEntries::default();
    let mut expiry_index = ProbeExpiryIndex::default();
    entries.insert(due, empty_state(10));
    expiry_index.entry(10).or_default().insert(due);
    for index in 0..1000_u16 {
      let source = SocketAddr::from(([198, 51, (index >> 8) as u8, index as u8], 4000));
      let key = UdpFlowKey::new(source, "127.0.0.1".parse().unwrap());
      entries.insert(key, empty_state(20));
      expiry_index.entry(20).or_default().insert(key);
    }

    assert_eq!(expire_due(&mut entries, &mut expiry_index, 9, &stats), 0);
    assert_eq!(entries.len(), 1001);
    assert_eq!(expire_due(&mut entries, &mut expiry_index, 10, &stats), 1);
    assert_eq!(entries.len(), 1000);
    assert_eq!(stats.count(ProbeDropReason::Expired), 1);
    assert_eq!(expiry_index.len(), 1);
  }

  #[test]
  fn test_synthetic_probe_path_cost_does_not_scan_active_population() {
    const OPERATIONS: usize = 2000;
    for population in [0, 256, 1024, 2048] {
      let mut entries = ProbeEntries::default();
      let mut expiry_index = ProbeExpiryIndex::default();
      for index in 0..population {
        let source = SocketAddr::from((
          [198, 18, ((index >> 8) & 0xff) as u8, (index & 0xff) as u8],
          4000 + (index % 1000) as u16,
        ));
        let key = UdpFlowKey::new(source, "127.0.0.1".parse().unwrap());
        entries.insert(key, empty_state(20));
        expiry_index.entry(20).or_default().insert(key);
      }

      let packet_keys = (0..OPERATIONS)
        .map(|index| {
          let source = SocketAddr::from((
            [203, 0, ((index >> 8) & 0xff) as u8, (index & 0xff) as u8],
            5000 + index as u16,
          ));
          UdpFlowKey::new(source, "127.0.0.1".parse().unwrap())
        })
        .collect::<Vec<_>>();
      entries.reserve(1);
      let packet_start = std::time::Instant::now();
      for packet_key in packet_keys {
        entries.insert(packet_key, empty_state(20));
        entries.remove(&packet_key).unwrap();
      }
      let packet_elapsed = packet_start.elapsed();

      let stats = ProbeStats::new();
      let expiry_start = std::time::Instant::now();
      for _ in 0..OPERATIONS {
        assert_eq!(expire_due(&mut entries, &mut expiry_index, 10, &stats), 0);
      }
      let expiry_elapsed = expiry_start.elapsed();

      assert_eq!(entries.len(), population);
      assert_eq!(expiry_index.len(), usize::from(population > 0));
      println!(
        "active_flows={population}, operations={OPERATIONS}, unrelated_packet_path={packet_elapsed:?}, non_due_expiry={expiry_elapsed:?}"
      );
    }
  }

  #[test]
  fn test_remove_expiry_deletes_empty_bucket() {
    let key = flow("192.0.2.1:4000", "127.0.0.1");
    let mut expiry_index = ProbeExpiryIndex::default();
    expiry_index.entry(10).or_default().insert(key);
    remove_expiry(&mut expiry_index, key, 10);
    assert!(expiry_index.is_empty());
  }

  #[test]
  fn test_expiry_and_active_state_drop_release_all_accounting() {
    let (budget, stats) = test_budget(generous_limits());
    let key = flow("192.0.2.1:4000", "127.0.0.1");
    let mut entries = ProbeEntries::default();
    let mut expiry_index = ProbeExpiryIndex::default();
    entries.insert(key, reserved_state(&budget, key, 10));
    expiry_index.entry(10).or_default().insert(key);

    assert_eq!(expire_due(&mut entries, &mut expiry_index, 10, stats.as_ref()), 1);
    assert_budget_empty(budget.as_ref());

    let key = flow("192.0.2.2:4000", "127.0.0.1");
    entries.insert(key, reserved_state(&budget, key, 20));
    drop(entries);
    assert_budget_empty(budget.as_ref());
  }

  #[test]
  fn test_follow_up_does_not_refresh_deadline() {
    let (budget, _) = test_budget(generous_limits());
    let key = flow("192.0.2.1:4000", "127.0.0.1");
    let mut state = reserved_state(&budget, key, 10);
    let payload_permit = budget.try_reserve_payload(key, 1).unwrap();
    state.push(QueuedProbeDatagram {
      flow_key: key,
      payload: vec![1],
      _payload_permit: payload_permit,
    });
    assert_eq!(state.expires_at, Some(10));
    drop(state);
    assert_budget_empty(budget.as_ref());
  }

  #[test]
  fn test_invalid_accounting_fails_closed() {
    let (budget, _) = test_budget(generous_limits());
    budget.state.lock().unwrap().accounting_valid = false;
    assert!(matches!(
      budget.try_reserve_payload(flow("192.0.2.1:4000", "127.0.0.1"), 1),
      Err(ProbeDropReason::AccountingUnavailable)
    ));
    assert_eq!(budget.snapshot().payload_bytes, 0);
  }
}
