mod access_log;
pub mod config;
pub mod connection;
mod constants;
mod count;
mod destination;
mod error;
mod probe;
mod proto;
mod protocol;
mod socket;
mod target;
mod tcp_proxy;
mod time_util;
mod trace;
mod udp_conn;
mod udp_proxy;

use constants::{DNS_CACHE_MAX_TTL, DNS_CACHE_MIN_TTL};
use std::sync::Arc;
use target::DnsCache;

pub use config::{Config, ConfigBuilder, EchProtocolConfig, ProtocolConfig, ProtocolConfigBuilder};
pub use connection::{
  ConnectionContext, ConnectionManager, ConnectionMetrics,
  pool::{ConnectionPool, DashMapConnectionPool, PoolEntry, PoolStats},
  tcp::{TcpConnection, TcpConnectionManager},
  udp::{UdpConnection, UdpConnectionInfo, UdpConnectionManager},
};
pub use constants::log_event_names;
pub use count::{ConnectionCount as TcpConnectionCount, ConnectionCountSum as UdpConnectionCount};
pub use destination::LoadBalance;
pub use error::{ConfigurationError, ConnectionError, ErrorContext, NetworkError, ProtocolError, ProxyBuildError, ProxyError};
pub use probe::ProbeResult;
pub use proto::ProtocolType;
pub use protocol::{
  ProtocolDetector,
  registry::{TcpProtocolRegistry, UdpProtocolRegistry},
  tcp::*,
  udp::*,
};
pub use target::TargetAddr;
pub use tcp_proxy::{TcpDestinationMux, TcpDestinationMuxBuilder, TcpProbedProtocol, TcpProxy, TcpProxyBuilder};
pub use udp_conn::UdpConnectionPool;
pub use udp_proxy::{UdpDestinationMux, UdpDestinationMuxBuilder, UdpProbedProtocol, UdpProxy, UdpProxyBuilder};

/* ---------------------------------------- */
/// Build TCP and UDP multiplexers from the configuration
pub fn build_multiplexers(config: &Config) -> Result<(TcpDestinationMux, UdpDestinationMux), ProxyBuildError> {
  let mut tcp_mux_builder = TcpDestinationMuxBuilder::default();
  let mut udp_mux_builder = UdpDestinationMuxBuilder::default();

  // Generate DNS cache
  let dns_cache = Arc::new(DnsCache::new(
    config.dns_cache_min_ttl.unwrap_or(DNS_CACHE_MIN_TTL),
    config.dns_cache_max_ttl.unwrap_or_else(|| DNS_CACHE_MAX_TTL),
  ));

  // For default targets
  if let Some(tcp_target) = config.tcp_target.as_ref() {
    tcp_mux_builder.set_base(
      proto::TcpProtocolType::Any,
      tcp_target.as_slice(),
      &dns_cache,
      config.tcp_load_balance.as_ref(),
    );
  }
  if let Some(udp_target) = config.udp_target.as_ref() {
    udp_mux_builder.set_base(
      proto::UdpProtocolType::Any,
      udp_target.as_slice(),
      &dns_cache,
      config.udp_load_balance.as_ref(),
      config.udp_idle_lifetime,
    );
  }

  // Implement protocol specific routers
  for (key, spec) in config.protocols.iter() {
    let target: &[_] = spec.target.as_ref();
    if target.is_empty() {
      return Err(ProxyBuildError::build_multiplexers_error(format!(
        "target is empty for key: {key}"
      )));
    }
    match spec.protocol {
      ProtocolType::Http => {
        tcp_mux_builder.set_base(proto::TcpProtocolType::Http, target, &dns_cache, spec.load_balance.as_ref());
      }
      /* ---------------------------------------- */
      ProtocolType::Ssh => {
        tcp_mux_builder.set_base(proto::TcpProtocolType::Ssh, target, &dns_cache, spec.load_balance.as_ref());
      }
      /* ---------------------------------------- */
      ProtocolType::Wireguard => {
        udp_mux_builder.set_base(
          proto::UdpProtocolType::Wireguard,
          target,
          &dns_cache,
          spec.load_balance.as_ref(),
          spec.idle_lifetime,
        );
      }
      /* ---------------------------------------- */
      ProtocolType::Tls => {
        let alpn = spec
          .alpn
          .as_ref()
          .map(|v| v.iter().map(|x| x.as_str()).collect::<Vec<&str>>());
        let server_names = spec
          .server_names
          .as_ref()
          .map(|v| v.iter().map(|x| x.as_str()).collect::<Vec<&str>>());
        tcp_mux_builder.set_tls(
          target,
          &dns_cache,
          spec.load_balance.as_ref(),
          server_names.as_deref(),
          alpn.as_deref(),
          spec.ech.as_ref(),
        );
      }
      /* ---------------------------------------- */
      ProtocolType::Quic => {
        let alpn = spec
          .alpn
          .as_ref()
          .map(|v| v.iter().map(|x| x.as_str()).collect::<Vec<&str>>());
        let server_names = spec
          .server_names
          .as_ref()
          .map(|v| v.iter().map(|x| x.as_str()).collect::<Vec<&str>>());
        // TODO: currently QUIC ECH is not supported
        if spec.ech.is_some() {
          trace::warn!("QUIC ECH is not supported yet");
        }
        udp_mux_builder.set_quic(
          target,
          &dns_cache,
          spec.load_balance.as_ref(),
          spec.idle_lifetime,
          server_names.as_deref(),
          alpn.as_deref(),
          spec.ech.as_ref(),
        );
      }
    }
  }

  Ok((tcp_mux_builder.build()?, udp_mux_builder.build()?))
}
