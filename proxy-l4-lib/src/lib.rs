mod config;
mod constants;
mod count;
mod destination;
mod error;
mod probe;
mod proto;
mod socket;
mod tcp_proxy;
mod time_util;
mod trace;
mod udp_conn;
mod udp_proxy;

pub use config::{Config, EchProtocolConfig, ProtocolConfig};
pub use count::{ConnectionCount as TcpConnectionCount, ConnectionCountSum as UdpConnectionCount};
pub use destination::LoadBalance;
pub use error::{ProxyBuildError, ProxyError};
pub use proto::ProtocolType;
pub use tcp_proxy::{TcpDestinationMux, TcpDestinationMuxBuilder, TcpProxy, TcpProxyBuilder};
pub use udp_proxy::{UdpDestinationMux, UdpDestinationMuxBuilder, UdpProxy, UdpProxyBuilder};

/* ---------------------------------------- */
/// Build TCP and UDP multiplexers from the configuration
pub fn build_multiplexers(config: &Config) -> Result<(TcpDestinationMux, UdpDestinationMux), ProxyBuildError> {
  let mut tcp_mux_builder = TcpDestinationMuxBuilder::default();
  let mut udp_mux_builder = UdpDestinationMuxBuilder::default();

  // For default targets
  if let Some(tcp_target) = config.tcp_target.as_ref() {
    tcp_mux_builder.set_base(
      proto::TcpProtocolType::Any,
      tcp_target.as_slice(),
      config.tcp_load_balance.as_ref(),
    );
  }
  if let Some(udp_target) = config.udp_target.as_ref() {
    udp_mux_builder.dst_any(
      udp_target.as_slice(),
      config.udp_load_balance.as_ref(),
      config.udp_idle_lifetime,
    );
  }

  // Implement protocol specific routers
  for (key, spec) in config.protocols.iter() {
    let target: &[_] = spec.target.as_ref();
    if target.is_empty() {
      return Err(ProxyBuildError::BuildMultiplexersError(format!(
        "target is empty for key: {key}"
      )));
    }
    match spec.protocol {
      ProtocolType::Http => {
        tcp_mux_builder.set_base(proto::TcpProtocolType::Http, target, spec.load_balance.as_ref());
      }
      /* ---------------------------------------- */
      ProtocolType::Ssh => {
        tcp_mux_builder.set_base(proto::TcpProtocolType::Ssh, target, spec.load_balance.as_ref());
      }
      /* ---------------------------------------- */
      ProtocolType::Wireguard => {
        udp_mux_builder.dst_wireguard(target, spec.load_balance.as_ref(), spec.idle_lifetime);
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
        udp_mux_builder.dst_quic(
          target,
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
