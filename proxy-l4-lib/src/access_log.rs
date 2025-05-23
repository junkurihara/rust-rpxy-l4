use crate::{
  proto::{TcpProtocolType, UdpProtocolType},
  trace::info,
};
use std::net::SocketAddr;

/// Protocol type for access log
pub(crate) enum AccessLogProtocolType {
  /// TCP
  Tcp(TcpProtocolType),
  /// UDP
  Udp(UdpProtocolType),
}
impl std::fmt::Display for AccessLogProtocolType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      AccessLogProtocolType::Tcp(t) => match t {
        TcpProtocolType::Any => write!(f, "tcp"),
        other => write!(f, "tcp:{}", other),
      },
      AccessLogProtocolType::Udp(u) => match u {
        UdpProtocolType::Any => write!(f, "udp"),
        other => write!(f, "udp:{}", other),
      },
    }
  }
}

/// Handle log for probed protocol, source and destination sockets, when establishing a connection
pub(crate) fn access_log_start(proto: &AccessLogProtocolType, src_addr: &SocketAddr, dst_addr: &SocketAddr) {
  info!(name: crate::constants::log_event_names::ACCESS_LOG_START, "[start] {}: {:?} -> {:?}", proto, src_addr, dst_addr);
}
/// Handle log for probed protocol, source and destination sockets, when closing a connection
pub(crate) fn access_log_finish(proto: &AccessLogProtocolType, src_addr: &SocketAddr, dst_addr: &SocketAddr) {
  info!(name: crate::constants::log_event_names::ACCESS_LOG_FINISH, "[finish] {}: {:?} -> {:?}", proto, src_addr, dst_addr);
}
