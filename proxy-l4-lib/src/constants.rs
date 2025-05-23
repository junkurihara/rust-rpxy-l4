use std::time::Duration;

/// TCP backlog size
pub const TCP_BACKLOG: u32 = 1024;

/// TCP timeout to read first few bytes in milliseconds
pub const TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC: u64 = 100;

/// TCP buffer size for protocol detection
/// The maximum size of the TLS record is 64KB = 2^14 bytes.
/// But considering the hybrid post-quantum key exchange (key_share extension is > 1KB in X25519MLKEM768),
/// the buffer size should be large, at least 2KB, to parse the Client Hello message.
/// https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
pub const TCP_PROTOCOL_DETECTION_BUFFER_SIZE: usize = 16384;

/// UDP buffer size, theoretical limit is 65535 bytes in IPv4
/// But the practical limit is, due to the MTU, less than 1500 bytes.
pub const UDP_BUFFER_SIZE: usize = 65536;

/// UDP channel Capacity TODO: めちゃ適当
pub const UDP_CHANNEL_CAPACITY: usize = 1024;

/// Max TCP concurrent connections in total of all spawned TCP proxies
pub const MAX_TCP_CONCURRENT_CONNECTIONS: usize = 1024;

/// Max UDP concurrent connections in total of all spawned UDP proxies
/// For UDP, the connection remains until the lifetime expires.
/// This means that even a short communication, e.g., DNS, does not immediately release the connection.
pub const MAX_UDP_CONCURRENT_CONNECTIONS: usize = 2048;

/// Default UDP connection lifetime in seconds, can be configured for each protocol
/// UDP connection is managed by the source address + port.
/// If the connection is not used for this duration, it is pruned.
pub const UDP_CONNECTION_IDLE_LIFETIME: u32 = 30;

/// Periodic interval to prune inactive UDP connections
pub const UDP_CONNECTION_PRUNE_INTERVAL: u64 = 10;

/// UDP initial buffer packet lifetime in seconds
pub const UDP_INITIAL_BUFFER_LIFETIME: u64 = 1;

/// Logging event name TODO: Other separated logs?
pub mod log_event_names {
  /// access log
  pub const ACCESS_LOG_START: &str = "rpxy-l4::conn::start";
  pub const ACCESS_LOG_FINISH: &str = "rpxy-l4::conn::finish";
}

/// DNS cache minimum TTL
/// Default: 30 seconds
pub const DNS_CACHE_MIN_TTL: Duration = Duration::from_secs(30);
/// DNS cache maximum TTL
/// Default: 1 hour
pub const DNS_CACHE_MAX_TTL: Duration = Duration::from_secs(3600);
