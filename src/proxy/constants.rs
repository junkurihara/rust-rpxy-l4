use std::{net::SocketAddr, sync::OnceLock};

/// TCP backlog size
pub const TCP_BACKLOG: u32 = 1024;

/// TCP timeout to read first few bytes in milliseconds
pub const TCP_PROTOCOL_DETECTION_TIMEOUT_MSEC: u64 = 100;

/// TCP buffer size for protocol detection
/// The maximum size of the TLS record is 64KB = 2^14 bytes.
/// But considering the hybrid post-quantum key exchange (key_share extension is > 1KB in X25519MLKEM768),
/// the buffer size should be large, at least 2KB, to parse the Client Hello message.
/// https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
pub const TCP_PROTOCOL_DETECTION_BUFFER_SIZE: usize = 4096;

/// UDP buffer size, theoretical limit is 65535 bytes in IPv4
/// But the practical limit is, due to the MTU, less than 1500 bytes.
pub const UDP_BUFFER_SIZE: usize = 65536;

/// UDP channel Capacity TODO: めちゃ適当
pub const UDP_CHANNEL_CAPACITY: usize = 1024;

/// Any socket address for IPv4 for auto-binding
pub static BASE_ANY_SOCKET_V4: OnceLock<SocketAddr> = OnceLock::new();
/// Any socket address for IPv6 for auto-binding
pub static BASE_ANY_SOCKET_V6: OnceLock<SocketAddr> = OnceLock::new();

/// Initialize once lock values
pub fn init_once_lock() {
  let _ = BASE_ANY_SOCKET_V4.get_or_init(|| "0.0.0.0:0".parse().unwrap());
  let _ = BASE_ANY_SOCKET_V6.get_or_init(|| "[::]:0".parse().unwrap());
}
