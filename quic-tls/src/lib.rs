mod client_hello;
mod ech;
mod ech_config;
mod ech_extension;
mod error;
mod quic;
mod serialize;
mod tls;

#[allow(unused)]
pub(crate) mod trace {
  pub(crate) use tracing::{debug, error, info, trace, warn};
}
/// TLS 1.0, TLS 1.1 and TLS 1.2 for ClientHello.legacy_version and TLSPlaintext.legacy_record_version.
/// Note that TLS 1.3 (0x304) is indicated in `supported_versions` extension,
/// then 0x303 is given to ClientHello.legacy_version and TLSPlaintext.legacy_record_version
pub(crate) const SUPPORTED_TLS_VERSIONS: [u16; 3] = [0x0301, 0x0302, 0x303];

pub use client_hello::TlsClientHelloInfo;
pub use error::TlsProbeFailure;
pub use quic::probe_quic_initial_packets;
pub use tls::probe_tls_handshake;
