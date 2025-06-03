//! Protocol-specific configuration modules
//! 
//! This module provides specialized configuration types for different protocols,
//! making it easier to construct and validate protocol-specific settings.

pub mod tcp;
pub mod tls;
pub mod udp;

pub use tcp::{HttpConfig, SshConfig, TcpProtocolConfig, TlsConfig};
pub use tls::{EchConfigBuilder, TlsProtocolConfig};
pub use udp::{QuicConfig, UdpProtocolConfig, WireguardConfig};

/// Re-export common types for convenience
pub use crate::{
    destination::LoadBalance,
    target::TargetAddr,
    config::validation::ConfigValidationError,
};
