//! TLS destination types
//!
//! This module contains types for handling TLS destinations with ECH support.

use crate::{config::EchProtocolConfig, target::DnsCache};
use std::sync::Arc;

/// TCP/UDP destinations + EchProtocolConfig
/// 
/// This wrapper provides TLS destinations with optional ECH (Encrypted Client Hello) support
/// and DNS cache integration for resolving private server names.
#[derive(Clone, Debug, Default)]
pub struct TlsDestinationItem<T> {
  /// Destination (UdpDestination or TcpDestination)
  /// If ECH decryption fails (no matched ECH config), this destination will be used as the default destination
  dest: T,
  /// EchProtocolConfig for handling ECH
  ech: Option<EchProtocolConfig>,
  /// DnsCache for resolving ECH private server names
  dns_cache: Arc<DnsCache>,
}

impl<T> TlsDestinationItem<T> {
  /// Create a new TLS destination item
  pub fn new(dest: T, ech: Option<EchProtocolConfig>, dns_cache: Arc<DnsCache>) -> Self {
    Self { dest, ech, dns_cache }
  }
  
  /// Get the destination
  pub fn destination(&self) -> &T {
    &self.dest
  }
  
  /// Get the ECH config
  pub fn ech(&self) -> Option<&EchProtocolConfig> {
    self.ech.as_ref()
  }
  
  /// Get the DNS cache
  pub fn dns_cache(&self) -> &Arc<DnsCache> {
    &self.dns_cache
  }
}
