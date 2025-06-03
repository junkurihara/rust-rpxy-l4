//! Destination resolution and routing components
//!
//! This module provides abstractions for DNS resolution, load balancing,
//! and TLS-based routing to enable pluggable destination resolution strategies.

pub mod dns;
pub mod integration;
pub mod legacy;
pub mod load_balancer;
pub mod migration_demo;
pub mod tls_router;

// Re-export public types
pub use dns::{CachingDnsResolver, DnsResolver, MockDnsResolver};
pub use integration::{ModernTargetDestination, ModernTlsDestinations, create_load_balancer};
pub use load_balancer::{
  FirstAvailableLoadBalancer, LoadBalancer, RandomLoadBalancer, RoundRobinLoadBalancer, SourceIpLoadBalancer,
  SourceSocketLoadBalancer,
};
pub use tls_router::{TlsRouter, TlsRoutingRule};

// Legacy exports for backward compatibility
pub use legacy::{LoadBalance, TargetDestination, TargetDestinationBuilder, TlsDestinationItem, TlsDestinations};
