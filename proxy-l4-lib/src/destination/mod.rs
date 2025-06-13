//! Destination resolution and routing components
//!
//! This module provides abstractions for DNS resolution, load balancing,
//! and TLS-based routing to enable pluggable destination resolution strategies.

pub mod config;
pub mod dns;
pub mod integration;
pub mod load_balancer;
pub mod tls;
pub mod tls_router;

// Re-export public types
pub use config::LoadBalance;
pub use dns::{CachingDnsResolver, DnsResolver, MockDnsResolver};
pub use integration::{TargetDestination, TlsDestinations, create_load_balancer};
pub use load_balancer::{
  FirstAvailableLoadBalancer, LoadBalancer, RandomLoadBalancer, RoundRobinLoadBalancer, SourceIpLoadBalancer,
  SourceSocketLoadBalancer,
};
pub use tls::TlsDestinationItem;
pub use tls_router::{TlsRouter, TlsRoutingRule};
