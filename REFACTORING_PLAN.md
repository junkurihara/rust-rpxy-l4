## Overview

This document outlines a comprehensive refactoring plan for the rust-rpxy-l4 project to improve code organization, maintainability, extensibility, and testability. The plan is structured in phases with small, incremental steps to minimize risk and enable continuous integration.

## Goals

- **Modularity**: Clear separation of concerns across components
- **Testability**: Enable isolated testing of individual components
- **Extensibility**: Make it easy to add new protocols and features
- **Maintainability**: Reduce complexity through smaller, focused modules
- **Performance**: Create optimization opportunities without affecting other components
- **Documentation**: Provide clear interfaces and comprehensive documentation

## Phase 1: Protocol Detection Abstraction (Foundation)

### Step 1.1: Extract Protocol Detection Trait
**Goal**: Create a unified interface for protocol detection
**Priority**: High
**Estimated Effort**: 1-2 days

**Files to Create**:
- `proxy-l4-lib/src/protocol/mod.rs`

```rust
use bytes::BytesMut;
use crate::{error::ProxyError, probe::ProbeResult};

/// Unified trait for protocol detection
pub trait ProtocolDetector<T> {
    /// Attempt to detect protocol from buffer
    async fn detect(&self, buffer: &mut BytesMut) -> Result<ProbeResult<T>, ProxyError>;

    /// Get the name of this protocol detector
    fn name(&self) -> &'static str;

    /// Get the minimum buffer size needed for detection
    fn min_buffer_size(&self) -> usize { 4 }

    /// Get the maximum buffer size to collect before giving up
    fn max_buffer_size(&self) -> usize { 8192 }
}
```

**Benefits**:
- Enables pluggable protocol detection
- Easier unit testing of individual detectors
- Cleaner separation of concerns
- Preparation for future protocol additions

### Step 1.2: Refactor TCP Protocol Detectors
**Goal**: Convert existing detection functions to implement the trait
**Priority**: High
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/protocol/tcp.rs`

```rust
use super::ProtocolDetector;
use crate::{tcp_proxy::TcpProbedProtocol, probe::ProbeResult, error::ProxyError};
use bytes::BytesMut;

pub struct SshDetector;
pub struct HttpDetector;
pub struct TlsDetector;

impl ProtocolDetector<TcpProbedProtocol> for SshDetector {
    async fn detect(&self, buffer: &mut BytesMut) -> Result<ProbeResult<TcpProbedProtocol>, ProxyError> {
        // Move existing is_ssh logic here
    }

    fn name(&self) -> &'static str { \"SSH\" }
}

// Similar implementations for HttpDetector and TlsDetector
```

**Migration Strategy**:
1. Create new detector structs
2. Move existing function logic into trait implementations
3. Update `TcpProbedProtocol::detect_protocol` to use detector registry
4. Keep old functions as wrappers initially
5. Remove old functions once migration is complete

### Step 1.3: Refactor UDP Protocol Detectors
**Goal**: Apply same pattern to UDP protocols
**Priority**: High
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/protocol/udp.rs`

```rust
use super::ProtocolDetector;
use crate::{udp_proxy::UdpProbedProtocol, probe::ProbeResult, error::ProxyError};
use bytes::BytesMut;

pub struct WireguardDetector;
pub struct QuicDetector;

impl ProtocolDetector<UdpProbedProtocol> for WireguardDetector {
    async fn detect(&self, buffer: &mut BytesMut) -> Result<ProbeResult<UdpProbedProtocol>, ProxyError> {
        // Move existing is_wireguard logic here
    }

    fn name(&self) -> &'static str { \"WireGuard\" }
    fn min_buffer_size(&self) -> usize { 148 } // WireGuard initiation packet size
}
```

### Step 1.4: Create Protocol Registry
**Goal**: Central registry for managing protocol detectors
**Priority**: Medium
**Estimated Effort**: 1-2 days

**Files to Create**:
- `proxy-l4-lib/src/protocol/registry.rs`

```rust
use super::ProtocolDetector;
use crate::{probe::ProbeResult, error::ProxyError};
use bytes::BytesMut;

pub struct ProtocolRegistry<T> {
    detectors: Vec<Box<dyn ProtocolDetector<T> + Send + Sync>>,
}

impl<T> ProtocolRegistry<T> {
    pub fn new() -> Self {
        Self { detectors: Vec::new() }
    }

    pub fn register<D: ProtocolDetector<T> + Send + Sync + 'static>(&mut self, detector: D) {
        self.detectors.push(Box::new(detector));
    }

    pub async fn detect_protocol(&self, buffer: &mut BytesMut) -> Result<ProbeResult<T>, ProxyError> {
        // Iterate through detectors and return first successful match
    }
}
```

## Phase 2: Configuration Management Improvement

### Step 2.1: Extract Configuration Validation
**Goal**: Separate validation logic from configuration parsing
**Priority**: Medium
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/config/validation.rs`

```rust
use crate::{config::Config, error::ConfigurationError};

pub trait ConfigValidator {
    fn validate(&self, config: &Config) -> Result<(), ConfigurationError>;
}

pub struct PortValidator;
pub struct TargetValidator;
pub struct ProtocolValidator;

// Individual validators for different aspects of configuration
impl ConfigValidator for PortValidator {
    fn validate(&self, config: &Config) -> Result<(), ConfigurationError> {
        if config.listen_port == 0 {
            return Err(ConfigurationError::InvalidPort(config.listen_port));
        }
        Ok(())
    }
}
```

### Step 2.2: Create Configuration Builder Pattern
**Goal**: Improve configuration construction ergonomics
**Priority**: Medium
**Estimated Effort**: 3-4 days

**Files to Modify**:
- `proxy-l4-lib/src/config/mod.rs`

```rust
pub struct ConfigBuilder {
    listen_port: Option<u16>,
    tcp_targets: Vec<String>,
    udp_targets: Vec<String>,
    protocols: HashMap<String, ProtocolConfig>,
    validators: Vec<Box<dyn ConfigValidator>>,
}

impl ConfigBuilder {
    pub fn new() -> Self { ... }

    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    pub fn with_tcp_target(mut self, target: &str) -> Self {
        self.tcp_targets.push(target.to_string());
        self
    }

    pub fn with_protocol(mut self, name: String, protocol: ProtocolConfig) -> Self {
        self.protocols.insert(name, protocol);
        self
    }

    pub fn build(self) -> Result<Config, ConfigurationError> {
        // Validate and build configuration
    }
}
```

### Step 2.3: Separate Protocol-Specific Configuration
**Goal**: Split large configuration into protocol-specific modules
**Priority**: Low
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/config/protocols/mod.rs`
- `proxy-l4-lib/src/config/protocols/tcp.rs`
- `proxy-l4-lib/src/config/protocols/udp.rs`
- `proxy-l4-lib/src/config/protocols/tls.rs`

```rust
// tcp.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpProtocolConfig {
    pub target: Vec<String>,
    pub load_balance: Option<String>,
    pub max_connections: Option<u32>,
}

// tls.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsProtocolConfig {
    pub target: Vec<String>,
    pub load_balance: Option<String>,
    pub server_names: Option<Vec<String>>,
    pub alpn: Option<Vec<String>>,
    pub ech: Option<EchProtocolConfig>,
}
```

## Phase 3: Error Handling Enhancement

### Step 3.1: Create Error Categories
**Goal**: Better error categorization and handling
**Priority**: High
**Estimated Effort**: 2-3 days

**Files to Modify**:
- `proxy-l4-lib/src/error.rs`

```rust
#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    #[error(transparent)]
    Network(#[from] NetworkError),

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error(transparent)]
    Connection(#[from] ConnectionError),
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigurationError {
    #[error(\"Invalid port: {0}\")]
    InvalidPort(u16),

    #[error(\"Invalid target address: {0}\")]
    InvalidTarget(String),

    #[error(\"Missing required configuration: {0}\")]
    MissingRequired(String),
}

#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error(\"DNS resolution failed for {host}: {source}\")]
    DnsResolution { host: String, source: std::io::Error },

    #[error(\"Connection failed to {address}: {source}\")]
    ConnectionFailed { address: std::net::SocketAddr, source: std::io::Error },

    #[error(\"Socket bind failed for {address}: {source}\")]
    BindFailed { address: std::net::SocketAddr, source: std::io::Error },
}

#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error(\"Protocol detection failed: {0}\")]
    DetectionFailed(String),

    #[error(\"Unsupported protocol: {0}\")]
    UnsupportedProtocol(String),

    #[error(\"Protocol parsing error: {0}\")]
    ParseError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum ConnectionError {
    #[error(\"Connection limit exceeded: {current}/{max}\")]
    LimitExceeded { current: usize, max: usize },

    #[error(\"Connection timeout for {address}\")]
    Timeout { address: std::net::SocketAddr },

    #[error(\"Connection broken: {0}\")]
    Broken(String),
}
```

### Step 3.2: Add Error Context
**Goal**: Provide better error context for debugging
**Priority**: Medium
**Estimated Effort**: 1-2 days

**Strategy**:
- Add context information to errors (source addresses, protocols, etc.)
- Use `anyhow::Context` trait for adding context to errors
- Update error usage throughout codebase

```rust
use anyhow::Context;

// Example usage
let destination = target.resolve_cached(&dns_cache)
    .await
    .with_context(|| format!(\"Failed to resolve target {} for source {}\", target, src_addr))?;
```

## Phase 4: Connection Management Refactoring

### Step 4.1: Extract Connection Lifecycle Management
**Goal**: Centralize connection management logic
**Priority**: High
**Estimated Effort**: 3-4 days

**Files to Create**:
- `proxy-l4-lib/src/connection/mod.rs`

```rust
use std::net::SocketAddr;
use crate::error::ConnectionError;

#[async_trait::async_trait]
pub trait ConnectionManager {
    type Connection;
    type ConnectionInfo;

    async fn create_connection(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        info: Self::ConnectionInfo
    ) -> Result<Self::Connection, ConnectionError>;

    async fn handle_connection(&self, conn: Self::Connection) -> Result<(), ConnectionError>;

    fn connection_count(&self) -> usize;
    fn max_connections(&self) -> usize;
}

pub struct ConnectionMetrics {
    pub created_at: std::time::Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub protocol: String,
}
```

### Step 4.2: Separate TCP Connection Handler
**Goal**: Extract TCP connection handling logic
**Priority**: High
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/connection/tcp.rs`

```rust
use super::{ConnectionManager, ConnectionMetrics};
use crate::tcp_proxy::TcpProbedProtocol;
use tokio::net::TcpStream;

pub struct TcpConnectionManager {
    connection_count: crate::count::ConnectionCount,
    max_connections: usize,
}

pub struct TcpConnection {
    incoming: TcpStream,
    outgoing: TcpStream,
    metrics: ConnectionMetrics,
    protocol: TcpProbedProtocol,
}

#[async_trait::async_trait]
impl ConnectionManager for TcpConnectionManager {
    type Connection = TcpConnection;
    type ConnectionInfo = TcpProbedProtocol;

    async fn create_connection(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        protocol: TcpProbedProtocol
    ) -> Result<TcpConnection, ConnectionError> {
        // Move connection creation logic here
    }

    async fn handle_connection(&self, conn: TcpConnection) -> Result<(), ConnectionError> {
        // Move handle_tcp_connection logic here
    }
}
```

### Step 4.3: Separate UDP Connection Handler
**Goal**: Extract UDP connection handling logic
**Priority**: High
**Estimated Effort**: 3-4 days

**Files to Create**:
- `proxy-l4-lib/src/connection/udp.rs`

```rust
use super::{ConnectionManager, ConnectionMetrics};
use crate::udp_proxy::UdpProbedProtocol;
use tokio::net::UdpSocket;

pub struct UdpConnectionManager {
    connection_pool: Arc<UdpConnectionPool>,
    max_connections: usize,
}

pub struct UdpConnection {
    client_socket: Arc<UdpSocket>,
    server_socket: UdpSocket,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    metrics: ConnectionMetrics,
    protocol: UdpProbedProtocol,
    idle_timeout: Duration,
}

#[async_trait::async_trait]
impl ConnectionManager for UdpConnectionManager {
    type Connection = UdpConnection;
    type ConnectionInfo = (UdpProbedProtocol, Duration);

    async fn create_connection(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        (protocol, idle_timeout): (UdpProbedProtocol, Duration)
    ) -> Result<UdpConnection, ConnectionError> {
        // Move UDP connection creation logic here
    }
}
```

### Step 4.4: Create Connection Pool Trait
**Goal**: Abstract connection pooling for both TCP and UDP
**Priority**: Medium
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/connection/pool.rs`

```rust
use std::hash::Hash;
use crate::error::ConnectionError;

#[async_trait::async_trait]
pub trait ConnectionPool<K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Send + Sync,
{
    async fn get_or_create<F, Fut>(&self, key: K, factory: F) -> Result<V, ConnectionError>
    where
        F: FnOnce(K) -> Fut + Send,
        Fut: std::future::Future<Output = Result<V, ConnectionError>> + Send;

    fn get(&self, key: &K) -> Option<V>;
    fn insert(&self, key: K, value: V);
    fn remove(&self, key: &K) -> Option<V>;
    fn prune_expired(&self);
    fn size(&self) -> usize;
}

pub struct DashMapConnectionPool<K, V> {
    inner: dashmap::DashMap<K, V>,
    max_size: usize,
}
```

## Phase 5: Destination Resolution Refactoring

### Step 5.1: Extract DNS Resolution Logic
**Goal**: Separate DNS concerns from load balancing
**Priority**: Medium
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/destination/dns.rs`

```rust
use std::net::SocketAddr;
use crate::error::NetworkError;

#[async_trait::async_trait]
pub trait DnsResolver {
    async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<SocketAddr>, NetworkError>;
}

pub struct CachingDnsResolver {
    cache: Arc<DnsCache>,
    min_ttl: Duration,
    max_ttl: Duration,
}

#[async_trait::async_trait]
impl DnsResolver for CachingDnsResolver {
    async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<SocketAddr>, NetworkError> {
        // Move DNS resolution logic here
    }
}

pub struct MockDnsResolver {
    responses: HashMap<String, Vec<SocketAddr>>,
}
```

### Step 5.2: Create Load Balancer Trait
**Goal**: Make load balancing strategies pluggable
**Priority**: Medium
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/destination/load_balancer.rs`

```rust
use std::net::SocketAddr;
use crate::error::ProxyError;

#[async_trait::async_trait]
pub trait LoadBalancer: Send + Sync {
    async fn select_target(
        &self,
        src: SocketAddr,
        targets: &[SocketAddr]
    ) -> Result<SocketAddr, ProxyError>;
}

pub struct SourceIpLoadBalancer {
    hasher: ahash::RandomState,
}

pub struct SourceSocketLoadBalancer {
    hasher: ahash::RandomState,
}

pub struct RandomLoadBalancer;

pub struct RoundRobinLoadBalancer {
    counter: AtomicUsize,
}

#[async_trait::async_trait]
impl LoadBalancer for SourceIpLoadBalancer {
    async fn select_target(&self, src: SocketAddr, targets: &[SocketAddr]) -> Result<SocketAddr, ProxyError> {
        let hash = self.hasher.hash_one(src.ip());
        let index = (hash % targets.len() as u64) as usize;
        Ok(targets[index])
    }
}
```

### Step 5.3: Refactor TLS Destination Matching
**Goal**: Simplify TLS routing logic
**Priority**: Medium
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/destination/tls_router.rs`

```rust
use crate::config::EchProtocolConfig;

pub struct TlsRoutingRule {
    pub server_names: Vec<String>,
    pub alpn_protocols: Vec<String>,
    pub priority: u8, // Higher number = higher priority
}

pub struct TlsRouter<T> {
    routes: Vec<(TlsRoutingRule, T)>,
}

impl<T> TlsRouter<T> {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn add_route(&mut self, rule: TlsRoutingRule, destination: T) {
        self.routes.push((rule, destination));
        // Sort by priority
        self.routes.sort_by(|a, b| b.0.priority.cmp(&a.0.priority));
    }

    pub fn find_destination(&self, client_hello: &quic_tls::TlsClientHello) -> Option<&T> {
        // Improved matching logic with priority handling
    }
}
```

## Phase 6: Testing Infrastructure

### Step 6.1: Create Test Utilities
**Goal**: Improve test infrastructure
**Priority**: High
**Estimated Effort**: 3-4 days

**Files to Create**:
- `proxy-l4-lib/src/testing/mod.rs`

```rust
use crate::{
    protocol::ProtocolDetector,
    connection::ConnectionManager,
    config::Config,
    destination::DnsResolver,
};

pub struct MockProtocolDetector<T> {
    pub responses: HashMap<Vec<u8>, ProbeResult<T>>,
}

pub struct MockConnectionManager<C> {
    pub connections: Vec<C>,
    pub max_connections: usize,
}

pub struct MockDnsResolver {
    pub responses: HashMap<String, Vec<SocketAddr>>,
}

pub struct TestConfigBuilder;

impl TestConfigBuilder {
    pub fn default_tcp_config() -> Config { ... }
    pub fn default_udp_config() -> Config { ... }
    pub fn tls_with_ech_config() -> Config { ... }
}

pub fn create_test_tcp_stream() -> (TcpStream, TcpStream) { ... }
pub fn create_test_udp_socket() -> UdpSocket { ... }
```

### Step 6.2: Add Integration Test Framework
**Goal**: Better integration testing
**Priority**: Medium
**Estimated Effort**: 4-5 days

**Files to Create**:
- `tests/integration/mod.rs`
- `tests/integration/tcp_proxy_tests.rs`
- `tests/integration/udp_proxy_tests.rs`
- `tests/integration/protocol_detection_tests.rs`

```rust
// tcp_proxy_tests.rs
use rpxy_l4_lib::testing::*;

#[tokio::test]
async fn test_tcp_proxy_basic_forwarding() {
    // Test basic TCP forwarding
}

#[tokio::test]
async fn test_tcp_proxy_protocol_detection() {
    // Test protocol detection and routing
}

#[tokio::test]
async fn test_tcp_proxy_load_balancing() {
    // Test load balancing algorithms
}
```

## Phase 7: Performance Optimizations

### Step 7.1: Extract Buffer Management
**Goal**: Centralize buffer allocation strategies
**Priority**: Medium
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/buffer.rs`

```rust
use bytes::BytesMut;

pub trait BufferManager: Send + Sync {
    fn get_buffer(&self, size: usize) -> BytesMut;
    fn return_buffer(&self, buffer: BytesMut);
}

pub struct PooledBufferManager {
    pools: Vec<ObjectPool<BytesMut>>,
    size_classes: Vec<usize>, // e.g., [1KB, 4KB, 16KB, 64KB]
}

pub struct SimpleBufferManager;

impl BufferManager for SimpleBufferManager {
    fn get_buffer(&self, size: usize) -> BytesMut {
        BytesMut::with_capacity(size)
    }

    fn return_buffer(&self, _buffer: BytesMut) {
        // No-op for simple manager
    }
}

impl BufferManager for PooledBufferManager {
    fn get_buffer(&self, size: usize) -> BytesMut {
        // Find appropriate size class and get from pool
    }

    fn return_buffer(&self, buffer: BytesMut) {
        // Return to appropriate pool if size matches
    }
}
```

### Step 7.2: Optimize Protocol Detection Pipeline
**Goal**: Reduce allocation during protocol detection
**Priority**: Medium
**Estimated Effort**: 2-3 days

**Strategy**:
- Use buffer pools in protocol detection
- Implement zero-copy techniques where possible
- Reduce buffer reallocations
- Optimize hot paths in detection logic

```rust
// Example optimization in protocol detection
impl ProtocolDetector<TcpProbedProtocol> for TlsDetector {
    async fn detect(&self, buffer: &mut BytesMut) -> Result<ProbeResult<TcpProbedProtocol>, ProxyError> {
        // Use slice-based parsing instead of allocation
        // Reuse parsing structures
        // Implement early returns for common cases
    }
}
```

## Phase 8: Observability Enhancement

### Step 8.1: Extract Metrics Collection
**Goal**: Better observability and monitoring
**Priority**: Medium
**Estimated Effort**: 2-3 days

**Files to Create**:
- `proxy-l4-lib/src/metrics/mod.rs`

```rust
use std::{net::SocketAddr, time::Duration};

pub trait MetricsCollector: Send + Sync {
    fn record_connection_started(&self, protocol: &str, src: SocketAddr, dst: SocketAddr);
    fn record_connection_ended(&self, protocol: &str, src: SocketAddr, dst: SocketAddr, duration: Duration);
    fn record_bytes_transferred(&self, protocol: &str, bytes: u64);
    fn record_error(&self, error_type: &str, protocol: Option<&str>);
    fn record_protocol_detection_time(&self, protocol: &str, duration: Duration);
}

pub struct PrometheusMetricsCollector {
    // Prometheus metrics
}

pub struct LogMetricsCollector {
    // Log-based metrics
}

pub struct NoOpMetricsCollector;

impl MetricsCollector for NoOpMetricsCollector {
    fn record_connection_started(&self, _: &str, _: SocketAddr, _: SocketAddr) {}
    fn record_connection_ended(&self, _: &str, _: SocketAddr, _: SocketAddr, _: Duration) {}
    fn record_bytes_transferred(&self, _: &str, _: u64) {}
    fn record_error(&self, _: &str, _: Option<&str>) {}
    fn record_protocol_detection_time(&self, _: &str, _: Duration) {}
}
```

### Step 8.2: Structured Logging
**Goal**: Improve logging consistency
**Priority**: Low
**Estimated Effort**: 1-2 days

**Files to Create**:
- `proxy-l4-lib/src/logging.rs`

```rust
use tracing::{info, warn, error};
use std::net::SocketAddr;

pub struct ConnectionLogContext {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub protocol: String,
    pub connection_id: uuid::Uuid,
}

impl ConnectionLogContext {
    pub fn log_connection_start(&self) {
        info!(
            src_addr = %self.src_addr,
            dst_addr = %self.dst_addr,
            protocol = %self.protocol,
            connection_id = %self.connection_id,
            \"Connection started\"
        );
    }

    pub fn log_connection_end(&self, duration: Duration, bytes_transferred: u64) {
        info!(
            src_addr = %self.src_addr,
            dst_addr = %self.dst_addr,
            protocol = %self.protocol,
            connection_id = %self.connection_id,
            duration_ms = duration.as_millis(),
            bytes_transferred = bytes_transferred,
            \"Connection ended\"
        );
    }
}
```

## Phase 9: API Cleanup

### Step 9.1: Consolidate Public API
**Goal**: Clean up public interface
**Priority**: Low
**Estimated Effort**: 1-2 days

**Files to Modify**:
- `proxy-l4-lib/src/lib.rs`

```rust
// Public API exports
pub use config::{Config, ConfigBuilder, ProtocolConfig};
pub use error::{ProxyError, ConfigurationError, NetworkError, ProtocolError, ConnectionError};
pub use tcp_proxy::{TcpProxy, TcpProxyBuilder};
pub use udp_proxy::{UdpProxy, UdpProxyBuilder};

// Re-export commonly used types
pub use destination::LoadBalance;
pub use target::TargetAddr;

// Optional features
#[cfg(feature = \"metrics\")]
pub use metrics::MetricsCollector;

#[cfg(feature = \"testing\")]
pub use testing::*;

// Internal modules (not public)
mod connection;
mod destination;
mod protocol;
mod buffer;
```

### Step 9.2: Documentation Enhancement
**Goal**: Improve API documentation
**Priority**: Medium
**Estimated Effort**: 3-4 days

**Strategy**:
- Add comprehensive rustdoc to all public APIs
- Include usage examples in documentation
- Create architecture documentation
- Add troubleshooting guides

```rust
/// A high-performance Layer 4 reverse proxy with protocol multiplexing capabilities.
///
/// # Examples
///
/// ```rust
/// use rpxy_l4_lib::{Config, TcpProxy};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = Config::builder()
///         .with_listen_port(8080)
///         .with_tcp_target(\"backend1.example.com:80\")
///         .with_tcp_target(\"backend2.example.com:80\")
///         .build()?;
///
///     let proxy = TcpProxy::builder()
///         .config(config)
///         .build()?;
///
///     proxy.start().await?;
///     Ok(())
/// }
/// ```
pub struct TcpProxy {
    // ...
}
```

## Implementation Guidelines

### Implementation Order

1. **Implement each phase sequentially**
2. **Complete all steps in a phase before moving to the next**
3. **Each step should be a separate pull request**
4. **Maintain backward compatibility during transition**

### Migration Strategy

For each step:

1. **Create new modules** without changing existing code
2. **Implement new interfaces** with existing functionality
3. **Add comprehensive tests** for new components
4. **Gradually migrate** existing code to use new abstractions
5. **Update integration points** one at a time
6. **Remove old code** once migration is complete
7. **Update documentation** to reflect changes

### Testing Strategy

- **Unit tests** for each new component
- **Integration tests** for component interactions
- **Regression tests** to ensure existing functionality works
- **Performance tests** to ensure no degradation
- **Load tests** for connection management components

### Code Review Guidelines

- **Small, focused changes** (max 400 lines per PR)
- **Clear commit messages** describing the change
- **Comprehensive test coverage** (aim for >80%)
- **Documentation updates** included in PR
- **Performance impact assessment** for critical path changes

## Benefits

### Short-term Benefits

- **Improved Code Organization**: Clear separation of concerns makes the codebase easier to navigate
- **Better Testability**: Individual components can be tested in isolation
- **Enhanced Error Handling**: More specific error types provide better debugging information
- **Reduced Complexity**: Smaller, focused modules are easier to understand and maintain

### Long-term Benefits

- **Extensibility**: Easy to add new protocols without modifying existing code
- **Performance Optimization**: Individual components can be optimized independently
- **Team Productivity**: Multiple developers can work on different components simultaneously
- **Maintenance Efficiency**: Bug fixes and updates are isolated to specific components

### Risk Mitigation

- **Incremental Changes**: Small steps reduce the risk of introducing bugs
- **Backward Compatibility**: Existing functionality continues to work during refactoring
- **Comprehensive Testing**: Each change is thoroughly tested before integration
- **Rollback Capability**: Each step can be reverted independently if issues arise

## Conclusion

This refactoring plan provides a structured approach to improving the rust-rpxy-l4 codebase while maintaining stability and functionality. The incremental nature of the plan ensures that the project remains operational throughout the refactoring process, while the clear separation of concerns will make the codebase more maintainable and extensible for future development.

The plan prioritizes foundation improvements first (protocol detection and error handling) before moving to higher-level optimizations (performance and observability). This approach ensures that the most critical improvements are implemented first, providing immediate benefits while building toward long-term architectural improvements.

Regular review and adjustment of this plan may be necessary based on implementation discoveries and changing project requirements. The modular nature of the plan allows for flexibility in prioritization and implementation timing based on project needs and resource availability.
