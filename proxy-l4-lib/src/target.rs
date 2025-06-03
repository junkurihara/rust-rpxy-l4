use crate::{
  constants::{DNS_CACHE_MAX_TTL, DNS_CACHE_MIN_TTL},
  error::ProxyError,
};
use dashmap::DashMap;
use hickory_resolver::{TokioResolver, config::ResolverOpts};
use std::{
  fmt,
  net::SocketAddr,
  str::FromStr,
  time::{Duration, Instant},
};
use tracing::{debug, trace, warn};

/// Represents a target address that can be either a direct socket address or a domain name with port
#[derive(Debug, Clone)]
pub enum TargetAddr {
  /// Direct socket address (IP and port)
  Socket(SocketAddr),
  /// Domain name and port combination
  Domain(String, u16),
}

/// DNS cache entry containing resolved addresses with TTL information
#[derive(Debug, Clone)]
struct CacheEntry {
  /// Resolved socket addresses
  addresses: Vec<SocketAddr>,
  /// When this entry expires
  expires_at: Instant,
}

impl CacheEntry {
  /// Create a new cache entry
  fn new(addresses: Vec<SocketAddr>, expires_at: Instant) -> Self {
    Self { addresses, expires_at }
  }

  /// Check if this entry is expired
  fn is_expired(&self) -> bool {
    Instant::now() > self.expires_at
  }
}

/// DNS cache for domain name resolution with TTL-based expiration
#[derive(Debug)]
pub struct DnsCache {
  /// Cache entries indexed by domain name
  entries: DashMap<String, CacheEntry>,
  /// Minimum TTL to enforce (default: 30 seconds)
  min_ttl: Duration,
  /// Maximum TTL to enforce (default: 1 hour)
  max_ttl: Duration,
}

impl Default for DnsCache {
  fn default() -> Self {
    Self::new(DNS_CACHE_MIN_TTL, DNS_CACHE_MAX_TTL)
  }
}

impl DnsCache {
  /// Create a new DNS cache with specified TTL bounds
  pub fn new(min_ttl: Duration, max_ttl: Duration) -> Self {
    Self {
      entries: DashMap::new(),
      min_ttl,
      max_ttl,
    }
  }

  /// Get or resolve a domain name with caching
  pub async fn get_or_resolve(&self, domain: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
    // Check cache first
    let Some(entry) = self.entries.get(domain) else {
      // No cache entry exists - resolve for the first time
      return self.resolve_and_cache(domain, port).await;
    };
    let entry_clone = entry.value().clone();
    drop(entry);

    if !entry_clone.is_expired() {
      debug!("DNS cache hit for domain: {}", domain);
      return Ok(entry_clone.addresses.clone());
    }

    // Entry is expired - try to resolve, but keep old IPs as fallback
    match self.resolve_and_cache(domain, port).await {
      Ok(addresses) => Ok(addresses),
      Err(e) => {
        warn!("Failed to refresh expired DNS entry for {}: {}", domain, e);
        // Continue to use expired entry rather than failing
        Ok(entry_clone.addresses.clone())
      }
    }
  }

  /// Resolve domain and update cache
  async fn resolve_and_cache(&self, domain: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
    debug!("Resolving DNS for: {}", domain);

    // Create resolver with default system config
    let mut opts = ResolverOpts::default();
    opts.cache_size = 0; // Disable internal cache since we implement our own
    let resolver = TokioResolver::builder_tokio()
      .map_err(|e| ProxyError::dns_resolution_error(format!("Failed to create resolver: {}", e)))?
      .with_options(opts)
      .build();

    trace!("domain: {}", domain);

    // Perform DNS resolution
    let response = resolver
      .lookup_ip(domain)
      .await
      .map_err(|e| ProxyError::dns_resolution_error(format!("Failed to resolve {}: {}", domain, e)))?;

    trace!("Response: {:?}", response);

    if response.iter().next().is_none() {
      // Try using last known good IPs if available
      if let Some(entry) = self.entries.get(domain) {
        debug!("No new addresses found, using last known good IPs for {}", domain);
        return Ok(entry.addresses.clone());
      }
      return Err(ProxyError::dns_resolution_error(format!("No addresses found for {}", domain)));
    }

    trace!("Response IPs: {:?}", response);

    // Convert IPs to socket addresses with port
    let addresses: Vec<SocketAddr> = response.iter().map(|ip| SocketAddr::new(ip, port)).collect();

    trace!("Addresses: {:?}", addresses);

    // Get minimum TTL from DNS response (or use default)
    let expired_at = self.clamp_ttl(response.valid_until().clone());

    trace!("Expired at: {:?}", expired_at);

    // Update cache with new addresses and TTL
    let entry = CacheEntry::new(addresses.clone(), expired_at);

    trace!("Cache entry: {:?}", entry);

    self.entries.insert(domain.to_string(), entry);

    trace!("Cache updated for {}: {:?}", domain, addresses);

    debug!(
      "DNS resolved {} to {} addresses, expires at {:?}",
      domain,
      addresses.len(),
      expired_at
    );

    Ok(addresses)
  }

  /// Clamp TTL to configured bounds
  fn clamp_ttl(&self, expires_at: Instant) -> Instant {
    let ttl = expires_at.duration_since(Instant::now());
    let min_ttl = self.min_ttl;
    let max_ttl = self.max_ttl;
    let clamped_ttl = if ttl < min_ttl {
      min_ttl
    } else if ttl > max_ttl {
      max_ttl
    } else {
      ttl
    };
    Instant::now() + clamped_ttl
  }
}

impl TargetAddr {
  /// Validates if the given domain name follows basic DNS naming rules
  /// Allows alphanumeric characters (a-z, A-Z, 0-9), dots (.), and hyphens (-)
  /// Does not allow:
  /// - Empty domains
  /// - Domains longer than 253 characters
  /// - Consecutive dots
  /// - Leading or trailing dots
  fn validate_domain(domain: &str) -> bool {
    !domain.is_empty()
      && domain.len() <= 253
      && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
      && !domain.starts_with('.')
      && !domain.ends_with('.')
      && !domain.contains("..")
  }

  /// Resolves the target address using a DNS cache
  ///
  /// For Socket variants, returns the socket address directly.
  /// For Domain variants, uses the provided DNS cache for resolution with TTL-based caching.
  pub async fn resolve_cached(&self, cache: &DnsCache) -> Result<Vec<SocketAddr>, ProxyError> {
    match self {
      TargetAddr::Socket(addr) => Ok(vec![*addr]),
      TargetAddr::Domain(domain, port) => cache.get_or_resolve(domain, *port).await,
    }
  }

  /// Returns the domain or IP address as a string
  pub fn domain_or_ip(&self) -> String {
    match self {
      TargetAddr::Socket(addr) => addr.ip().to_string(),
      TargetAddr::Domain(domain, _) => domain.clone(),
    }
  }
}

impl fmt::Display for TargetAddr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      TargetAddr::Socket(addr) => write!(f, "{}", addr),
      TargetAddr::Domain(domain, port) => write!(f, "{}:{}", domain, port),
    }
  }
}

impl FromStr for TargetAddr {
  type Err = ProxyError;

  /// Parses a string into a TargetAddr
  ///
  /// The string should be in one of these formats:
  /// - IP:PORT (e.g., "127.0.0.1:8080")
  /// - DOMAIN:PORT (e.g., "example.com:8080")
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    // First try to parse as a socket address
    if let Ok(socket_addr) = s.parse::<SocketAddr>() {
      return Ok(TargetAddr::Socket(socket_addr));
    }

    // If that fails, try to parse as domain:port
    match s.rsplit_once(':') {
      Some((domain, port)) => {
        if !Self::validate_domain(domain) {
          return Err(ProxyError::invalid_address("Invalid domain name"));
        }

        let port = port
          .parse::<u16>()
          .map_err(|_| ProxyError::invalid_address("Invalid port number"))?;
        Ok(TargetAddr::Domain(domain.to_string(), port))
      }
      None => Err(ProxyError::invalid_address("Invalid address format - missing port number")),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_socket_addr() {
    let addr = "127.0.0.1:8080".parse::<TargetAddr>().unwrap();
    match addr {
      TargetAddr::Socket(socket) => {
        assert_eq!(socket.to_string(), "127.0.0.1:8080");
      }
      _ => panic!("Expected Socket variant"),
    }
  }

  #[test]
  fn test_parse_domain() {
    let addr = "example.com:8080".parse::<TargetAddr>().unwrap();
    match addr {
      TargetAddr::Domain(domain, port) => {
        assert_eq!(domain, "example.com");
        assert_eq!(port, 8080);
      }
      _ => panic!("Expected Domain variant"),
    }
  }

  #[test]
  fn test_invalid_address() {
    assert!("invalid".parse::<TargetAddr>().is_err());
    assert!("invalid:invalid".parse::<TargetAddr>().is_err());
    assert!("example.com".parse::<TargetAddr>().is_err());
    assert!("..example.com:8080".parse::<TargetAddr>().is_err());
    assert!("example..com:8080".parse::<TargetAddr>().is_err());
    assert!(".example.com:8080".parse::<TargetAddr>().is_err());
    assert!("example.com.:8080".parse::<TargetAddr>().is_err());
  }

  #[test]
  fn test_display() {
    let socket_addr = TargetAddr::Socket("127.0.0.1:8080".parse().unwrap());
    assert_eq!(socket_addr.to_string(), "127.0.0.1:8080");

    let domain_addr = TargetAddr::Domain("example.com".to_string(), 8080);
    assert_eq!(domain_addr.to_string(), "example.com:8080");
  }

  #[tokio::test]
  async fn test_dns_cache() {
    let cache = DnsCache::default();

    // Test initial resolution
    let resolved1 = cache.get_or_resolve("localhost", 8080).await.unwrap();
    assert!(!resolved1.is_empty());

    // Test cache hit
    let resolved2 = cache.get_or_resolve("localhost", 8080).await.unwrap();
    assert_eq!(resolved1, resolved2);
  }

  #[tokio::test]
  async fn test_dns_cache_expiration() {
    use tokio::time::sleep;

    // Create cache with short TTL bounds
    let cache = DnsCache::new(
      Duration::from_secs(1), // min TTL
      Duration::from_secs(2), // max TTL
    );

    // Initial resolution - use Cloudflare DNS which should be reliable
    let test_domain = "one.one.one.one";
    let resolved1 = cache.get_or_resolve(test_domain, 53).await.unwrap();
    assert!(!resolved1.is_empty());

    // Check the resolved IPs contain at least one Cloudflare DNS IP
    let resolved_ips: Vec<String> = resolved1.iter().map(|addr| addr.ip().to_string()).collect();
    let expected_ips = ["1.1.1.1", "1.0.0.1"];
    assert!(
      expected_ips.iter().any(|ip| resolved_ips.contains(&ip.to_string())),
      "Expected one of {:?} in resolved IPs: {:?}",
      expected_ips,
      resolved_ips
    );

    // Test cache hit (should be immediate, no DNS query)
    let resolved2 = cache.get_or_resolve(test_domain, 53).await.unwrap();
    assert_eq!(resolved1, resolved2);

    // Wait for min TTL to expire
    sleep(Duration::from_secs(3)).await;

    // Should refetch DNS entry since TTL expired
    let resolved3 = cache.get_or_resolve(test_domain, 53).await.unwrap();
    assert!(!resolved3.is_empty());
  }

  #[tokio::test]
  async fn test_dns_ttl_bounds() {
    let min_ttl = Duration::from_secs(10);
    let max_ttl = Duration::from_secs(60);
    let cache = DnsCache::new(min_ttl, max_ttl);

    // Test TTL clamping
    let expires_at = Instant::now() + Duration::from_secs(5);
    let clamped = cache.clamp_ttl(expires_at);
    assert!(Instant::now() < clamped);
  }

  #[tokio::test]
  async fn test_dns_resolution_error() {
    let cache = DnsCache::default();

    // First successful resolution
    let resolved1 = cache.get_or_resolve("localhost", 8080).await.unwrap();

    // Try with invalid domain, should fail with no fallback since no cache exists
    let err = cache.get_or_resolve("invalid.domain", 8080).await.unwrap_err();
    assert!(matches!(
      err,
      ProxyError::Network(crate::error::NetworkError::DnsError { .. })
    ));

    // Try localhost again, should still work
    let resolved2 = cache.get_or_resolve("localhost", 8080).await.unwrap();
    assert_eq!(resolved1, resolved2);
  }
}
