//! TLS-based routing
//!
//! This module provides improved TLS routing based on SNI and ALPN with priority-based matching.

/// TLS routing rule with priority support
#[derive(Debug, Clone)]
pub struct TlsRoutingRule {
  /// Server names to match (SNI)
  pub server_names: Vec<String>,
  /// ALPN protocols to match
  pub alpn_protocols: Vec<String>,
  /// Priority for this rule (higher number = higher priority)
  pub priority: u8,
}

impl TlsRoutingRule {
  /// Create a new TLS routing rule
  pub fn new() -> Self {
    Self {
      server_names: Vec::new(),
      alpn_protocols: Vec::new(),
      priority: 0,
    }
  }

  /// Add server names to match
  pub fn with_server_names(mut self, server_names: &[&str]) -> Self {
    self.server_names = server_names.iter().map(|s| s.to_lowercase()).collect();
    self
  }

  /// Add ALPN protocols to match
  pub fn with_alpn_protocols(mut self, protocols: &[&str]) -> Self {
    self.alpn_protocols = protocols.iter().map(|s| s.to_lowercase()).collect();
    self
  }

  /// Set the priority for this rule
  pub fn with_priority(mut self, priority: u8) -> Self {
    self.priority = priority;
    self
  }

  /// Check if this rule matches the given client hello
  pub fn matches(&self, client_hello: &quic_tls::TlsClientHello) -> bool {
    let sni_match = self.matches_sni(client_hello);
    let alpn_match = self.matches_alpn(client_hello);

    match (self.server_names.is_empty(), self.alpn_protocols.is_empty()) {
      (true, true) => true,                      // Wildcard rule
      (true, false) => alpn_match,               // ALPN-only rule
      (false, true) => sni_match,                // SNI-only rule
      (false, false) => sni_match && alpn_match, // Both must match
    }
  }

  /// Check if SNI matches
  fn matches_sni(&self, client_hello: &quic_tls::TlsClientHello) -> bool {
    if self.server_names.is_empty() {
      return true;
    }

    let received_sni = client_hello.sni();
    received_sni.iter().any(|received| {
      let received_lower = received.to_lowercase();
      self
        .server_names
        .iter()
        .any(|rule_sni| rule_sni == &received_lower || self.is_wildcard_match(rule_sni, &received_lower))
    })
  }

  /// Check if ALPN matches
  fn matches_alpn(&self, client_hello: &quic_tls::TlsClientHello) -> bool {
    if self.alpn_protocols.is_empty() {
      return true;
    }

    let received_alpn = client_hello.alpn();
    received_alpn.iter().any(|received| {
      let received_lower = received.to_lowercase();
      self.alpn_protocols.iter().any(|rule_alpn| rule_alpn == &received_lower)
    })
  }

  /// Check wildcard matching for SNI (supports *.example.com patterns)
  pub fn is_wildcard_match(&self, pattern: &str, hostname: &str) -> bool {
    if !pattern.starts_with("*.") {
      return false;
    }

    let domain_suffix = &pattern[2..]; // Remove "*."
    if !hostname.ends_with(domain_suffix) || hostname.len() <= domain_suffix.len() {
      return false;
    }

    // Ensure there's a dot before the domain suffix (proper subdomain)
    let prefix_len = hostname.len() - domain_suffix.len();
    hostname.chars().nth(prefix_len - 1) == Some('.')
  }

  /// Calculate match specificity score for prioritization
  pub fn specificity_score(&self) -> u16 {
    let mut score = 0u16;

    // Higher score for more specific SNI rules
    if !self.server_names.is_empty() {
      score += 100;
      // Bonus for non-wildcard SNI rules
      if self.server_names.iter().any(|sni| !sni.starts_with("*.")) {
        score += 50;
      }
    }

    // Higher score for ALPN rules
    if !self.alpn_protocols.is_empty() {
      score += 100;
    }

    // Add priority as tiebreaker
    score += self.priority as u16;

    score
  }
}

impl Default for TlsRoutingRule {
  fn default() -> Self {
    Self::new()
  }
}

/// TLS router with priority-based destination matching
#[derive(Debug, Clone)]
pub struct TlsRouter<T> {
  routes: Vec<(TlsRoutingRule, T)>,
}

impl<T> TlsRouter<T> {
  /// Create a new TLS router
  pub fn new() -> Self {
    Self { routes: Vec::new() }
  }

  /// Add a route with associated destination
  pub fn add_route(&mut self, rule: TlsRoutingRule, destination: T) {
    self.routes.push((rule, destination));
    self.sort_routes();
  }

  /// Add a route using builder pattern
  pub fn with_route(mut self, rule: TlsRoutingRule, destination: T) -> Self {
    self.add_route(rule, destination);
    self
  }

  /// Sort routes by priority and specificity
  fn sort_routes(&mut self) {
    self.routes.sort_by(|a, b| {
      // First sort by priority (higher first)
      let priority_cmp = b.0.priority.cmp(&a.0.priority);
      if priority_cmp != std::cmp::Ordering::Equal {
        return priority_cmp;
      }

      // Then by specificity score (higher first)
      b.0.specificity_score().cmp(&a.0.specificity_score())
    });
  }

  /// Find the best matching destination for a TLS client hello
  pub fn find_destination(&self, client_hello: &quic_tls::TlsClientHello) -> Option<&T> {
    self
      .routes
      .iter()
      .find(|(rule, _)| rule.matches(client_hello))
      .map(|(_, destination)| destination)
  }

  /// Get all routes
  pub fn routes(&self) -> &[(TlsRoutingRule, T)] {
    &self.routes
  }

  /// Get the number of routes
  pub fn len(&self) -> usize {
    self.routes.len()
  }

  /// Check if the router is empty
  pub fn is_empty(&self) -> bool {
    self.routes.is_empty()
  }
}

impl<T> Default for TlsRouter<T> {
  fn default() -> Self {
    Self::new()
  }
}



#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_tls_routing_rule_creation() {
    let rule = TlsRoutingRule::new()
      .with_server_names(&["example.com", "www.example.com"])
      .with_alpn_protocols(&["h2", "http/1.1"])
      .with_priority(10);

    assert_eq!(rule.server_names, vec!["example.com", "www.example.com"]);
    assert_eq!(rule.alpn_protocols, vec!["h2", "http/1.1"]);
    assert_eq!(rule.priority, 10);
  }

  #[test]
  fn test_wildcard_matching() {
    let rule = TlsRoutingRule::new().with_server_names(&["*.example.com"]);

    assert!(rule.is_wildcard_match("*.example.com", "sub.example.com"));
    assert!(rule.is_wildcard_match("*.example.com", "www.example.com"));
    assert!(!rule.is_wildcard_match("*.example.com", "example.com"));
    assert!(!rule.is_wildcard_match("*.example.com", "notexample.com"));
    assert!(!rule.is_wildcard_match("example.com", "sub.example.com"));
  }

  #[test]
  fn test_specificity_score() {
    let rule1 = TlsRoutingRule::new(); // Wildcard
    let rule2 = TlsRoutingRule::new().with_server_names(&["example.com"]);
    let rule3 = TlsRoutingRule::new().with_alpn_protocols(&["h2"]);
    let rule4 = TlsRoutingRule::new()
      .with_server_names(&["example.com"])
      .with_alpn_protocols(&["h2"]);
    let rule5 = TlsRoutingRule::new().with_server_names(&["*.example.com"]).with_priority(10);

    assert!(rule1.specificity_score() < rule2.specificity_score());
    assert!(rule2.specificity_score() < rule4.specificity_score());
    assert!(rule3.specificity_score() < rule4.specificity_score());
    assert_eq!(rule5.specificity_score(), 110); // 100 (SNI) + 10 (priority)
  }

  #[test]
  fn test_tls_router_basic() {
    let mut router = TlsRouter::new();

    let rule1 = TlsRoutingRule::new().with_server_names(&["example.com"]).with_priority(1);
    router.add_route(rule1, "destination1");

    let rule2 = TlsRoutingRule::new().with_alpn_protocols(&["h2"]).with_priority(2);
    router.add_route(rule2, "destination2");

    let rule3 = TlsRoutingRule::new(); // Wildcard
    router.add_route(rule3, "destination3");

    assert_eq!(router.len(), 3);

    // Routes should be sorted by priority
    let routes = router.routes();
    assert_eq!(routes[0].0.priority, 2); // h2 rule first (higher priority)
    assert_eq!(routes[1].0.priority, 1); // example.com rule second
    assert_eq!(routes[2].0.priority, 0); // wildcard last
  }

  #[test]
  fn test_tls_router_matching() {
    let mut client_hello = quic_tls::TlsClientHello::default();

    // Add SNI
    let mut sni = quic_tls::extension::ServerNameIndication::default();
    sni.add_server_name("example.com");
    client_hello.add_replace_sni(&sni);

    let mut router = TlsRouter::new();

    let rule1 = TlsRoutingRule::new().with_server_names(&["example.com"]);
    router.add_route(rule1, "sni_match");

    let rule2 = TlsRoutingRule::new(); // Wildcard
    router.add_route(rule2, "wildcard");

    let destination = router.find_destination(&client_hello);
    assert_eq!(destination, Some(&"sni_match"));
  }

  #[test]
  fn test_tls_destination_item() {
    // Import our TLS destination item from the tls module
    use crate::destination::tls::TlsDestinationItem;
    use crate::target::DnsCache;
    use std::sync::Arc;
    
    let dns_cache = Arc::new(DnsCache::default());
    let item = TlsDestinationItem::new("test_destination", None, dns_cache);
    assert_eq!(item.destination(), &"test_destination");
    assert!(item.ech().is_none());
  }

  #[test]
  fn test_tls_router_complex_matching() {
    let mut router = TlsRouter::new();

    // Most specific: SNI + ALPN
    let rule1 = TlsRoutingRule::new()
      .with_server_names(&["api.example.com"])
      .with_alpn_protocols(&["h2"])
      .with_priority(10);
    router.add_route(rule1, "api_h2");

    // Less specific: SNI only
    let rule2 = TlsRoutingRule::new().with_server_names(&["api.example.com"]).with_priority(5);
    router.add_route(rule2, "api_any");

    // Wildcard
    let rule3 = TlsRoutingRule::new();
    router.add_route(rule3, "default");

    // Test with matching SNI and ALPN
    let mut client_hello = quic_tls::TlsClientHello::default();

    let mut sni = quic_tls::extension::ServerNameIndication::default();
    sni.add_server_name("api.example.com");
    client_hello.add_replace_sni(&sni);

    let mut alpn = quic_tls::extension::ApplicationLayerProtocolNegotiation::default();
    alpn.add_protocol_name("h2");
    client_hello.add_replace_alpn(&alpn);

    let destination = router.find_destination(&client_hello);
    assert_eq!(destination, Some(&"api_h2"));

    // Test with SNI only (no ALPN)
    let mut client_hello2 = quic_tls::TlsClientHello::default();
    let mut sni2 = quic_tls::extension::ServerNameIndication::default();
    sni2.add_server_name("api.example.com");
    client_hello2.add_replace_sni(&sni2);

    let destination2 = router.find_destination(&client_hello2);
    assert_eq!(destination2, Some(&"api_any"));
  }
}
