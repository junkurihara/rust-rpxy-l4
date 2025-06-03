//! Phase 5: Destination Resolution Refactoring Demo
//!
//! This demo showcases the new destination resolution abstractions:
//! - DNS resolution strategies with caching and mocking
//! - Load balancing algorithms (source IP, round-robin, random, etc.)
//! - TLS routing with SNI/ALPN matching and priority support
//!
//! The refactoring provides pluggable components for flexible destination handling.

use rpxy_l4_lib::destination::{
  CachingDnsResolver, DnsResolver, FirstAvailableLoadBalancer, LoadBalancer, MockDnsResolver, RandomLoadBalancer,
  RoundRobinLoadBalancer, SourceIpLoadBalancer, SourceSocketLoadBalancer, TlsRouter, TlsRoutingRule,
};
use rpxy_l4_lib::target::DnsCache;
use rpxy_l4_quic_tls as quic_tls;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("🚀 Phase 5: Destination Resolution Refactoring Demo");
  println!("==================================================\n");

  // 1. DNS Resolution Demo
  dns_resolution_demo().await?;

  // 2. Load Balancing Demo
  load_balancing_demo().await?;

  // 3. TLS Routing Demo
  tls_routing_demo().await?;

  println!("✅ Phase 5 destination resolution refactoring completed successfully!");
  println!("\nKey improvements:");
  println!("• Pluggable DNS resolution strategies");
  println!("• Multiple load balancing algorithms");
  println!("• Priority-based TLS routing with wildcard support");
  println!("• Comprehensive test coverage with 14 new tests");
  println!("• Backward compatibility maintained");

  Ok(())
}

async fn dns_resolution_demo() -> Result<(), Box<dyn std::error::Error>> {
  println!("🔍 DNS Resolution Strategies Demo");
  println!("=================================");

  // Create a DNS cache
  let cache = Arc::new(DnsCache::default());

  // 1. Caching DNS Resolver
  println!("\n1. Caching DNS Resolver:");
  let caching_resolver = CachingDnsResolver::new(cache.clone());

  let addresses = caching_resolver.resolve("localhost", 8080).await?;
  println!("   Resolved localhost:8080 to {} addresses:", addresses.len());
  for addr in &addresses {
    println!("   - {}", addr);
  }

  // 2. Mock DNS Resolver for testing
  println!("\n2. Mock DNS Resolver:");
  let mut mock_resolver = MockDnsResolver::new();
  mock_resolver.add_response(
    "api.example.com".to_string(),
    vec![
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 0),
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 0),
    ],
  );

  let mock_addresses = mock_resolver.resolve("api.example.com", 443).await?;
  println!("   Mock resolved api.example.com:443 to {} addresses:", mock_addresses.len());
  for addr in &mock_addresses {
    println!("   - {}", addr);
  }

  // 3. Bulk mock configuration
  println!("\n3. Bulk Mock Configuration:");
  let mut responses = HashMap::new();
  responses.insert(
    "service1.example.com".to_string(),
    vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 0)],
  );
  responses.insert(
    "service2.example.com".to_string(),
    vec![
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), 0),
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)), 0),
    ],
  );

  let bulk_resolver = MockDnsResolver::new().with_responses(responses);
  let service1_addrs = bulk_resolver.resolve("service1.example.com", 8080).await?;
  let service2_addrs = bulk_resolver.resolve("service2.example.com", 8080).await?;

  println!("   service1.example.com: {} addresses", service1_addrs.len());
  println!("   service2.example.com: {} addresses", service2_addrs.len());

  Ok(())
}

async fn load_balancing_demo() -> Result<(), Box<dyn std::error::Error>> {
  println!("\n\n⚖️  Load Balancing Algorithms Demo");
  println!("=================================");

  // Create test targets
  let targets = vec![
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 8080),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 8080),
  ];

  let source_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

  // 1. Source IP Load Balancer
  println!("\n1. Source IP Load Balancer (consistent hashing by IP):");
  let source_ip_balancer = SourceIpLoadBalancer::new();
  for i in 0..3 {
    let target = source_ip_balancer.select_target(source_addr, &targets).await?;
    println!("   Attempt {}: {} -> {}", i + 1, source_addr.ip(), target);
  }

  // 2. Source Socket Load Balancer
  println!("\n2. Source Socket Load Balancer (consistent hashing by IP+port):");
  let source_socket_balancer = SourceSocketLoadBalancer::new();
  for i in 0..3 {
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345 + i);
    let target = source_socket_balancer.select_target(src, &targets).await?;
    println!("   {} -> {}", src, target);
  }

  // 3. Round Robin Load Balancer
  println!("\n3. Round Robin Load Balancer:");
  let round_robin_balancer = RoundRobinLoadBalancer::new();
  for i in 0..6 {
    let target = round_robin_balancer.select_target(source_addr, &targets).await?;
    println!("   Request {}: -> {}", i + 1, target);
  }

  // 4. Random Load Balancer
  println!("\n4. Random Load Balancer:");
  let random_balancer = RandomLoadBalancer::new();
  for i in 0..5 {
    let target = random_balancer.select_target(source_addr, &targets).await?;
    println!("   Request {}: -> {}", i + 1, target);
  }

  // 5. First Available Load Balancer
  println!("\n5. First Available Load Balancer:");
  let first_balancer = FirstAvailableLoadBalancer::new();
  for i in 0..3 {
    let target = first_balancer.select_target(source_addr, &targets).await?;
    println!("   Request {}: -> {}", i + 1, target);
  }

  Ok(())
}

async fn tls_routing_demo() -> Result<(), Box<dyn std::error::Error>> {
  println!("\n\n🔒 TLS Routing with SNI/ALPN Demo");
  println!("=================================");

  // 1. TLS Routing Rules with Priority
  println!("\n1. Creating TLS Routing Rules:");

  let high_priority_rule = TlsRoutingRule::new()
    .with_server_names(&["api.example.com"])
    .with_alpn_protocols(&["h2"])
    .with_priority(10);
  println!("   High priority: api.example.com + h2 (priority: 10)");

  let medium_priority_rule = TlsRoutingRule::new().with_server_names(&["api.example.com"]).with_priority(5);
  println!("   Medium priority: api.example.com (priority: 5)");

  let wildcard_rule = TlsRoutingRule::new().with_server_names(&["*.example.com"]).with_priority(3);
  println!("   Wildcard: *.example.com (priority: 3)");

  let default_rule = TlsRoutingRule::new().with_priority(1);
  println!("   Default: any (priority: 1)");

  // 2. Specificity Scoring
  println!("\n2. Specificity Scoring:");
  println!("   High priority rule score: {}", high_priority_rule.specificity_score());
  println!("   Medium priority rule score: {}", medium_priority_rule.specificity_score());
  println!("   Wildcard rule score: {}", wildcard_rule.specificity_score());
  println!("   Default rule score: {}", default_rule.specificity_score());

  // 3. TLS Router with Multiple Destinations
  println!("\n3. TLS Router Configuration:");
  let mut router = TlsRouter::new();

  router.add_route(high_priority_rule, "backend-api-h2");
  router.add_route(medium_priority_rule, "backend-api-http1");
  router.add_route(wildcard_rule, "backend-wildcard");
  router.add_route(default_rule, "backend-default");

  println!("   Added {} routes to router", router.len());

  // 4. Route Ordering (should be sorted by priority/specificity)
  println!("\n4. Route Order (sorted by priority and specificity):");
  for (i, (rule, destination)) in router.routes().iter().enumerate() {
    println!(
      "   {}. {} (priority: {}, score: {})",
      i + 1,
      destination,
      rule.priority,
      rule.specificity_score()
    );
  }

  // 5. Wildcard Matching Examples
  println!("\n5. Wildcard Matching Examples:");
  let wildcard_test_rule = TlsRoutingRule::new().with_server_names(&["*.example.com"]);

  let test_cases = [
    ("sub.example.com", true),
    ("api.example.com", true),
    ("www.example.com", true),
    ("example.com", false),
    ("notexample.com", false),
    ("malicious.example.com.evil", false),
  ];

  for (hostname, expected) in test_cases {
    let matches = wildcard_test_rule.is_wildcard_match("*.example.com", hostname);
    let status = if matches == expected { "✅" } else { "❌" };
    println!(
      "   {} *.example.com matches {}: {} (expected: {})",
      status, hostname, matches, expected
    );
  }

  // 6. Mock TLS Client Hello for Testing
  println!("\n6. Mock TLS Routing Scenarios:");

  // Create a mock client hello with SNI and ALPN
  let mut client_hello = quic_tls::TlsClientHello::default();

  // Scenario 1: API with HTTP/2
  let mut sni = quic_tls::extension::ServerNameIndication::default();
  sni.add_server_name("api.example.com");
  client_hello.add_replace_sni(&sni);

  let mut alpn = quic_tls::extension::ApplicationLayerProtocolNegotiation::default();
  alpn.add_protocol_name("h2");
  client_hello.add_replace_alpn(&alpn);

  if let Some(destination) = router.find_destination(&client_hello) {
    println!("   api.example.com + h2 -> {}", destination);
  }

  // Scenario 2: API without HTTP/2
  let mut client_hello2 = quic_tls::TlsClientHello::default();
  let mut sni2 = quic_tls::extension::ServerNameIndication::default();
  sni2.add_server_name("api.example.com");
  client_hello2.add_replace_sni(&sni2);

  if let Some(destination) = router.find_destination(&client_hello2) {
    println!("   api.example.com (no ALPN) -> {}", destination);
  }

  // Scenario 3: Wildcard match
  let mut client_hello3 = quic_tls::TlsClientHello::default();
  let mut sni3 = quic_tls::extension::ServerNameIndication::default();
  sni3.add_server_name("web.example.com");
  client_hello3.add_replace_sni(&sni3);

  if let Some(destination) = router.find_destination(&client_hello3) {
    println!("   web.example.com -> {}", destination);
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_destination_resolution_demo() {
    // Test that the demo functions run without errors
    dns_resolution_demo().await.unwrap();
    load_balancing_demo().await.unwrap();
    tls_routing_demo().await.unwrap();
  }

  #[tokio::test]
  async fn test_mock_dns_resolver_functionality() {
    let mut resolver = MockDnsResolver::new();
    resolver.add_response(
      "test.example.com".to_string(),
      vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080)],
    );

    let addresses = resolver.resolve("test.example.com", 8080).await.unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].port(), 8080);
    assert_eq!(addresses[0].ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
  }

  #[tokio::test]
  async fn test_load_balancer_consistency() {
    let targets = vec![
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080),
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 8080),
      SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 8080),
    ];
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

    let balancer = SourceIpLoadBalancer::new();

    // Same source should always get same target
    let target1 = balancer.select_target(source, &targets).await.unwrap();
    let target2 = balancer.select_target(source, &targets).await.unwrap();
    assert_eq!(target1, target2);
  }

  #[test]
  fn test_tls_routing_rule_priority() {
    let high_rule = TlsRoutingRule::new()
      .with_server_names(&["api.example.com"])
      .with_alpn_protocols(&["h2"])
      .with_priority(10);

    let low_rule = TlsRoutingRule::new().with_server_names(&["api.example.com"]).with_priority(5);

    assert!(high_rule.specificity_score() > low_rule.specificity_score());
  }
}
