use crate::error::ProxyError;
use std::{
  fmt,
  net::{SocketAddr, ToSocketAddrs},
  str::FromStr,
};

/// Represents a target address that can be either a direct socket address or a domain name with port
#[derive(Debug, Clone)]
pub enum TargetAddr {
  /// Direct socket address (IP and port)
  Socket(SocketAddr),
  /// Domain name and port combination
  Domain(String, u16),
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

  /// Resolves the target address to a list of socket addresses
  ///
  /// For Socket variants, returns the socket address directly.
  /// For Domain variants, performs DNS resolution to get one or more IP addresses.
  pub fn resolve(&self) -> Result<Vec<SocketAddr>, ProxyError> {
    match self {
      TargetAddr::Socket(addr) => Ok(vec![*addr]),
      TargetAddr::Domain(domain, port) => {
        // Use a stack-allocated array to avoid heap allocation for the string
        let mut buf = [0u8; 256];
        let domain_bytes = domain.as_bytes();
        let port_str = port.to_string();
        let port_bytes = port_str.as_bytes();

        if domain_bytes.len() + port_bytes.len() + 1 > buf.len() {
          return Err(ProxyError::InvalidAddress(String::from("Address too long")));
        }

        // Construct domain:port string in the buffer
        buf[..domain_bytes.len()].copy_from_slice(domain_bytes);
        buf[domain_bytes.len()] = b':';
        buf[domain_bytes.len() + 1..domain_bytes.len() + 1 + port_bytes.len()].copy_from_slice(port_bytes);

        // Create string slice from the buffer
        let addr_str = std::str::from_utf8(&buf[..domain_bytes.len() + 1 + port_bytes.len()])
          .map_err(|_| ProxyError::InvalidAddress(String::from("Invalid UTF-8")))?;

        addr_str
          .to_socket_addrs()
          .map(|addrs| addrs.collect())
          .map_err(|e| ProxyError::DnsResolutionError(e.to_string()))
      }
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
          return Err(ProxyError::InvalidAddress(String::from("Invalid domain name")));
        }

        let port = port
          .parse::<u16>()
          .map_err(|_| ProxyError::InvalidAddress(String::from("Invalid port number")))?;
        Ok(TargetAddr::Domain(domain.to_string(), port))
      }
      None => Err(ProxyError::InvalidAddress(String::from(
        "Invalid address format - missing port number",
      ))),
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
  fn test_resolve() {
    // Test Socket variant
    let addr = TargetAddr::Socket("127.0.0.1:8080".parse().unwrap());
    let resolved = addr.resolve().unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].to_string(), "127.0.0.1:8080");

    // Test Domain variant with localhost
    let addr = TargetAddr::Domain("localhost".to_string(), 8080);
    let resolved = addr.resolve().unwrap();
    assert!(!resolved.is_empty());
  }

  #[test]
  fn test_display() {
    let socket_addr = TargetAddr::Socket("127.0.0.1:8080".parse().unwrap());
    assert_eq!(socket_addr.to_string(), "127.0.0.1:8080");

    let domain_addr = TargetAddr::Domain("example.com".to_string(), 8080);
    assert_eq!(domain_addr.to_string(), "example.com:8080");
  }

  #[test]
  fn test_cloudflare_dns() {
    let addr = "one.one.one.one:53".parse::<TargetAddr>().unwrap();

    if let TargetAddr::Domain(domain, port) = addr.clone() {
      assert_eq!(domain, "one.one.one.one");
      assert_eq!(port, 53);
    } else {
      panic!("Expected Domain variant");
    }

    // Test resolution to Cloudflare DNS IPs
    let resolved = addr.resolve().unwrap();
    assert!(!resolved.is_empty());

    // Convert resolved addresses to strings for easier comparison
    let resolved_ips: Vec<String> = resolved.iter().map(|addr| addr.ip().to_string()).collect();

    // Check that at least one of the expected Cloudflare DNS IPs is present
    let expected_ips = ["1.1.1.1", "1.0.0.1"];
    assert!(
      expected_ips.iter().any(|ip| resolved_ips.contains(&ip.to_string())),
      "Expected one of {:?} in resolved IPs: {:?}",
      expected_ips,
      resolved_ips
    );
  }
}
