use crate::{
    config::{EchProtocolConfig, validation::*},
    destination::LoadBalance,
    target::TargetAddr,
};

/// Configuration specific to TCP protocols
#[derive(Debug, Clone)]
pub struct TcpProtocolConfig {
    /// Target addresses
    pub targets: Vec<TargetAddr>,
    /// Load balancing strategy
    pub load_balance: Option<LoadBalance>,
}

impl TcpProtocolConfig {
    /// Create a new TCP protocol configuration
    pub fn new(targets: Vec<TargetAddr>) -> Result<Self, ConfigValidationError> {
        TargetValidator::validate_targets(&targets)?;
        Ok(Self {
            targets,
            load_balance: None,
        })
    }

    /// Set load balancing strategy
    pub fn with_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
        TargetValidator::validate_load_balance_with_targets(Some(&lb), &self.targets)?;
        self.load_balance = Some(lb);
        Ok(self)
    }
}

/// Configuration specific to HTTP protocol
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Base TCP configuration
    pub tcp: TcpProtocolConfig,
}

impl HttpConfig {
    /// Create a new HTTP configuration
    pub fn new(targets: Vec<TargetAddr>) -> Result<Self, ConfigValidationError> {
        let tcp = TcpProtocolConfig::new(targets)?;
        Ok(Self { tcp })
    }

    /// Set load balancing strategy
    pub fn with_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
        self.tcp = self.tcp.with_load_balance(lb)?;
        Ok(self)
    }
}

/// Configuration specific to SSH protocol
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// Base TCP configuration
    pub tcp: TcpProtocolConfig,
}

impl SshConfig {
    /// Create a new SSH configuration
    pub fn new(targets: Vec<TargetAddr>) -> Result<Self, ConfigValidationError> {
        let tcp = TcpProtocolConfig::new(targets)?;
        Ok(Self { tcp })
    }

    /// Set load balancing strategy
    pub fn with_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
        self.tcp = self.tcp.with_load_balance(lb)?;
        Ok(self)
    }
}

/// Configuration specific to TLS protocol
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Base TCP configuration
    pub tcp: TcpProtocolConfig,
    /// ALPN protocols
    pub alpn: Option<Vec<String>>,
    /// Server names (SNI)
    pub server_names: Option<Vec<String>>,
    /// ECH configuration
    pub ech: Option<EchProtocolConfig>,
}

impl TlsConfig {
    /// Create a new TLS configuration
    pub fn new(targets: Vec<TargetAddr>) -> Result<Self, ConfigValidationError> {
        let tcp = TcpProtocolConfig::new(targets)?;
        Ok(Self {
            tcp,
            alpn: None,
            server_names: None,
            ech: None,
        })
    }

    /// Set load balancing strategy
    pub fn with_load_balance(mut self, lb: LoadBalance) -> Result<Self, ConfigValidationError> {
        self.tcp = self.tcp.with_load_balance(lb)?;
        Ok(self)
    }

    /// Set ALPN protocols
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Result<Self, ConfigValidationError> {
        ProtocolValidator::validate_tls_config("tls", Some(&alpn), self.server_names.as_deref())?;
        self.alpn = Some(alpn);
        Ok(self)
    }

    /// Set server names (SNI)
    pub fn with_server_names(mut self, server_names: Vec<String>) -> Result<Self, ConfigValidationError> {
        ProtocolValidator::validate_tls_config("tls", self.alpn.as_deref(), Some(&server_names))?;
        self.server_names = Some(server_names);
        Ok(self)
    }

    /// Set ECH configuration
    pub fn with_ech(mut self, ech: EchProtocolConfig) -> Self {
        self.ech = Some(ech);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_tcp_protocol_config() {
        let targets = vec![TargetAddr::from_str("192.168.1.1:80").unwrap()];
        let config = TcpProtocolConfig::new(targets).unwrap();
        assert_eq!(config.targets.len(), 1);
        assert!(config.load_balance.is_none());
    }

    #[test]
    fn test_tcp_with_load_balance() {
        let targets = vec![
            TargetAddr::from_str("192.168.1.1:80").unwrap(),
            TargetAddr::from_str("192.168.1.2:80").unwrap(),
        ];
        let config = TcpProtocolConfig::new(targets)
            .unwrap()
            .with_load_balance(LoadBalance::SourceIp)
            .unwrap();
        assert_eq!(config.load_balance, Some(LoadBalance::SourceIp));
    }

    #[test]
    fn test_http_config() {
        let targets = vec![TargetAddr::from_str("192.168.1.1:80").unwrap()];
        let config = HttpConfig::new(targets).unwrap();
        assert_eq!(config.tcp.targets.len(), 1);
    }

    #[test]
    fn test_tls_config() {
        let targets = vec![TargetAddr::from_str("192.168.1.1:443").unwrap()];
        let config = TlsConfig::new(targets)
            .unwrap()
            .with_alpn(vec!["h2".to_string(), "http/1.1".to_string()])
            .unwrap()
            .with_server_names(vec!["example.com".to_string()])
            .unwrap();
        
        assert!(config.alpn.is_some());
        assert!(config.server_names.is_some());
        assert_eq!(config.alpn.as_ref().unwrap().len(), 2);
        assert_eq!(config.server_names.as_ref().unwrap()[0], "example.com");
    }

    #[test]
    fn test_tls_config_validation_error() {
        let targets = vec![TargetAddr::from_str("192.168.1.1:443").unwrap()];
        // Try to set invalid server name (contains space)
        let result = TlsConfig::new(targets)
            .unwrap()
            .with_server_names(vec!["invalid domain.com".to_string()]);
        assert!(result.is_err());
    }
}
