use crate::{
    config::{EchProtocolConfig, validation::*},
};

/// Configuration specific to TLS-based protocols (TLS over TCP and QUIC over UDP)
#[derive(Debug, Clone)]
pub struct TlsProtocolConfig {
    /// ALPN protocols for negotiation
    pub alpn: Option<Vec<String>>,
    /// Server names for SNI matching
    pub server_names: Option<Vec<String>>,
    /// ECH (Encrypted Client Hello) configuration
    pub ech: Option<EchProtocolConfig>,
}

impl Default for TlsProtocolConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsProtocolConfig {
    /// Create a new TLS protocol configuration
    pub fn new() -> Self {
        Self {
            alpn: None,
            server_names: None,
            ech: None,
        }
    }

    /// Set ALPN protocols
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Result<Self, ConfigValidationError> {
        // Validate ALPN protocols
        for alpn_proto in &alpn {
            if alpn_proto.is_empty() {
                return Err(ConfigValidationError::ProtocolValidationError {
                    protocol_name: "tls".to_string(),
                    reason: "ALPN protocol name cannot be empty".to_string(),
                });
            }
        }
        
        // Validate the combination with existing server names
        ProtocolValidator::validate_tls_config("tls", Some(&alpn), self.server_names.as_deref())?;
        self.alpn = Some(alpn);
        Ok(self)
    }

    /// Set server names for SNI matching
    pub fn with_server_names(mut self, server_names: Vec<String>) -> Result<Self, ConfigValidationError> {
        // Validate server names
        for server_name in &server_names {
            if server_name.is_empty() {
                return Err(ConfigValidationError::ProtocolValidationError {
                    protocol_name: "tls".to_string(),
                    reason: "Server name cannot be empty".to_string(),
                });
            }
            if server_name.contains(' ') {
                return Err(ConfigValidationError::ProtocolValidationError {
                    protocol_name: "tls".to_string(),
                    reason: format!("Invalid server name '{}': cannot contain spaces", server_name),
                });
            }
        }
        
        // Validate the combination with existing ALPN
        ProtocolValidator::validate_tls_config("tls", self.alpn.as_deref(), Some(&server_names))?;
        self.server_names = Some(server_names);
        Ok(self)
    }

    /// Set ECH configuration
    pub fn with_ech(mut self, ech: EchProtocolConfig) -> Self {
        self.ech = Some(ech);
        self
    }

    /// Validate this TLS configuration
    pub fn validate(&self, protocol_name: &str) -> Result<(), ConfigValidationError> {
        ProtocolValidator::validate_tls_config(
            protocol_name,
            self.alpn.as_deref(),
            self.server_names.as_deref(),
        )
    }

    /// Check if this configuration has any TLS-specific settings
    pub fn is_empty(&self) -> bool {
        self.alpn.is_none() && self.server_names.is_none() && self.ech.is_none()
    }

    /// Get recommended ALPN protocols for a given protocol type
    pub fn recommended_alpn_for_protocol(protocol: &str) -> Vec<String> {
        match protocol.to_lowercase().as_str() {
            "http" => vec!["http/1.1".to_string()],
            "http2" => vec!["h2".to_string(), "http/1.1".to_string()],
            "quic" | "http3" => vec!["h3".to_string()],
            "dot" => vec!["dot".to_string()], // DNS over TLS
            _ => vec![],
        }
    }

    /// Create a configuration with recommended ALPN for a protocol
    pub fn with_recommended_alpn_for(protocol: &str) -> Self {
        let alpn = Self::recommended_alpn_for_protocol(protocol);
        if alpn.is_empty() {
            Self::new()
        } else {
            Self::new().with_alpn(alpn).unwrap_or_else(|_| Self::new())
        }
    }
}

/// Builder for ECH configuration
#[derive(Debug, Default)]
pub struct EchConfigBuilder {
    ech_config_list: Option<String>,
    private_keys: Vec<String>,
    private_server_names: Vec<String>,
    listen_port: Option<u16>,
}

impl EchConfigBuilder {
    /// Create a new ECH configuration builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the ECH config list (base64 encoded)
    pub fn with_config_list(mut self, config_list: String) -> Self {
        self.ech_config_list = Some(config_list);
        self
    }

    /// Add a private key (base64 encoded)
    pub fn with_private_key(mut self, private_key: String) -> Self {
        self.private_keys.push(private_key);
        self
    }

    /// Add multiple private keys
    pub fn with_private_keys(mut self, private_keys: Vec<String>) -> Self {
        self.private_keys.extend(private_keys);
        self
    }

    /// Add a private server name
    pub fn with_private_server_name(mut self, server_name: String) -> Self {
        self.private_server_names.push(server_name);
        self
    }

    /// Add multiple private server names
    pub fn with_private_server_names(mut self, server_names: Vec<String>) -> Self {
        self.private_server_names.extend(server_names);
        self
    }

    /// Set the listen port for ECH targets
    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Build the ECH configuration
    pub fn build(self) -> Result<EchProtocolConfig, ConfigValidationError> {
        let config_list = self.ech_config_list.ok_or(ConfigValidationError::MissingRequiredField {
            field: "ech_config_list".to_string(),
        })?;

        let listen_port = self.listen_port.ok_or(ConfigValidationError::MissingRequiredField {
            field: "listen_port".to_string(),
        })?;

        if self.private_keys.is_empty() {
            return Err(ConfigValidationError::EchConfigurationError {
                reason: "At least one private key is required".to_string(),
            });
        }

        if self.private_server_names.is_empty() {
            return Err(ConfigValidationError::EchConfigurationError {
                reason: "At least one private server name is required".to_string(),
            });
        }

        EchProtocolConfig::try_new(
            &config_list,
            &self.private_keys,
            &self.private_server_names,
            &listen_port,
        ).map_err(|e| ConfigValidationError::EchConfigurationError {
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_protocol_config_creation() {
        let config = TlsProtocolConfig::new();
        assert!(config.is_empty());
        assert!(config.alpn.is_none());
        assert!(config.server_names.is_none());
        assert!(config.ech.is_none());
    }

    #[test]
    fn test_tls_with_alpn() {
        let config = TlsProtocolConfig::new()
            .with_alpn(vec!["h2".to_string(), "http/1.1".to_string()])
            .unwrap();
        
        assert!(!config.is_empty());
        assert!(config.alpn.is_some());
        assert_eq!(config.alpn.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_tls_with_server_names() {
        let config = TlsProtocolConfig::new()
            .with_server_names(vec!["example.com".to_string(), "www.example.com".to_string()])
            .unwrap();
        
        assert!(!config.is_empty());
        assert!(config.server_names.is_some());
        assert_eq!(config.server_names.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_tls_validation_errors() {
        // Empty ALPN
        let result = TlsProtocolConfig::new()
            .with_alpn(vec!["".to_string()]);
        assert!(result.is_err());

        // Empty server name
        let result = TlsProtocolConfig::new()
            .with_server_names(vec!["".to_string()]);
        assert!(result.is_err());

        // Server name with space
        let result = TlsProtocolConfig::new()
            .with_server_names(vec!["invalid domain.com".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_recommended_alpn() {
        let http_alpn = TlsProtocolConfig::recommended_alpn_for_protocol("http");
        assert_eq!(http_alpn, vec!["http/1.1"]);

        let http2_alpn = TlsProtocolConfig::recommended_alpn_for_protocol("http2");
        assert_eq!(http2_alpn, vec!["h2", "http/1.1"]);

        let quic_alpn = TlsProtocolConfig::recommended_alpn_for_protocol("quic");
        assert_eq!(quic_alpn, vec!["h3"]);

        let unknown_alpn = TlsProtocolConfig::recommended_alpn_for_protocol("unknown");
        assert!(unknown_alpn.is_empty());
    }

    #[test]
    fn test_with_recommended_alpn() {
        let config = TlsProtocolConfig::with_recommended_alpn_for("http2");
        assert!(!config.is_empty());
        assert!(config.alpn.is_some());
        assert_eq!(config.alpn.as_ref().unwrap(), &vec!["h2", "http/1.1"]);
    }

    #[test]
    fn test_ech_config_builder() {
        let builder = EchConfigBuilder::new()
            .with_config_list("base64_config".to_string())
            .with_private_key("base64_key".to_string())
            .with_private_server_name("secret.example.com".to_string())
            .with_listen_port(443);

        // Note: This will fail because we're using dummy base64 data,
        // but it tests the builder pattern
        let result = builder.build();
        assert!(result.is_err()); // Expected to fail with invalid base64
    }

    #[test]
    fn test_ech_builder_validation() {
        // Missing config list
        let result = EchConfigBuilder::new()
            .with_private_key("key".to_string())
            .with_private_server_name("server".to_string())
            .with_listen_port(443)
            .build();
        assert!(result.is_err());

        // Missing private keys
        let result = EchConfigBuilder::new()
            .with_config_list("config".to_string())
            .with_private_server_name("server".to_string())
            .with_listen_port(443)
            .build();
        assert!(result.is_err());

        // Missing server names
        let result = EchConfigBuilder::new()
            .with_config_list("config".to_string())
            .with_private_key("key".to_string())
            .with_listen_port(443)
            .build();
        assert!(result.is_err());
    }
}
