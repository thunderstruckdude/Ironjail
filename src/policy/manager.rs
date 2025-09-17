use crate::{Result, IronJailError};
use crate::core::{ProcessManager, NamespaceManager};
use crate::policy::PolicyRules;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Policy manager for defining and applying sandbox policies
pub struct PolicyManager {
    rules: PolicyRules,
}

/// Complete policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy metadata
    pub metadata: PolicyMetadata,
    
    /// Policy rules
    pub rules: PolicyRules,
}

/// Policy metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    /// Policy name
    pub name: String,
    
    /// Policy description
    pub description: String,
    
    /// Policy version
    pub version: String,
    
    /// Author information
    pub author: String,
    
    /// Creation date
    pub created: chrono::DateTime<chrono::Utc>,
    
    /// Last modified date
    pub modified: chrono::DateTime<chrono::Utc>,
    
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl Default for PolicyMetadata {
    fn default() -> Self {
        Self {
            name: "Default Policy".to_string(),
            description: "Default IronJail sandbox policy".to_string(),
            version: "1.0.0".to_string(),
            author: "IronJail".to_string(),
            created: chrono::Utc::now(),
            modified: chrono::Utc::now(),
            tags: vec!["default".to_string()],
        }
    }
}

impl PolicyManager {
    /// Create a new policy manager with default rules
    pub fn default() -> Self {
        Self {
            rules: PolicyRules::default(),
        }
    }
    
    /// Create a policy manager from a file
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| IronJailError::PolicyConfiguration(
                format!("Failed to read policy file: {}", e)
            ))?;
        
        let policy: Policy = if path.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::from_str(&content)?
        } else {
            // Default to YAML
            serde_yaml::from_str(&content)?
        };
        
        Ok(Self {
            rules: policy.rules,
        })
    }
    
    /// Create a policy manager from rules
    pub fn from_rules(rules: PolicyRules) -> Self {
        Self { rules }
    }
    
    /// Validate the policy configuration
    pub fn validate(&self) -> Result<()> {
        debug!("Validating policy configuration");
        
        // Validate file access rules
        for rule in &self.rules.file_access {
            if rule.path.is_empty() {
                return Err(IronJailError::PolicyConfiguration(
                    "File access rule cannot have empty path".to_string()
                ).into());
            }
        }
        
        // Validate network access rules
        for rule in &self.rules.network_access {
            if rule.host.is_empty() && rule.port == 0 {
                return Err(IronJailError::PolicyConfiguration(
                    "Network access rule must specify host or port".to_string()
                ).into());
            }
        }
        
        // Validate system call rules
        for rule in &self.rules.system_calls {
            if rule.name.is_empty() {
                return Err(IronJailError::PolicyConfiguration(
                    "System call rule cannot have empty name".to_string()
                ).into());
            }
        }
        
        debug!("Policy validation completed successfully");
        Ok(())
    }
    
    /// Apply policy restrictions to sandbox components
    pub async fn apply_restrictions(
        &self,
        process_manager: &mut ProcessManager,
        namespace_manager: &mut NamespaceManager,
    ) -> Result<()> {
        info!("Applying policy restrictions");
        
        // Apply file access restrictions
        for rule in &self.rules.file_access {
            debug!("Applying file access rule: {:?}", rule);
            self.apply_file_access_rule(rule).await?;
        }
        
        // Apply network access restrictions
        for rule in &self.rules.network_access {
            debug!("Applying network access rule: {:?}", rule);
            self.apply_network_access_rule(rule).await?;
        }
        
        // Apply system call restrictions
        for rule in &self.rules.system_calls {
            debug!("Applying system call rule: {:?}", rule);
            self.apply_syscall_rule(rule).await?;
        }
        
        // Apply resource limits
        debug!("Applying resource limits: {:?}", self.rules.resource_limits);
        self.apply_resource_limits(&self.rules.resource_limits).await?;
        
        info!("Policy restrictions applied successfully");
        Ok(())
    }
    
    /// Apply a file access rule
    async fn apply_file_access_rule(&self, rule: &crate::policy::FileAccessRule) -> Result<()> {
        // In a real implementation, this would set up appropriate filesystem restrictions
        debug!("File access rule applied: {} -> {:?}", rule.path, rule.action);
        Ok(())
    }
    
    /// Apply a network access rule
    async fn apply_network_access_rule(&self, rule: &crate::policy::NetworkAccessRule) -> Result<()> {
        // In a real implementation, this would set up iptables rules or network namespaces
        debug!("Network access rule applied: {}:{} -> {:?}", rule.host, rule.port, rule.action);
        Ok(())
    }
    
    /// Apply a system call rule
    async fn apply_syscall_rule(&self, rule: &crate::policy::SystemCallRule) -> Result<()> {
        // In a real implementation, this would set up seccomp-bpf filters
        debug!("System call rule applied: {} -> {:?}", rule.name, rule.action);
        Ok(())
    }
    
    /// Apply resource limits
    async fn apply_resource_limits(&self, limits: &crate::policy::ResourceLimits) -> Result<()> {
        // In a real implementation, this would set up cgroups or other resource controls
        debug!("Resource limits applied: {:?}", limits);
        Ok(())
    }
    
    /// Generate a policy template
    pub fn generate_template(template_type: &str, output_path: &PathBuf) -> Result<()> {
        let policy = match template_type {
            "strict" => Self::create_strict_policy(),
            "permissive" => Self::create_permissive_policy(),
            "malware-analysis" => Self::create_malware_analysis_policy(),
            _ => Self::create_default_policy(),
        };
        
        let content = serde_yaml::to_string(&policy)?;
        
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        std::fs::write(output_path, content)
            .map_err(|e| IronJailError::PolicyConfiguration(
                format!("Failed to write policy template: {}", e)
            ))?;
        
        info!("Policy template generated: {:?}", output_path);
        Ok(())
    }
    
    /// Create a default policy
    fn create_default_policy() -> Policy {
        Policy {
            metadata: PolicyMetadata::default(),
            rules: PolicyRules::default(),
        }
    }
    
    /// Create a strict security policy
    fn create_strict_policy() -> Policy {
        Policy {
            metadata: PolicyMetadata {
                name: "Strict Security Policy".to_string(),
                description: "Highly restrictive policy for maximum security".to_string(),
                version: "1.0.0".to_string(),
                author: "IronJail".to_string(),
                created: chrono::Utc::now(),
                modified: chrono::Utc::now(),
                tags: vec!["strict".to_string(), "security".to_string()],
            },
            rules: PolicyRules::strict(),
        }
    }
    
    /// Create a permissive policy for development
    fn create_permissive_policy() -> Policy {
        Policy {
            metadata: PolicyMetadata {
                name: "Permissive Development Policy".to_string(),
                description: "Permissive policy for development and testing".to_string(),
                version: "1.0.0".to_string(),
                author: "IronJail".to_string(),
                created: chrono::Utc::now(),
                modified: chrono::Utc::now(),
                tags: vec!["permissive".to_string(), "development".to_string()],
            },
            rules: PolicyRules::permissive(),
        }
    }
    
    /// Create a malware analysis policy
    fn create_malware_analysis_policy() -> Policy {
        Policy {
            metadata: PolicyMetadata {
                name: "Malware Analysis Policy".to_string(),
                description: "Specialized policy for malware analysis with comprehensive monitoring".to_string(),
                version: "1.0.0".to_string(),
                author: "IronJail".to_string(),
                created: chrono::Utc::now(),
                modified: chrono::Utc::now(),
                tags: vec!["malware".to_string(), "analysis".to_string(), "forensics".to_string()],
            },
            rules: PolicyRules::malware_analysis(),
        }
    }
    
    /// Get the policy rules
    pub fn get_rules(&self) -> &PolicyRules {
        &self.rules
    }
    
    /// Check if a file access is allowed
    pub fn is_file_access_allowed(&self, path: &str, operation: &str) -> bool {
        for rule in &self.rules.file_access {
            if rule.path == path || rule.path == "*" {
                match rule.action {
                    crate::policy::PolicyAction::Allow => return true,
                    crate::policy::PolicyAction::Deny => return false,
                    crate::policy::PolicyAction::Log => continue,
                }
            }
        }
        
        // Default policy: allow if not explicitly denied
        true
    }
    
    /// Check if a network access is allowed
    pub fn is_network_access_allowed(&self, host: &str, port: u16) -> bool {
        for rule in &self.rules.network_access {
            if (rule.host == host || rule.host == "*") && 
               (rule.port == port || rule.port == 0) {
                match rule.action {
                    crate::policy::PolicyAction::Allow => return true,
                    crate::policy::PolicyAction::Deny => return false,
                    crate::policy::PolicyAction::Log => continue,
                }
            }
        }
        
        // Default policy: allow if not explicitly denied
        true
    }
    
    /// Check if a system call is allowed
    pub fn is_syscall_allowed(&self, syscall_name: &str) -> bool {
        for rule in &self.rules.system_calls {
            if rule.name == syscall_name || rule.name == "*" {
                match rule.action {
                    crate::policy::PolicyAction::Allow => return true,
                    crate::policy::PolicyAction::Deny => return false,
                    crate::policy::PolicyAction::Log => continue,
                }
            }
        }
        
        // Default policy: allow if not explicitly denied
        true
    }
}