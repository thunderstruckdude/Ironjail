use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete set of policy rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRules {
    /// File access rules
    pub file_access: Vec<FileAccessRule>,
    
    /// Network access rules
    pub network_access: Vec<NetworkAccessRule>,
    
    /// System call rules
    pub system_calls: Vec<SystemCallRule>,
    
    /// Resource limits
    pub resource_limits: ResourceLimits,
    
    /// Environment restrictions
    pub environment: EnvironmentRules,
    
    /// Monitoring settings
    pub monitoring: MonitoringRules,
}

/// File access rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessRule {
    /// File path or pattern
    pub path: String,
    
    /// Action to take
    pub action: PolicyAction,
    
    /// Operations this rule applies to
    pub operations: Vec<String>,
    
    /// Additional conditions
    pub conditions: HashMap<String, String>,
}

/// Network access rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAccessRule {
    /// Host or IP address (* for all)
    pub host: String,
    
    /// Port number (0 for all)
    pub port: u16,
    
    /// Protocol (tcp, udp, all)
    pub protocol: String,
    
    /// Action to take
    pub action: PolicyAction,
    
    /// Additional conditions
    pub conditions: HashMap<String, String>,
}

/// System call rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCallRule {
    /// System call name
    pub name: String,
    
    /// Action to take
    pub action: PolicyAction,
    
    /// Arguments to match
    pub arguments: Vec<ArgumentMatch>,
    
    /// Additional conditions
    pub conditions: HashMap<String, String>,
}

/// Argument matching for system calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgumentMatch {
    /// Argument index
    pub index: usize,
    
    /// Value to match
    pub value: String,
    
    /// Match type (exact, regex, range)
    pub match_type: String,
}

/// Resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory usage (MB)
    pub max_memory: Option<u64>,
    
    /// Maximum CPU time (seconds)
    pub max_cpu_time: Option<u64>,
    
    /// Maximum number of processes
    pub max_processes: Option<u64>,
    
    /// Maximum number of open files
    pub max_open_files: Option<u64>,
    
    /// Maximum file size (MB)
    pub max_file_size: Option<u64>,
    
    /// Maximum network bandwidth (KB/s)
    pub max_network_bandwidth: Option<u64>,
}

/// Environment rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentRules {
    /// Allowed environment variables
    pub allowed_env_vars: Vec<String>,
    
    /// Blocked environment variables
    pub blocked_env_vars: Vec<String>,
    
    /// Environment variable overrides
    pub env_overrides: HashMap<String, String>,
    
    /// Working directory restrictions
    pub allowed_working_dirs: Vec<String>,
    
    /// Shell restrictions
    pub allowed_shells: Vec<String>,
}

/// Monitoring rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringRules {
    /// Enable system call tracing
    pub trace_syscalls: bool,
    
    /// System calls to trace (empty = all)
    pub traced_syscalls: Vec<String>,
    
    /// Enable file system monitoring
    pub monitor_filesystem: bool,
    
    /// Directories to monitor
    pub monitored_directories: Vec<String>,
    
    /// Enable network monitoring
    pub monitor_network: bool,
    
    /// Enable packet capture
    pub capture_packets: bool,
    
    /// Log level for monitoring
    pub log_level: String,
}

/// Policy actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allow the operation
    Allow,
    
    /// Deny the operation
    Deny,
    
    /// Log the operation but allow it
    Log,
}

impl Default for PolicyRules {
    fn default() -> Self {
        Self {
            file_access: vec![
                FileAccessRule {
                    path: "/tmp/*".to_string(),
                    action: PolicyAction::Allow,
                    operations: vec!["read".to_string(), "write".to_string(), "create".to_string()],
                    conditions: HashMap::new(),
                },
                FileAccessRule {
                    path: "/etc/*".to_string(),
                    action: PolicyAction::Log,
                    operations: vec!["read".to_string()],
                    conditions: HashMap::new(),
                },
                FileAccessRule {
                    path: "/proc/*".to_string(),
                    action: PolicyAction::Log,
                    operations: vec!["read".to_string()],
                    conditions: HashMap::new(),
                },
            ],
            network_access: vec![
                NetworkAccessRule {
                    host: "*".to_string(),
                    port: 80,
                    protocol: "tcp".to_string(),
                    action: PolicyAction::Log,
                    conditions: HashMap::new(),
                },
                NetworkAccessRule {
                    host: "*".to_string(),
                    port: 443,
                    protocol: "tcp".to_string(),
                    action: PolicyAction::Log,
                    conditions: HashMap::new(),
                },
            ],
            system_calls: vec![
                SystemCallRule {
                    name: "execve".to_string(),
                    action: PolicyAction::Log,
                    arguments: vec![],
                    conditions: HashMap::new(),
                },
                SystemCallRule {
                    name: "connect".to_string(),
                    action: PolicyAction::Log,
                    arguments: vec![],
                    conditions: HashMap::new(),
                },
            ],
            resource_limits: ResourceLimits {
                max_memory: Some(1024), // 1GB
                max_cpu_time: Some(300), // 5 minutes
                max_processes: Some(100),
                max_open_files: Some(1024),
                max_file_size: Some(100), // 100MB
                max_network_bandwidth: Some(1024), // 1MB/s
            },
            environment: EnvironmentRules {
                allowed_env_vars: vec![
                    "PATH".to_string(),
                    "HOME".to_string(),
                    "USER".to_string(),
                    "SHELL".to_string(),
                    "LANG".to_string(),
                    "TERM".to_string(),
                ],
                blocked_env_vars: vec![
                    "LD_PRELOAD".to_string(),
                    "LD_LIBRARY_PATH".to_string(),
                ],
                env_overrides: HashMap::new(),
                allowed_working_dirs: vec![
                    "/tmp".to_string(),
                    "/home/user".to_string(),
                ],
                allowed_shells: vec![
                    "/bin/bash".to_string(),
                    "/bin/sh".to_string(),
                ],
            },
            monitoring: MonitoringRules {
                trace_syscalls: true,
                traced_syscalls: vec![],
                monitor_filesystem: true,
                monitored_directories: vec!["/tmp".to_string(), "/home".to_string()],
                monitor_network: true,
                capture_packets: false,
                log_level: "info".to_string(),
            },
        }
    }
}

impl PolicyRules {
    /// Create strict security policy rules
    pub fn strict() -> Self {
        Self {
            file_access: vec![
                FileAccessRule {
                    path: "/tmp/*".to_string(),
                    action: PolicyAction::Allow,
                    operations: vec!["read".to_string(), "write".to_string()],
                    conditions: HashMap::new(),
                },
                FileAccessRule {
                    path: "*".to_string(),
                    action: PolicyAction::Deny,
                    operations: vec!["write".to_string(), "execute".to_string()],
                    conditions: HashMap::new(),
                },
            ],
            network_access: vec![
                NetworkAccessRule {
                    host: "*".to_string(),
                    port: 0,
                    protocol: "all".to_string(),
                    action: PolicyAction::Deny,
                    conditions: HashMap::new(),
                },
            ],
            system_calls: vec![
                SystemCallRule {
                    name: "execve".to_string(),
                    action: PolicyAction::Deny,
                    arguments: vec![],
                    conditions: HashMap::new(),
                },
                SystemCallRule {
                    name: "socket".to_string(),
                    action: PolicyAction::Deny,
                    arguments: vec![],
                    conditions: HashMap::new(),
                },
            ],
            resource_limits: ResourceLimits {
                max_memory: Some(256), // 256MB
                max_cpu_time: Some(60), // 1 minute
                max_processes: Some(10),
                max_open_files: Some(256),
                max_file_size: Some(10), // 10MB
                max_network_bandwidth: Some(0), // No network
            },
            environment: EnvironmentRules {
                allowed_env_vars: vec!["PATH".to_string()],
                blocked_env_vars: vec![
                    "LD_PRELOAD".to_string(),
                    "LD_LIBRARY_PATH".to_string(),
                    "PYTHONPATH".to_string(),
                ],
                env_overrides: HashMap::new(),
                allowed_working_dirs: vec!["/tmp".to_string()],
                allowed_shells: vec![],
            },
            monitoring: MonitoringRules {
                trace_syscalls: true,
                traced_syscalls: vec![],
                monitor_filesystem: true,
                monitored_directories: vec!["/".to_string()],
                monitor_network: true,
                capture_packets: true,
                log_level: "debug".to_string(),
            },
        }
    }
    
    /// Create permissive policy rules for development
    pub fn permissive() -> Self {
        Self {
            file_access: vec![
                FileAccessRule {
                    path: "*".to_string(),
                    action: PolicyAction::Log,
                    operations: vec!["read".to_string(), "write".to_string(), "execute".to_string()],
                    conditions: HashMap::new(),
                },
            ],
            network_access: vec![
                NetworkAccessRule {
                    host: "*".to_string(),
                    port: 0,
                    protocol: "all".to_string(),
                    action: PolicyAction::Log,
                    conditions: HashMap::new(),
                },
            ],
            system_calls: vec![
                SystemCallRule {
                    name: "*".to_string(),
                    action: PolicyAction::Log,
                    arguments: vec![],
                    conditions: HashMap::new(),
                },
            ],
            resource_limits: ResourceLimits {
                max_memory: Some(4096), // 4GB
                max_cpu_time: Some(3600), // 1 hour
                max_processes: Some(1000),
                max_open_files: Some(4096),
                max_file_size: Some(1024), // 1GB
                max_network_bandwidth: Some(10240), // 10MB/s
            },
            environment: EnvironmentRules {
                allowed_env_vars: vec!["*".to_string()],
                blocked_env_vars: vec![],
                env_overrides: HashMap::new(),
                allowed_working_dirs: vec!["*".to_string()],
                allowed_shells: vec!["*".to_string()],
            },
            monitoring: MonitoringRules {
                trace_syscalls: true,
                traced_syscalls: vec![],
                monitor_filesystem: true,
                monitored_directories: vec!["/tmp".to_string(), "/home".to_string()],
                monitor_network: true,
                capture_packets: false,
                log_level: "info".to_string(),
            },
        }
    }
    
    /// Create malware analysis policy rules
    pub fn malware_analysis() -> Self {
        Self {
            file_access: vec![
                FileAccessRule {
                    path: "*".to_string(),
                    action: PolicyAction::Log,
                    operations: vec!["read".to_string(), "write".to_string(), "execute".to_string(), "delete".to_string()],
                    conditions: HashMap::new(),
                },
            ],
            network_access: vec![
                NetworkAccessRule {
                    host: "*".to_string(),
                    port: 0,
                    protocol: "all".to_string(),
                    action: PolicyAction::Log,
                    conditions: HashMap::new(),
                },
            ],
            system_calls: vec![
                SystemCallRule {
                    name: "*".to_string(),
                    action: PolicyAction::Log,
                    arguments: vec![],
                    conditions: HashMap::new(),
                },
            ],
            resource_limits: ResourceLimits {
                max_memory: Some(2048), // 2GB
                max_cpu_time: Some(1800), // 30 minutes
                max_processes: Some(500),
                max_open_files: Some(2048),
                max_file_size: Some(512), // 512MB
                max_network_bandwidth: Some(5120), // 5MB/s
            },
            environment: EnvironmentRules {
                allowed_env_vars: vec!["*".to_string()],
                blocked_env_vars: vec![],
                env_overrides: HashMap::new(),
                allowed_working_dirs: vec!["*".to_string()],
                allowed_shells: vec!["*".to_string()],
            },
            monitoring: MonitoringRules {
                trace_syscalls: true,
                traced_syscalls: vec![], // Trace all
                monitor_filesystem: true,
                monitored_directories: vec!["/".to_string()], // Monitor everything
                monitor_network: true,
                capture_packets: true,
                log_level: "trace".to_string(),
            },
        }
    }
}