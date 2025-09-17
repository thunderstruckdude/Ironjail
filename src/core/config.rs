use crate::{Result, IronJailError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Main configuration for the IronJail sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// General sandbox settings
    pub general: GeneralConfig,
    
    /// Security settings
    pub security: SecurityConfig,
    
    /// Monitoring settings
    pub monitoring: MonitoringConfig,
    
    /// Deception settings
    pub deception: DeceptionConfig,
    
    /// Resource limits
    pub limits: ResourceLimits,
    
    /// Network configuration
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Default timeout for sandbox execution (seconds)
    pub default_timeout: u64,
    
    /// Working directory inside sandbox
    pub sandbox_root: PathBuf,
    
    /// Temporary directory for sandbox files
    pub temp_dir: PathBuf,
    
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
    
    /// Enable detailed logging
    pub verbose_logging: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable user namespace isolation
    pub enable_user_namespace: bool,
    
    /// Enable network namespace isolation
    pub enable_network_namespace: bool,
    
    /// Enable PID namespace isolation
    pub enable_pid_namespace: bool,
    
    /// Enable mount namespace isolation
    pub enable_mount_namespace: bool,
    
    /// Enable IPC namespace isolation
    pub enable_ipc_namespace: bool,
    
    /// Enable UTS namespace isolation
    pub enable_uts_namespace: bool,
    
    /// Enable seccomp filtering
    pub enable_seccomp: bool,
    
    /// Drop capabilities
    pub drop_capabilities: Vec<String>,
    
    /// Keep capabilities
    pub keep_capabilities: Vec<String>,
    
    /// Enable no-new-privileges
    pub no_new_privileges: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable system call tracing
    pub enable_syscall_tracing: bool,
    
    /// Enable file system monitoring
    pub enable_fs_monitoring: bool,
    
    /// Enable network monitoring
    pub enable_network_monitoring: bool,
    
    /// Enable process monitoring
    pub enable_process_monitoring: bool,
    
    /// System calls to trace (empty = all)
    pub traced_syscalls: Vec<String>,
    
    /// Directories to monitor
    pub monitored_directories: Vec<PathBuf>,
    
    /// Network interfaces to monitor
    pub monitored_interfaces: Vec<String>,
    
    /// Enable packet capture
    pub enable_packet_capture: bool,
    
    /// Maximum log file size (MB)
    pub max_log_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionConfig {
    /// Enable environment deception
    pub enable_deception: bool,
    
    /// Fake /proc values
    pub fake_proc: HashMap<String, String>,
    
    /// Fake /sys values
    pub fake_sys: HashMap<String, String>,
    
    /// Fake environment variables
    pub fake_env: HashMap<String, String>,
    
    /// Fake hostname
    pub fake_hostname: Option<String>,
    
    /// Fake system information
    pub fake_system_info: FakeSystemInfo,
    
    /// Decoy files to create
    pub decoy_files: Vec<DecoyFile>,
    
    /// Network redirection rules
    pub network_redirects: Vec<NetworkRedirect>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeSystemInfo {
    /// Fake CPU information
    pub cpu_info: Option<String>,
    
    /// Fake memory information
    pub memory_info: Option<String>,
    
    /// Fake kernel version
    pub kernel_version: Option<String>,
    
    /// Fake distribution information
    pub distro_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyFile {
    /// Path where the decoy file should be created
    pub path: PathBuf,
    
    /// Content of the decoy file
    pub content: String,
    
    /// File permissions (octal)
    pub permissions: Option<u32>,
    
    /// Whether to monitor access to this file
    pub monitor_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRedirect {
    /// Original destination (IP or hostname)
    pub original: String,
    
    /// Redirect destination
    pub redirect_to: String,
    
    /// Port to redirect (0 = all ports)
    pub port: u16,
    
    /// Protocol (tcp, udp, all)
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory usage (MB)
    pub max_memory: Option<u64>,
    
    /// Maximum CPU time (seconds)
    pub max_cpu_time: Option<u64>,
    
    /// Maximum number of processes
    pub max_processes: Option<u64>,
    
    /// Maximum number of file descriptors
    pub max_file_descriptors: Option<u64>,
    
    /// Maximum file size (MB)
    pub max_file_size: Option<u64>,
    
    /// Maximum disk usage (MB)
    pub max_disk_usage: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable network isolation
    pub isolate_network: bool,
    
    /// Allow loopback interface
    pub allow_loopback: bool,
    
    /// Allowed outbound ports
    pub allowed_ports: Vec<u16>,
    
    /// Blocked domains
    pub blocked_domains: Vec<String>,
    
    /// DNS servers to use in sandbox
    pub dns_servers: Vec<String>,
    
    /// Enable fake network responses
    pub enable_fake_responses: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                default_timeout: 300,
                sandbox_root: PathBuf::from("/tmp/ironjail"),
                temp_dir: PathBuf::from("/tmp/ironjail/tmp"),
                log_level: "info".to_string(),
                verbose_logging: false,
            },
            security: SecurityConfig {
                enable_user_namespace: true,
                enable_network_namespace: true,
                enable_pid_namespace: true,
                enable_mount_namespace: true,
                enable_ipc_namespace: true,
                enable_uts_namespace: true,
                enable_seccomp: true,
                drop_capabilities: vec![
                    "CAP_SYS_ADMIN".to_string(),
                    "CAP_SYS_PTRACE".to_string(),
                    "CAP_SYS_MODULE".to_string(),
                    "CAP_SYS_RAWIO".to_string(),
                ],
                keep_capabilities: vec![],
                no_new_privileges: true,
            },
            monitoring: MonitoringConfig {
                enable_syscall_tracing: true,
                enable_fs_monitoring: true,
                enable_network_monitoring: true,
                enable_process_monitoring: true,
                traced_syscalls: vec![],
                monitored_directories: vec![
                    PathBuf::from("/tmp"),
                    PathBuf::from("/home"),
                ],
                monitored_interfaces: vec!["all".to_string()],
                enable_packet_capture: false,
                max_log_size: 100,
            },
            deception: DeceptionConfig {
                enable_deception: false,
                fake_proc: HashMap::new(),
                fake_sys: HashMap::new(),
                fake_env: HashMap::new(),
                fake_hostname: None,
                fake_system_info: FakeSystemInfo {
                    cpu_info: None,
                    memory_info: None,
                    kernel_version: None,
                    distro_info: None,
                },
                decoy_files: vec![],
                network_redirects: vec![],
            },
            limits: ResourceLimits {
                max_memory: Some(1024), // 1GB
                max_cpu_time: Some(300), // 5 minutes
                max_processes: Some(100),
                max_file_descriptors: Some(1024),
                max_file_size: Some(100), // 100MB
                max_disk_usage: Some(1024), // 1GB
            },
            network: NetworkConfig {
                isolate_network: true,
                allow_loopback: true,
                allowed_ports: vec![],
                blocked_domains: vec![],
                dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
                enable_fake_responses: false,
            },
        }
    }
}

impl SandboxConfig {
    /// Load configuration from a file
    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            tracing::warn!("Configuration file not found: {:?}, using defaults", path);
            return Ok(Self::default());
        }
        
        let content = std::fs::read_to_string(path)
            .map_err(|e| IronJailError::PolicyConfiguration(
                format!("Failed to read config file: {}", e)
            ))?;
        
        let config: SandboxConfig = if path.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::from_str(&content)?
        } else {
            // Default to YAML
            serde_yaml::from_str(&content)?
        };
        
        Ok(config)
    }
    
    /// Save configuration to a file
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = if path.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::to_string_pretty(self)?
        } else {
            // Default to YAML
            serde_yaml::to_string(self)?
        };
        
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        std::fs::write(path, content)
            .map_err(|e| IronJailError::PolicyConfiguration(
                format!("Failed to write config file: {}", e)
            ))?;
        
        Ok(())
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate timeout
        if self.general.default_timeout == 0 {
            return Err(IronJailError::PolicyConfiguration(
                "Default timeout must be greater than 0".to_string()
            ).into());
        }
        
        // Validate paths
        if !self.general.sandbox_root.is_absolute() {
            return Err(IronJailError::PolicyConfiguration(
                "Sandbox root must be an absolute path".to_string()
            ).into());
        }
        
        // Validate resource limits
        if let Some(max_memory) = self.limits.max_memory {
            if max_memory == 0 {
                return Err(IronJailError::PolicyConfiguration(
                    "Maximum memory must be greater than 0".to_string()
                ).into());
            }
        }
        
        // Validate capabilities
        for cap in &self.security.drop_capabilities {
            if !cap.starts_with("CAP_") {
                return Err(IronJailError::PolicyConfiguration(
                    format!("Invalid capability format: {}", cap)
                ).into());
            }
        }
        
        Ok(())
    }
    
    /// Generate a sample configuration file
    pub fn generate_sample(path: &PathBuf) -> Result<()> {
        let config = Self::default();
        config.save(path)?;
        Ok(())
    }
}