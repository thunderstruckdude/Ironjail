use crate::{Result, IronJailError};
use crate::core::{SandboxConfig, ProcessManager, NamespaceManager};
use crate::policy::PolicyManager;
use crate::tracing::SystemCallTracer;
use crate::monitoring::{FileSystemMonitor, NetworkMonitor};
use crate::deception::EnvironmentDeception;
use crate::reporting::AnalysisResult;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error, debug};
use uuid::Uuid;

/// Main sandbox engine that orchestrates all components
pub struct SandboxEngine {
    config: SandboxConfig,
    process_manager: ProcessManager,
    namespace_manager: NamespaceManager,
    syscall_tracer: Option<SystemCallTracer>,
    fs_monitor: Option<FileSystemMonitor>,
    network_monitor: Option<NetworkMonitor>,
    env_deception: Option<EnvironmentDeception>,
    
    // Runtime configuration
    capture_network: bool,
    enable_deception: bool,
    timeout: u64,
    working_directory: Option<PathBuf>,
}

impl SandboxEngine {
    /// Create a new sandbox engine with the given configuration
    pub fn new(config: SandboxConfig) -> Result<Self> {
        info!("Initializing IronJail sandbox engine");
        
        // Validate configuration
        config.validate()?;
        
        // Initialize components
        let process_manager = ProcessManager::new(&config)?;
        let namespace_manager = NamespaceManager::new(&config)?;
        
        // Initialize optional components based on configuration
        let syscall_tracer = if config.monitoring.enable_syscall_tracing {
            Some(SystemCallTracer::new(&config)?)
        } else {
            None
        };
        
        let fs_monitor = if config.monitoring.enable_fs_monitoring {
            Some(FileSystemMonitor::new(&config)?)
        } else {
            None
        };
        
        let network_monitor = if config.monitoring.enable_network_monitoring {
            Some(NetworkMonitor::new(&config)?)
        } else {
            None
        };
        
        let env_deception = if config.deception.enable_deception {
            Some(EnvironmentDeception::new(&config)?)
        } else {
            None
        };
        
        Ok(Self {
            config: config.clone(),
            process_manager,
            namespace_manager,
            syscall_tracer,
            fs_monitor,
            network_monitor,
            env_deception,
            capture_network: config.monitoring.enable_packet_capture,
            enable_deception: config.deception.enable_deception,
            timeout: config.general.default_timeout,
            working_directory: None,
        })
    }
    
    /// Set whether to capture network traffic
    pub fn set_capture_network(&mut self, capture: bool) {
        self.capture_network = capture;
    }
    
    /// Set whether to enable environment deception
    pub fn set_enable_deception(&mut self, enable: bool) {
        self.enable_deception = enable;
        
        // Initialize deception if not already done and requested
        if enable && self.env_deception.is_none() {
            match EnvironmentDeception::new(&self.config) {
                Ok(deception) => self.env_deception = Some(deception),
                Err(e) => warn!("Failed to initialize environment deception: {}", e),
            }
        }
    }
    
    /// Set execution timeout
    pub fn set_timeout(&mut self, timeout: u64) {
        self.timeout = timeout;
    }
    
    /// Set working directory for the sandboxed process
    pub fn set_working_directory(&mut self, workdir: PathBuf) {
        self.working_directory = Some(workdir);
    }
    
    /// Execute a binary with full monitoring and analysis
    pub async fn execute_with_monitoring(
        &mut self,
        binary: &PathBuf,
        args: &[String],
        policy: &PolicyManager,
        session_id: &str,
    ) -> Result<AnalysisResult> {
        info!("Starting analysis session: {}", session_id);
        info!("Executing binary: {:?} with args: {:?}", binary, args);
        
        // Validate binary exists and is executable
        if !binary.exists() {
            return Err(IronJailError::ResourceNotFound(
                format!("Binary not found: {:?}", binary)
            ).into());
        }
        
        // Create analysis result structure
        let mut analysis_result = AnalysisResult::new(session_id, binary, args);
        analysis_result.start_timestamp = chrono::Utc::now();
        
        // Setup sandbox environment
        self.setup_sandbox_environment(session_id).await?;
        
        // Start monitoring services
        let monitoring_handles = self.start_monitoring_services(session_id).await?;
        
        // Setup environment deception if enabled
        if self.enable_deception {
            if let Some(ref mut deception) = self.env_deception {
                deception.setup_deception_environment(session_id).await?;
                analysis_result.deception_enabled = true;
            }
        }
        
        // Execute the binary in the sandbox
        let execution_result = self.execute_in_sandbox(
            binary,
            args,
            policy,
            session_id,
        ).await;
        
        // Stop monitoring and collect results
        let monitoring_data = self.stop_monitoring_and_collect(monitoring_handles).await?;
        
        // Update analysis result
        analysis_result.end_timestamp = chrono::Utc::now();
        analysis_result.duration = (analysis_result.end_timestamp - analysis_result.start_timestamp)
            .num_seconds() as u64;
        
        match execution_result {
            Ok(exit_status) => {
                analysis_result.exit_code = Some(exit_status);
                analysis_result.status = "completed".to_string();
                info!("Binary execution completed with exit code: {}", exit_status);
            }
            Err(e) => {
                analysis_result.error = Some(e.to_string());
                analysis_result.status = "failed".to_string();
                error!("Binary execution failed: {}", e);
            }
        }
        
        // Attach monitoring data
        analysis_result.syscalls = monitoring_data.syscalls;
        analysis_result.file_activities = monitoring_data.file_activities;
        analysis_result.network_activities = monitoring_data.network_activities;
        analysis_result.process_activities = monitoring_data.process_activities;
        
        // Cleanup sandbox environment
        self.cleanup_sandbox_environment(session_id).await?;
        
        info!("Analysis session completed: {}", session_id);
        Ok(analysis_result)
    }
    
    /// Setup the sandbox environment
    async fn setup_sandbox_environment(&mut self, session_id: &str) -> Result<()> {
        debug!("Setting up sandbox environment for session: {}", session_id);
        
        // Create sandbox root directory
        let sandbox_root = self.config.general.sandbox_root.join(session_id);
        std::fs::create_dir_all(&sandbox_root)?;
        
        // Setup namespaces
        self.namespace_manager.setup_namespaces().await?;
        
        // Setup resource limits
        self.process_manager.setup_resource_limits(&self.config.limits).await?;
        
        // Setup security restrictions
        self.process_manager.setup_security_restrictions(&self.config.security).await?;
        
        debug!("Sandbox environment setup completed");
        Ok(())
    }
    
    /// Start all monitoring services
    async fn start_monitoring_services(&mut self, session_id: &str) -> Result<MonitoringHandles> {
        debug!("Starting monitoring services for session: {}", session_id);
        
        let mut handles = MonitoringHandles::default();
        
        // Start system call tracing
        if let Some(ref mut tracer) = self.syscall_tracer {
            handles.syscall_handle = Some(tracer.start_tracing(session_id).await?);
        }
        
        // Start file system monitoring
        if let Some(ref mut monitor) = self.fs_monitor {
            handles.fs_handle = Some(monitor.start_monitoring(session_id).await?);
        }
        
        // Start network monitoring
        if let Some(ref mut monitor) = self.network_monitor {
            handles.network_handle = Some(monitor.start_monitoring(session_id, self.capture_network).await?);
        }
        
        debug!("All monitoring services started");
        Ok(handles)
    }
    
    /// Execute the binary in the isolated sandbox
    async fn execute_in_sandbox(
        &mut self,
        binary: &PathBuf,
        args: &[String],
        policy: &PolicyManager,
        session_id: &str,
    ) -> Result<i32> {
        debug!("Executing binary in sandbox: {:?}", binary);
        
        // Apply policy restrictions
        policy.apply_restrictions(&mut self.process_manager, &mut self.namespace_manager).await?;
        
        // Set working directory if specified
        let workdir = self.working_directory.clone()
            .unwrap_or_else(|| self.config.general.sandbox_root.join(session_id));
        
        // Execute the process with timeout
        let execution_result = tokio::time::timeout(
            std::time::Duration::from_secs(self.timeout),
            self.process_manager.execute_process(binary, args, &workdir)
        ).await;
        
        match execution_result {
            Ok(result) => result,
            Err(_) => {
                warn!("Process execution timed out after {} seconds", self.timeout);
                // Kill the process and return timeout error
                self.process_manager.kill_all_processes().await?;
                Err(IronJailError::ProcessExecution("Process timed out".to_string()).into())
            }
        }
    }
    
    /// Stop monitoring services and collect data
    async fn stop_monitoring_and_collect(&mut self, handles: MonitoringHandles) -> Result<MonitoringData> {
        debug!("Stopping monitoring services and collecting data");
        
        let mut data = MonitoringData::default();
        
        // Stop system call tracing and collect data
        if let Some(handle) = handles.syscall_handle {
            if let Some(ref mut tracer) = self.syscall_tracer {
                data.syscalls = tracer.stop_and_collect(handle).await?;
            }
        }
        
        // Stop file system monitoring and collect data
        if let Some(handle) = handles.fs_handle {
            if let Some(ref mut monitor) = self.fs_monitor {
                data.file_activities = monitor.stop_and_collect(handle).await?;
            }
        }
        
        // Stop network monitoring and collect data
        if let Some(handle) = handles.network_handle {
            if let Some(ref mut monitor) = self.network_monitor {
                data.network_activities = monitor.stop_and_collect(handle).await?;
            }
        }
        
        debug!("Monitoring data collection completed");
        Ok(data)
    }
    
    /// Cleanup sandbox environment
    async fn cleanup_sandbox_environment(&self, session_id: &str) -> Result<()> {
        debug!("Cleaning up sandbox environment for session: {}", session_id);
        
        // Kill any remaining processes
        let _ = self.process_manager.kill_all_processes().await;
        
        // Cleanup namespaces
        let _ = self.namespace_manager.cleanup_namespaces().await;
        
        // Remove temporary files (optionally, based on configuration)
        if !self.config.general.verbose_logging {
            let sandbox_root = self.config.general.sandbox_root.join(session_id);
            if sandbox_root.exists() {
                let _ = std::fs::remove_dir_all(&sandbox_root);
            }
        }
        
        debug!("Sandbox cleanup completed");
        Ok(())
    }
}

/// Handles for monitoring services
#[derive(Default)]
struct MonitoringHandles {
    syscall_handle: Option<tokio::task::JoinHandle<()>>,
    fs_handle: Option<tokio::task::JoinHandle<()>>,
    network_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Collected monitoring data
#[derive(Default)]
pub struct MonitoringData {
    pub syscalls: Vec<crate::tracing::SystemCall>,
    pub file_activities: Vec<crate::monitoring::FileActivity>,
    pub network_activities: Vec<crate::monitoring::NetworkActivity>,
    pub process_activities: Vec<crate::monitoring::ProcessActivity>,
}