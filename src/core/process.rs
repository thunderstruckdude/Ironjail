use crate::{Result, IronJailError};  
use crate::core::{SandboxConfig, ResourceLimits, SecurityConfig};
use nix::sys::{signal, wait};
use nix::unistd::{Pid, ForkResult, fork, execv, setpgid, setsid};
use nix::libc;
use std::collections::HashMap;
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::{debug, info, error, warn};

/// Manages process execution and lifecycle within the sandbox
pub struct ProcessManager {
    config: SandboxConfig,
    active_processes: Arc<RwLock<HashMap<Pid, ProcessInfo>>>,
    resource_limits: Arc<Mutex<Option<ResourceLimits>>>,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: Pid,
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub status: ProcessStatus,
}

#[derive(Debug, Clone)]
pub enum ProcessStatus {
    Running,
    Stopped,
    Killed,
    Exited(i32),
}

impl ProcessManager {
    pub fn new(config: &SandboxConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            active_processes: Arc::new(RwLock::new(HashMap::new())),
            resource_limits: Arc::new(Mutex::new(None)),
        })
    }
    
    /// Setup resource limits for processes
    pub async fn setup_resource_limits(&self, limits: &ResourceLimits) -> Result<()> {
        debug!("Setting up resource limits");
        
        // Set memory limits
        if let Some(max_memory) = limits.max_memory {
            let memory_bytes = max_memory * 1024 * 1024; // Convert MB to bytes
            let rlimit = libc::rlimit {
                rlim_cur: memory_bytes,
                rlim_max: memory_bytes,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_AS, &rlimit) };
            if ret != 0 {
                return Err(IronJailError::ProcessExecution("Failed to set memory limit".to_string()).into());
            }
        }
        
        // Set CPU time limits
        if let Some(max_cpu_time) = limits.max_cpu_time {
            let rlimit = libc::rlimit {
                rlim_cur: max_cpu_time,
                rlim_max: max_cpu_time,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_CPU, &rlimit) };
            if ret != 0 {
                return Err(IronJailError::ProcessExecution("Failed to set CPU time limit".to_string()).into());
            }
        }
        
        // Set process limits  
        if let Some(max_processes) = limits.max_processes {
            let rlimit = libc::rlimit {
                rlim_cur: max_processes,
                rlim_max: max_processes,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlimit) };
            if ret != 0 {
                return Err(IronJailError::ProcessExecution("Failed to set process limit".to_string()).into());
            }
        }
        
        // Set file descriptor limits
        if let Some(max_fds) = limits.max_file_descriptors {
            let rlimit = libc::rlimit {
                rlim_cur: max_fds,
                rlim_max: max_fds,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) };
            if ret != 0 {
                return Err(IronJailError::ProcessExecution("Failed to set file descriptor limit".to_string()).into());
            }
        }
        
        // Set file size limits
        if let Some(max_file_size) = limits.max_file_size {
            let file_size_bytes = max_file_size * 1024 * 1024; // Convert MB to bytes
            let rlimit = libc::rlimit {
                rlim_cur: file_size_bytes,
                rlim_max: file_size_bytes,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &rlimit) };
            if ret != 0 {
                return Err(IronJailError::ProcessExecution("Failed to set file size limit".to_string()).into());
            }
        }
        
        *self.resource_limits.lock().unwrap() = Some(limits.clone());
        debug!("Resource limits configured successfully");
        Ok(())
    }
    
    /// Setup security restrictions
    pub async fn setup_security_restrictions(&self, security: &SecurityConfig) -> Result<()> {
        debug!("Setting up security restrictions");
        
        // Drop capabilities
        for cap_name in &security.drop_capabilities {
            self.drop_capability(cap_name)?;
        }
        
        // Set no-new-privileges if enabled
        if security.no_new_privileges {
            self.set_no_new_privileges()?;
        }
        
        debug!("Security restrictions configured successfully");
        Ok(())
    }
    
    /// Execute a process in the sandbox
    pub async fn execute_process(
        &self,
        binary: &PathBuf,
        args: &[String],
        workdir: &PathBuf,
    ) -> Result<i32> {
        debug!("Executing process: {:?} with args: {:?}", binary, args);
        
        // Convert to absolute path to avoid issues with working directory changes
        let absolute_binary = if binary.is_absolute() {
            binary.clone()
        } else {
            std::env::current_dir()
                .map_err(|e| IronJailError::ProcessExecution(
                    format!("Failed to get current directory: {}", e)
                ))?
                .join(binary)
        };
        
        debug!("Using absolute binary path: {:?}", absolute_binary);
        
        // Verify the binary exists and is executable
        if !absolute_binary.exists() {
            return Err(IronJailError::ProcessExecution(
                format!("Binary not found: {:?}", absolute_binary)
            ).into());
        }
        
        // Prepare arguments for execv
        let binary_cstring = CString::new(absolute_binary.to_string_lossy().as_bytes())
            .map_err(|e| IronJailError::ProcessExecution(
                format!("Invalid binary path: {}", e)
            ))?;
        
        let mut arg_cstrings = vec![binary_cstring.clone()];
        for arg in args {
            arg_cstrings.push(CString::new(arg.as_bytes())
                .map_err(|e| IronJailError::ProcessExecution(
                    format!("Invalid argument: {}", e)
                ))?);
        }
        
        // Fork the process
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Parent process - monitor the child
                debug!("Forked child process with PID: {}", child);
                
                // Store process information
                let process_info = ProcessInfo {
                    pid: child,
                    binary: binary.clone(),
                    args: args.to_vec(),
                    start_time: chrono::Utc::now(),
                    status: ProcessStatus::Running,
                };
                
                self.active_processes.write().await.insert(child, process_info);
                
                // Wait for child process to complete
                self.wait_for_process(child).await
            }
            
            Ok(ForkResult::Child) => {
                // Child process - execute the binary
                self.setup_child_process(workdir).await?;
                
                // Execute the binary
                match execv(&binary_cstring, &arg_cstrings) {
                    Ok(_) => unreachable!("execv should not return on success"),
                    Err(e) => {
                        error!("Failed to execute binary: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            
            Err(e) => {
                error!("Failed to fork process: {}", e);
                Err(IronJailError::ProcessExecution(
                    format!("Fork failed: {}", e)
                ).into())
            }
        }
    }
    
    /// Setup child process environment
    async fn setup_child_process(&self, workdir: &PathBuf) -> Result<()> {
        // Change working directory
        std::env::set_current_dir(workdir)
            .map_err(|e| IronJailError::ProcessExecution(
                format!("Failed to change working directory: {}", e)
            ))?;
        
        // Create new session
        setsid().map_err(|e| IronJailError::ProcessExecution(
            format!("Failed to create new session: {}", e)
        ))?;
        
        // Set process group (non-fatal if it fails)
        if let Err(e) = setpgid(Pid::this(), Pid::from_raw(0)) {
            warn!("Failed to set process group (continuing anyway): {}", e);
        }
        
        Ok(())
    }
    
    /// Wait for a process to complete and return its exit code
    async fn wait_for_process(&self, pid: Pid) -> Result<i32> {
        debug!("Waiting for process {} to complete", pid);
        
        loop {
            match wait::waitpid(pid, Some(wait::WaitPidFlag::WNOHANG)) {
                Ok(wait::WaitStatus::Exited(_, exit_code)) => {
                    debug!("Process {} exited with code: {}", pid, exit_code);
                    
                    // Update process status
                    let mut processes = self.active_processes.write().await;
                    if let Some(process_info) = processes.get_mut(&pid) {
                        process_info.status = ProcessStatus::Exited(exit_code);
                    }
                    
                    return Ok(exit_code);
                }
                
                Ok(wait::WaitStatus::Signaled(_, signal, _)) => {
                    warn!("Process {} was killed by signal: {:?}", pid, signal);
                    
                    // Update process status
                    let mut processes = self.active_processes.write().await;
                    if let Some(process_info) = processes.get_mut(&pid) {
                        process_info.status = ProcessStatus::Killed;
                    }
                    
                    return Ok(-1);
                }
                
                Ok(wait::WaitStatus::StillAlive) => {
                    // Process is still running, wait a bit
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                
                Ok(status) => {
                    debug!("Process {} status: {:?}", pid, status);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                
                Err(e) => {
                    error!("Error waiting for process {}: {}", pid, e);
                    return Err(IronJailError::ProcessExecution(
                        format!("Wait failed: {}", e)
                    ).into());
                }
            }
        }
    }
    
    /// Kill all active processes
    pub async fn kill_all_processes(&self) -> Result<()> {
        debug!("Killing all active processes");
        
        let processes = self.active_processes.read().await;
        for (pid, process_info) in processes.iter() {
            if matches!(process_info.status, ProcessStatus::Running) {
                debug!("Killing process: {}", pid);
                
                // Send SIGTERM first
                if let Err(e) = signal::kill(*pid, signal::Signal::SIGTERM) {
                    warn!("Failed to send SIGTERM to process {}: {}", pid, e);
                }
                
                // Wait a bit for graceful shutdown
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                
                // Send SIGKILL if still running
                if let Err(e) = signal::kill(*pid, signal::Signal::SIGKILL) {
                    warn!("Failed to send SIGKILL to process {}: {}", pid, e);
                }
            }
        }
        
        // Clear the process list
        drop(processes);
        self.active_processes.write().await.clear();
        
        debug!("All processes killed");
        Ok(())
    }
    
    /// Get information about active processes
    pub async fn get_active_processes(&self) -> HashMap<Pid, ProcessInfo> {
        self.active_processes.read().await.clone()
    }
    
    /// Drop a specific capability
    fn drop_capability(&self, cap_name: &str) -> Result<()> {
        debug!("Dropping capability: {}", cap_name);
        
        // Convert capability name to capability value
        let cap_value = match cap_name {
            "CAP_SYS_ADMIN" => caps::Capability::CAP_SYS_ADMIN,
            "CAP_SYS_PTRACE" => caps::Capability::CAP_SYS_PTRACE,
            "CAP_SYS_MODULE" => caps::Capability::CAP_SYS_MODULE,
            "CAP_SYS_RAWIO" => caps::Capability::CAP_SYS_RAWIO,
            "CAP_NET_ADMIN" => caps::Capability::CAP_NET_ADMIN,
            "CAP_NET_RAW" => caps::Capability::CAP_NET_RAW,
            "CAP_DAC_OVERRIDE" => caps::Capability::CAP_DAC_OVERRIDE,
            "CAP_SETUID" => caps::Capability::CAP_SETUID,
            "CAP_SETGID" => caps::Capability::CAP_SETGID,
            _ => {
                warn!("Unknown capability: {}", cap_name);
                return Ok(());
            }
        };
        
        // Drop the capability
        caps::drop(None, caps::CapSet::Effective, cap_value)
            .map_err(|e| IronJailError::ProcessExecution(
                format!("Failed to drop capability {}: {}", cap_name, e)
            ))?;
        
        caps::drop(None, caps::CapSet::Permitted, cap_value)
            .map_err(|e| IronJailError::ProcessExecution(
                format!("Failed to drop capability {}: {}", cap_name, e)
            ))?;
        
        caps::drop(None, caps::CapSet::Inheritable, cap_value)
            .map_err(|e| IronJailError::ProcessExecution(
                format!("Failed to drop capability {}: {}", cap_name, e)
            ))?;
        
        debug!("Successfully dropped capability: {}", cap_name);
        Ok(())
    }
    
    /// Set no-new-privileges flag
    fn set_no_new_privileges(&self) -> Result<()> {
        debug!("Setting no-new-privileges flag");
        
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(IronJailError::ProcessExecution(
                    "Failed to set no-new-privileges".to_string()
                ).into());
            }
        }
        
        debug!("No-new-privileges flag set successfully");
        Ok(())
    }
}