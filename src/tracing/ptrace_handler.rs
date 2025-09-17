use crate::{Result, IronJailError};
use nix::sys::ptrace;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, warn, error};

/// Handles ptrace operations for system call tracing
#[derive(Clone)]
pub struct PtraceHandler {
    traced_processes: Arc<Mutex<HashMap<Pid, ProcessState>>>,
    is_running: Arc<Mutex<bool>>,
}

/// State of a traced process
#[derive(Debug, Clone)]
pub struct ProcessState {
    pub pid: Pid,
    pub in_syscall: bool,
    pub syscall_entry: Option<SyscallInfo>,
    pub parent: Option<Pid>,
}

/// Information about a system call
#[derive(Debug, Clone)]
pub struct SyscallInfo {
    pub syscall_number: i64,
    pub arguments: Vec<u64>,
    pub return_value: Option<i64>,
    pub entry_time: std::time::Instant,
    pub duration_us: Option<u64>,
}

impl PtraceHandler {
    /// Create a new ptrace handler
    pub fn new() -> Result<Self> {
        Ok(Self {
            traced_processes: Arc::new(Mutex::new(HashMap::new())),
            is_running: Arc::new(Mutex::new(false)),
        })
    }
    
    /// Start the ptrace handler
    pub async fn start(&mut self) -> Result<()> {
        debug!("Starting ptrace handler");
        *self.is_running.lock().await = true;
        Ok(())
    }
    
    /// Stop the ptrace handler
    pub async fn stop(&mut self) -> Result<()> {
        debug!("Stopping ptrace handler");
        *self.is_running.lock().await = false;
        
        // Detach from all traced processes
        let processes = self.traced_processes.lock().await.clone();
        for (pid, _) in processes {
            if let Err(e) = ptrace::detach(pid, None) {
                warn!("Failed to detach from process {}: {}", pid, e);
            }
        }
        
        self.traced_processes.lock().await.clear();
        Ok(())
    }
    
    /// Attach to a process for tracing
    pub async fn attach_process(&mut self, pid: Pid) -> Result<()> {
        debug!("Attaching to process: {}", pid);
        
        // Attach using ptrace
        ptrace::attach(pid)
            .map_err(|e| IronJailError::SystemCallTracing(
                format!("Failed to attach to process {}: {}", pid, e)
            ))?;
        
        // Wait for the process to stop
        match wait::waitpid(pid, None) {
            Ok(WaitStatus::Stopped(stopped_pid, _)) => {
                debug!("Process {} stopped after attach", stopped_pid);
            }
            Ok(status) => {
                warn!("Unexpected status after attach: {:?}", status);
            }
            Err(e) => {
                return Err(IronJailError::SystemCallTracing(
                    format!("Failed to wait for process {}: {}", pid, e)
                ).into());
            }
        }
        
        // Set ptrace options for syscall tracing
        let options = ptrace::Options::PTRACE_O_TRACESYSGOOD 
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEEXEC;
        
        ptrace::setoptions(pid, options)
            .map_err(|e| IronJailError::SystemCallTracing(
                format!("Failed to set ptrace options for {}: {}", pid, e)
            ))?;
        
        // Add to traced processes
        let process_state = ProcessState {
            pid,
            in_syscall: false,
            syscall_entry: None,
            parent: None,
        };
        
        self.traced_processes.lock().await.insert(pid, process_state);
        
        // Continue the process
        ptrace::syscall(pid, None)
            .map_err(|e| IronJailError::SystemCallTracing(
                format!("Failed to continue process {}: {}", pid, e)
            ))?;
        
        debug!("Successfully attached to process: {}", pid);
        Ok(())
    }
    
    /// Wait for the next system call from any traced process
    pub async fn wait_for_syscall(&mut self) -> Result<Option<(Pid, SyscallInfo)>> {
        if !*self.is_running.lock().await {
            return Ok(None);
        }
        
        // Wait for any child process
        match wait::wait() {
            Ok(WaitStatus::PtraceSyscall(pid)) => {
                self.handle_syscall_stop(pid).await
            }
            
            Ok(WaitStatus::Stopped(pid, signal)) => {
                debug!("Process {} stopped with signal: {:?}", pid, signal);
                
                // Continue the process
                ptrace::syscall(pid, Some(signal))
                    .map_err(|e| IronJailError::SystemCallTracing(
                        format!("Failed to continue process {}: {}", pid, e)
                    ))?;
                
                // Try again
                Box::pin(self.wait_for_syscall()).await
            }
            
            Ok(WaitStatus::Exited(pid, exit_code)) => {
                debug!("Process {} exited with code: {}", pid, exit_code);
                self.traced_processes.lock().await.remove(&pid);
                
                // Check if we have more processes to trace
                if self.traced_processes.lock().await.is_empty() {
                    Ok(None)
                } else {
                    Box::pin(self.wait_for_syscall()).await
                }
            }
            
            Ok(WaitStatus::Signaled(pid, signal, _)) => {
                debug!("Process {} was killed by signal: {:?}", pid, signal);
                self.traced_processes.lock().await.remove(&pid);
                
                // Check if we have more processes to trace
                if self.traced_processes.lock().await.is_empty() {
                    Ok(None)
                } else {
                    Box::pin(self.wait_for_syscall()).await
                }
            }
            
            Ok(WaitStatus::Continued(pid)) => {
                debug!("Process {} continued", pid);
                Box::pin(self.wait_for_syscall()).await
            }
            
            Ok(status) => {
                debug!("Unhandled wait status: {:?}", status);
                Box::pin(self.wait_for_syscall()).await
            }
            
            Err(nix::errno::Errno::ECHILD) => {
                // No more child processes
                debug!("No more child processes to trace");
                Ok(None)
            }
            
            Err(e) => {
                error!("Wait failed: {}", e);
                Err(IronJailError::SystemCallTracing(
                    format!("Wait failed: {}", e)
                ).into())
            }
        }
    }
    
    /// Handle a system call stop
    async fn handle_syscall_stop(&mut self, pid: Pid) -> Result<Option<(Pid, SyscallInfo)>> {
        let in_syscall = {
            let mut processes = self.traced_processes.lock().await;
            let process_state = processes.get_mut(&pid);
            
            if process_state.is_none() {
                warn!("Received syscall stop for untraced process: {}", pid);
                return Ok(None);
            }
            
            let process_state = process_state.unwrap();
            process_state.in_syscall
        };
        
        if !in_syscall {
            // This is a syscall entry
            {
                let mut processes = self.traced_processes.lock().await;
                let process_state = processes.get_mut(&pid).unwrap();
                process_state.in_syscall = true;
                
                // Get syscall information
                let syscall_info = self.get_syscall_info(pid)?;
                process_state.syscall_entry = Some(syscall_info);
            }
            
            // Continue to syscall exit
            ptrace::syscall(pid, None)
                .map_err(|e| IronJailError::SystemCallTracing(
                    format!("Failed to continue to syscall exit for {}: {}", pid, e)
                ))?;
            
            // Wait for syscall exit
            Box::pin(self.wait_for_syscall()).await
        } else {
            // This is a syscall exit
            let mut syscall_info = {
                let mut processes = self.traced_processes.lock().await;
                let process_state = processes.get_mut(&pid).unwrap();
                process_state.in_syscall = false;
                
                process_state.syscall_entry.take()
                    .ok_or_else(|| IronJailError::SystemCallTracing(
                        "Missing syscall entry information".to_string()
                    ))?
            };
            
            // Get return value
            syscall_info.return_value = Some(self.get_return_value(pid)?);
            syscall_info.duration_us = Some(syscall_info.entry_time.elapsed().as_micros() as u64);
            
            // Continue the process
            ptrace::syscall(pid, None)
                .map_err(|e| IronJailError::SystemCallTracing(
                    format!("Failed to continue process {}: {}", pid, e)
                ))?;
            
            Ok(Some((pid, syscall_info)))
        }
    }
    
    /// Get system call information from registers
    fn get_syscall_info(&self, pid: Pid) -> Result<SyscallInfo> {
        let regs = ptrace::getregs(pid)
            .map_err(|e| IronJailError::SystemCallTracing(
                format!("Failed to get registers for {}: {}", pid, e)
            ))?;
        
        // Extract syscall number and arguments based on architecture
        #[cfg(target_arch = "x86_64")]
        {
            Ok(SyscallInfo {
                syscall_number: regs.orig_rax as i64,
                arguments: vec![
                    regs.rdi,
                    regs.rsi,
                    regs.rdx,
                    regs.r10,
                    regs.r8,
                    regs.r9,
                ],
                return_value: None,
                entry_time: std::time::Instant::now(),
                duration_us: None,
            })
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            Ok(SyscallInfo {
                syscall_number: regs.regs[8] as i64,
                arguments: vec![
                    regs.regs[0],
                    regs.regs[1],
                    regs.regs[2],
                    regs.regs[3],
                    regs.regs[4],
                    regs.regs[5],
                ],
                return_value: None,
                entry_time: std::time::Instant::now(),
                duration_us: None,
            })
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(IronJailError::SystemCallTracing(
                "Unsupported architecture for syscall tracing".to_string()
            ))
        }
    }
    
    /// Get return value from registers
    fn get_return_value(&self, pid: Pid) -> Result<i64> {
        let regs = ptrace::getregs(pid)
            .map_err(|e| IronJailError::SystemCallTracing(
                format!("Failed to get registers for {}: {}", pid, e)
            ))?;
        
        #[cfg(target_arch = "x86_64")]
        {
            Ok(regs.rax as i64)
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            Ok(regs.regs[0] as i64)
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(IronJailError::SystemCallTracing(
                "Unsupported architecture for syscall tracing".to_string()
            ))
        }
    }
    
    /// Get list of currently traced processes
    pub async fn get_traced_processes(&self) -> Vec<Pid> {
        self.traced_processes.lock().await.keys().cloned().collect()
    }
    
    /// Check if the handler is running
    pub async fn is_running(&self) -> bool {
        *self.is_running.lock().await
    }
}