use crate::Result;
use crate::core::SandboxConfig;
use crate::tracing::PtraceHandler;
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{debug, info, warn, error};

/// System call tracer using ptrace
pub struct SystemCallTracer {
    config: SandboxConfig,
    ptrace_handler: PtraceHandler,
    traced_syscalls: Vec<String>,
    syscall_buffer: Arc<Mutex<Vec<SystemCall>>>,
}

/// Represents a single system call with all its details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCall {
    /// Unique identifier for this syscall
    pub id: String,
    
    /// Process ID that made the syscall
    pub pid: i32,
    
    /// Thread ID
    pub tid: i32,
    
    /// Timestamp when the syscall was made
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// System call number
    pub syscall_number: i64,
    
    /// System call name
    pub syscall_name: String,
    
    /// Arguments passed to the syscall
    pub arguments: Vec<SyscallArgument>,
    
    /// Return value of the syscall
    pub return_value: Option<i64>,
    
    /// Error code if the syscall failed
    pub error_code: Option<i32>,
    
    /// Duration of the syscall in microseconds
    pub duration_us: Option<u64>,
    
    /// Stack trace at the time of the syscall (if available)
    pub stack_trace: Option<Vec<String>>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Represents a system call argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallArgument {
    /// Argument index (0-based)
    pub index: usize,
    
    /// Raw value of the argument
    pub raw_value: u64,
    
    /// Interpreted value (e.g., string, filename, etc.)
    pub interpreted_value: Option<String>,
    
    /// Type of the argument
    pub arg_type: ArgumentType,
    
    /// Size of data pointed to by this argument (for pointers)
    pub data_size: Option<usize>,
    
    /// Actual data if this is a pointer to readable data
    pub data: Option<Vec<u8>>,
}

/// Types of system call arguments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArgumentType {
    Integer,
    Pointer,
    String,
    Filename,
    FileDescriptor,
    SocketAddress,
    Buffer,
    Flags,
    Mode,
    Signal,
    Unknown,
}

/// Statistics about system call tracing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingStats {
    pub total_syscalls: u64,
    pub syscalls_by_name: HashMap<String, u64>,
    pub syscalls_by_pid: HashMap<i32, u64>,
    pub failed_syscalls: u64,
    pub tracing_errors: u64,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl SystemCallTracer {
    /// Create a new system call tracer
    pub fn new(config: &SandboxConfig) -> Result<Self> {
        let ptrace_handler = PtraceHandler::new()?;
        
        let traced_syscalls = if config.monitoring.traced_syscalls.is_empty() {
            // Default syscalls to trace
            vec![
                "open".to_string(),
                "openat".to_string(),
                "read".to_string(),
                "write".to_string(),
                "close".to_string(),
                "execve".to_string(),
                "execveat".to_string(),
                "clone".to_string(),
                "fork".to_string(),
                "vfork".to_string(),
                "connect".to_string(),
                "accept".to_string(),
                "bind".to_string(),
                "listen".to_string(),
                "socket".to_string(),
                "sendto".to_string(),
                "recvfrom".to_string(),
                "mmap".to_string(),
                "munmap".to_string(),
                "mprotect".to_string(),
                "unlink".to_string(),
                "unlinkat".to_string(),
                "rename".to_string(),
                "renameat".to_string(),
                "mkdir".to_string(),
                "mkdirat".to_string(),
                "rmdir".to_string(),
                "chdir".to_string(),
                "fchdir".to_string(),
                "chmod".to_string(),
                "fchmod".to_string(),
                "chown".to_string(),
                "fchown".to_string(),
                "stat".to_string(),
                "fstat".to_string(),
                "lstat".to_string(),
                "access".to_string(),
                "faccessat".to_string(),
            ]
        } else {
            config.monitoring.traced_syscalls.clone()
        };
        
        Ok(Self {
            config: config.clone(),
            ptrace_handler,
            traced_syscalls,
            syscall_buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }
    
    /// Start tracing system calls for the given session
    pub async fn start_tracing(&mut self, session_id: &str) -> Result<tokio::task::JoinHandle<()>> {
        info!("Starting system call tracing for session: {}", session_id);
        
        let (tx, mut rx) = mpsc::channel::<SystemCall>(10000);
        let syscall_buffer = self.syscall_buffer.clone();
        
        // Start the ptrace handler
        self.ptrace_handler.start().await?;
        
        // Spawn a task to collect and buffer syscalls
        let _collector_handle = tokio::spawn(async move {
            while let Some(syscall) = rx.recv().await {
                if let Ok(mut buffer) = syscall_buffer.lock() {
                    buffer.push(syscall);
                } else {
                    error!("Failed to acquire syscall buffer lock");
                }
            }
        });
        
        // Spawn the main tracing task
        let tracer_config = self.config.clone();
        let traced_syscalls = self.traced_syscalls.clone();
        let ptrace_handler = self.ptrace_handler.clone();
        
        let tracing_handle = tokio::spawn(async move {
            if let Err(e) = Self::trace_syscalls(tracer_config, traced_syscalls, ptrace_handler, tx).await {
                error!("System call tracing failed: {}", e);
            }
        });
        
        debug!("System call tracing started");
        Ok(tracing_handle)
    }
    
    /// Main tracing loop
    async fn trace_syscalls(
        _config: SandboxConfig,
        traced_syscalls: Vec<String>,
        mut ptrace_handler: PtraceHandler,
        tx: mpsc::Sender<SystemCall>,
    ) -> Result<()> {
        let mut stats = TracingStats {
            total_syscalls: 0,
            syscalls_by_name: HashMap::new(),
            syscalls_by_pid: HashMap::new(),
            failed_syscalls: 0,
            tracing_errors: 0,
            start_time: chrono::Utc::now(),
            end_time: None,
        };
        
        loop {
            // Wait for a process to make a system call
            match ptrace_handler.wait_for_syscall().await {
                Ok(Some((pid, syscall_info))) => {
                    let syscall = Self::process_syscall(pid, syscall_info, &traced_syscalls).await?;
                    
                    // Update statistics
                    stats.total_syscalls += 1;
                    *stats.syscalls_by_name.entry(syscall.syscall_name.clone()).or_insert(0) += 1;
                    *stats.syscalls_by_pid.entry(syscall.pid).or_insert(0) += 1;
                    
                    if syscall.error_code.is_some() {
                        stats.failed_syscalls += 1;
                    }
                    
                    // Send syscall to collector
                    if let Err(e) = tx.send(syscall).await {
                        warn!("Failed to send syscall to collector: {}", e);
                        break;
                    }
                }
                Ok(None) => {
                    // No more processes to trace
                    debug!("No more processes to trace, ending syscall tracing");
                    break;
                }
                Err(e) => {
                    error!("Error in syscall tracing: {}", e);
                    stats.tracing_errors += 1;
                    
                    // Continue tracing unless it's a critical error
                    if stats.tracing_errors > 100 {
                        error!("Too many tracing errors, stopping");
                        break;
                    }
                }
            }
        }
        
        stats.end_time = Some(chrono::Utc::now());
        info!("System call tracing completed. Stats: {:?}", stats);
        
        Ok(())
    }
    
    /// Process a single system call and create a SystemCall record
    async fn process_syscall(
        pid: Pid,
        syscall_info: crate::tracing::SyscallInfo,
        traced_syscalls: &[String],
    ) -> Result<SystemCall> {
        let syscall_name = Self::get_syscall_name(syscall_info.syscall_number);
        
        // Skip if not in our traced syscalls list (unless empty = trace all)
        if !traced_syscalls.is_empty() && !traced_syscalls.contains(&syscall_name) {
            // Create a minimal record for untraced syscalls
            return Ok(SystemCall {
                id: uuid::Uuid::new_v4().to_string(),
                pid: pid.as_raw(),
                tid: pid.as_raw(), // TODO: Get actual TID
                timestamp: chrono::Utc::now(),
                syscall_number: syscall_info.syscall_number,
                syscall_name,
                arguments: vec![],
                return_value: syscall_info.return_value,
                error_code: None,
                duration_us: None,
                stack_trace: None,
                metadata: HashMap::new(),
            });
        }
        
        // Process arguments based on syscall type
        let arguments = Self::process_syscall_arguments(
            &syscall_name,
            &syscall_info.arguments,
            pid,
        ).await?;
        
        // Determine error code from return value
        let (return_val, error_code) = if let Some(ret) = syscall_info.return_value {
            if ret < 0 {
                (Some(ret), Some((-ret) as i32))
            } else {
                (Some(ret), None)
            }
        } else {
            (None, None)
        };
        
        Ok(SystemCall {
            id: uuid::Uuid::new_v4().to_string(),
            pid: pid.as_raw(),
            tid: pid.as_raw(), // TODO: Get actual TID
            timestamp: chrono::Utc::now(),
            syscall_number: syscall_info.syscall_number,
            syscall_name,
            arguments,
            return_value: return_val,
            error_code,
            duration_us: syscall_info.duration_us,
            stack_trace: None, // TODO: Implement stack trace collection
            metadata: HashMap::new(),
        })
    }
    
    /// Process system call arguments and interpret them
    async fn process_syscall_arguments(
        syscall_name: &str,
        raw_args: &[u64],
        pid: Pid,
    ) -> Result<Vec<SyscallArgument>> {
        let mut arguments = Vec::new();
        
        for (index, &raw_value) in raw_args.iter().enumerate() {
            let arg_type = Self::determine_argument_type(syscall_name, index);
            let mut interpreted_value = None;
            let mut data = None;
            let mut data_size = None;
            
            match arg_type {
                ArgumentType::String | ArgumentType::Filename => {
                    if raw_value != 0 {
                        if let Ok(string_data) = Self::read_string_from_process(pid, raw_value as *const u8) {
                            interpreted_value = Some(string_data.clone());
                            data = Some(string_data.into_bytes());
                            data_size = Some(data.as_ref().unwrap().len());
                        }
                    }
                }
                ArgumentType::Buffer => {
                    // For buffers, we might want to read some data
                    if raw_value != 0 && index + 1 < raw_args.len() {
                        let buffer_size = raw_args[index + 1] as usize;
                        if buffer_size > 0 && buffer_size <= 4096 { // Reasonable size limit
                            if let Ok(buffer_data) = Self::read_buffer_from_process(
                                pid, raw_value as *const u8, buffer_size
                            ) {
                                data = Some(buffer_data);
                                data_size = Some(buffer_size);
                            }
                        }
                    }
                }
                ArgumentType::FileDescriptor => {
                    interpreted_value = Some(format!("fd:{}", raw_value));
                }
                ArgumentType::Flags => {
                    interpreted_value = Some(Self::interpret_flags(syscall_name, index, raw_value));
                }
                ArgumentType::Mode => {
                    interpreted_value = Some(format!("0{:o}", raw_value));
                }
                _ => {}
            }
            
            arguments.push(SyscallArgument {
                index,
                raw_value,
                interpreted_value,
                arg_type,
                data_size,
                data,
            });
        }
        
        Ok(arguments)
    }
    
    /// Determine the type of an argument based on syscall and position
    fn determine_argument_type(syscall_name: &str, index: usize) -> ArgumentType {
        match (syscall_name, index) {
            ("open" | "openat", 0) | ("open" | "openat", 1) => ArgumentType::Filename,
            ("read" | "write", 1) => ArgumentType::Buffer,
            ("execve" | "execveat", 0) => ArgumentType::Filename,
            ("connect" | "bind", 1) => ArgumentType::SocketAddress,
            ("mmap", 0) => ArgumentType::Pointer,
            ("chmod" | "fchmod", 1) => ArgumentType::Mode,
            ("open" | "openat", 2) => ArgumentType::Flags,
            (_, 0) if syscall_name.contains("fd") => ArgumentType::FileDescriptor,
            _ => {
                if syscall_name.ends_with("at") && index == 0 {
                    ArgumentType::FileDescriptor
                } else {
                    ArgumentType::Integer
                }
            }
        }
    }
    
    /// Read a null-terminated string from a process memory
    fn read_string_from_process(pid: Pid, addr: *const u8) -> Result<String> {
        // This is a simplified implementation
        // In practice, you'd use ptrace to read memory
        let mut result = String::new();
        let mut current_addr = addr as usize;
        
        // Read up to 4096 characters to prevent infinite loops
        for _ in 0..4096 {
            match nix::sys::ptrace::read(pid, current_addr as *mut libc::c_void) {
                Ok(data) => {
                    let bytes = data.to_le_bytes();
                    for &byte in &bytes {
                        if byte == 0 {
                            return Ok(result);
                        }
                        if byte.is_ascii() && !byte.is_ascii_control() {
                            result.push(byte as char);
                        } else if byte == b'\n' || byte == b'\t' {
                            result.push(byte as char);
                        } else {
                            result.push('?');
                        }
                    }
                    current_addr += std::mem::size_of::<libc::c_long>();
                }
                Err(_) => break,
            }
        }
        
        Ok(result)
    }
    
    /// Read a buffer from process memory
    fn read_buffer_from_process(pid: Pid, addr: *const u8, size: usize) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut current_addr = addr as usize;
        let words_to_read = (size + std::mem::size_of::<libc::c_long>() - 1) / std::mem::size_of::<libc::c_long>();
        
        for _ in 0..words_to_read {
            match nix::sys::ptrace::read(pid, current_addr as *mut libc::c_void) {
                Ok(data) => {
                    let bytes = data.to_le_bytes();
                    for &byte in &bytes {
                        if buffer.len() >= size {
                            break;
                        }
                        buffer.push(byte);
                    }
                    current_addr += std::mem::size_of::<libc::c_long>();
                }
                Err(_) => break,
            }
        }
        
        buffer.truncate(size);
        Ok(buffer)
    }
    
    /// Interpret flags based on syscall and argument position
    fn interpret_flags(syscall_name: &str, index: usize, flags: u64) -> String {
        match (syscall_name, index) {
            ("open" | "openat", 2) => Self::interpret_open_flags(flags as i32),
            ("mmap", 3) => Self::interpret_mmap_prot_flags(flags as i32),
            ("mmap", 4) => Self::interpret_mmap_flags(flags as i32),
            _ => format!("0x{:x}", flags),
        }
    }
    
    /// Interpret open() flags
    fn interpret_open_flags(flags: i32) -> String {
        let mut result = Vec::new();
        
        match flags & libc::O_ACCMODE {
            libc::O_RDONLY => result.push("O_RDONLY"),
            libc::O_WRONLY => result.push("O_WRONLY"),
            libc::O_RDWR => result.push("O_RDWR"),
            _ => result.push("O_UNKNOWN"),
        }
        
        if flags & libc::O_CREAT != 0 { result.push("O_CREAT"); }
        if flags & libc::O_EXCL != 0 { result.push("O_EXCL"); }
        if flags & libc::O_TRUNC != 0 { result.push("O_TRUNC"); }
        if flags & libc::O_APPEND != 0 { result.push("O_APPEND"); }
        if flags & libc::O_NONBLOCK != 0 { result.push("O_NONBLOCK"); }
        if flags & libc::O_SYNC != 0 { result.push("O_SYNC"); }
        
        if result.is_empty() {
            format!("0x{:x}", flags)
        } else {
            result.join("|")
        }
    }
    
    /// Interpret mmap() protection flags
    fn interpret_mmap_prot_flags(prot: i32) -> String {
        let mut result = Vec::new();
        
        if prot & libc::PROT_READ != 0 { result.push("PROT_READ"); }
        if prot & libc::PROT_WRITE != 0 { result.push("PROT_WRITE"); }
        if prot & libc::PROT_EXEC != 0 { result.push("PROT_EXEC"); }
        if prot == libc::PROT_NONE { result.push("PROT_NONE"); }
        
        if result.is_empty() {
            format!("0x{:x}", prot)
        } else {
            result.join("|")
        }
    }
    
    /// Interpret mmap() flags
    fn interpret_mmap_flags(flags: i32) -> String {
        let mut result = Vec::new();
        
        if flags & libc::MAP_SHARED != 0 { result.push("MAP_SHARED"); }
        if flags & libc::MAP_PRIVATE != 0 { result.push("MAP_PRIVATE"); }
        if flags & libc::MAP_ANONYMOUS != 0 { result.push("MAP_ANONYMOUS"); }
        if flags & libc::MAP_FIXED != 0 { result.push("MAP_FIXED"); }
        
        if result.is_empty() {
            format!("0x{:x}", flags)
        } else {
            result.join("|")
        }
    }
    
    /// Get system call name from number
    fn get_syscall_name(syscall_number: i64) -> String {
        // This is a simplified mapping - in practice, you'd have a complete syscall table
        match syscall_number {
            0 => "read".to_string(),
            1 => "write".to_string(),
            2 => "open".to_string(),
            3 => "close".to_string(),
            4 => "stat".to_string(),
            5 => "fstat".to_string(),
            6 => "lstat".to_string(),
            9 => "mmap".to_string(),
            10 => "mprotect".to_string(),
            11 => "munmap".to_string(),
            56 => "clone".to_string(),
            57 => "fork".to_string(),
            58 => "vfork".to_string(),
            59 => "execve".to_string(),
            257 => "openat".to_string(),
            322 => "execveat".to_string(),
            _ => format!("syscall_{}", syscall_number),
        }
    }
    
    /// Stop tracing and collect all syscalls
    pub async fn stop_and_collect(&mut self, handle: tokio::task::JoinHandle<()>) -> Result<Vec<SystemCall>> {
        debug!("Stopping system call tracing");
        
        // Stop the ptrace handler
        self.ptrace_handler.stop().await?;
        
        // Wait for the tracing task to complete
        if let Err(e) = handle.await {
            warn!("Tracing task ended with error: {}", e);
        }
        
        // Collect all buffered syscalls
        let syscalls = if let Ok(mut buffer) = self.syscall_buffer.lock() {
            let result = buffer.drain(..).collect();
            result
        } else {
            error!("Failed to acquire syscall buffer lock during collection");
            Vec::new()
        };
        
        info!("Collected {} system calls", syscalls.len());
        Ok(syscalls)
    }
}