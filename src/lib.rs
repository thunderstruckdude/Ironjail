//! IronJail - Advanced Malware Analysis Sandbox
//! 
//! A comprehensive security research tool that provides layered containment,
//! system call tracing, network monitoring, and environment deception capabilities.

pub mod core;
pub mod tracing;
pub mod monitoring;
pub mod deception;
pub mod policy;
pub mod reporting;

pub use core::*;

/// Result type used throughout the crate
pub type Result<T> = anyhow::Result<T>;

/// Common error types specific to IronJail
#[derive(thiserror::Error, Debug)]
pub enum IronJailError {
    #[error("Sandbox initialization failed: {0}")]
    SandboxInit(String),
    
    #[error("Process execution failed: {0}")]
    ProcessExecution(String),
    
    #[error("System call tracing error: {0}")]
    SystemCallTracing(String),
    
    #[error("Network monitoring error: {0}")]
    NetworkMonitoring(String),
    
    #[error("File system monitoring error: {0}")]
    FileSystemMonitoring(String),
    
    #[error("Policy configuration error: {0}")]
    PolicyConfiguration(String),
    
    #[error("Report generation error: {0}")]
    ReportGeneration(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}