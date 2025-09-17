use crate::{Result, IronJailError};
use crate::tracing::SystemCall;
use crate::monitoring::{FileActivity, NetworkActivity, ProcessActivity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use handlebars::Handlebars;
use tracing::{debug, info, error};

/// Analysis result containing all monitoring data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Session identifier
    pub session_id: String,
    
    /// Binary that was analyzed
    pub binary: PathBuf,
    
    /// Arguments passed to the binary
    pub args: Vec<String>,
    
    /// Start timestamp
    pub start_timestamp: chrono::DateTime<chrono::Utc>,
    
    /// End timestamp
    pub end_timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Duration in seconds
    pub duration: u64,
    
    /// Exit code of the analyzed binary
    pub exit_code: Option<i32>,
    
    /// Status of the analysis
    pub status: String,
    
    /// Error message if analysis failed
    pub error: Option<String>,
    
    /// System calls captured
    pub syscalls: Vec<SystemCall>,
    
    /// File system activities captured
    pub file_activities: Vec<FileActivity>,
    
    /// Network activities captured
    pub network_activities: Vec<NetworkActivity>,
    
    /// Process activities captured
    pub process_activities: Vec<ProcessActivity>,
    
    /// Whether deception was enabled
    pub deception_enabled: bool,
    
    /// Analysis statistics
    pub statistics: AnalysisStatistics,
    
    /// Threat assessment
    pub threat_assessment: ThreatAssessment,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Analysis statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisStatistics {
    /// Total number of system calls
    pub total_syscalls: u64,
    
    /// System calls by name
    pub syscalls_by_name: HashMap<String, u64>,
    
    /// Total file activities
    pub total_file_activities: u64,
    
    /// File activities by type
    pub file_activities_by_type: HashMap<String, u64>,
    
    /// Total network activities
    pub total_network_activities: u64,
    
    /// Network activities by type
    pub network_activities_by_type: HashMap<String, u64>,
    
    /// Unique files accessed
    pub unique_files_accessed: u64,
    
    /// Unique network destinations
    pub unique_network_destinations: u64,
    
    /// Total bytes written
    pub total_bytes_written: u64,
    
    /// Total bytes read
    pub total_bytes_read: u64,
    
    /// Peak memory usage
    pub peak_memory_usage: Option<u64>,
    
    /// CPU usage percentage
    pub cpu_usage_percent: Option<f64>,
}

/// Threat assessment result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatAssessment {
    /// Overall threat level (0-10)
    pub threat_level: u8,
    
    /// Risk category
    pub risk_category: String,
    
    /// Behavioral indicators
    pub behavioral_indicators: Vec<BehavioralIndicator>,
    
    /// Suspicious activities
    pub suspicious_activities: Vec<SuspiciousActivity>,
    
    /// MITRE ATT&CK techniques detected
    pub mitre_techniques: Vec<MitreTechnique>,
    
    /// IOCs (Indicators of Compromise)
    pub iocs: Vec<IndicatorOfCompromise>,
    
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Behavioral indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralIndicator {
    /// Indicator type
    pub indicator_type: String,
    
    /// Description
    pub description: String,
    
    /// Severity level (1-5)  
    pub severity: u8,
    
    /// Evidence
    pub evidence: Vec<String>,
    
    /// Confidence level (0-100)
    pub confidence: u8,
}

/// Suspicious activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousActivity {
    /// Activity type
    pub activity_type: String,
    
    /// Description
    pub description: String,
    
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Associated process
    pub process: Option<String>,
    
    /// Details
    pub details: HashMap<String, String>,
}

/// MITRE ATT&CK technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    /// Technique ID (e.g., T1055)
    pub technique_id: String,
    
    /// Technique name
    pub technique_name: String,
    
    /// Tactic
    pub tactic: String,
    
    /// Description
    pub description: String,
    
    /// Evidence
    pub evidence: Vec<String>,
}

/// Indicator of Compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorOfCompromise {
    /// IOC type (file_hash, ip_address, domain, etc.)
    pub ioc_type: String,
    
    /// IOC value
    pub value: String,
    
    /// Description
    pub description: String,
    
    /// First seen timestamp
    pub first_seen: chrono::DateTime<chrono::Utc>,
    
    /// Last seen timestamp
    pub last_seen: chrono::DateTime<chrono::Utc>,
    
    /// Confidence level (0-100)
    pub confidence: u8,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session name/ID
    pub name: String,
    
    /// Binary analyzed
    pub binary: String,
    
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Duration in seconds
    pub duration: u64,
    
    /// Status
    pub status: String,
    
    /// Threat level
    pub threat_level: u8,
}

impl AnalysisResult {
    /// Create a new analysis result
    pub fn new(session_id: &str, binary: &Path, args: &[String]) -> Self {
        Self {
            session_id: session_id.to_string(),
            binary: binary.to_path_buf(),
            args: args.to_vec(),
            start_timestamp: chrono::Utc::now(),
            end_timestamp: chrono::Utc::now(),
            duration: 0,
            exit_code: None,
            status: "running".to_string(),
            error: None,
            syscalls: Vec::new(),
            file_activities: Vec::new(),
            network_activities: Vec::new(),
            process_activities: Vec::new(),
            deception_enabled: false,
            statistics: AnalysisStatistics::default(),
            threat_assessment: ThreatAssessment::default(),
            metadata: HashMap::new(),
        }
    }
    
    /// Calculate statistics from the collected data
    pub fn calculate_statistics(&mut self) {
        // Calculate syscall statistics
        self.statistics.total_syscalls = self.syscalls.len() as u64;
        self.statistics.syscalls_by_name.clear();
        for syscall in &self.syscalls {
            *self.statistics.syscalls_by_name
                .entry(syscall.syscall_name.clone())
                .or_insert(0) += 1;
        }
        
        // Calculate file activity statistics
        self.statistics.total_file_activities = self.file_activities.len() as u64;
        self.statistics.file_activities_by_type.clear();
        let mut unique_files = std::collections::HashSet::new();
        let mut total_bytes_written = 0;
        let mut total_bytes_read = 0;
        
        for activity in &self.file_activities {
            let activity_type = format!("{:?}", activity.activity_type);
            *self.statistics.file_activities_by_type
                .entry(activity_type)
                .or_insert(0) += 1;
            
            unique_files.insert(activity.path.clone());
            
            if let Some(size) = activity.size_after {
                total_bytes_written += size;
            }
        }
        
        self.statistics.unique_files_accessed = unique_files.len() as u64;
        self.statistics.total_bytes_written = total_bytes_written;
        
        // Calculate network activity statistics
        self.statistics.total_network_activities = self.network_activities.len() as u64;
        self.statistics.network_activities_by_type.clear();
        let mut unique_destinations = std::collections::HashSet::new();
        
        for activity in &self.network_activities {
            let activity_type = format!("{:?}", activity.activity_type);
            *self.statistics.network_activities_by_type
                .entry(activity_type)
                .or_insert(0) += 1;
            
            unique_destinations.insert(activity.destination.to_string());
        }
        
        self.statistics.unique_network_destinations = unique_destinations.len() as u64;
    }
    
    /// Perform threat assessment
    pub fn assess_threats(&mut self) {
        let mut behavioral_indicators = Vec::new();
        let mut suspicious_activities = Vec::new();
        let mut mitre_techniques = Vec::new();
        let mut iocs = Vec::new();
        let mut threat_level = 0u8;
        
        // Analyze system calls for suspicious patterns
        self.analyze_syscalls(&mut behavioral_indicators, &mut suspicious_activities, &mut threat_level);
        
        // Analyze file activities
        self.analyze_file_activities(&mut behavioral_indicators, &mut suspicious_activities, &mut threat_level);
        
        // Analyze network activities
        self.analyze_network_activities(&mut behavioral_indicators, &mut suspicious_activities, &mut threat_level, &mut iocs);
        
        // Detect MITRE ATT&CK techniques
        self.detect_mitre_techniques(&mut mitre_techniques);
        
        // Determine risk category
        let risk_category = match threat_level {
            0..=2 => "Low",
            3..=5 => "Medium", 
            6..=8 => "High",
            9..=10 => "Critical",
            _ => "Unknown",
        }.to_string();
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(threat_level, &behavioral_indicators);
        
        self.threat_assessment = ThreatAssessment {
            threat_level,
            risk_category,
            behavioral_indicators,
            suspicious_activities,
            mitre_techniques,
            iocs,
            recommendations,
        };
    }
    
    /// Analyze system calls for threats
    fn analyze_syscalls(&self, indicators: &mut Vec<BehavioralIndicator>, activities: &mut Vec<SuspiciousActivity>, threat_level: &mut u8) {
        // Look for suspicious syscall patterns
        let mut execve_count = 0;
        let mut ptrace_count = 0;
        let mut socket_count = 0;
        
        for syscall in &self.syscalls {
            match syscall.syscall_name.as_str() {
                "execve" | "execveat" => execve_count += 1,
                "ptrace" => ptrace_count += 1,
                "socket" | "connect" => socket_count += 1,
                _ => {}
            }
        }
        
        // Excessive process creation
        if execve_count > 10 {
            indicators.push(BehavioralIndicator {
                indicator_type: "Process Creation".to_string(),
                description: format!("Excessive process creation detected ({} execve calls)", execve_count),
                severity: 3,
                evidence: vec![format!("{} execve/execveat system calls", execve_count)],
                confidence: 85,
            });
            *threat_level = (*threat_level).max(4);
        }
        
        // Debugging/injection attempts
        if ptrace_count > 0 {
            indicators.push(BehavioralIndicator {
                indicator_type: "Process Injection".to_string(),
                description: "Potential process injection or debugging activity".to_string(),
                severity: 4,
                evidence: vec![format!("{} ptrace system calls", ptrace_count)],
                confidence: 90,
            });
            *threat_level = (*threat_level).max(6);
        }
        
        // Network activity
        if socket_count > 5 {
            indicators.push(BehavioralIndicator {
                indicator_type: "Network Communication".to_string(),
                description: "High network activity detected".to_string(),
                severity: 2,
                evidence: vec![format!("{} network-related system calls", socket_count)],
                confidence: 70,
            });
            *threat_level = (*threat_level).max(3);
        }
    }
    
    /// Analyze file activities for threats
    fn analyze_file_activities(&self, indicators: &mut Vec<BehavioralIndicator>, activities: &mut Vec<SuspiciousActivity>, threat_level: &mut u8) {
        let mut system_file_access = 0;
        let mut file_deletion_count = 0;
        let mut executable_creation = 0;
        
        for activity in &self.file_activities {
            // Check for system file access
            if activity.path.starts_with("/etc") || 
               activity.path.starts_with("/sys") || 
               activity.path.starts_with("/proc") {
                system_file_access += 1;
            }
            
            // Check for file deletions
            if matches!(activity.activity_type, crate::monitoring::FileActivityType::Delete) {
                file_deletion_count += 1;
            }
            
            // Check for executable file creation
            if matches!(activity.activity_type, crate::monitoring::FileActivityType::Create) {
                if let Some(path_str) = activity.path.to_str() {
                    if path_str.ends_with(".exe") || path_str.ends_with(".sh") || path_str.ends_with(".bat") {
                        executable_creation += 1;
                    }
                }
            }
        }
        
        if system_file_access > 5 {
            indicators.push(BehavioralIndicator {
                indicator_type: "System File Access".to_string(),
                description: "Excessive access to system files".to_string(),
                severity: 3,
                evidence: vec![format!("{} system file accesses", system_file_access)],
                confidence: 75,
            });
            *threat_level = (*threat_level).max(4);
        }
        
        if file_deletion_count > 3 {
            indicators.push(BehavioralIndicator {
                indicator_type: "File Destruction".to_string(),
                description: "Multiple file deletions detected".to_string(),
                severity: 4,
                evidence: vec![format!("{} file deletions", file_deletion_count)],
                confidence: 80,
            });
            *threat_level = (*threat_level).max(5);
        }
    }
    
    /// Analyze network activities for threats
    fn analyze_network_activities(&self, indicators: &mut Vec<BehavioralIndicator>, activities: &mut Vec<SuspiciousActivity>, threat_level: &mut u8, iocs: &mut Vec<IndicatorOfCompromise>) {
        let mut external_connections = 0;
        let mut unique_domains = std::collections::HashSet::new();
        
        for activity in &self.network_activities {
            if !activity.destination.ip().is_loopback() && !Self::is_private_ip(activity.destination.ip()) {
                external_connections += 1;
                unique_domains.insert(activity.destination.ip().to_string());
                
                // Add as IOC
                iocs.push(IndicatorOfCompromise {
                    ioc_type: "ip_address".to_string(),
                    value: activity.destination.ip().to_string(),
                    description: "External IP contacted by analyzed binary".to_string(),
                    first_seen: activity.timestamp,
                    last_seen: activity.timestamp,
                    confidence: 70,
                });
            }
        }
        
        if external_connections > 0 {
            indicators.push(BehavioralIndicator {
                indicator_type: "External Communication".to_string(),
                description: format!("Communication with {} external hosts", unique_domains.len()),
                severity: 3,
                evidence: vec![format!("{} external connections to {} unique hosts", external_connections, unique_domains.len())],
                confidence: 85,
            });
            *threat_level = (*threat_level).max(4);
        }
    }
    
    /// Detect MITRE ATT&CK techniques
    fn detect_mitre_techniques(&self, techniques: &mut Vec<MitreTechnique>) {
        // T1055 - Process Injection
        if self.syscalls.iter().any(|s| s.syscall_name == "ptrace") {
            techniques.push(MitreTechnique {
                technique_id: "T1055".to_string(),
                technique_name: "Process Injection".to_string(),
                tactic: "Defense Evasion".to_string(),
                description: "Potential process injection detected through ptrace usage".to_string(),
                evidence: vec!["ptrace system calls observed".to_string()],
            });
        }
        
        // T1083 - File and Directory Discovery
        if self.file_activities.len() > 20 {
            techniques.push(MitreTechnique {
                technique_id: "T1083".to_string(),
                technique_name: "File and Directory Discovery".to_string(),
                tactic: "Discovery".to_string(),
                description: "Extensive file system enumeration detected".to_string(),
                evidence: vec![format!("{} file system activities", self.file_activities.len())],
            });
        }
        
        // T1071 - Application Layer Protocol
        if self.network_activities.iter().any(|a| matches!(a.activity_type, crate::monitoring::NetworkActivityType::HttpRequest)) {
            techniques.push(MitreTechnique {
                technique_id: "T1071.001".to_string(),
                technique_name: "Web Protocols".to_string(),
                tactic: "Command and Control".to_string(),
                description: "HTTP communication detected".to_string(),
                evidence: vec!["HTTP requests observed".to_string()],
            });
        }
    }
    
    /// Generate recommendations based on threat assessment
    fn generate_recommendations(&self, threat_level: u8, indicators: &[BehavioralIndicator]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        match threat_level {
            0..=2 => {
                recommendations.push("No immediate action required. Continue monitoring.".to_string());
            }
            3..=5 => {
                recommendations.push("Moderate risk detected. Recommend additional analysis.".to_string());
                recommendations.push("Consider network segmentation for similar binaries.".to_string());
            }
            6..=8 => {
                recommendations.push("High risk detected. Immediate investigation recommended.".to_string());
                recommendations.push("Block network access for this binary.".to_string());
                recommendations.push("Quarantine the binary and associated files.".to_string());
            }
            9..=10 => {
                recommendations.push("Critical threat detected. Immediate containment required.".to_string());
                recommendations.push("Block all network access and quarantine immediately.".to_string());
                recommendations.push("Notify security team and initiate incident response.".to_string());
                recommendations.push("Perform full forensic analysis.".to_string());
            }
            _ => {}
        }
        
        // Add specific recommendations based on indicators
        for indicator in indicators {
            match indicator.indicator_type.as_str() {
                "Process Injection" => {
                    recommendations.push("Enable additional process monitoring and EDR solutions.".to_string());
                }
                "External Communication" => {
                    recommendations.push("Review network logs and implement DNS monitoring.".to_string());
                }
                "File Destruction" => {
                    recommendations.push("Enable file system monitoring and backup critical data.".to_string());
                }
                _ => {}
            }
        }
        
        recommendations.dedup();
        recommendations
    }
    
    /// Check if an IP address is private
    fn is_private_ip(ip: std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_private()
            }
            std::net::IpAddr::V6(ipv6) => {
                // Simple IPv6 private check (site-local and unique local)
                let segments = ipv6.segments();
                (segments[0] & 0xfe00) == 0xfc00 || // Unique local
                (segments[0] & 0xffc0) == 0xfe80    // Link-local
            }
        }
    }
}