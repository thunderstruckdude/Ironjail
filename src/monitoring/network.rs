use crate::{Result, IronJailError};
use crate::core::SandboxConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{debug, info, warn, error};

/// Network monitor for capturing network activities
pub struct NetworkMonitor {
    config: SandboxConfig,
    activity_buffer: Arc<Mutex<Vec<NetworkActivity>>>,
    packet_capture: Option<pcap::Capture<pcap::Active>>,
}

/// Represents a network activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkActivity {
    /// Unique identifier for this activity
    pub id: String,
    
    /// Timestamp when the activity occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Type of network activity
    pub activity_type: NetworkActivityType,
    
    /// Source address and port
    pub source: SocketAddr,
    
    /// Destination address and port
    pub destination: SocketAddr,
    
    /// Protocol used (TCP, UDP, ICMP, etc.)
    pub protocol: String,
    
    /// Process ID that initiated the activity
    pub pid: Option<i32>,
    
    /// Process name that initiated the activity
    pub process_name: Option<String>,
    
    /// Amount of data transferred (bytes)
    pub data_size: Option<u64>,
    
    /// Connection state (for TCP)
    pub connection_state: Option<String>,
    
    /// DNS query information
    pub dns_info: Option<DnsInfo>,
    
    /// HTTP request information
    pub http_info: Option<HttpInfo>,
    
    /// Raw packet data (if packet capture is enabled)
    pub packet_data: Option<Vec<u8>>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Types of network activities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkActivityType {
    /// TCP connection established
    TcpConnect,
    
    /// TCP connection accepted
    TcpAccept,
    
    /// TCP connection closed
    TcpClose,
    
    /// UDP packet sent
    UdpSend,
    
    /// UDP packet received
    UdpReceive,
    
    /// DNS query made
    DnsQuery,
    
    /// DNS response received
    DnsResponse,
    
    /// HTTP request sent
    HttpRequest,
    
    /// HTTP response received
    HttpResponse,
    
    /// Raw packet captured
    PacketCapture,
    
    /// Connection attempt blocked
    ConnectionBlocked,
}

/// DNS query/response information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    /// Domain name queried
    pub domain: String,
    
    /// Query type (A, AAAA, MX, etc.)
    pub query_type: String,
    
    /// Response IPs (for responses)
    pub response_ips: Vec<IpAddr>,
    
    /// Response code
    pub response_code: Option<u16>,
    
    /// Time taken for DNS resolution
    pub resolution_time_ms: Option<u64>,
}

/// HTTP request/response information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    /// HTTP method (GET, POST, etc.)
    pub method: Option<String>,
    
    /// Request URL
    pub url: Option<String>,
    
    /// HTTP status code (for responses)
    pub status_code: Option<u16>,
    
    /// Content type
    pub content_type: Option<String>,
    
    /// User agent
    pub user_agent: Option<String>,
    
    /// Request/response headers
    pub headers: HashMap<String, String>,
    
    /// Body size
    pub body_size: Option<u64>,
}

/// Network monitoring statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_activities: u64,
    pub activities_by_type: HashMap<String, u64>,
    pub tcp_connections: u64,
    pub udp_packets: u64,
    pub dns_queries: u64,
    pub http_requests: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub unique_destinations: u64,
    pub blocked_connections: u64,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new(config: &SandboxConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            activity_buffer: Arc::new(Mutex::new(Vec::new())),
            packet_capture: None,
        })
    }
    
    /// Start monitoring network activities
    pub async fn start_monitoring(
        &mut self, 
        session_id: &str,
        enable_packet_capture: bool,
    ) -> Result<tokio::task::JoinHandle<()>> {
        info!("Starting network monitoring for session: {}", session_id);
        
        // Initialize packet capture if enabled
        if enable_packet_capture {
            self.init_packet_capture().await?;
        }
        
        let (tx, mut rx) = mpsc::channel::<NetworkActivity>(10000);
        let activity_buffer = self.activity_buffer.clone();
        
        // Spawn collector task
        let _collector_handle = tokio::spawn(async move {
            while let Some(activity) = rx.recv().await {
                if let Ok(mut buffer) = activity_buffer.lock() {
                    buffer.push(activity);
                } else {
                    error!("Failed to acquire network activity buffer lock");
                }
            }
        });
        
        // Spawn monitoring tasks
        let config = self.config.clone();
        let packet_capture = self.packet_capture.take();
        
        let monitoring_handle = tokio::spawn(async move {
            // Start multiple monitoring methods
            let mut handles = vec![];
            
            // Network connection monitoring
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = Self::monitor_network_connections(config_clone, tx_clone).await {
                    error!("Network connection monitoring failed: {}", e);
                }
            }));
            
            // DNS monitoring
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = Self::monitor_dns_activity(config_clone, tx_clone).await {
                    error!("DNS monitoring failed: {}", e);
                }
            }));
            
            // Packet capture monitoring
            if let Some(capture) = packet_capture {
                let tx_clone = tx.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = Self::monitor_packet_capture(capture, tx_clone).await {
                        error!("Packet capture monitoring failed: {}", e);
                    }
                }));
            }
            
            // Wait for all monitoring tasks
            for handle in handles {
                let _ = handle.await;
            }
        });
        
        debug!("Network monitoring started");
        Ok(monitoring_handle)
    }
    
    /// Initialize packet capture
    async fn init_packet_capture(&mut self) -> Result<()> {
        debug!("Initializing packet capture");
        
        // Find a suitable network interface
        let interfaces = pcap::Device::list()
            .map_err(|e| IronJailError::NetworkMonitoring(
                format!("Failed to list network interfaces: {}", e)
            ))?;
        
        let interface = interfaces
            .into_iter()
            .find(|dev| dev.name == "lo" || dev.name.starts_with("eth") || dev.name.starts_with("wlan"))
            .ok_or_else(|| IronJailError::NetworkMonitoring(
                "No suitable network interface found".to_string()
            ))?;
        
        debug!("Using network interface: {}", interface.name);
        
        // Open capture
        let capture = pcap::Capture::from_device(interface.name.as_str())
            .map_err(|e| IronJailError::NetworkMonitoring(
                format!("Failed to open capture device: {}", e)
            ))?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .map_err(|e| IronJailError::NetworkMonitoring(
                format!("Failed to activate capture: {}", e)
            ))?;
        
        self.packet_capture = Some(capture);
        debug!("Packet capture initialized successfully");
        Ok(())
    }
    
    /// Monitor network connections using /proc/net
    async fn monitor_network_connections(
        _config: SandboxConfig,
        tx: mpsc::Sender<NetworkActivity>,
    ) -> Result<()> {
        let mut previous_connections = HashMap::new();
        
        loop {
            // Read TCP connections
            if let Ok(tcp_connections) = Self::read_tcp_connections().await {
                for conn in tcp_connections {
                    let key = format!("{}:{}-{}:{}", 
                        conn.local_addr.ip(), conn.local_addr.port(),
                        conn.remote_addr.ip(), conn.remote_addr.port());
                    
                    if !previous_connections.contains_key(&key) {
                        let activity = NetworkActivity {
                            id: uuid::Uuid::new_v4().to_string(),
                            timestamp: chrono::Utc::now(),
                            activity_type: NetworkActivityType::TcpConnect,
                            source: conn.local_addr,
                            destination: conn.remote_addr,
                            protocol: "TCP".to_string(),
                            pid: conn.pid,
                            process_name: conn.process_name.clone(),
                            data_size: None,
                            connection_state: Some(conn.state.clone()),
                            dns_info: None,
                            http_info: None,
                            packet_data: None,
                            metadata: HashMap::new(),
                        };
                        
                        previous_connections.insert(key, conn);
                        
                        if let Err(e) = tx.send(activity).await {
                            warn!("Failed to send network activity: {}", e);
                            break;
                        }
                    }
                }
            }
            
            // Read UDP connections
            if let Ok(udp_connections) = Self::read_udp_connections().await {
                for conn in udp_connections {
                    let activity = NetworkActivity {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: chrono::Utc::now(),
                        activity_type: NetworkActivityType::UdpSend,
                        source: conn.local_addr,
                        destination: conn.remote_addr,
                        protocol: "UDP".to_string(),
                        pid: conn.pid,
                        process_name: conn.process_name,
                        data_size: None,
                        connection_state: None,
                        dns_info: None,
                        http_info: None,
                        packet_data: None,
                        metadata: HashMap::new(),
                    };
                    
                    if let Err(e) = tx.send(activity).await {
                        warn!("Failed to send network activity: {}", e);
                        break;
                    }
                }
            }
            
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    
    /// Monitor DNS activities
    async fn monitor_dns_activity(
        _config: SandboxConfig,
        _tx: mpsc::Sender<NetworkActivity>,
    ) -> Result<()> {
        // This is a simplified DNS monitoring implementation
        // In practice, you'd intercept DNS queries at the network level
        
        loop {
            // Monitor /var/log/syslog or dnsmasq logs for DNS queries
            // This is a placeholder implementation
            
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
    
    /// Monitor packet capture
    async fn monitor_packet_capture(
        mut capture: pcap::Capture<pcap::Active>,
        tx: mpsc::Sender<NetworkActivity>,
    ) -> Result<()> {
        loop {
            match capture.next_packet() {
                Ok(packet) => {
                    let activity = Self::parse_packet(packet).await?;
                    
                    if let Err(e) = tx.send(activity).await {
                        warn!("Failed to send packet capture activity: {}", e);
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Timeout is normal, continue
                    continue;
                }
                Err(e) => {
                    error!("Packet capture error: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Parse a captured packet
    async fn parse_packet(packet: pcap::Packet<'_>) -> Result<NetworkActivity> {
        // This is a simplified packet parsing implementation
        // In practice, you'd use proper packet parsing libraries
        
        let activity = NetworkActivity {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            activity_type: NetworkActivityType::PacketCapture,
            source: "0.0.0.0:0".parse().unwrap(),
            destination: "0.0.0.0:0".parse().unwrap(),
            protocol: "Unknown".to_string(),
            pid: None,
            process_name: None,
            data_size: Some(packet.data.len() as u64),
            connection_state: None,
            dns_info: None,
            http_info: None,
            packet_data: Some(packet.data.to_vec()),
            metadata: HashMap::new(),
        };
        
        Ok(activity)
    }
    
    /// Read TCP connections from /proc/net/tcp
    async fn read_tcp_connections() -> Result<Vec<ConnectionInfo>> {
        // Simplified implementation
        Ok(vec![])
    }
    
    /// Read UDP connections from /proc/net/udp
    async fn read_udp_connections() -> Result<Vec<ConnectionInfo>> {
        // Simplified implementation
        Ok(vec![])
    }
    
    /// Stop monitoring and collect all activities
    pub async fn stop_and_collect(&mut self, handle: tokio::task::JoinHandle<()>) -> Result<Vec<NetworkActivity>> {
        debug!("Stopping network monitoring");
        
        // Stop the monitoring task
        handle.abort();
        
        // Collect all buffered activities
        let activities = if let Ok(mut buffer) = self.activity_buffer.lock() {
            buffer.drain(..).collect()
        } else {
            error!("Failed to acquire network activity buffer lock during collection");
            Vec::new()
        };
        
        info!("Collected {} network activities", activities.len());
        Ok(activities)
    }
}

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: String,
    pub pid: Option<i32>,
    pub process_name: Option<String>,
}

/// Process activity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessActivity {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub pid: i32,
    pub ppid: Option<i32>,
    pub process_name: String,
    pub command_line: String,
    pub working_directory: Option<String>,
    pub environment_variables: HashMap<String, String>,
    pub activity_type: ProcessActivityType,
    pub user_id: u32,
    pub group_id: u32,
    pub exit_code: Option<i32>,
    pub duration: Option<u64>,
    pub metadata: HashMap<String, String>,
}

/// Types of process activities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessActivityType {
    ProcessStart,
    ProcessExit,
    ProcessKilled,
    ProcessSuspended,
    ProcessResumed,
}