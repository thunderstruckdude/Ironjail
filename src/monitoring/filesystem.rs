use crate::{Result, IronJailError};
use crate::core::SandboxConfig;
use inotify::{Inotify, WatchMask, EventMask};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{PathBuf, Path};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{debug, info, warn, error};
use walkdir::WalkDir;
use std::os::unix::fs::PermissionsExt;

/// File system monitor using inotify
pub struct FileSystemMonitor {
    config: SandboxConfig,
    monitored_paths: Vec<PathBuf>,
    activity_buffer: Arc<Mutex<Vec<FileActivity>>>,
    inotify: Option<Inotify>,
}

/// Represents a file system activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileActivity {
    /// Unique identifier for this activity
    pub id: String,
    
    /// Timestamp when the activity occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Type of file system activity
    pub activity_type: FileActivityType,
    
    /// Path of the file or directory involved
    pub path: PathBuf,
    
    /// Process ID that performed the activity
    pub pid: Option<i32>,
    
    /// Process name that performed the activity
    pub process_name: Option<String>,
    
    /// User ID that performed the activity
    pub uid: Option<u32>,
    
    /// Group ID that performed the activity
    pub gid: Option<u32>,
    
    /// File size before the operation
    pub size_before: Option<u64>,
    
    /// File size after the operation
    pub size_after: Option<u64>,
    
    /// File permissions
    pub permissions: Option<u32>,
    
    /// File content hash (for small files)
    pub content_hash: Option<String>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Types of file system activities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileActivityType {
    /// File was opened
    Open { flags: Vec<String> },
    
    /// File was created
    Create,
    
    /// File was deleted
    Delete,
    
    /// File was modified
    Modify,
    
    /// File was moved/renamed
    Move { from: PathBuf, to: PathBuf },
    
    /// File attributes were changed
    AttributeChange,
    
    /// Directory was created
    DirectoryCreate,
    
    /// Directory was deleted
    DirectoryDelete,
    
    /// File was accessed (read)
    Access,
    
    /// File permissions were changed
    PermissionChange { old_mode: u32, new_mode: u32 },
    
    /// File ownership was changed
    OwnershipChange { old_uid: u32, old_gid: u32, new_uid: u32, new_gid: u32 },
}

/// Statistics about file system monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemStats {
    pub total_activities: u64,
    pub activities_by_type: HashMap<String, u64>,
    pub files_created: u64,
    pub files_deleted: u64,
    pub files_modified: u64,
    pub directories_created: u64,
    pub directories_deleted: u64,
    pub total_bytes_written: u64,
    pub total_bytes_read: u64,
    pub most_active_processes: HashMap<String, u64>,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl FileSystemMonitor {
    /// Create a new file system monitor
    pub fn new(config: &SandboxConfig) -> Result<Self> {
        let monitored_paths = if config.monitoring.monitored_directories.is_empty() {
            vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/var/tmp"),
                PathBuf::from("/home"),
            ]
        } else {
            config.monitoring.monitored_directories.clone()
        };
        
        Ok(Self {
            config: config.clone(),
            monitored_paths,
            activity_buffer: Arc::new(Mutex::new(Vec::new())),
            inotify: None,
        })
    }
    
    /// Start monitoring file system activities
    pub async fn start_monitoring(&mut self, session_id: &str) -> Result<tokio::task::JoinHandle<()>> {
        info!("Starting file system monitoring for session: {}", session_id);
        
        // Initialize inotify
        let mut inotify = Inotify::init()
            .map_err(|e| IronJailError::FileSystemMonitoring(
                format!("Failed to initialize inotify: {}", e)
            ))?;
        
        // Set up watches for monitored paths
        let mut watches = HashMap::new();
        for path in &self.monitored_paths {
            self.setup_recursive_watch(&mut inotify, path, &mut watches).await?;
        }
        
        self.inotify = Some(inotify);
        
        let (tx, mut rx) = mpsc::channel::<FileActivity>(10000);
        let activity_buffer = self.activity_buffer.clone();
        
        // Spawn collector task
        let _collector_handle = tokio::spawn(async move {
            while let Some(activity) = rx.recv().await {
                if let Ok(mut buffer) = activity_buffer.lock() {
                    buffer.push(activity);
                } else {
                    error!("Failed to acquire activity buffer lock");
                }
            }
        });
        
        // Spawn monitoring task
        let inotify = self.inotify.take().unwrap();
        let config = self.config.clone();
        let monitored_paths = self.monitored_paths.clone();
        
        let monitoring_handle = tokio::spawn(async move {
            if let Err(e) = Self::monitor_filesystem_activities(
                config, 
                monitored_paths, 
                inotify, 
                tx
            ).await {
                error!("File system monitoring failed: {}", e);
            }
        });
        
        debug!("File system monitoring started");
        Ok(monitoring_handle)
    }
    
    /// Setup recursive watch for a directory
    async fn setup_recursive_watch(
        &self,
        inotify: &mut Inotify,
        path: &Path,
        watches: &mut HashMap<PathBuf, inotify::WatchDescriptor>,
    ) -> Result<()> {
        if !path.exists() {
            warn!("Path does not exist, skipping: {:?}", path);
            return Ok(());
        }
        
        // Watch mask for comprehensive monitoring
        let mask = WatchMask::ACCESS
            | WatchMask::MODIFY
            | WatchMask::ATTRIB
            | WatchMask::CLOSE_WRITE
            | WatchMask::CLOSE_NOWRITE
            | WatchMask::OPEN
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO
            | WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::DELETE_SELF
            | WatchMask::MOVE_SELF;
        
        // Add watch for this directory
        match inotify.watches().add(path, mask) {
            Ok(wd) => {
                watches.insert(path.to_path_buf(), wd);
                debug!("Added watch for: {:?}", path);
            }
            Err(e) => {
                warn!("Failed to add watch for {:?}: {}", path, e);
                return Ok(()); // Continue with other paths
            }
        }
        
        // Recursively add watches for subdirectories
        if path.is_dir() {
            for entry in WalkDir::new(path)
                .max_depth(10) // Prevent infinite recursion
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_dir() && entry.path() != path {
                    match inotify.watches().add(entry.path(), mask) {
                        Ok(wd) => {
                            watches.insert(entry.path().to_path_buf(), wd);
                            debug!("Added recursive watch for: {:?}", entry.path());
                        }
                        Err(e) => {
                            debug!("Failed to add recursive watch for {:?}: {}", entry.path(), e);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Main monitoring loop
    async fn monitor_filesystem_activities(
        _config: SandboxConfig,
        _monitored_paths: Vec<PathBuf>,
        mut inotify: Inotify,
        tx: mpsc::Sender<FileActivity>,
    ) -> Result<()> {
        let mut stats = FileSystemStats {
            total_activities: 0,
            activities_by_type: HashMap::new(),
            files_created: 0,
            files_deleted: 0,
            files_modified: 0,
            directories_created: 0,
            directories_deleted: 0,
            total_bytes_written: 0,
            total_bytes_read: 0,
            most_active_processes: HashMap::new(),
            start_time: chrono::Utc::now(),
            end_time: None,
        };
        
        let mut buffer = [0; 4096];
        
        loop {
            // Read inotify events
            let events = match inotify.read_events(&mut buffer) {
                Ok(events) => events,
                Err(e) => {
                    // Log error but don't spam - sleep longer on errors
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        error!("Failed to read inotify events: {}", e);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                    continue;
                }
            };
            
            for event in events {
                let activity = Self::process_inotify_event(event).await?;
                
                // Update statistics
                stats.total_activities += 1;
                let activity_type_str = format!("{:?}", activity.activity_type);
                *stats.activities_by_type.entry(activity_type_str).or_insert(0) += 1;
                
                match activity.activity_type {
                    FileActivityType::Create => stats.files_created += 1,
                    FileActivityType::Delete => stats.files_deleted += 1,
                    FileActivityType::Modify => stats.files_modified += 1,
                    FileActivityType::DirectoryCreate => stats.directories_created += 1,
                    FileActivityType::DirectoryDelete => stats.directories_deleted += 1,
                    _ => {}
                }
                
                if let Some(ref process_name) = activity.process_name {
                    *stats.most_active_processes.entry(process_name.clone()).or_insert(0) += 1;
                }
                
                // Send activity to collector
                if let Err(e) = tx.send(activity).await {
                    warn!("Failed to send file activity to collector: {}", e);
                    break;
                }
            }
            
            // Small delay to prevent excessive CPU usage
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        
        stats.end_time = Some(chrono::Utc::now());
        info!("File system monitoring completed. Stats: {:?}", stats);
        
        Ok(())
    }
    
    /// Process an inotify event and create a FileActivity
    async fn process_inotify_event(event: inotify::Event<&std::ffi::OsStr>) -> Result<FileActivity> {
        let path = if let Some(name) = event.name {
            PathBuf::from(name)
        } else {
            PathBuf::from("unknown")
        };
        
        let activity_type = Self::determine_activity_type(&event.mask, &path).await;
        
        // Get process information
        let (pid, process_name, uid, gid) = Self::get_process_info().await;
        
        // Get file information
        let (size_before, size_after, permissions, content_hash) = 
            Self::get_file_info(&path, &activity_type).await;
        
        Ok(FileActivity {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            activity_type,
            path,
            pid,
            process_name,
            uid,
            gid,
            size_before,
            size_after,
            permissions,
            content_hash,
            metadata: HashMap::new(),
        })
    }
    
    /// Determine the type of file activity from inotify event mask
    async fn determine_activity_type(mask: &EventMask, path: &Path) -> FileActivityType {
        if mask.contains(EventMask::CREATE) {
            if path.is_dir() {
                FileActivityType::DirectoryCreate
            } else {
                FileActivityType::Create
            }
        } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::DELETE_SELF) {
            if path.is_dir() {
                FileActivityType::DirectoryDelete
            } else {
                FileActivityType::Delete
            }
        } else if mask.contains(EventMask::MODIFY) || mask.contains(EventMask::CLOSE_WRITE) {
            FileActivityType::Modify
        } else if mask.contains(EventMask::MOVED_FROM) || mask.contains(EventMask::MOVED_TO) {
            // For simplicity, we'll treat moves as separate from/to events
            // A more sophisticated implementation would correlate them
            FileActivityType::Move {
                from: path.to_path_buf(),
                to: path.to_path_buf(), // Would need to correlate with MOVED_TO event
            }
        } else if mask.contains(EventMask::ATTRIB) {
            FileActivityType::AttributeChange
        } else if mask.contains(EventMask::ACCESS) {
            FileActivityType::Access
        } else if mask.contains(EventMask::OPEN) {
            FileActivityType::Open {
                flags: vec!["unknown".to_string()], // Would need to get from syscall trace
            }
        } else {
            FileActivityType::Access // Default fallback
        }
    }
    
    /// Get process information for the current activity
    async fn get_process_info() -> (Option<i32>, Option<String>, Option<u32>, Option<u32>) {
        // This is a simplified implementation
        // In practice, you'd correlate with syscall traces or use other methods
        let pid = Some(std::process::id() as i32);
        let process_name = Some("unknown".to_string());
        let uid = Some(nix::unistd::getuid().as_raw());
        let gid = Some(nix::unistd::getgid().as_raw());
        
        (pid, process_name, uid, gid)
    }
    
    /// Get file information
    async fn get_file_info(
        path: &Path,
        activity_type: &FileActivityType,
    ) -> (Option<u64>, Option<u64>, Option<u32>, Option<String>) {
        let mut size_before = None;
        let mut size_after = None;
        let mut permissions = None;
        let mut content_hash = None;
        
        if path.exists() {
            if let Ok(metadata) = std::fs::metadata(path) {
                size_after = Some(metadata.len());
                permissions = Some(metadata.permissions().mode());
                
                // Calculate content hash for small files
                if metadata.len() <= 1024 * 1024 && metadata.is_file() { // 1MB limit
                    if let Ok(content) = std::fs::read(path) {
                        use sha2::{Sha256, Digest};
                        let mut hasher = Sha256::new();
                        hasher.update(&content);
                        content_hash = Some(hex::encode(hasher.finalize()));
                    }
                }
            }
        }
        
        (size_before, size_after, permissions, content_hash)
    }
    
    /// Stop monitoring and collect all activities
    pub async fn stop_and_collect(&mut self, handle: tokio::task::JoinHandle<()>) -> Result<Vec<FileActivity>> {
        debug!("Stopping file system monitoring");
        
        // Stop the monitoring task
        handle.abort();
        
        // Collect all buffered activities
        let activities = if let Ok(mut buffer) = self.activity_buffer.lock() {
            buffer.drain(..).collect()
        } else {
            error!("Failed to acquire activity buffer lock during collection");
            Vec::new()
        };
        
        info!("Collected {} file system activities", activities.len());
        Ok(activities)
    }
    
    /// Get real-time statistics
    pub async fn get_statistics(&self) -> Result<FileSystemStats> {
        let activities = self.activity_buffer.lock().unwrap();
        
        let mut stats = FileSystemStats {
            total_activities: activities.len() as u64,
            activities_by_type: HashMap::new(),
            files_created: 0,
            files_deleted: 0,
            files_modified: 0,
            directories_created: 0,
            directories_deleted: 0,
            total_bytes_written: 0,
            total_bytes_read: 0,
            most_active_processes: HashMap::new(),
            start_time: chrono::Utc::now(),
            end_time: None,
        };
        
        for activity in activities.iter() {
            let activity_type_str = format!("{:?}", activity.activity_type);
            *stats.activities_by_type.entry(activity_type_str).or_insert(0) += 1;
            
            match activity.activity_type {
                FileActivityType::Create => stats.files_created += 1,
                FileActivityType::Delete => stats.files_deleted += 1,
                FileActivityType::Modify => stats.files_modified += 1,
                FileActivityType::DirectoryCreate => stats.directories_created += 1,
                FileActivityType::DirectoryDelete => stats.directories_deleted += 1,
                _ => {}
            }
            
            if let Some(ref process_name) = activity.process_name {
                *stats.most_active_processes.entry(process_name.clone()).or_insert(0) += 1;
            }
        }
        
        Ok(stats)
    }
}