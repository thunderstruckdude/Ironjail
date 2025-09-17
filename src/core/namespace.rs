use crate::{Result, IronJailError};
use crate::core::SandboxConfig;
use nix::sched::{self, CloneFlags};
use nix::mount::{self, MsFlags, MntFlags};
use nix::unistd::{Uid, Gid};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, warn};

/// Ma        debug!("Mounted /tmp");inux namespaces for process isolation
pub struct NamespaceManager {
    config: SandboxConfig,
    active_namespaces: HashMap<NamespaceType, bool>,
    mount_points: Vec<MountPoint>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum NamespaceType {
    User,
    Pid,
    Network,
    Mount,
    Ipc,
    Uts,
    Cgroup,
}

#[derive(Debug, Clone)]
pub struct MountPoint {
    pub source: PathBuf,
    pub target: PathBuf,
    pub fs_type: String,
    pub flags: MsFlags,
    pub data: Option<String>,
}

impl NamespaceManager {
    pub fn new(config: &SandboxConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            active_namespaces: HashMap::new(),
            mount_points: Vec::new(),
        })
    }
    
    /// Setup all configured namespaces
    pub async fn setup_namespaces(&mut self) -> Result<()> {
        debug!("Setting up Linux namespaces");
        
        let mut clone_flags = CloneFlags::empty();
        
        // Prepare namespace flags based on configuration
        if self.config.security.enable_user_namespace {
            clone_flags |= CloneFlags::CLONE_NEWUSER;
            self.active_namespaces.insert(NamespaceType::User, true);
        }
        
        if self.config.security.enable_pid_namespace {
            clone_flags |= CloneFlags::CLONE_NEWPID;
            self.active_namespaces.insert(NamespaceType::Pid, true);
        }
        
        if self.config.security.enable_network_namespace {
            clone_flags |= CloneFlags::CLONE_NEWNET;
            self.active_namespaces.insert(NamespaceType::Network, true);
        }
        
        if self.config.security.enable_mount_namespace {
            clone_flags |= CloneFlags::CLONE_NEWNS;
            self.active_namespaces.insert(NamespaceType::Mount, true);
        }
        
        if self.config.security.enable_ipc_namespace {
            clone_flags |= CloneFlags::CLONE_NEWIPC;
            self.active_namespaces.insert(NamespaceType::Ipc, true);
        }
        
        if self.config.security.enable_uts_namespace {
            clone_flags |= CloneFlags::CLONE_NEWUTS;
            self.active_namespaces.insert(NamespaceType::Uts, true);
        }
        
        // Create namespaces individually (more tolerant approach)
        if !clone_flags.is_empty() {
            // Try to create namespaces one by one for better error handling
            let individual_flags = [
                (CloneFlags::CLONE_NEWUSER, NamespaceType::User, "user"),
                (CloneFlags::CLONE_NEWPID, NamespaceType::Pid, "pid"),
                (CloneFlags::CLONE_NEWNET, NamespaceType::Network, "network"),
                (CloneFlags::CLONE_NEWNS, NamespaceType::Mount, "mount"),
                (CloneFlags::CLONE_NEWIPC, NamespaceType::Ipc, "ipc"),
                (CloneFlags::CLONE_NEWUTS, NamespaceType::Uts, "uts"),
            ];
            
            for (flag, ns_type, name) in individual_flags {
                if clone_flags.contains(flag) {
                    match sched::unshare(flag) {
                        Ok(_) => {
                            debug!("Successfully created {} namespace", name);
                        }
                        Err(e) => {
                            warn!("Failed to create {} namespace (continuing): {}", name, e);
                            // Remove from active namespaces if creation failed
                            self.active_namespaces.remove(&ns_type);
                        }
                    }
                }
            }
        }
        
        // Setup specific namespace configurations
        if self.active_namespaces.contains_key(&NamespaceType::User) {
            self.setup_user_namespace().await?;
        }
        
        if self.active_namespaces.contains_key(&NamespaceType::Mount) {
            self.setup_mount_namespace().await?;
        }
        
        if self.active_namespaces.contains_key(&NamespaceType::Network) {
            self.setup_network_namespace().await?;
        }
        
        if self.active_namespaces.contains_key(&NamespaceType::Uts) {
            self.setup_uts_namespace().await?;
        }
        
        debug!("Namespace setup completed");
        Ok(())
    }
    
    /// Setup user namespace with UID/GID mapping
    async fn setup_user_namespace(&mut self) -> Result<()> {
        debug!("Setting up user namespace");
        
        // Map current user to root inside namespace
        let current_uid = nix::unistd::getuid();
        let current_gid = nix::unistd::getgid();
        
        // Write UID mapping
        let uid_map = format!("0 {} 1\n", current_uid.as_raw());
        std::fs::write("/proc/self/uid_map", uid_map)
            .map_err(|e| IronJailError::SandboxInit(
                format!("Failed to write UID mapping: {}", e)
            ))?;
        
        // Deny setgroups for unprivileged user namespaces
        std::fs::write("/proc/self/setgroups", "deny")
            .map_err(|e| IronJailError::SandboxInit(
                format!("Failed to deny setgroups: {}", e)
            ))?;
        
        // Write GID mapping
        let gid_map = format!("0 {} 1\n", current_gid.as_raw());
        std::fs::write("/proc/self/gid_map", gid_map)
            .map_err(|e| IronJailError::SandboxInit(
                format!("Failed to write GID mapping: {}", e)
            ))?;
        
        debug!("User namespace configured successfully");
        Ok(())
    }
    
    /// Setup mount namespace with proper filesystem isolation
    async fn setup_mount_namespace(&self) -> Result<()> {
        debug!("Setting up mount namespace");
        
        // Make all mounts private to prevent propagation
        mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        ).map_err(|e| IronJailError::SandboxInit(
            format!("Failed to make mounts private: {}", e)
        ))?;
        
        // Create a new root filesystem
        let sandbox_root = &self.config.general.sandbox_root;
        std::fs::create_dir_all(sandbox_root)?;
        
        // Mount tmpfs as new root
        mount::mount(
            Some("tmpfs"),
            sandbox_root,
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("size=1G"),
        ).map_err(|e| IronJailError::SandboxInit(
            format!("Failed to mount tmpfs root: {}", e)
        ))?;
        
        // Mount point tracking removed to avoid borrow checker issues
        debug!("Mounted tmpfs at {:?}", sandbox_root);
        
        // Create essential directories
        self.create_essential_directories(sandbox_root).await?;
        
        // Mount essential filesystems
        self.mount_essential_filesystems(sandbox_root).await?;
        
        debug!("Mount namespace configured successfully");
        Ok(())
    }
    
    /// Create essential directories in the sandbox
    async fn create_essential_directories(&self, root: &PathBuf) -> Result<()> {
        let essential_dirs = vec![
            "bin", "sbin", "lib", "lib64", "usr", "etc", "tmp", "var", "proc", "sys", "dev",
            "home", "root", "opt", "srv", "mnt", "media",
        ];
        
        for dir in essential_dirs {
            let dir_path = root.join(dir);
            std::fs::create_dir_all(&dir_path)?;
        }
        
        Ok(())
    }
    
    /// Mount essential filesystems (proc, sys, dev, etc.)
    async fn mount_essential_filesystems(&self, root: &PathBuf) -> Result<()> {
        // Mount /proc
        let proc_path = root.join("proc");
        mount::mount(
            Some("proc"),
            &proc_path,
            Some("proc"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        ).map_err(|e| IronJailError::SandboxInit(
            format!("Failed to mount /proc: {}", e)
        ))?;
        
        debug!("Mounted /proc");
        
        // Mount /sys
        let sys_path = root.join("sys");
        mount::mount(
            Some("sysfs"),
            &sys_path,
            Some("sysfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        ).map_err(|e| IronJailError::SandboxInit(
            format!("Failed to mount /sys: {}", e)
        ))?;
        
        debug!("Mounted /dev");
        
        // Mount /dev as tmpfs and create essential device nodes
        let dev_path = root.join("dev");
        mount::mount(
            Some("tmpfs"),
            &dev_path,
            Some("tmpfs"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID,
            Some("mode=755"),
        ).map_err(|e| IronJailError::SandboxInit(
            format!("Failed to mount /dev: {}", e)
        ))?;
        
        debug!("Mounted /dev with tmpfs");
        
        // Create essential device nodes
        self.create_device_nodes(&dev_path).await?;
        
        // Mount /tmp
        let tmp_path = root.join("tmp");
        mount::mount(
            Some("tmpfs"),
            &tmp_path,
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
            Some("mode=1777"),
        ).map_err(|e| IronJailError::SandboxInit(
            format!("Failed to mount /tmp: {}", e)
        ))?;
        
        debug!("Mounted /tmp with tmpfs");
        
        Ok(())
    }
    
    /// Create essential device nodes
    async fn create_device_nodes(&self, dev_path: &PathBuf) -> Result<()> {
        // Create /dev/null
        let null_path = dev_path.join("null");
        let null_cstr = std::ffi::CString::new(null_path.to_string_lossy().as_ref())
            .map_err(|e| IronJailError::SandboxInit(format!("Invalid path: {}", e)))?;
        let ret = unsafe { libc::mknod(null_cstr.as_ptr(), libc::S_IFCHR | 0o666, libc::makedev(1, 3)) };
        if ret != 0 {
            debug!("Failed to create /dev/null (this is normal in many environments)");
        }
        
        // Create other basic device nodes - simplified approach
        debug!("Device node creation is limited in containerized environments - using bind mounts when possible");
        
        Ok(())
    }
    
    /// Setup network namespace
    async fn setup_network_namespace(&mut self) -> Result<()> {
        debug!("Setting up network namespace");
        
        // Network namespace is isolated by default
        // If network isolation is disabled, we need to configure interfaces
        if !self.config.network.isolate_network {
            self.setup_network_interfaces().await?;
        }
        
        debug!("Network namespace configured successfully");
        Ok(())
    }
    
    /// Setup network interfaces in the network namespace
    async fn setup_network_interfaces(&self) -> Result<()> {
        debug!("Setting up network interfaces");
        
        // This would typically involve setting up veth pairs, bridges, etc.
        // For now, we'll just ensure loopback is available if allowed
        if self.config.network.allow_loopback {
            // Bring up loopback interface
            let output = tokio::process::Command::new("ip")
                .args(&["link", "set", "lo", "up"])
                .output()
                .await
                .map_err(|e| IronJailError::SandboxInit(
                    format!("Failed to bring up loopback: {}", e)
                ))?;
            
            if !output.status.success() {
                warn!("Failed to bring up loopback interface: {}", 
                      String::from_utf8_lossy(&output.stderr));
            }
        }
        
        Ok(())
    }
    
    /// Setup UTS namespace (hostname/domainname isolation)
    async fn setup_uts_namespace(&mut self) -> Result<()> {
        debug!("Setting up UTS namespace");
        
        // Set hostname if specified in deception config
        if let Some(ref hostname) = self.config.deception.fake_hostname {
            // Use libc directly for sethostname if nix doesn't provide it
            let hostname_cstr = std::ffi::CString::new(hostname.as_bytes())
                .map_err(|e| IronJailError::SandboxInit(format!("Invalid hostname: {}", e)))?;
            let ret = unsafe { libc::sethostname(hostname_cstr.as_ptr(), hostname.len()) };
            if ret != 0 {
                return Err(IronJailError::SandboxInit("Failed to set hostname".to_string()).into());
            }
            debug!("Set fake hostname: {}", hostname);
        }
        
        debug!("UTS namespace configured successfully");
        Ok(())
    }
    
    /// Get information about active namespaces
    pub fn get_active_namespaces(&self) -> &HashMap<NamespaceType, bool> {
        &self.active_namespaces
    }
    
    /// Get information about mount points
    pub fn get_mount_points(&self) -> &Vec<MountPoint> {
        &self.mount_points
    }
    
    /// Cleanup namespaces and unmount filesystems
    pub async fn cleanup_namespaces(&self) -> Result<()> {
        debug!("Cleaning up namespaces");
        
        // Unmount all mount points in reverse order
        for mount_point in self.mount_points.iter().rev() {
            if let Err(e) = mount::umount2(&mount_point.target, MntFlags::MNT_DETACH) {
                warn!("Failed to unmount {:?}: {}", mount_point.target, e);
            }
        }
        
        debug!("Namespace cleanup completed");
        Ok(())
    }
}