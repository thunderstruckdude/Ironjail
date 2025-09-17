use crate::{Result, IronJailError};
use crate::core::{SandboxConfig, DecoyFile};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn, error};

/// Environment deception system to make malware think it's in a real system
pub struct EnvironmentDeception {
    config: SandboxConfig,
    fake_proc_files: HashMap<PathBuf, String>,
    fake_sys_files: HashMap<PathBuf, String>,
    decoy_files: Vec<DecoyFile>,
    original_values: HashMap<String, String>,
}

impl EnvironmentDeception {
    /// Create a new environment deception system
    pub fn new(config: &SandboxConfig) -> Result<Self> {
        let mut deception = Self {
            config: config.clone(),
            fake_proc_files: HashMap::new(),
            fake_sys_files: HashMap::new(),
            decoy_files: config.deception.decoy_files.clone(),
            original_values: HashMap::new(),
        };
        
        deception.prepare_fake_proc_files();
        deception.prepare_fake_sys_files();
        
        Ok(deception)
    }
    
    /// Setup the deception environment
    pub async fn setup_deception_environment(&mut self, session_id: &str) -> Result<()> {
        info!("Setting up environment deception for session: {}", session_id);
        
        // Create fake /proc files
        self.create_fake_proc_files().await?;
        
        // Create fake /sys files
        self.create_fake_sys_files().await?;
        
        // Create decoy files
        self.create_decoy_files().await?;
        
        // Set fake environment variables
        self.set_fake_environment_variables().await?;
        
        // Setup network deception
        self.setup_network_deception().await?;
        
        info!("Environment deception setup completed");
        Ok(())
    }
    
    /// Prepare fake /proc file contents
    fn prepare_fake_proc_files(&mut self) {
        // Fake CPU information to make it look like a different system
        let fake_cpuinfo = r#"processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
stepping	: 12
microcode	: 0xf0
cpu MHz		: 1800.000
cache size	: 8192 KB
physical id	: 0
siblings	: 8
core id		: 0
cpu cores	: 4
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d arch_capabilities
bugs		: spectre_v1 spectre_v2 spec_store_bypass swapgs itlb_multihit srbds
bogomips	: 3999.93
clflush size	: 64
cache_alignment	: 64
address sizes	: 39 bits physical, 48 bits virtual
power management:
"#;
        
        self.fake_proc_files.insert(
            PathBuf::from("/proc/cpuinfo"),
            fake_cpuinfo.to_string(),
        );
        
        // Fake memory information
        let fake_meminfo = r#"MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   12288000 kB
Buffers:          512000 kB
Cached:          3072000 kB
SwapCached:            0 kB
Active:          4096000 kB
Inactive:        2048000 kB
Active(anon):    2048000 kB
Inactive(anon):   512000 kB
Active(file):    2048000 kB
Inactive(file):  1536000 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:       2097152 kB
SwapFree:        2097152 kB
Dirty:               256 kB
Writeback:             0 kB
AnonPages:       2048000 kB
Mapped:           512000 kB
Shmem:            256000 kB
KReclaimable:     256000 kB
Slab:             512000 kB
SReclaimable:     256000 kB
SUnreclaim:       256000 kB
KernelStack:       32000 kB
PageTables:        64000 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:    10239000 kB
Committed_AS:    4096000 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       32000 kB
VmallocChunk:          0 kB
Percpu:             8192 kB
HardwareCorrupted:     0 kB
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
CmaTotal:              0 kB
CmaFree:               0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
DirectMap4k:      262144 kB
DirectMap2M:     8126464 kB
DirectMap1G:     8388608 kB
"#;
        
        self.fake_proc_files.insert(
            PathBuf::from("/proc/meminfo"),
            fake_meminfo.to_string(),
        );
        
        // Fake version information
        let fake_version = "Linux version 5.15.0-76-generic (buildd@lcy02-amd64-089) (gcc (Ubuntu 11.4.0-1ubuntu1) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #83-Ubuntu SMP Thu Jun 15 19:16:32 UTC 2023";
        
        self.fake_proc_files.insert(
            PathBuf::from("/proc/version"),
            fake_version.to_string(),
        );
        
        // Add more fake proc files from config
        for (path, content) in &self.config.deception.fake_proc {
            self.fake_proc_files.insert(
                PathBuf::from(path),
                content.clone(),
            );
        }
    }
    
    /// Prepare fake /sys file contents
    fn prepare_fake_sys_files(&mut self) {
        // Fake DMI information
        let fake_dmi_vendor = "Dell Inc.";
        let fake_dmi_product = "OptiPlex 7090";
        let fake_dmi_version = "1.0.0";
        
        self.fake_sys_files.insert(
            PathBuf::from("/sys/class/dmi/id/sys_vendor"),
            fake_dmi_vendor.to_string(),
        );
        
        self.fake_sys_files.insert(
            PathBuf::from("/sys/class/dmi/id/product_name"),
            fake_dmi_product.to_string(),
        );
        
        self.fake_sys_files.insert(
            PathBuf::from("/sys/class/dmi/id/product_version"),
            fake_dmi_version.to_string(),
        );
        
        // Add more fake sys files from config
        for (path, content) in &self.config.deception.fake_sys {
            self.fake_sys_files.insert(
                PathBuf::from(path),
                content.clone(),
            );
        }
    }
    
    /// Create fake /proc files
    async fn create_fake_proc_files(&self) -> Result<()> {
        debug!("Creating fake /proc files");
        
        for (path, content) in &self.fake_proc_files {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            
            tokio::fs::write(path, content).await
                .map_err(|e| IronJailError::SandboxInit(
                    format!("Failed to create fake proc file {:?}: {}", path, e)
                ))?;
            
            debug!("Created fake proc file: {:?}", path);
        }
        
        Ok(())
    }
    
    /// Create fake /sys files
    async fn create_fake_sys_files(&self) -> Result<()> {
        debug!("Creating fake /sys files");
        
        for (path, content) in &self.fake_sys_files {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            
            tokio::fs::write(path, content).await
                .map_err(|e| IronJailError::SandboxInit(
                    format!("Failed to create fake sys file {:?}: {}", path, e)
                ))?;
            
            debug!("Created fake sys file: {:?}", path);
        }
        
        Ok(())
    }
    
    /// Create decoy files to entice malware
    async fn create_decoy_files(&self) -> Result<()> {
        debug!("Creating decoy files");
        
        // Create default decoy files if none specified
        let default_decoys = vec![
            DecoyFile {
                path: PathBuf::from("/home/user/Documents/passwords.txt"),
                content: "admin:password123\nuser:qwerty\nroot:toor\n".to_string(),
                permissions: Some(0o600),
                monitor_access: true,
            },
            DecoyFile {
                path: PathBuf::from("/home/user/Documents/private_key.pem"),
                content: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----\n".to_string(),
                permissions: Some(0o600),
                monitor_access: true,
            },
            DecoyFile {
                path: PathBuf::from("/home/user/Documents/credit_cards.txt"),
                content: "4111111111111111\n5555555555554444\n378282246310005\n".to_string(),
                permissions: Some(0o600),
                monitor_access: true,
            },
        ];
        
        let decoys = if self.decoy_files.is_empty() {
            &default_decoys
        } else {
            &self.decoy_files
        };
        
        for decoy in decoys {
            if let Some(parent) = decoy.path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            
            tokio::fs::write(&decoy.path, &decoy.content).await
                .map_err(|e| IronJailError::SandboxInit(
                    format!("Failed to create decoy file {:?}: {}", decoy.path, e)
                ))?;
            
            // Set permissions if specified
            if let Some(mode) = decoy.permissions {
                use std::os::unix::fs::PermissionsExt;
                let permissions = std::fs::Permissions::from_mode(mode);
                tokio::fs::set_permissions(&decoy.path, permissions).await
                    .map_err(|e| IronJailError::SandboxInit(
                        format!("Failed to set permissions for decoy file {:?}: {}", decoy.path, e)
                    ))?;
            }
            
            debug!("Created decoy file: {:?}", decoy.path);
        }
        
        Ok(())
    }
    
    /// Set fake environment variables
    async fn set_fake_environment_variables(&mut self) -> Result<()> {
        debug!("Setting fake environment variables");
        
        // Default fake environment variables
        let default_env = vec![
            ("USER", "user"),
            ("HOME", "/home/user"),
            ("SHELL", "/bin/bash"),
            ("LANG", "en_US.UTF-8"),
            ("PWD", "/home/user"),
            ("DISPLAY", ":0"),
            ("TERM", "xterm-256color"),
        ];
        
        for (key, value) in default_env {
            // Store original value
            if let Ok(original) = std::env::var(key) {
                self.original_values.insert(key.to_string(), original);
            }
            
            std::env::set_var(key, value);
            debug!("Set fake environment variable: {}={}", key, value);
        }
        
        // Set custom fake environment variables from config
        for (key, value) in &self.config.deception.fake_env {
            // Store original value
            if let Ok(original) = std::env::var(key) {
                self.original_values.insert(key.to_string(), original);
            }
            
            std::env::set_var(key, value);
            debug!("Set custom fake environment variable: {}={}", key, value);
        }
        
        Ok(())
    }
    
    /// Setup network deception (fake DNS responses, redirects, etc.)
    async fn setup_network_deception(&self) -> Result<()> {
        debug!("Setting up network deception");
        
        // This would involve setting up iptables rules, DNS redirects, etc.
        // For now, we'll just log the network redirects that would be applied
        for redirect in &self.config.deception.network_redirects {
            info!("Network redirect configured: {} -> {} ({}:{})", 
                  redirect.original, redirect.redirect_to, redirect.protocol, redirect.port);
        }
        
        Ok(())
    }
    
    /// Check if a file path should be intercepted and provide fake content
    pub fn intercept_file_access(&self, path: &Path) -> Option<String> {
        if let Some(content) = self.fake_proc_files.get(path) {
            return Some(content.clone());
        }
        
        if let Some(content) = self.fake_sys_files.get(path) {
            return Some(content.clone());
        }
        
        None
    }
    
    /// Check if a network connection should be redirected
    pub fn intercept_network_connection(&self, destination: &str, port: u16) -> Option<(String, u16)> {
        for redirect in &self.config.deception.network_redirects {
            if redirect.original == destination || 
               (redirect.port == 0 || redirect.port == port) {
                return Some((redirect.redirect_to.clone(), 
                           if redirect.port == 0 { port } else { redirect.port }));
            }
        }
        
        None
    }
    
    /// Get information about access to decoy files
    pub fn get_decoy_file_access(&self, path: &Path) -> Option<&DecoyFile> {
        self.decoy_files.iter()
            .find(|decoy| decoy.path == path && decoy.monitor_access)
    }
    
    /// Cleanup deception environment
    pub async fn cleanup(&mut self) -> Result<()> {
        debug!("Cleaning up environment deception");
        
        // Restore original environment variables
        for (key, value) in &self.original_values {
            std::env::set_var(key, value);
        }
        
        // Remove fake files (optional, based on configuration)
        if !self.config.general.verbose_logging {
            for path in self.fake_proc_files.keys() {
                let _ = tokio::fs::remove_file(path).await;
            }
            
            for path in self.fake_sys_files.keys() {
                let _ = tokio::fs::remove_file(path).await;
            }
            
            for decoy in &self.decoy_files {
                let _ = tokio::fs::remove_file(&decoy.path).await;
            }
        }
        
        debug!("Environment deception cleanup completed");
        Ok(())
    }
}