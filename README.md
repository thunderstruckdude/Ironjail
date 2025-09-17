# IronJail - Advanced Malware Analysis Sandbox

<p align="center">
  <img src="docs/assets/ironjail-logo.png" alt="IronJail Logo" width="200"/>
</p>

<p align="center">
  <strong>A comprehensive, Rust-based malware analysis sandbox with advanced anti-detection capabilities</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#documentation">Documentation</a>
</p>

---

## 🛡️ Overview

IronJail is a modern, high-performance malware analysis sandbox built in Rust. It provides comprehensive monitoring and containment capabilities while being easier to use than traditional solutions like Firejail or AppArmor, yet maintaining advanced features for security researchers and analysts.

### Why IronJail?

- **🔒 Advanced Containment**: Linux namespace isolation with custom security policies
- **👁️ Comprehensive Monitoring**: System calls, file activities, network communications
- **🎭 Anti-Detection**: Environment deception to evade sandbox-aware malware
- **📊 Rich Reporting**: Interactive HTML reports with timeline visualization and threat assessment
- **⚡ High Performance**: Rust-based implementation with minimal overhead
- **🛠️ Easy Configuration**: YAML/JSON policy files with built-in templates

## ✨ Features

### Core Sandbox Capabilities
- **Process Isolation**: Linux namespaces (user, PID, network, mount, IPC, UTS)
- **System Call Tracing**: ptrace-based syscall monitoring with argument interpretation
- **Resource Limits**: CPU, memory, disk, and network bandwidth controls
- **Capability Management**: Fine-grained privilege dropping and capability control

### Monitoring & Analysis
- **📞 System Call Monitoring**: Comprehensive syscall tracing with strace-like functionality
- **📁 File System Monitoring**: Real-time file activity tracking with inotify
- **🌐 Network Monitoring**: Packet capture and network activity analysis
- **🔍 Process Monitoring**: Process creation, termination, and resource usage tracking

### Environment Deception
- **🎪 Fake System Information**: Deceptive `/proc` and `/sys` filesystem entries
- **🗂️ Decoy Files**: Realistic filesystem structure to fool analysis-aware malware
- **🔧 Hardware Spoofing**: CPU, memory, and system information manipulation
- **🌍 Network Deception**: Fake network interfaces and routing tables

### Policy & Configuration
- **📋 Policy-Driven**: YAML/JSON configuration files for flexible security policies
- **📚 Built-in Templates**: Pre-configured policies for different analysis scenarios
- **🔧 Custom Rules**: File access, network access, syscall filtering, and resource limits
- **✅ Policy Validation**: Built-in validation and testing for policy configurations

### Reporting & Visualization
- **📄 JSON Export**: Machine-readable analysis results for automation
- **🌐 HTML Reports**: Interactive web-based reports with charts and timelines
- **📈 Threat Assessment**: Automated behavioral analysis and risk scoring
- **🎯 MITRE ATT&CK**: Technique detection and mapping to the MITRE framework
- **📊 Timeline Visualization**: Chronological view of all activities

## 🚀 Installation

### Prerequisites

- Linux operating system (kernel 3.8+ for namespace support)
- Rust 1.70+ (for building from source)
- Root privileges (for namespace creation and ptrace)

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/ironjail.git
cd ironjail

# Build in release mode
cargo build --release

# Install to system
sudo cp target/release/ironjail /usr/local/bin/
sudo chmod +x /usr/local/bin/ironjail
```

### Using Cargo

```bash
cargo install ironjail
```

### Package Managers

```bash
# Debian/Ubuntu (coming soon)
apt install ironjail

# Arch Linux (AUR)
yay -S ironjail

# Fedora/RHEL (coming soon)
dnf install ironjail
```

## 📖 Usage

### Basic Analysis

```bash
# Analyze a binary with default settings
sudo ironjail run /path/to/suspicious/binary

# Analyze with custom arguments
sudo ironjail run /bin/ls -- -la /etc

# Use a specific policy
sudo ironjail run --policy strict /path/to/malware.exe

# Generate reports in specific formats
sudo ironjail run --report-format both --output /tmp/reports /path/to/binary
```

### Advanced Usage

```bash
# Enable environment deception
sudo ironjail run --enable-deception --policy malware-analysis /path/to/sample

# Custom timeout and resource limits
sudo ironjail run --timeout 300 --memory-limit 1G --cpu-limit 50 /path/to/binary

# Network monitoring with packet capture
sudo ironjail run --enable-network-monitoring --pcap-file capture.pcap /path/to/binary

# Custom configuration file
sudo ironjail run --config /path/to/custom-config.yaml /path/to/binary
```

### Policy Management

```bash
# Generate a new policy template
ironjail generate-policy --template strict --output my-policy.yaml

# Validate a policy file
ironjail validate --policy my-policy.yaml

# List available policy templates
ironjail generate-policy --list-templates
```

### Report Management

```bash
# List previous analysis sessions
ironjail report list

# Generate report for specific session
ironjail report generate --session abc123 --format html

# Clean up old reports
ironjail report cleanup --older-than 30d
```

## ⚙️ Configuration

### Policy Configuration

IronJail uses YAML or JSON configuration files to define security policies:

```yaml
# example-policy.yaml
name: "Custom Analysis Policy"
description: "Policy for analyzing suspicious binaries"

# Sandbox settings
sandbox:
  timeout_seconds: 300
  enable_network: true
  enable_deception: true
  working_directory: "/tmp/sandbox"

# Resource limits
resources:
  memory_limit: "1GB"
  cpu_limit_percent: 50
  disk_quota: "500MB"
  max_processes: 50

# File access rules
file_access:
  allowed_read:
    - "/lib/**"
    - "/usr/lib/**"
    - "/etc/ld.so.cache"
  allowed_write:
    - "/tmp/**"
    - "/var/tmp/**"
  blocked_paths:
    - "/etc/passwd"
    - "/etc/shadow"
    - "/root/**"

# Network access rules
network_access:
  allowed_ports: [80, 443, 53]
  blocked_ips:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
  dns_servers: ["8.8.8.8", "1.1.1.1"]

# System call filtering
syscall_rules:
  blocked_syscalls:
    - "ptrace"
    - "mount"
    - "umount"
  monitored_syscalls:
    - "open"
    - "write"
    - "connect"
    - "execve"

# Monitoring settings
monitoring:
  capture_syscalls: true
  capture_network: true
  capture_files: true
  pcap_enabled: true
  
# Deception settings
deception:
  fake_cpu_count: 4
  fake_memory_total: "8GB"
  fake_hostname: "analysis-machine"
  decoy_files:
    - "/home/user/documents/passwords.txt"
    - "/home/user/desktop/important.doc"
```

### Environment Variables

```bash
# Set default configuration directory
export IRONJAIL_CONFIG_DIR="/etc/ironjail"

# Set default output directory
export IRONJAIL_OUTPUT_DIR="/var/log/ironjail"

# Enable debug logging
export RUST_LOG=debug

# Set custom policy directory
export IRONJAIL_POLICY_DIR="/opt/ironjail/policies"
```

## 📊 Report Examples

### JSON Report Structure

```json
{
  "session_id": "analysis_20231201_143052_abc123",
  "binary": "/path/to/analyzed/binary",
  "start_timestamp": "2023-12-01T14:30:52Z",
  "duration": 120,
  "exit_code": 0,
  "threat_assessment": {
    "threat_level": 6,
    "risk_category": "High",
    "behavioral_indicators": [
      {
        "indicator_type": "Process Injection",
        "description": "Potential process injection detected",
        "severity": 4,
        "confidence": 90,
        "evidence": ["ptrace system calls observed"]
      }
    ],
    "mitre_techniques": [
      {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion"
      }
    ]
  },
  "statistics": {
    "total_syscalls": 1547,
    "total_file_activities": 23,
    "total_network_activities": 5,
    "unique_files_accessed": 12
  }
}
```

### HTML Report Features

- **Interactive Timeline**: Chronological view of all activities
- **Threat Assessment Dashboard**: Visual risk indicators and recommendations
- **Detailed Activity Tables**: Sortable and filterable data tables
- **Charts and Graphs**: Statistical visualizations of analysis data
- **MITRE ATT&CK Mapping**: Detected techniques with evidence
- **IOC Extraction**: Identified indicators of compromise

## 🏗️ Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                        IronJail Core                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Sandbox   │  │   Policy    │  │      Monitoring     │ │
│  │   Engine    │  │   Manager   │  │       System        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Tracing   │  │  Deception  │  │      Reporting      │ │
│  │   System    │  │    Layer    │  │       System        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Linux Kernel APIs                       │
│         (namespaces, ptrace, inotify, netfilter)           │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

- **Core Language**: Rust 2021 Edition
- **Async Runtime**: Tokio for concurrent operations
- **System Integration**: nix crate for Linux system calls
- **Monitoring**: inotify, ptrace, netlink sockets
- **Network Capture**: libpcap integration
- **Serialization**: serde with JSON/YAML support
- **Templating**: Handlebars for HTML report generation
- **CLI**: clap for command-line interface

## 🔧 Development

### Building from Source

```bash
# Clone and enter directory
git clone https://github.com/your-org/ironjail.git
cd ironjail

# Install development dependencies
sudo apt-get install build-essential libpcap-dev

# Run tests
cargo test

# Build with all features
cargo build --release --all-features

# Run with development logging
RUST_LOG=debug cargo run -- run /bin/echo hello
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration

# Run with coverage
cargo tarpaulin --out Html

# Benchmark performance
cargo bench
```

## 📚 Documentation

- [User Guide](docs/user-guide.md) - Comprehensive usage documentation
- [Policy Configuration](docs/policy-configuration.md) - Policy file reference
- [API Documentation](docs/api.md) - Rust API documentation
- [Architecture Guide](docs/architecture.md) - Technical architecture details
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions

## 🤝 Community

- [GitHub Issues](https://github.com/your-org/ironjail/issues) - Bug reports and feature requests
- [Discussions](https://github.com/your-org/ironjail/discussions) - Community discussions
- [Security Advisory](https://github.com/your-org/ironjail/security/advisories) - Security reports

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Linux kernel developers for namespace and security features
- The Rust community for excellent crates and tooling
- Security researchers who provided feedback and testing
- Open source projects that inspired this work

## 🔒 Security

If you discover a security vulnerability, please send an email to security@ironjail.dev. All security vulnerabilities will be promptly addressed.

---

<p align="center">
  Made with ❤️ by the IronJail team
</p>