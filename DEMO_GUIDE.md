# IronJail Demo Guide for Expo/Conference

## 🎯 Executive Summary
IronJail is an advanced malware analysis sandbox built in Rust that provides comprehensive behavioral analysis of suspicious binaries in an isolated environment.

## 🚀 Quick Demo Script (5-10 minutes)

### 1. Introduction (30 seconds)
"IronJail is a next-generation malware analysis sandbox that isolates and monitors suspicious binaries to understand their behavior without compromising your system."

### 2. Live Demo Setup (1 minute)

#### Create a sample "malicious" script for demo:
```bash
# Create demo directory
mkdir -p ~/demo-samples
cd ~/demo-samples

# Create a harmless "suspicious" script that simulates malware behavior
cat > suspicious_script.sh << 'EOF'
#!/bin/bash
echo "Simulated malware starting..."
sleep 1

# File operations
echo "secret data" > /tmp/stolen_data.txt
mkdir -p /tmp/malware_dir
touch /tmp/malware_dir/payload.bin

# Network simulation (will fail in sandbox)
echo "Attempting network connection..."
ping -c 1 google.com 2>/dev/null || echo "Network blocked by sandbox"

# Process enumeration
ps aux | head -5

echo "Malware simulation complete"
EOF

chmod +x suspicious_script.sh
```

### 3. Core Demo (3-4 minutes)

#### Step 1: Generate Policy
```bash
cd ~/demo-samples
ironjail generate-policy
# Show the policy file contents
cat policy.yaml
```

#### Step 2: Run Analysis
```bash
# Run the "malware" in sandbox
ironjail run ./suspicious_script.sh --policy policy.yaml --output demo-results
```

#### Step 3: Show Results
```bash
# List sessions
ironjail list

# Generate HTML report
ironjail report [SESSION_ID] html

# Open report in browser (prepare this beforehand)
```

### 4. Key Features Highlight (2-3 minutes)

#### Show the generated HTML report highlighting:
- **Timeline visualization** of all activities
- **System call tracing** (show syscall logs)
- **File system monitoring** (files created/modified)
- **Network activity** (blocked connections)
- **Process isolation** metrics
- **Threat assessment** scores

### 5. Technical Deep Dive (Optional - for technical audience)

#### Architecture Overview:
```bash
# Show project structure
tree src/ -L 2

# Highlight key components
echo "Core Components:"
echo "- Namespace isolation (Linux containers)"
echo "- Ptrace system call tracing"
echo "- Inotify file monitoring"
echo "- Seccomp-BPF filtering"
echo "- Environment deception"
```

## 🎪 Expo Booth Setup

### Visual Setup
1. **Large Monitor/TV** displaying the HTML report dashboard
2. **Laptop** for live demos
3. **Infographic poster** showing IronJail architecture
4. **QR code** linking to GitHub repository

### Interactive Elements

#### Create a "Malware Zoo" for demos:
```bash
mkdir -p ~/expo-samples

# Benign but "suspicious-looking" samples
cat > ~/expo-samples/crypto_miner.sh << 'EOF'
#!/bin/bash
echo "Mining cryptocurrency..."
for i in {1..5}; do
    echo "Hash $i: $(date | md5sum)"
    sleep 1
done
EOF

cat > ~/expo-samples/data_exfiltrator.py << 'EOF'
#!/usr/bin/env python3
import os
import time

print("Scanning for sensitive files...")
for root, dirs, files in os.walk("/tmp"):
    for file in files[:3]:  # Limit for demo
        print(f"Found: {os.path.join(root, file)}")
        time.sleep(0.5)

print("Attempting data upload...")
print("Connection to attacker server: BLOCKED")
EOF

cat > ~/expo-samples/system_info.sh << 'EOF'
#!/bin/bash
echo "Gathering system information..."
uname -a
whoami
id
echo "Process enumeration:"
ps aux | head -10
echo "Network interfaces:"
ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Network enumeration blocked"
EOF

chmod +x ~/expo-samples/*
```

### 📊 Talking Points & Value Propositions

#### For Security Teams:
- "Analyze unknown binaries safely without risking your infrastructure"
- "Get detailed behavioral reports in minutes, not hours"
- "Built-in evasion detection prevents sandbox-aware malware"

#### For Researchers:
- "Open-source Rust implementation for customization"
- "Comprehensive API for integration with existing tools"
- "Export data in multiple formats (JSON, HTML, CSV)"

#### For Enterprises:
- "Zero-trust analysis of email attachments and downloads"
- "Automated threat hunting and IOC extraction"
- "Compliance reporting for security audits"

## 🎭 Demo Scenarios

### Scenario 1: "Email Attachment Analysis"
```bash
# Simulate analyzing a suspicious email attachment
ironjail run ~/expo-samples/crypto_miner.sh --timeout 30 --verbose
```
*Highlight*: File creation, network attempts, resource usage

### Scenario 2: "Unknown Binary Investigation"  
```bash
# Analyze system information gathering
ironjail run ~/expo-samples/system_info.sh --policy restrictive-policy.yaml
```
*Highlight*: System call filtering, information leakage prevention

### Scenario 3: "Data Exfiltration Detection"
```bash
# Python malware simulation
ironjail run ~/expo-samples/data_exfiltrator.py --network-isolation
```
*Highlight*: Network blocking, file access monitoring

## 🎬 Presentation Slides Outline

### Slide 1: Problem Statement
- "73% of organizations can't analyze suspicious files safely"
- "Traditional solutions are slow, expensive, or incomplete"

### Slide 2: IronJail Solution
- "Fast, accurate, open-source malware analysis"
- "Built with modern Rust for performance and safety"

### Slide 3: Key Features
- Process isolation, System call tracing, File monitoring
- Network capture, Environment deception, Policy engine

### Slide 4: Live Demo
- [Run live demo here]

### Slide 5: Results Dashboard
- [Show HTML report visualization]

### Slide 6: Technical Innovation
- "First Rust-based sandbox with full Linux namespace isolation"
- "Sub-second analysis startup time"
- "Comprehensive behavioral profiling"

### Slide 7: Use Cases
- Incident response, Threat hunting, Security research
- Email security, Endpoint protection, Forensics

### Slide 8: Open Source & Community
- GitHub repository, Documentation, Contributing

## 📋 Preparation Checklist

### Before the Expo:
- [ ] Test all demo scripts thoroughly
- [ ] Pre-generate sample reports for backup
- [ ] Prepare offline version in case of network issues
- [ ] Create business cards with GitHub QR code
- [ ] Prepare technical FAQ document
- [ ] Test on the exact hardware you'll use

### Materials to Bring:
- [ ] Laptop with IronJail installed
- [ ] HDMI/USB-C adapters for displays
- [ ] Demo samples prepared
- [ ] Printed architecture diagrams
- [ ] Business cards/flyers
- [ ] Power cables and backup battery

### Backup Plans:
- [ ] Pre-recorded demo video
- [ ] Static screenshots of reports
- [ ] Offline presentation slides
- [ ] Sample report files to show

## 🎤 Elevator Pitch (30 seconds)
"IronJail is like having a bulletproof lab for analyzing suspicious files. Drop in any binary, and within seconds you get a complete behavioral report showing exactly what it tried to do - file access, network connections, system changes - all safely isolated from your real system. It's open-source, lightning-fast, and built for security teams who need answers now, not later."

## 📈 Success Metrics
- Number of live demos performed
- GitHub stars/forks gained
- Contact information collected
- Follow-up meeting requests
- Technical questions answered

Remember: Focus on the problem you're solving, not just the technology. Show real value through practical demonstrations!