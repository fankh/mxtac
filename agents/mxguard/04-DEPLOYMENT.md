# MxGuard - Deployment Guide

> **Version**: 1.0
> **Date**: 2026-01-19
> **Target**: System Administrators, DevOps Engineers

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Installation](#2-installation)
3. [Service Configuration](#3-service-configuration)
4. [Verification](#4-verification)
5. [Upgrading](#5-upgrading)
6. [Uninstallation](#6-uninstallation)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. System Requirements

### 1.1 Minimum Requirements

| Resource | Linux | Windows | macOS |
|----------|-------|---------|-------|
| **OS Version** | RHEL 7+, Ubuntu 18.04+ | Windows 10, Server 2016+ | macOS 10.15+ |
| **CPU** | 1 core @ 1 GHz | 1 core @ 1 GHz | 1 core @ 1 GHz |
| **Memory** | 50 MB | 50 MB | 50 MB |
| **Disk** | 100 MB | 100 MB | 100 MB |
| **Kernel** | 3.10+ | N/A | N/A |

### 1.2 Recommended Requirements

| Resource | Specification |
|----------|---------------|
| **CPU** | 2 cores @ 2 GHz |
| **Memory** | 100 MB |
| **Disk** | 1 GB (with log retention) |
| **Network** | 100 Kbps sustained |

### 1.3 Required Permissions

**Linux/macOS**:
- Root access (for system-wide monitoring)
- CAP_NET_RAW (for network packet capture, optional)

**Windows**:
- Administrator privileges
- SeDebugPrivilege (for process monitoring)

---

## 2. Installation

### 2.1 Linux Installation

#### Method 1: Package Manager (Recommended)

**Debian/Ubuntu**:
```bash
# Add MxTac repository
curl -fsSL https://packages.mxtac.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/mxtac-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/mxtac-archive-keyring.gpg] https://packages.mxtac.io/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/mxtac.list

# Install MxGuard
sudo apt update
sudo apt install mxguard
```

**RHEL/CentOS/Fedora**:
```bash
# Add MxTac repository
sudo tee /etc/yum.repos.d/mxtac.repo <<EOF
[mxtac]
name=MxTac Repository
baseurl=https://packages.mxtac.io/yum/
enabled=1
gpgcheck=1
gpgkey=https://packages.mxtac.io/gpg
EOF

# Install MxGuard
sudo yum install mxguard
```

#### Method 2: Manual Installation

```bash
# Download latest release
LATEST_VERSION=$(curl -s https://api.github.com/repos/mxtac/mxguard/releases/latest | grep tag_name | cut -d '"' -f 4)
wget "https://github.com/mxtac/mxguard/releases/download/${LATEST_VERSION}/mxguard-linux-amd64"

# Verify checksum
wget "https://github.com/mxtac/mxguard/releases/download/${LATEST_VERSION}/checksums.txt"
sha256sum -c checksums.txt --ignore-missing

# Install binary
chmod +x mxguard-linux-amd64
sudo mv mxguard-linux-amd64 /usr/local/bin/mxguard

# Create directories
sudo mkdir -p /etc/mxguard
sudo mkdir -p /var/lib/mxguard
sudo mkdir -p /var/log/mxguard

# Create user
sudo useradd -r -s /bin/false mxguard

# Set permissions
sudo chown -R mxguard:mxguard /var/lib/mxguard
sudo chown -R mxguard:mxguard /var/log/mxguard
```

#### Method 3: Installation Script

```bash
# Download and run installation script
curl -fsSL https://install.mxtac.io/mxguard.sh | sudo bash

# Or with custom options
curl -fsSL https://install.mxtac.io/mxguard.sh | sudo bash -s -- \
  --version v1.0.0 \
  --config /etc/mxguard/config.yaml \
  --api-key "${MXGUARD_API_KEY}"
```

### 2.2 Windows Installation

#### Method 1: MSI Installer (Recommended)

```powershell
# Download MSI installer
Invoke-WebRequest -Uri "https://github.com/mxtac/mxguard/releases/latest/download/mxguard-windows-amd64.msi" -OutFile "mxguard.msi"

# Install silently
msiexec /i mxguard.msi /quiet /qn /norestart

# Or with custom options
msiexec /i mxguard.msi /quiet INSTALLDIR="C:\MxGuard" API_KEY="${env:MXGUARD_API_KEY}"
```

#### Method 2: Manual Installation

```powershell
# Download binary
Invoke-WebRequest -Uri "https://github.com/mxtac/mxguard/releases/latest/download/mxguard-windows-amd64.exe" -OutFile "mxguard.exe"

# Create directories
New-Item -ItemType Directory -Path "C:\Program Files\MxGuard" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\MxGuard" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\MxGuard\logs" -Force

# Move binary
Move-Item -Path "mxguard.exe" -Destination "C:\Program Files\MxGuard\mxguard.exe" -Force

# Install as Windows service
& "C:\Program Files\MxGuard\mxguard.exe" service install --config "C:\ProgramData\MxGuard\config.yaml"

# Start service
Start-Service MxGuard
```

### 2.3 macOS Installation

#### Method 1: Homebrew (Recommended)

```bash
# Add MxTac tap
brew tap mxtac/tap

# Install MxGuard
brew install mxguard

# Start service
brew services start mxguard
```

#### Method 2: Manual Installation

```bash
# Download binary
LATEST_VERSION=$(curl -s https://api.github.com/repos/mxtac/mxguard/releases/latest | grep tag_name | cut -d '"' -f 4)

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    BINARY="mxguard-darwin-arm64"
else
    BINARY="mxguard-darwin-amd64"
fi

curl -L "https://github.com/mxtac/mxguard/releases/download/${LATEST_VERSION}/${BINARY}" -o mxguard

# Install binary
chmod +x mxguard
sudo mv mxguard /usr/local/bin/

# Create directories
sudo mkdir -p /usr/local/etc/mxguard
sudo mkdir -p /usr/local/var/lib/mxguard
sudo mkdir -p /usr/local/var/log/mxguard
```

---

## 3. Service Configuration

### 3.1 Linux (systemd)

```bash
# Create systemd service file
sudo tee /etc/systemd/system/mxguard.service <<EOF
[Unit]
Description=MxGuard EDR Agent
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/mxguard --config /etc/mxguard/config.yaml
Restart=on-failure
RestartSec=10
User=root
Group=root

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mxguard /var/log/mxguard

# Resource limits
LimitNOFILE=8192
CPUQuota=10%
MemoryLimit=200M

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable mxguard
sudo systemctl start mxguard

# Check status
sudo systemctl status mxguard
```

### 3.2 Linux (init.d)

```bash
# Create init.d script
sudo tee /etc/init.d/mxguard <<'EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          mxguard
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: MxGuard EDR Agent
### END INIT INFO

DAEMON=/usr/local/bin/mxguard
CONFIG=/etc/mxguard/config.yaml
PIDFILE=/var/run/mxguard.pid

case "$1" in
    start)
        echo "Starting MxGuard..."
        $DAEMON --config $CONFIG --daemon --pid-file $PIDFILE
        ;;
    stop)
        echo "Stopping MxGuard..."
        kill $(cat $PIDFILE)
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        if [ -f $PIDFILE ]; then
            echo "MxGuard is running (PID: $(cat $PIDFILE))"
        else
            echo "MxGuard is not running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
EOF

# Make executable
sudo chmod +x /etc/init.d/mxguard

# Enable and start
sudo update-rc.d mxguard defaults
sudo service mxguard start
```

### 3.3 Windows Service

```powershell
# Install Windows service
& "C:\Program Files\MxGuard\mxguard.exe" service install `
  --name "MxGuard" `
  --display-name "MxGuard EDR Agent" `
  --description "Endpoint detection and response agent for MxTac platform" `
  --config "C:\ProgramData\MxGuard\config.yaml"

# Set service to start automatically
Set-Service -Name MxGuard -StartupType Automatic

# Start service
Start-Service MxGuard

# Check status
Get-Service MxGuard
```

### 3.4 macOS (launchd)

```bash
# Create launchd plist
sudo tee /Library/LaunchDaemons/com.mxtac.mxguard.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mxtac.mxguard</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/mxguard</string>
        <string>--config</string>
        <string>/usr/local/etc/mxguard/config.yaml</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/usr/local/var/log/mxguard/stdout.log</string>

    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/mxguard/stderr.log</string>

    <key>WorkingDirectory</key>
    <string>/usr/local/var/lib/mxguard</string>
</dict>
</plist>
EOF

# Set permissions
sudo chown root:wheel /Library/LaunchDaemons/com.mxtac.mxguard.plist
sudo chmod 644 /Library/LaunchDaemons/com.mxtac.mxguard.plist

# Load and start service
sudo launchctl load /Library/LaunchDaemons/com.mxtac.mxguard.plist

# Check status
sudo launchctl list | grep mxguard
```

---

## 4. Verification

### 4.1 Verify Installation

```bash
# Check binary version
mxguard --version
# Output: MxGuard v1.0.0 (commit: abc123, built: 2026-01-19T10:00:00Z)

# Check configuration
mxguard --config /etc/mxguard/config.yaml --validate
# Output: ✓ Configuration is valid

# Test connection to MxTac platform
mxguard --config /etc/mxguard/config.yaml --test-connection
# Output: ✓ Connection successful (200 OK)
```

### 4.2 Verify Service

**Linux (systemd)**:
```bash
# Check service status
sudo systemctl status mxguard

# Check logs
sudo journalctl -u mxguard -f

# Check if agent is sending events
sudo journalctl -u mxguard | grep "Sent batch"
```

**Windows**:
```powershell
# Check service status
Get-Service MxGuard

# Check event logs
Get-EventLog -LogName Application -Source MxGuard -Newest 20

# Check if agent is sending events
Get-EventLog -LogName Application -Source MxGuard | Where-Object { $_.Message -like "*Sent batch*" }
```

**macOS**:
```bash
# Check service status
sudo launchctl list | grep mxguard

# Check logs
tail -f /usr/local/var/log/mxguard/agent.log

# Check if agent is sending events
grep "Sent batch" /usr/local/var/log/mxguard/agent.log
```

### 4.3 Verify Events in MxTac

```bash
# Check agent registration in MxTac UI
# Navigate to: Settings → Agents → MxGuard

# Verify event ingestion
# Navigate to: Events → Search
# Filter: source.product.name = "MxGuard"
```

---

## 5. Upgrading

### 5.1 Linux Upgrade

**Package Manager**:
```bash
# Debian/Ubuntu
sudo apt update
sudo apt upgrade mxguard

# RHEL/CentOS
sudo yum update mxguard
```

**Manual Upgrade**:
```bash
# Stop service
sudo systemctl stop mxguard

# Backup configuration
sudo cp /etc/mxguard/config.yaml /etc/mxguard/config.yaml.bak

# Download new binary
wget https://github.com/mxtac/mxguard/releases/download/v1.1.0/mxguard-linux-amd64

# Replace binary
sudo mv mxguard-linux-amd64 /usr/local/bin/mxguard
sudo chmod +x /usr/local/bin/mxguard

# Start service
sudo systemctl start mxguard

# Verify upgrade
mxguard --version
```

### 5.2 Windows Upgrade

```powershell
# Stop service
Stop-Service MxGuard

# Download new MSI
Invoke-WebRequest -Uri "https://github.com/mxtac/mxguard/releases/download/v1.1.0/mxguard-windows-amd64.msi" -OutFile "mxguard.msi"

# Upgrade
msiexec /i mxguard.msi /quiet /qn /norestart

# Start service
Start-Service MxGuard

# Verify upgrade
& "C:\Program Files\MxGuard\mxguard.exe" --version
```

### 5.3 macOS Upgrade

```bash
# Homebrew
brew upgrade mxguard
brew services restart mxguard

# Manual
sudo launchctl unload /Library/LaunchDaemons/com.mxtac.mxguard.plist
# Download and replace binary
sudo launchctl load /Library/LaunchDaemons/com.mxtac.mxguard.plist
```

---

## 6. Uninstallation

### 6.1 Linux Uninstallation

**Package Manager**:
```bash
# Debian/Ubuntu
sudo apt remove --purge mxguard

# RHEL/CentOS
sudo yum remove mxguard
```

**Manual Uninstallation**:
```bash
# Stop and disable service
sudo systemctl stop mxguard
sudo systemctl disable mxguard
sudo rm /etc/systemd/system/mxguard.service
sudo systemctl daemon-reload

# Remove binary
sudo rm /usr/local/bin/mxguard

# Remove configuration (optional)
sudo rm -rf /etc/mxguard

# Remove data (optional)
sudo rm -rf /var/lib/mxguard
sudo rm -rf /var/log/mxguard

# Remove user
sudo userdel mxguard
```

### 6.2 Windows Uninstallation

```powershell
# Stop and remove service
Stop-Service MxGuard
& "C:\Program Files\MxGuard\mxguard.exe" service uninstall

# Uninstall via MSI
msiexec /x {PRODUCT-GUID} /quiet /qn /norestart

# Or use Control Panel → Programs → Uninstall

# Remove data (optional)
Remove-Item -Recurse -Force "C:\ProgramData\MxGuard"
```

### 6.3 macOS Uninstallation

```bash
# Homebrew
brew services stop mxguard
brew uninstall mxguard

# Manual
sudo launchctl unload /Library/LaunchDaemons/com.mxtac.mxguard.plist
sudo rm /Library/LaunchDaemons/com.mxtac.mxguard.plist
sudo rm /usr/local/bin/mxguard

# Remove data (optional)
sudo rm -rf /usr/local/etc/mxguard
sudo rm -rf /usr/local/var/lib/mxguard
sudo rm -rf /usr/local/var/log/mxguard
```

---

## 7. Troubleshooting

### 7.1 Agent Won't Start

**Check logs**:
```bash
# Linux
sudo journalctl -u mxguard -n 50

# Windows
Get-EventLog -LogName Application -Source MxGuard -Newest 20

# macOS
tail -n 50 /usr/local/var/log/mxguard/agent.log
```

**Common issues**:
- **Permission denied**: Ensure agent runs as root/administrator
- **Config file not found**: Check config path in service definition
- **Port already in use**: Check if another instance is running

### 7.2 Events Not Appearing in MxTac

**Check connectivity**:
```bash
# Test connection
mxguard --config /etc/mxguard/config.yaml --test-connection

# Check firewall
curl -v https://mxtac.example.com/api/v1/ingest/ocsf
```

**Check authentication**:
```bash
# Verify API key
echo $MXGUARD_API_KEY

# Test with curl
curl -H "Authorization: Bearer $MXGUARD_API_KEY" \
  https://mxtac.example.com/api/v1/health
```

**Check agent logs**:
```bash
# Look for error messages
grep -i "error\|failed" /var/log/mxguard/agent.log
```

### 7.3 High Resource Usage

**Check CPU/Memory**:
```bash
# Linux
top -p $(pgrep mxguard)

# Windows
Get-Process mxguard | Select-Object CPU, WorkingSet

# macOS
top -pid $(pgrep mxguard)
```

**Reduce resource usage**:
```yaml
# In config.yaml
performance:
  cpu:
    max_percent: 5
  memory:
    max_mb: 50

collectors:
  file:
    rate_limit: 500    # Reduce event rate
  process:
    scan_interval: 5s  # Increase interval
```

### 7.4 Missing Events

**Check collector status**:
```bash
# Get agent status
mxguard --config /etc/mxguard/config.yaml --status

# Output:
# ✓ File monitor: Running (1234 events)
# ✓ Process monitor: Running (567 events)
# ✗ Network monitor: Disabled
# ✓ Log monitor: Running (890 events)
```

**Enable debug logging**:
```yaml
# In config.yaml
agent:
  log_level: "debug"
```

**Check buffer status**:
```bash
# Look for buffer full messages
grep "buffer full" /var/log/mxguard/agent.log

# Increase buffer size
# In config.yaml:
buffer:
  size: 20000  # Increase from 10000
```

---

## Deployment Best Practices

### 1. Pre-Deployment Checklist

- [ ] Review system requirements
- [ ] Obtain MxTac API key
- [ ] Configure firewall rules (allow HTTPS to MxTac)
- [ ] Test configuration in development environment
- [ ] Plan rollout strategy (phased vs. all-at-once)

### 2. Configuration Management

- Use configuration management tools (Ansible, Puppet, Chef)
- Store API keys in secrets manager (HashiCorp Vault, AWS Secrets Manager)
- Version control configuration files
- Use environment-specific configs (dev, staging, prod)

### 3. Monitoring

- Monitor agent health via MxTac UI
- Set up alerts for agent offline
- Monitor resource usage
- Track event ingestion rates

### 4. Security Hardening

- Run agent with least privilege
- Enable tamper protection
- Use TLS client certificates
- Regularly update agent

---

*Deployment guide for production environments*
*Next: See 05-DEVELOPMENT.md for development setup*
