# Win10-Network-Tuning

A modern PowerShell-based network optimization tool for Windows 10/11, designed for remote execution and comprehensive network performance enhancement. This script modernizes and expands upon traditional network optimization techniques with advanced PowerShell features, safety mechanisms, and enterprise-ready deployment capabilities.

## 🚀 Quick Start (Remote Execution)

Execute the network optimizer directly from GitHub without downloading files:

```powershell
# Basic execution (recommended method)
$webClient = New-Object System.Net.WebClient; $webClient.Encoding = [System.Text.Encoding]::UTF8; iex $webClient.DownloadString("https://raw.githubusercontent.com/Cykeek/Win10-Network-Tuning/main/NetworkOptimizer.ps1")

# Alternative shorter method (may have encoding issues on some systems)
iex (irm "https://raw.githubusercontent.com/Cykeek/Win10-Network-Tuning/main/NetworkOptimizer.ps1")

# Silent mode with recommended settings
$webClient = New-Object System.Net.WebClient; $webClient.Encoding = [System.Text.Encoding]::UTF8; $script = $webClient.DownloadString("https://raw.githubusercontent.com/Cykeek/Win10-Network-Tuning/main/NetworkOptimizer.ps1"); iex "& { $script } -Silent"

# Preview mode (show changes without applying)
$webClient = New-Object System.Net.WebClient; $webClient.Encoding = [System.Text.Encoding]::UTF8; $script = $webClient.DownloadString("https://raw.githubusercontent.com/Cykeek/Win10-Network-Tuning/main/NetworkOptimizer.ps1"); iex "& { $script } -WhatIf"
```

## 📋 Features

- **🌐 Remote Execution**: Single PowerShell command execution from GitHub
- **🛡️ Advanced Safety**: Automatic restore points, registry backups, and rollback capabilities
- **📊 Real-time Progress**: Interactive progress bars and detailed operation feedback
- **🎯 Smart Detection**: Auto-detects connection types and hardware for optimal settings
- **📈 Performance Analytics**: Comprehensive before/after reports and network health analysis
- **🔧 Enterprise Ready**: Silent mode, custom configurations, and parameter support
- **⚡ Modern Architecture**: PowerShell 5.1+ with advanced error handling and validation
- **🎮 Gaming Optimized**: Specialized settings for gaming, streaming, and cloud gaming services

## 💻 Requirements

- **Windows 10/11** (build 1809 or later recommended)
- **PowerShell 5.1+** (PowerShell 7+ supported)
- **Administrator privileges** (automatically validated)
- **Internet connection** (for remote execution only)

## 🎛️ Execution Methods

### Remote Execution (Recommended)
Execute directly from GitHub without downloading files:
```powershell
# Recommended method with proper encoding
$webClient = New-Object System.Net.WebClient; $webClient.Encoding = [System.Text.Encoding]::UTF8; iex $webClient.DownloadString("https://raw.githubusercontent.com/Cykeek/Win10-Network-Tuning/main/NetworkOptimizer.ps1")

# Alternative (may have encoding issues)
iex (irm "https://raw.githubusercontent.com/Cykeek/Win10-Network-Tuning/main/NetworkOptimizer.ps1")
```

### Local Execution
1. Download `NetworkOptimizer.ps1`
2. Right-click → "Run with PowerShell" (as administrator)
   
Or from PowerShell:
```powershell
.\NetworkOptimizer.ps1
```

### Advanced Parameters
```powershell
# Silent mode for automation
.\NetworkOptimizer.ps1 -Silent

# Custom configuration file
.\NetworkOptimizer.ps1 -ConfigFile "C:\MyConfig.json"

# Preview changes without applying
.\NetworkOptimizer.ps1 -WhatIf

# Custom log location
.\NetworkOptimizer.ps1 -LogPath "C:\NetworkOptimization.log"
```

## 🎮 Usage

### Interactive Mode (Default)
1. Execute the script with administrator privileges
2. Navigate through the interactive menu system:
   - **Browse categories** to see available optimizations
   - **Select specific optimizations** or use "Recommended Settings"
   - **Preview changes** with detailed explanations
   - **Apply optimizations** with real-time progress tracking
3. **Restart** when prompted to apply all changes

### Silent Mode (Automation)
For automated deployment or enterprise environments:
```powershell
# Apply recommended settings automatically
iex "& { $(irm 'https://raw.githubusercontent.com/Cykeek/Win10-Network-Tuning/main/NetworkOptimizer.ps1') } -Silent"
```

### Preview Mode (Testing)
See what changes would be made without applying them:
```powershell
# Show all changes that would be applied
iex "& { $(irm 'https://raw.githubusercontent.com/Cykeek/Win10-Network-Tuning/main/NetworkOptimizer.ps1') } -WhatIf"
```

## 🔧 Optimization Categories

### 🌐 TCP/IP Protocol Stack
- **TCP Window Scaling** - Improves throughput for high-bandwidth connections
- **Nagle's Algorithm Control** - Reduces latency for interactive applications
- **TCP ACK Frequency** - Optimizes acknowledgment timing
- **Time-To-Live (TTL)** - Network routing optimization
- **UDP Buffer Management** - Enhanced real-time communication

### 🔌 Connection Type Optimization
- **Auto-Detection** - Identifies WiFi, Ethernet, or Fiber connections
- **WiFi Stability** - Roaming and power management enhancements
- **Ethernet Performance** - Wired connection optimizations
- **Fiber High-Bandwidth** - Settings for gigabit+ connections
- **Power Management** - Prevents network adapter throttling

### 🗂️ DNS and Memory Management
- **DNS Cache Optimization** - Faster domain resolution
- **Connection Limits** - Increased concurrent connection handling
- **Memory Allocation** - Optimized network buffer management
- **Port Range Expansion** - More available ports for applications

### 🔒 Network Security
- **Firewall Configuration** - Optimized rules for performance and security
- **Protocol Hardening** - Disable vulnerable protocols (SMBv1, weak TLS)
- **Port Security** - Protection against common network attacks
- **Network Discovery** - Balanced security and functionality

### 🎮 Gaming and Streaming
- **Gaming Mode** - Low-latency optimizations for competitive gaming
- **Streaming Mode** - Buffer and bandwidth optimizations for video streaming
- **Cloud Gaming** - Specialized settings for GeForce NOW, Xbox Cloud Gaming
- **Video Conferencing** - Optimizations for Zoom, Teams, Meet applications

### ⚙️ Hardware-Specific Tuning
- **Vendor Detection** - Automatic identification of Intel, Realtek, Killer adapters
- **Adapter Optimizations** - Brand-specific registry optimizations
- **Hardware Offloading** - Utilizes adapter-specific features
- **Jumbo Frames** - Large packet support for compatible hardware

### 🚦 Congestion Control Algorithms
- **Auto-Selection** - AI-driven algorithm selection based on network analysis
- **CTCP (Compound TCP)** - Windows default, balanced performance
- **CUBIC** - Optimized for high-bandwidth, high-latency networks
- **NewReno** - Conservative approach for unstable connections
- **DCTCP** - Data center optimized for low latency

## 🛠️ Advanced Features

### 🔄 Safety and Backup Systems
- **Automatic Restore Points** - System protection before any changes
- **Registry Backups** - Complete backup of modified settings with timestamps
- **Rollback Capability** - Easy restoration of previous settings
- **Validation Checks** - Pre-flight safety verification
- **Emergency Recovery** - Automatic rollback on critical failures

### 📊 Monitoring and Reporting
- **Real-time Progress** - Visual progress bars during optimization
- **Network Health Reports** - Comprehensive before/after analysis in HTML format
- **Detailed Logging** - Structured logs with timestamps and operation results
- **Performance Metrics** - Bandwidth, latency, and connection quality measurements
- **Change Tracking** - Complete record of all applied modifications

### 🏢 Enterprise Features
- **Silent Deployment** - Unattended execution for IT automation
- **Custom Configurations** - JSON-based configuration file support
- **Parameter Support** - Command-line arguments for scripted environments
- **Centralized Logging** - Custom log file locations for management
- **Group Policy Compatible** - Suitable for domain environments

### 🔧 Developer Tools
- **WhatIf Mode** - Preview all changes without applying them
- **Verbose Logging** - Detailed operation information for troubleshooting
- **Error Handling** - Comprehensive exception management with recovery
- **Modular Design** - Easy to extend and customize
- **PowerShell Integration** - Native cmdlet support and pipeline compatibility

## 📝 Important Notes

- **System Restart Required**: A reboot is necessary to apply all network stack changes
- **Administrator Privileges**: The script automatically validates and requires admin rights
- **Compatibility**: Tested on Windows 10 (1809+) and Windows 11
- **Logging**: Detailed logs saved to `%USERPROFILE%\Documents\NetworkOptimizer\Logs`
- **Backup Location**: Registry backups stored in `%USERPROFILE%\Documents\NetworkOptimizer\Backups`
- **Hardware Detection**: Some optimizations are automatically adjusted based on detected hardware
- **Remote Execution**: Internet connection required only for initial download in remote mode

## ⚠️ Safety Information

This PowerShell script includes comprehensive safety mechanisms:

- **Automatic Restore Points** created before any system changes
- **Complete Registry Backups** with timestamped exports
- **Validation Checks** ensure system compatibility before applying changes
- **Rollback Functionality** allows easy restoration of previous settings
- **WhatIf Mode** lets you preview all changes before applying them

While these safety features significantly reduce risks, any system optimization carries inherent risks. The script is designed with enterprise-grade safety practices, but users should understand the changes being made.

## 🆕 Version Information

**Current Version**: 4.0.0 (PowerShell Edition)

### Major Changes in v4.0.0:
- **Complete rewrite** from batch to modern PowerShell
- **Remote execution capability** via single command from GitHub
- **Advanced safety mechanisms** with automatic backups and restore points
- **Real-time progress tracking** and detailed reporting
- **Enterprise deployment features** with silent mode and custom configurations
- **Enhanced hardware detection** and vendor-specific optimizations
- **Improved user experience** with interactive menus and help system

### Migration from v3.x:
- All functionality from the batch version has been preserved and enhanced
- New PowerShell version offers significantly more features and safety
- Backward compatibility maintained for all optimization settings
- Improved reliability and error handling
