# Win10-Network-Tuning

A batch script to optimize network settings on Windows 10, enhancing performance through TCP tweaks, DNS cache adjustments, IPv4 prioritization, and disabling SMB packet signing and Windows Update Delivery Optimization.

## Features

- **TCP/IP Protocol Stack Optimizations**: Improves latency, throughput, and packet handling
- **Connection Type Detection**: Automatically detects WiFi, Ethernet, or Fiber connection and applies specific optimizations
- **DNS and Memory Management**: Enhances browsing speed with optimized DNS caching
- **Network Security Settings**: Configures firewall and secures vulnerable ports
- **Gaming & Streaming Mode**: Prioritizes network traffic for games and streaming services
- **Video Conferencing Optimizations**: Enhances performance for Zoom, Teams, Meet, and other video conferencing apps
- **Cloud Gaming Optimizations**: Specific tweaks for GeForce NOW, Xbox Cloud Gaming, and other cloud gaming services
- **Hardware-Specific Network Adapter Tuning**: Automatically detects adapter model and applies vendor-specific optimizations
- **Congestion Control Algorithm Selection**: Automatically analyzes network conditions and selects the optimal algorithm
- **System Protection**: Creates restore points and backups before applying changes
- **Network Health Reports**: Generates detailed before/after comparison reports

## Requirements

- Windows 10 operating system
- Administrator privileges
- PowerShell 3.0 or higher

## Installation

1. Download the `network-enhance.bat` file
2. Right-click and select "Run as administrator"

## Usage

1. Run the script with administrator privileges
2. Select optimization options from the main menu:
   - Individual optimizations can be selected from category menus
   - Use the "Recommended Settings" option for most users
3. Apply selected optimizations
4. Restart your computer when prompted to apply all changes

## Optimization Categories

### TCP/IP Protocol Stack
- TCP Window Scaling
- Nagle's Algorithm disabling
- Time-To-Live optimization
- UDP buffer handling

### Connection-Specific
- WiFi stability enhancements
- Ethernet performance tuning
- Fiber high-bandwidth optimizations
- Power management settings

### DNS and Memory
- DNS cache size increase
- Lookup time reduction
- Maximum connection ports increase
- TCP connection handling improvement

### Security
- Firewall configuration
- Vulnerable port protection
- Protocol hardening (SMB signing, TLS 1.2)
- Network discovery protection

### Gaming and Streaming
- Game traffic prioritization
- Streaming buffer optimization
- Reduced buffering for video services
- Input lag reduction

### Video Conferencing
- Media foundation priority adjustments
- Audio/video processing thread priority
- Buffer management for reduced latency
- Application-specific optimizations (Zoom, Teams, Meet)

### Cloud Gaming
- TCP Quick ACK for cloud gaming
- QoS tagging for cloud gaming services
- Buffer management for reduced input latency
- Service-specific optimizations (GeForce NOW, Xbox Cloud Gaming)

### Congestion Control
- Network conditions analysis
- Optimal algorithm selection (CTCP, CUBIC, NewReno, DCTCP)
- Periodic re-evaluation for optimal performance
- Bandwidth and latency optimization

### Hardware-Specific Tuning
- Vendor detection (Intel, Realtek, Killer, etc.)
- Adapter-specific registry optimizations
- Hardware offloading configuration
- Jumbo frames for supported adapters

## Tools and Utilities

- **System Restore Point**: Creates a restore point for easy rollback
- **Settings Backup**: Exports registry settings before changes
- **Network Health Report**: Detailed HTML report of optimizations
- **Network Maintenance**: Resets components and flushes caches

## Notes

- A system restart is required to apply all changes
- The script creates logs in `%USERPROFILE%\Documents\Networks\Logs`
- Some optimizations may need to be adjusted for specific hardware
- Use the "View Details" option to see exactly what changes will be made

## Warning

Some optimizations modify system registry settings. While the script includes safety features like restore points and backups, modifications to system settings always carry some risk. Use at your own discretion.

## Version

Current version: 3.1
