# Network Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform: Multi](https://img.shields.io/badge/platform-Windows%20|%20macOS%20|%20Linux-brightgreen)
![Python: 3.6+](https://img.shields.io/badge/python-3.6%2B-blue)

A powerful command-line tool for scanning local networks, discovering and identifying connected devices, monitoring network health, and tracking device information.

## Features

- **Device Discovery**: Automatically finds all devices on your local network using ARP scanning
- **Network Health Monitoring**: Checks latency and packet loss for all devices with ping tests
- **Device Identification**: Identifies device types based on:
  - MAC address vendor lookup
  - Open ports and services
  - Hostname analysis
- **Custom Device Labeling**: Add persistent labels to devices for easier identification
- **Port Scanning**: Optional port scanning for more detailed device identification (requires nmap)
- **Cross-Platform**: Works on Windows, macOS, and Linux

## System Requirements

- **Python 3.6+**: Required for running the scanner
- **Root/Administrator Privileges**: Required for network scanning operations
- **Network Interface**: Functioning network interface with IPv4 connectivity
- **nmap** (optional): For port scanning capabilities (automatically detected)

## Installation

### Option 1: Quick Install (Recommended)

```bash
# Download and run the setup script
python3 setup_netscan.py

# Or install directly
sudo pip3 install -e /Users/addamhughes/netscan
```

### Option 2: Manual Installation

1. Create the directory structure:
```bash
mkdir -p ~/netscan/src/netscan
mkdir -p ~/netscan/tests
```

2. Copy source files into the directory structure

3. Install the package:
```bash
# On macOS/Linux:
sudo pip3 install -e ~/netscan

# On Windows (with Administrator privileges):
pip install -e %USERPROFILE%\netscan
```

## Usage

### Basic Scanning

Run a basic network scan to discover all devices:

```bash
# On macOS/Linux:
sudo netscan

# On Windows (with Administrator privileges):
netscan
```

### Common Options

```bash
# Scan a specific network
sudo netscan -n 192.168.0.0/24

# Enable port scanning (requires nmap)
sudo netscan -p

# Perform a more thorough port scan
sudo netscan --deep-scan

# Disable health checks for faster scanning
sudo netscan --no-health-check

# Save results to a JSON file
sudo netscan --output results.json
```

### Device Labeling

```bash
# Add a label to a device
sudo netscan --label 192.168.1.10 "Office Printer"

# View all saved labels
sudo netscan --list-labels

# Remove a label
sudo netscan --remove-label 192.168.1.10
```

### Full Command Reference

Run the following command to see all available options:

```bash
sudo netscan --help
```

## Example Output

```
========== NETWORK SCANNER ==========
Interface: en0
IP Address: 192.168.1.100
Network CIDR: 192.168.1.0/24
Default Gateway: 192.168.1.1
=====================================

Scanning network 192.168.1.0/24
Scan complete!       
Checking network health...
Identifying devices...

+---------------------+-------------------+------------------------+-------------------------+------------------------+---------------------+-------------------------+
|      IP Address     |    MAC Address    |        Hostname        |          Vendor         |       Device Type      |        Health       |          Ports          |
+---------------------+-------------------+------------------------+-------------------------+------------------------+---------------------+-------------------------+
| 192.168.1.1 (Gateway) | e4:8d:8c:xx:xx:xx |        router         |     Routerboard.com     |         Router         | Good (1.2ms, 0% loss) | 53, 80, 443            |
|     192.168.1.10    | 11:22:33:xx:xx:xx |        printer        |      HP Enterprise      | Printer (Office Printer) | Fair (72.5ms, 0% loss) | 9100, 631, 80           |
|     192.168.1.100   | aa:bb:cc:xx:xx:xx |       MacBook         |       Apple, Inc.       |      Workstation       | Good (0.3ms, 0% loss) | 22, 5000                |
+---------------------+-------------------+------------------------+-------------------------+------------------------+---------------------+-------------------------+

Total devices: 3

Tips:
• Install nmap to enable port scanning: brew install nmap (macOS) or apt install nmap (Linux)
• Label devices with: sudo netscan --label 192.168.1.x "My Device"
• View all labels with: sudo netscan --list-labels
• Health statuses: Good (< 50ms, 0% loss), Fair (50-100ms, < 10% loss), Poor (> 100ms or > 10% loss)
• Run with --no-health-check for faster scanning
```

## Interpreting Results

- **IP Address**: Device's IPv4 address on the network (the gateway is highlighted)
- **MAC Address**: Device's physical hardware address
- **Hostname**: Device's hostname (if available)
- **Vendor**: Manufacturer determined from the MAC address
- **Device Type**: Type of device determined from ports, vendor, and hostname
  - Labels appear in parentheses next to the device type
- **Health**: Network health status with latency and packet loss:
  - Good: < 50ms with 0% loss (optimal)
  - Fair: 50-100ms with < 10% loss (acceptable)
  - Poor: > 100ms or > 10% loss (problematic)
  - Offline: Device not responding to pings
- **Ports**: Open ports detected on the device (if port scanning is enabled)

## Troubleshooting

### Common Issues

#### "Permission denied" or "Access is denied"
- **Problem**: Network scanning requires administrative privileges
- **Solution**: Run with `sudo` on macOS/Linux or as Administrator on Windows

#### "No devices found"
- **Problem**: The scanner couldn't detect any devices
- **Solutions**:
  - Check network connectivity
  - Try specifying the correct network with `-n 192.168.x.0/24`
  - Verify your network interface is active

#### "nmap not available"
- **Problem**: Port scanning requires nmap
- **Solution**: Install nmap
  - macOS: `brew install nmap`
  - Ubuntu/Debian: `sudo apt install nmap`
  - Windows: Download from [nmap.org](https://nmap.org/download.html)

#### "Error getting network information"
- **Problem**: The scanner couldn't determine network settings
- **Solution**: Manually specify your network:
  ```bash
  sudo netscan -n 192.168.1.0/24 -i eth0
  ```

## Security Considerations

- This tool performs active network scanning which should only be used on networks you own or have permission to scan
- Root/administrator privileges are required but care has been taken to minimize security risks
- All user inputs are validated and sanitized to prevent command injection

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Dependencies

- **scapy**: Network packet manipulation
- **python-nmap**: Port scanning interface (requires nmap binary)
- **netifaces**: Network interface information
- **mac-vendor-lookup**: MAC address vendor lookup
- **tabulate**: Terminal table formatting
- **ping3**: ICMP ping functionality

**Note: nmap must be installed separately as it is a binary program, not a Python package.**
