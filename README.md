# Network Scanner - ALL COMMANDS LISTED ARE BASH COMMANDS

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

<<<<<<< HEAD
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
=======
To install `netscan`, run the following command in your terminal:
```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/vinerequest/netscan/main/easy_netscan_install.sh)"



Usage
To run the network scanner, use the following command:

sudo netscan


This will scan your local network and display a table of connected devices, including their IP addresses, MAC addresses, hostnames, vendors, and network health status.
Important: netscan requires root privileges to perform network scanning. Always run it with sudo.
Command Line Arguments
netscan supports several options to customize the scan:
* -n, --network CIDR: Specify the network CIDR to scan (e.g., 192.168.1.0/24). If not provided, it defaults to your local network.
* -p, --ports: Enable port scanning (requires nmap to be installed).
* --deep-scan: Perform a more thorough port scan (slower but more detailed).
* --no-health-check: Disable network health monitoring to speed up the scan.
* --label IP "LABEL": Add a custom label for a device (e.g., sudo netscan --label 192.168.1.100 "My Laptop").
* --list-labels: List all saved device labels.
For a full list of options, run:

>>>>>>> e30008d566f141646eaaff568bc52f5fa99b4d14
sudo netscan --help
 
