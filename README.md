Network Scanner - ALL COMMANDS LISTED ARE BASH COMMANDS
License: MIT Platform: Multi Python: 3.6+

A powerful command-line tool for scanning local networks, discovering and identifying connected devices, monitoring network health, and tracking device information.

Features
Device Discovery: Automatically finds all devices on your local network using ARP scanning
Network Health Monitoring: Checks latency and packet loss for all devices with ping tests
Device Identification: Identifies device types based on:
MAC address vendor lookup
Open ports and services
Hostname analysis
Custom Device Labeling: Add persistent labels to devices for easier identification
Port Scanning: Optional port scanning for more detailed device identification (requires nmap)
Cross-Platform: Works on Windows, macOS, and Linux

System Requirements
Python 3.6+: Required for running the scanner
Root/Administrator Privileges: Required for network scanning operations
Network Interface: Functioning network interface with IPv4 connectivity
nmap (optional): For port scanning capabilities (automatically detected)

Installation
To install `netscan`, run the following command in your terminal:
```bash
sudo bash -c ""
```

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

sudo netscan --help

Requirements
* Python: Version 3.6 or higher.
* Root Privileges: Required for network scanning (sudo).
* Port Scanning: Requires nmap to be installed. On macOS, install it with:   
MAC
brew install nmap

LINUX
sudo apt install nmap

Uninstall
To remove netscan, run the following commands:

sudo pip3 uninstall netscan
sudo rm -rf ~/netscan

About
netscan is a simple tool to scan your local network and display connected devices with network health information. It uses Python libraries like scapy, python-nmap, and aiohttp to perform network discovery, device identification, and health checks.

Troubleshooting
* Permission Issues: Ensure you run netscan with sudo.
* Missing Dependencies: The install script handles dependencies, but if issues arise, manually install them with:

sudo pip3 install -r ~/netscan/requirements.txt

* Port Scanning Errors: Install nmap if not already present (see Requirements)

Contributing
Feel free to fork the repository and submit pull requests for improvements or bug fixes. For major changes, please open an issue first to discuss.

