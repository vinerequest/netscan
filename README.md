# Network Scanner

A command-line tool to scan your local network and display all connected devices. It shows network health status, identifies devices by hostname and MAC vendor, and provides port scanning capabilities.

## Installation

Install with a single command:

sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/vinerequest/netscan/main/easy_netscan_install.sh)"
text

Collapse

Wrap

Copy

## Usage

Run the scanner with sudo privileges:
sudo netscan
text

Collapse

Wrap

Copy

## Command Line Arguments

- `-n, --network`: Specify network CIDR to scan (e.g., 192.168.1.0/24)
- `-p, --ports`: Enable port scanning (requires nmap)
- `--deep-scan`: Perform a more thorough port scan
- `--no-health-check`: Disable network health monitoring
- `--label IP "LABEL"`: Add a custom label for a device
- `--list-labels`: List all saved device labels

For more options, run:
sudo netscan --help
text

Collapse

Wrap

Copy

## Requirements
- Python 3.6+
- Root/sudo privileges for network scanning
- For port scanning: `nmap` must be installed

## Uninstall
Remove the package:
sudo pip3 uninstall netscan sudo rm -rf ~/netscan
text

Collapse

Wrap

Copy

## About
A simple tool to scan local network and display connected devices with network health info.
