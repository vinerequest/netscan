# Network Scanner

A command-line tool to scan your local network and display all connected devices. It shows network health status, identifies devices by hostname and MAC vendor, and provides port scanning capabilities.

## Installation

Install with a single command:

```bash
sudo pip3 install -e /Users/addamhughes/netscan
```

## Usage

Run the scanner with sudo privileges:

```bash
sudo netscan
```

### Command Line Arguments

- `-n, --network`: Specify network CIDR to scan (e.g., 192.168.1.0/24)
- `-p, --ports`: Enable port scanning (requires nmap)
- `--deep-scan`: Perform a more thorough port scan
- `--no-health-check`: Disable network health monitoring
- `--label IP "LABEL"`: Add a custom label for a device
- `--list-labels`: List all saved device labels

For more options, run:
```bash
sudo netscan --help
```

## Requirements

- Python 3.6+
- Root/sudo privileges for network scanning
- For port scanning: nmap must be installed
