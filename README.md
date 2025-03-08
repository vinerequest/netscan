Network Scanner

A simple command-line tool to scan your local network, display all connected devices, and show their network health status, hostnames, MAC vendors, and more.

## System Requirements
Before installing, ensure your system meets these requirements:
- **Python**: Version 3.6 or higher (check with `python3 --version`)
- **Root Privileges**: You’ll need to run commands with `sudo` on macOS/Linux or as Administrator on Windows
- **Port Scanning (Optional)**: If you want to use port scanning, install `nmap`:
  - macOS: `brew install nmap` (install Homebrew first if needed: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`)
  - Linux: `sudo apt install nmap`
  - Windows: Download and install from [nmap.org](https://nmap.org/download.html)

## Installation

### Step 1: Clone the Repository
First, download the project files from GitHub:
```bash
git clone https://github.com/vinerequest/netscan.git netscan
cd netscan
```
- This creates a folder called `netscan` in your current directory and moves you into it.
- If you don’t have `git` installed:
  - macOS: Install with `xcode-select --install`
  - Linux: Install with `sudo apt install git`
  - Windows: Download from [git-scm.com](https://git-scm.com/download/win)

### Step 2: Run the Installer
Use the provided Python script to install `netscan` and its dependencies:
```bash
sudo python3 setup_netscan.py
```
- On macOS/Linux, use `sudo` to allow the script to install system-wide.
- On Windows, open a Command Prompt as Administrator and run:
  ```bash
  python setup_netscan.py
  ```
- If you get an error about missing Python:
  - macOS/Linux: Install with `brew install python3` (macOS) or `sudo apt install python3` (Linux)
  - Windows: Download from [python.org](https://www.python.org/downloads/)

## Usage
Run the scanner to discover devices on your network:
```bash
sudo netscan
```
- On macOS/Linux, use `sudo`.
- On Windows, run in a Command Prompt as Administrator.
- This will display a table of devices, including IP addresses, MAC addresses, hostnames, vendors, and network health.

## Command Line Options
Customize your scan with these options:
- `-n, --network CIDR`: Specify a network to scan (e.g., `192.168.1.0/24`)
- `-p, --ports`: Enable port scanning (requires `nmap`)
- `--deep-scan`: Perform a detailed port scan (slower)
- `--no-health-check`: Skip health checks for faster scanning
- `--label IP "LABEL"`: Add a custom label to a device (e.g., `sudo netscan --label 192.168.1.100 "My Laptop"`)
- `--list-labels`: Show all saved labels

For a full list, run:
```bash
sudo netscan --help
```

## Uninstall
To remove `netscan`:
```bash
sudo pip3 uninstall netscan
sudo rm -rf ~/netscan
```
- On Windows, use `pip uninstall netscan` in an Administrator Command Prompt.

## About
`netscan` is a tool to scan your local network and display connected devices with network health information. It uses Python libraries like `scapy`, `python-nmap`, and `aiohttp`.

## Troubleshooting
- **Permission Errors**: Ensure you use `sudo` (macOS/Linux) or run as Administrator (Windows).
- **Missing `nmap`**: Install `nmap` for port scanning (see System Requirements).
- **Missing Dependencies**: If the installer fails, install dependencies manually:
  ```bash
  sudo pip3 install scapy python-nmap netifaces mac-vendor-lookup tabulate aiofiles aiohttp ping3
  ```

## Contributing
Fork the repo on GitHub, make improvements, and submit a pull request. Report issues on the [GitHub Issues page](https://github.com/vinerequest/netscan/issues).

## License
MIT License - see [LICENSE](LICENSE) for details.

