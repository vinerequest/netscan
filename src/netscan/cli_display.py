#!/usr/bin/env python3

import sys
import time
import os
import platform
from tabulate import tabulate
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("netscan")

class CLIDisplay:
    """Class for displaying device information in the terminal"""
    
    def __init__(self, use_color=True):
        """
        Initialize CLIDisplay
        
        Args:
            use_color: Whether to use colored output (default: True)
        """
        # ANSI color escape sequences
        if use_color and self._supports_color():
            self.clear_screen = "\033[H\033[J"
            self.green = "\033[92m"
            self.yellow = "\033[93m"
            self.red = "\033[91m"
            self.blue = "\033[94m"
            self.magenta = "\033[95m"
            self.cyan = "\033[96m"
            self.bold = "\033[1m"
            self.underline = "\033[4m"
            self.end = "\033[0m"
        else:
            # No colors if not supported
            self.clear_screen = ""
            self.green = ""
            self.yellow = ""
            self.red = ""
            self.blue = ""
            self.magenta = ""
            self.cyan = ""
            self.bold = ""
            self.underline = ""
            self.end = ""
    
    def _supports_color(self):
        """Check if the terminal supports color output"""
        # Windows 10 supports ANSI escape sequences
        if platform.system() == 'Windows':
            if int(platform.release()) >= 10:
                return True
            return False
            
        # Unix-like systems usually support color
        if platform.system() in ['Darwin', 'Linux']:
            return True
            
        # Check if output is a TTY
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    
    def clear(self):
        """Clear the terminal screen"""
        if platform.system() == 'Windows':
            os.system('cls')
        else:
            os.system('clear')
    
    def print_header(self, network_info):
        """
        Print network information header
        
        Args:
            network_info: Dictionary with network information
        """
        # Clear screen
        print(f"{self.clear_screen}")
        
        # Print title
        title = "NETWORK SCANNER"
        print(f"{self.bold}{self.blue}{'=' * 10} {title} {'=' * 10}{self.end}")
        
        # Print network information
        print(f"Interface: {self.green}{network_info.get('interface', 'Unknown')}{self.end}")
        print(f"IP Address: {self.green}{network_info.get('ip_address', 'Unknown')}{self.end}")
        print(f"Network CIDR: {self.green}{network_info.get('network_cidr', 'Unknown')}{self.end}")
        print(f"Default Gateway: {self.green}{network_info.get('default_gateway', 'Unknown')}{self.end}")
        
        # Print separator
        print(f"{self.bold}{self.blue}{'=' * (22 + len(title))}{self.end}\n")
    
    def display_devices(self, devices):
        """
        Display the list of discovered devices in a table
        
        Args:
            devices: List of device dictionaries
        """
        if not devices:
            print(f"{self.yellow}No devices found on the network.{self.end}")
            return
        
        # Prepare table data
        table_data = []
        for device in devices:
            # Format IP address (highlight gateway)
            ip = device.get('ip', 'Unknown')
            if device.get('is_gateway', False):
                ip = f"{self.bold}{ip} (Gateway){self.end}"
                
            # Format MAC address
            mac = device.get('mac', 'Unknown')
            
            # Format hostname
            hostname = device.get('hostname', 'Unknown')
            if hostname is None or hostname == 'Unknown':
                hostname = '-'
            # Truncate if too long
            if len(hostname) > 25:
                hostname = hostname[:22] + '...'
                
            # Format vendor
            vendor = device.get('vendor', 'Unknown')
            if vendor is None or vendor == 'Unknown':
                vendor = '-'
            # Truncate if too long
            if len(vendor) > 20:
                vendor = vendor[:17] + '...'
                
            # Format device type (with label if available)
            device_type = device.get('type', 'Unknown')
            if device.get('label'):
                device_type = f"{device_type} {self.green}({device['label']}){self.end}"
                
            # Format health information
            health_info = ""
            health = device.get('health', {})
            if health:
                status = health.get('status', 'Unknown')
                latency = health.get('latency_ms')
                packet_loss = health.get('packet_loss_pct')
                
                # Color-code based on health status
                if status == 'Good':
                    status_display = f"{self.green}{status}{self.end}"
                elif status == 'Fair':
                    status_display = f"{self.yellow}{status}{self.end}"
                elif status == 'Poor' or status == 'Offline':
                    status_display = f"{self.red}{status}{self.end}"
                else:
                    status_display = status
                
                # Format complete health info
                if latency is not None and packet_loss is not None:
                    health_info = f"{status_display} ({latency}ms, {packet_loss}% loss)"
                else:
                    health_info = status_display
            
            # Format port information
            port_info = ""
            open_ports = device.get('open_ports', {})
            if open_ports and isinstance(open_ports, dict):
                if "error" in open_ports:
                    port_info = f"{self.yellow}Error: {open_ports['error']}{self.end}"
                else:
                    # For many ports, just show count and important ones
                    port_nums = list(open_ports.keys())
                    if len(port_nums) > 5:
                        important_ports = [80, 443, 22, 53, 3389, 445, 139, 21, 25, 110, 631, 9100]
                        highlights = [p for p in port_nums if p in important_ports]
                        if highlights:
                            port_info = f"{len(port_nums)} ports, including: {', '.join(map(str, sorted(highlights)))}"
                        else:
                            port_info = f"{len(port_nums)} open ports"
                    else:
                        # If just a few ports, show them all
                        port_info = f"Ports: {', '.join(map(str, sorted(port_nums)))}"
            
            # Build the complete row
            row = [ip, mac, hostname, vendor, device_type, health_info, port_info]
            table_data.append(row)
        
        # Define table headers
        headers = ["IP Address", "MAC Address", "Hostname", "Vendor", "Device Type", "Health", "Ports"]
        
        # Print the table
        print(tabulate(table_data, headers=headers, tablefmt="pretty"))
        print(f"\nTotal devices: {self.bold}{len(devices)}{self.end}")
    
    def show_scanning_progress(self, network_cidr):
        """
        Show a simple scanning animation
        
        Args:
            network_cidr: Network CIDR being scanned
        """
        print(f"Scanning network {self.bold}{network_cidr}{self.end}")
        
        # Simple animation
        spinner = ['|', '/', '-', '\\']
        for _ in range(10):
            for char in spinner:
                sys.stdout.write(f'\rScanning... {char}')
                sys.stdout.flush()
                time.sleep(0.1)
                
        print("\rScan complete!       ")
    
    def display_tips(self, devices):
        """
        Display helpful tips based on scan results
        
        Args:
            devices: List of device dictionaries
        """
        tips = []
        
        # Add tips related to port scanning
        if any(not device.get('port_scan_available', False) for device in devices):
            tips.append(f"{self.yellow}• Install nmap to enable port scanning: brew install nmap (macOS) or apt install nmap (Linux){self.end}")
        
        # Add tips related to device labeling
        tips.append(f"{self.cyan}• Label devices with: sudo netscan --label 192.168.1.x \"My Device\"{self.end}")
        tips.append(f"{self.cyan}• View all labels with: sudo netscan --list-labels{self.end}")
        
        # Add tips related to health monitoring
        tips.append(f"{self.cyan}• Health statuses: Good (< 50ms, 0% loss), Fair (50-100ms, < 10% loss), Poor (> 100ms or > 10% loss){self.end}")
        tips.append(f"{self.cyan}• Run with --no-health-check for faster scanning{self.end}")
        
        # Print tips
        if tips:
            print(f"\n{self.bold}Tips:{self.end}")
            for tip in tips:
                print(tip)
    
    def display_error(self, message, exit_code=None):
        """
        Display an error message
        
        Args:
            message: Error message to display
            exit_code: Optional exit code if the program should exit
        """
        print(f"{self.red}ERROR: {message}{self.end}")
        
        # Exit with provided code if specified
        if exit_code is not None:
            sys.exit(exit_code)
    
    def display_warning(self, message):
        """
        Display a warning message
        
        Args:
            message: Warning message to display
        """
        print(f"{self.yellow}WARNING: {message}{self.end}")
    
    def display_success(self, message):
        """
        Display a success message
        
        Args:
            message: Success message to display
        """
        print(f"{self.green}SUCCESS: {message}{self.end}")
    
    def display_scan_phase(self, phase, total_phases=4):
        """
        Display current scan phase
        
        Args:
            phase: Current phase number
            total_phases: Total number of phases
        """
        phases = [
            "Discovering network",
            "Checking device health",
            "Identifying devices", 
            "Analyzing results"
        ]
        
        phase_idx = min(phase - 1, len(phases) - 1)
        current_phase = phases[phase_idx]
        
        # Create progress bar
        progress = "=" * phase + ">" + " " * (total_phases - phase)
        
        # Display progress
        sys.stdout.write(f"\r[{progress}] {current_phase}...")
        sys.stdout.flush()
        
        # Add newline if completed
        if phase == total_phases:
            print()
