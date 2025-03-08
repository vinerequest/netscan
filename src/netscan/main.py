#!/usr/bin/env python3

import os
import sys
import argparse
import platform
import time
import logging
import json
import shutil
import socket
import re
from tabulate import tabulate

# Import network scanner modules
from .network_discovery import get_network_info, discover_devices
from .device_identification import DeviceIdentifier
from .cli_display import CLIDisplay

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("netscan")

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description='Network Scanner Tool')
    
    # Scanning arguments
    parser.add_argument('-n', '--network', help='Network CIDR to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', action='store_true', help='Enable port scanning (requires nmap)')
    parser.add_argument('-i', '--interface', help='Specify network interface to use')
    parser.add_argument('--skip-checks', action='store_true', help='Skip permission and dependency checks')
    parser.add_argument('--no-health-check', action='store_true', help='Disable network health checks (ping tests)')
    
    # Device labeling arguments
    parser.add_argument('--label', nargs=2, metavar=('IP', 'LABEL'), 
                       help='Add or update a label for a device (e.g., --label 192.168.1.10 "Office Printer")')
    parser.add_argument('--remove-label', metavar='IP',
                       help='Remove a label for a device (e.g., --remove-label 192.168.1.10)')
    parser.add_argument('--list-labels', action='store_true',
                       help='List all device labels')
    parser.add_argument('--labels-file', metavar='FILE',
                       help='Specify a custom file to store device labels (default: ~/devices.json)')
    
    # Advanced scan options
    parser.add_argument('--deep-scan', action='store_true',
                       help='Perform a more thorough port scan (slower but more accurate)')
    
    # Output control
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all non-essential output')
    
    # Export results
    parser.add_argument('--output', metavar='FILE', help='Save scan results to a JSON file')
    
    return parser.parse_args()

def check_requirements():
    """Check if all required system dependencies are available"""
    issues = []
    
    # Check for nmap if we're going to use port scanning
    nmap_path = shutil.which('nmap')
    if not nmap_path:
        issues.append({
            'type': 'warning',
            'message': 'nmap not found. Port scanning will be disabled.',
            'fix': f"Install nmap with: {'brew install nmap' if platform.system() == 'Darwin' else 'apt install nmap'}"
        })
    
    return issues

def validate_ip(ip):
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def display_labels(identifier, display):
    """Display all saved device labels"""
    if not identifier.device_labels:
        display.display_warning("No device labels found.")
        return
    
    print(f"\n{display.bold}Saved Device Labels:{display.end}")
    table_data = []
    for ip, label in identifier.device_labels.items():
        table_data.append([ip, label])
    
    print(tabulate(table_data, headers=["IP Address", "Label"], tablefmt="pretty"))

def save_results(devices, filename):
    """Save scan results to a JSON file"""
    # Convert devices to a serializable format
    serializable_devices = []
    for device in devices:
        # Create a copy to avoid modifying the original
        device_copy = device.copy()
        
        # Remove ANSI color codes from any string fields
        for key, value in device_copy.items():
            if isinstance(value, str):
                # Remove ANSI escape sequences
                device_copy[key] = re.sub(r'\033\[\d+m', '', value)
        
        serializable_devices.append(device_copy)
    
    try:
        with open(filename, 'w') as f:
            json.dump(serializable_devices, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving results to {filename}: {str(e)}")
        return False

def is_root():
    """Check if the script is running with root privileges"""
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False

def main():
    """Main entry point for the netscan package"""
    # Parse command-line arguments
    args = parse_arguments()
    
    # Setup CLI display
    display = CLIDisplay(use_color=not args.no_color)
    
    # Configure logging based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    try:
        # Check if running as root (required for network scanning)
        if not is_root():
            display.display_error("This program requires root privileges to perform network scanning.", exit_code=1)
        
        # Initialize device identifier with custom labels file if specified
        identifier = DeviceIdentifier(labels_file=args.labels_file)
        
        # Handle label management commands
        if args.list_labels:
            display_labels(identifier, display)
            return 0
        
        if args.label:
            ip, label = args.label
            # Validate IP address
            if not validate_ip(ip):
                display.display_error(f"Invalid IP address: {ip}")
                return 1
                
            if identifier.add_device_label(ip, label):
                display.display_success(f"Added label '{label}' for device {ip}")
            else:
                display.display_error(f"Failed to add label for device {ip}")
            return 0
        
        if args.remove_label:
            ip = args.remove_label
            if not validate_ip(ip):
                display.display_error(f"Invalid IP address: {ip}")
                return 1
                
            if identifier.remove_device_label(ip):
                display.display_success(f"Removed label for device {ip}")
            else:
                display.display_error(f"Failed to remove label for device {ip} (label may not exist)")
            return 0
        
        # Check system requirements
        if not args.skip_checks:
            issues = check_requirements()
            for issue in issues:
                if issue['type'] == 'error':
                    display.display_error(f"{issue['message']} {issue['fix']}")
                else:
                    display.display_warning(f"{issue['message']} {issue['fix']}")
        
        # Get network information
        try:
            network_info = get_network_info(interface=args.interface)
            if not network_info:
                display.display_error("Failed to get network information")
                return 1
                
            # Override with user-specified network if provided
            if args.network:
                network_info['network_cidr'] = args.network
        except Exception as e:
            display.display_error(f"Failed to get network information: {str(e)}")
            return 1
        
        # Display header
        if not args.quiet:
            display.print_header(network_info)
        
        # Discover devices
        if not args.quiet:
            display.show_scanning_progress(network_info['network_cidr'])
            
        # Discover devices with or without health check
        devices = discover_devices(
            network_cidr=network_info['network_cidr'],
            check_health_status=not args.no_health_check,
            interface=args.interface
        )
        
        if not devices:
            display.display_error("No devices found. Try scanning a different network range.")
            return 1
        
        # Identify and scan devices
        if not args.quiet:
            print("Identifying devices...")
            
        for device in devices:
            # First scan ports if requested
            open_ports = None
            if args.ports or args.deep_scan:
                if identifier.nmap_available:
                    if not args.quiet:
                        print(f"Scanning ports on {device['ip']}...")
                        
                    if args.deep_scan:
                        # Use expanded port range for deep scan
                        port_range = "1-1024,1433,1521,3000,3306,3389,5000,5432,5900,5901,6379,8000-8100,9000-9200,27017"
                        open_ports = identifier.scan_ports(device['ip'], ports=port_range)
                    else:
                        # Use standard port range
                        open_ports = identifier.scan_ports(device['ip'])
                else:
                    if not args.quiet:
                        display.display_warning(f"Skipping port scan for {device['ip']} (nmap not available)")
            
            # Identify the device with all available information
            hostname = device.get('hostname')
            device_info = identifier.identify_device(
                device['ip'], 
                device['mac'], 
                hostname=hostname, 
                ports=open_ports
            )
            
            # Add health info if it was collected
            if 'health' in device:
                device_info['health'] = device.get('health')
                
            # Add gateway flag if applicable
            if device.get('is_gateway', False):
                device_info['is_gateway'] = True
                
            # Update the device in the list with full identification
            for i, d in enumerate(devices):
                if d['ip'] == device_info['ip']:
                    devices[i] = device_info
                    break
        
        # Display results
        if not args.quiet:
            display.display_devices(devices)
            display.display_tips(devices)
        
        # Save results to file if requested
        if args.output:
            if save_results(devices, args.output):
                display.display_success(f"Scan results saved to {args.output}")
            else:
                display.display_error(f"Failed to save scan results to {args.output}")
        
        return 0
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        display.display_error(f"An unexpected error occurred: {str(e)}")
        return 1

if __name__ == "__main__":
    # When run directly, check if we're inside a virtual environment
    in_venv = sys.prefix != sys.base_prefix
    if not in_venv:
        print("\033[93mWarning: Not running inside virtual environment. Dependencies may be missing.\033[0m")
    
    # Check if running as root (required for network scanning)
    if not is_root():
        print("\033[91mThis program requires root privileges to perform network scanning.\033[0m")
        print("\033[91mPlease run with sudo: sudo netscan\033[0m")
        sys.exit(1)
    
    sys.exit(main())
