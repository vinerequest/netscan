#!/usr/bin/env python3

import os
import json
import logging
import shutil
import nmap
import re
import socket
from mac_vendor_lookup import MacLookup
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("netscan")

class DeviceIdentifier:
    """Class for identifying devices based on MAC, IP, and open ports"""
    
    def __init__(self, labels_file=None):
        """
        Initialize DeviceIdentifier
        
        Args:
            labels_file: Path to the file storing device labels (default: ~/devices.json)
        """
        # Initialize MAC vendor lookup
        self.mac_lookup = MacLookup()
        try:
            # Update the MAC address database if needed
            self.mac_lookup.update_vendors()
        except Exception as e:
            logger.warning(f"Failed to update MAC vendors database: {str(e)}")
            
        # Check if nmap is available
        self.nmap_available = shutil.which('nmap') is not None
        if not self.nmap_available:
            logger.warning("nmap not found. Port scanning will be disabled.")
        
        # Setup device labels file
        self.labels_file = labels_file or os.path.expanduser("~/devices.json")
        self.device_labels = self._load_device_labels()
        
        # Define common port-to-device type mappings
        self.port_device_types = {
            # Web servers and services
            80: "HTTP Server",
            443: "HTTPS Server",
            8080: "Web Service",
            8443: "Web Service",
            
            # File sharing
            21: "FTP Server",
            22: "SSH Server",
            139: "SMB/File Server",
            445: "SMB/File Server",
            
            # Network infrastructure
            53: "DNS Server",
            67: "DHCP Server",
            68: "DHCP Client",
            
            # Printing
            631: "Printer",
            9100: "Printer",
            515: "Print Server",
            
            # Remote access
            3389: "Remote Desktop",
            5900: "VNC Server",
            
            # Database services
            1433: "SQL Server",
            3306: "MySQL Database",
            5432: "PostgreSQL Database",
            27017: "MongoDB Database",
            
            # Mail services
            25: "Mail Server",
            110: "POP3 Mail Server",
            143: "IMAP Mail Server",
            587: "SMTP Mail Server",
            
            # Network storage
            548: "Network Storage",
            111: "NFS Server",
            2049: "NFS Server",
            
            # IoT and home automation
            1883: "MQTT (IoT Device)",
            8883: "MQTT (IoT Device)",
            9000: "Home Automation"
        }
    
    def _load_device_labels(self):
        """Load device labels from the labels file"""
        if not os.path.exists(self.labels_file):
            return {}
            
        try:
            with open(self.labels_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading device labels: {str(e)}")
            return {}
    
    def _save_device_labels(self):
        """Save device labels to the labels file"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(self.labels_file)), exist_ok=True)
            
            with open(self.labels_file, 'w') as f:
                json.dump(self.device_labels, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving device labels: {str(e)}")
            return False
    
    def add_device_label(self, ip, label):
        """
        Add or update a label for a device
        
        Args:
            ip: IP address of the device
            label: Custom label to assign
            
        Returns:
            True if successful, False otherwise
        """
        # Validate IP address
        try:
            socket.inet_aton(ip)
        except socket.error:
            logger.error(f"Invalid IP address: {ip}")
            return False
            
        # Sanitize label (remove control characters, limit length)
        label = re.sub(r'[\x00-\x1F\x7F]', '', label)
        label = label[:50]  # Limit length
        
        self.device_labels[ip] = label
        return self._save_device_labels()
    
    def remove_device_label(self, ip):
        """
        Remove a device label
        
        Args:
            ip: IP address of the device
            
        Returns:
            True if successful, False otherwise
        """
        if ip in self.device_labels:
            del self.device_labels[ip]
            return self._save_device_labels()
        return False
    
    def scan_ports(self, ip, ports="1-1024", arguments=None):
        """
        Scan ports on a device using nmap
        
        Args:
            ip: IP address to scan
            ports: Port range to scan (default: 1-1024)
            arguments: Additional nmap arguments
            
        Returns:
            Dictionary of open ports and services
        """
        if not self.nmap_available:
            return {"error": "nmap not available"}
            
        # Validate IP address
        try:
            socket.inet_aton(ip)
        except socket.error:
            return {"error": f"Invalid IP address: {ip}"}
            
        # Sanitize inputs to prevent command injection
        ip = re.sub(r'[^0-9.]', '', ip)
        ports = re.sub(r'[^0-9,\-]', '', ports)
        
        try:
            # Initialize nmap scanner
            nm = nmap.PortScanner()
            
            # Build nmap arguments
            scan_args = "-sV -T4"  # Version detection, aggressive timing
            if arguments:
                # Only allow safe arguments
                safe_args = re.sub(r'[&|;`$><]', '', arguments)
                scan_args += f" {safe_args}"
                
            # Execute nmap scan
            logger.info(f"Scanning ports {ports} on {ip}...")
            nm.scan(ip, ports, arguments=scan_args)
            
            # Process results
            open_ports = {}
            if ip in nm.all_hosts():
                host = nm[ip]
                if 'tcp' in host:
                    for port, data in host['tcp'].items():
                        if data['state'] == 'open':
                            open_ports[port] = {
                                'name': data['name'],
                                'product': data.get('product', ''),
                                'version': data.get('version', '')
                            }
            
            return open_ports
        except Exception as e:
            logger.error(f"Error scanning ports on {ip}: {str(e)}")
            return {"error": str(e)}
    
    def get_mac_vendor(self, mac):
        """
        Look up vendor from MAC address
        
        Args:
            mac: MAC address string
            
        Returns:
            Vendor name or "Unknown"
        """
        if not mac or mac == 'Unknown':
            return "Unknown"
            
        try:
            return self.mac_lookup.lookup(mac)
        except Exception:
            return "Unknown"
    
    def determine_device_type(self, vendor, ports=None, hostname=None):
        """
        Determine device type based on vendor, open ports, and hostname
        
        Args:
            vendor: Device vendor name
            ports: Dictionary of open ports
            hostname: Device hostname
            
        Returns:
            Device type string
        """
        # Known vendors and their device types
        vendor_to_type = {
            "Apple": "Apple Device",
            "Microsoft": "Windows Device",
            "Google": "Google Device",
            "Amazon": "Amazon Device",
            "Raspberry Pi": "Raspberry Pi",
            "Arduino": "Arduino Device",
            "Intel": "Computer",
            "Dell": "Dell Computer",
            "HP": "HP Device",
            "Cisco": "Network Device",
            "Juniper": "Network Device",
            "Ubiquiti": "Network Device",
            "Aruba": "Network Device",
            "TP-Link": "Network Device",
            "Netgear": "Network Device",
            "D-Link": "Network Device",
            "Linksys": "Network Device",
            "ASUS": "Network Device",
            "Sony": "Media Device",
            "Samsung": "Samsung Device",
            "LG": "LG Device",
            "Huawei": "Huawei Device",
            "Xiaomi": "Xiaomi Device",
            "Brother": "Printer",
            "Canon": "Printer",
            "Epson": "Printer",
            "HP Inc.": "Printer",
            "Philips": "IoT Device",
            "Nest": "IoT Device",
            "Honeywell": "IoT Device",
            "Synology": "NAS Device",
            "QNAP": "NAS Device",
            "Roku": "Media Device",
            "Sony": "Media Device",
            "Nintendo": "Gaming Console",
            "Microsoft Xbox": "Gaming Console",
            "Sony PlayStation": "Gaming Console"
        }
        
        # First, check for port-based identification
        if ports and isinstance(ports, dict) and len(ports) > 0:
            # Check for common combinations
            port_set = set(ports.keys())
            
            # Router detection (common combinations)
            if (53 in port_set and (80 in port_set or 443 in port_set)) or \
               (67 in port_set and 68 in port_set):
                return "Router"
                
            # NAS detection
            if 445 in port_set and (139 in port_set or 111 in port_set or 2049 in port_set):
                return "NAS Device"
                
            # Printer detection
            if 631 in port_set or 9100 in port_set or 515 in port_set:
                return "Printer"
                
            # IoT hub/controller
            if 1883 in port_set or 8883 in port_set:
                return "IoT Hub"
                
            # Check individual ports for device type hints
            for port in sorted(ports.keys()):
                if port in self.port_device_types:
                    return self.port_device_types[port]
        
        # Hostname-based detection
        if hostname:
            hostname_lower = hostname.lower()
            if "router" in hostname_lower or "gateway" in hostname_lower:
                return "Router"
            if "printer" in hostname_lower:
                return "Printer"
            if "camera" in hostname_lower:
                return "IP Camera"
            if "phone" in hostname_lower or "mobile" in hostname_lower:
                return "Mobile Device"
        
        # Vendor-based detection
        for known_vendor, device_type in vendor_to_type.items():
            if vendor and known_vendor.lower() in vendor.lower():
                return device_type
        
        return "Unknown Device"
    
    def identify_device(self, ip, mac, hostname=None, ports=None):
        """
        Identify a device based on IP, MAC, and possibly open ports
        
        Args:
            ip: IP address
            mac: MAC address
            hostname: Hostname (optional)
            ports: Dictionary of open ports (optional)
            
        Returns:
            Device information dictionary
        """
        # Get vendor information
        vendor = self.get_mac_vendor(mac)
        
        # Determine device type
        device_type = self.determine_device_type(vendor, ports, hostname)
        
        # Check if there's a custom label
        label = self.device_labels.get(ip)
        
        # Build device info
        device_info = {
            'ip': ip,
            'mac': mac,
            'hostname': hostname or "Unknown",
            'vendor': vendor,
            'type': device_type,
            'port_scan_available': self.nmap_available
        }
        
        # Add optional fields
        if label:
            device_info['label'] = label
        
        if ports:
            device_info['open_ports'] = ports
        
        return device_info
