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
        
    def get_device_label(self, ip):
        """
        Get the label for a device
        
        Args:
            ip: IP address of the device
            
        Returns:
            Label string or None if no label exists
        """
        return self.device_labels.get(ip)
    
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
                            # Format data to ensure it's all strings to avoid "expected string or bytes-like object" error
                            port_str = str(port)
                            service_info = {
                                'name': str(data['name']) if data['name'] else 'unknown',
                                'product': str(data.get('product', '')),
                                'version': str(data.get('version', ''))
                            }
                            open_ports[port_str] = service_info
                            
                            # Also add a string representation for compatibility
                            if data['name']:
                                service_name = data['name']
                                if data.get('product'):
                                    service_name += f" ({data['product']})"
                                    if data.get('version'):
                                        service_name += f" {data['version']}"
                            else:
                                service_name = "unknown"
                            
                            # Store in a format that both interfaces can handle correctly
                            open_ports[port_str] = service_name
                            
                            # For advanced usage, store full details
                            if "detailed" not in open_ports:
                                open_ports["detailed"] = {}
                            open_ports["detailed"][port_str] = service_info
            
            logger.info(f"Scan found {len(open_ports) - (1 if 'detailed' in open_ports else 0)} open ports on {ip}")
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
            "Nintendo": "Gaming Console",
            "Microsoft Xbox": "Gaming Console",
            "Sony PlayStation": "Gaming Console"
        }
        
        # Enhanced hostname-based detection for common devices
        if hostname:
            hostname_lower = hostname.lower()
            
            # Apple device detection
            if "macbook" in hostname_lower or "mbp" in hostname_lower:
                return "Laptop (MacBook)"
            if "imac" in hostname_lower:
                return "Desktop (iMac)"
            if "iphone" in hostname_lower:
                return "Mobile Phone (iPhone)"
            if "ipad" in hostname_lower:
                return "Tablet (iPad)"
            if "macmini" in hostname_lower or "mac-mini" in hostname_lower:
                return "Desktop (Mac Mini)"
            if "apple" in hostname_lower and "tv" in hostname_lower:
                return "Media Device (Apple TV)"
                
            # Router/network detection
            if "router" in hostname_lower or "gateway" in hostname_lower or "modem" in hostname_lower:
                return "Router/Gateway"
            if "switch" in hostname_lower:
                return "Network Switch"
            if "access-point" in hostname_lower or "accesspoint" in hostname_lower or "ap-" in hostname_lower:
                return "Wireless Access Point"
                
            # Common device types
            if "printer" in hostname_lower:
                return "Printer"
            if "camera" in hostname_lower or "cam-" in hostname_lower:
                return "IP Camera"
            if "phone" in hostname_lower or "mobile" in hostname_lower:
                return "Mobile Device"
            if "laptop" in hostname_lower or "notebook" in hostname_lower:
                return "Laptop"
            if "desktop" in hostname_lower or "pc-" in hostname_lower:
                return "Desktop Computer"
            if "nas" in hostname_lower or "storage" in hostname_lower:
                return "Network Storage (NAS)"
            if "pi" in hostname_lower or "raspberry" in hostname_lower:
                return "Raspberry Pi"
            if "server" in hostname_lower:
                return "Server"
            if "tv" in hostname_lower or "television" in hostname_lower:
                return "Smart TV"
            if "xbox" in hostname_lower:
                return "Gaming Console (Xbox)"
            if "playstation" in hostname_lower or "ps4" in hostname_lower or "ps5" in hostname_lower:
                return "Gaming Console (PlayStation)"
        
        # Convert port strings to integers for port set detection
        port_set = set()
        if ports and isinstance(ports, dict):
            # Handle cases where the scan result might contain the 'detailed' key
            ports_to_check = {k: v for k, v in ports.items() if k != 'detailed' and k != 'error'}
            
            try:
                # Convert port strings to integers for comparison
                for port_str in ports_to_check.keys():
                    try:
                        port_set.add(int(port_str))
                    except (ValueError, TypeError):
                        # Skip non-numeric keys
                        continue
            except Exception as e:
                logger.error(f"Error processing ports for device type detection: {str(e)}")
        
        # Check for common port combinations
        if port_set:
            # Router/Gateway detection 
            if (53 in port_set and (80 in port_set or 443 in port_set)) or \
                (67 in port_set and 68 in port_set):
                return "Router/Gateway"
                
            # Web Server detection
            if (80 in port_set or 443 in port_set) and len(port_set) <= 5:
                return "Web Server"
                
            # NAS detection
            if 445 in port_set and (139 in port_set or 111 in port_set or 2049 in port_set):
                return "Network Storage (NAS)"
                
            # Printer detection
            if 631 in port_set or 9100 in port_set or 515 in port_set:
                return "Printer"
                
            # IoT hub/controller
            if 1883 in port_set or 8883 in port_set:
                return "IoT Hub/Controller"
                
            # SSH-enabled device
            if 22 in port_set and len(port_set) <= 3:
                return "SSH-enabled Device"
                
            # Database server
            if (3306 in port_set or 5432 in port_set or 27017 in port_set or 6379 in port_set):
                return "Database Server"
                
            # Remote desktop
            if 3389 in port_set or 5900 in port_set:
                return "Remote Access Device"
                
            # Media server
            if 8096 in port_set or 32400 in port_set or 8080 in port_set:
                return "Media Server"
                
            # Mail server
            if 25 in port_set or 143 in port_set or 110 in port_set or 587 in port_set:
                return "Mail Server"
                
            # If multiple common ports are open, it might be a multipurpose device
            common_ports = {22, 80, 443, 445, 139, 3306, 5432, 8080}
            intersection = port_set.intersection(common_ports)
            if len(intersection) >= 3:
                return "Multipurpose Server"
            if len(intersection) == 2 and 22 in intersection:
                return "SSH-enabled Server"
        
        # Vendor-based detection for specific device types
        if vendor and vendor != "Unknown":
            # Look for exact matches in vendor_to_type
            for known_vendor, device_type in vendor_to_type.items():
                if vendor.lower() == known_vendor.lower():
                    return device_type
                    
            # More specific Apple device detection
            if "apple" in vendor.lower():
                if hostname:
                    hostname_lower = hostname.lower()
                    if "iphone" in hostname_lower:
                        return "iPhone"
                    if "ipad" in hostname_lower:
                        return "iPad"
                    if "macbook" in hostname_lower:
                        return "MacBook"
                    if "imac" in hostname_lower:
                        return "iMac"
                return "Apple Device"
                
            # Try for partial matches
            for known_vendor, device_type in vendor_to_type.items():
                if known_vendor.lower() in vendor.lower() or vendor.lower() in known_vendor.lower():
                    return device_type
        
        # If we have an open port, determine based on most common port
        if port_set:
            # Find the lowest common port as it might be most characteristic
            common_ports_ordered = [22, 80, 443, 8080, 25, 21, 23, 3389, 445, 139]
            for port in common_ports_ordered:
                if port in port_set:
                    if port in self.port_device_types:
                        return self.port_device_types[port]
            
            # If no common port match, use any port in our mapping
            for port in sorted(port_set):
                if port in self.port_device_types:
                    return self.port_device_types[port]
        
        # Default based on hostname clues if all else fails
        if hostname:
            hostname_lower = hostname.lower()
            common_words = {
                "router": "Network Device",
                "gateway": "Network Device",
                "switch": "Network Device",
                "server": "Server",
                "desktop": "Desktop Computer",
                "laptop": "Laptop",
                "phone": "Mobile Device",
                "printer": "Printer",
                "camera": "IP Camera",
                "hub": "IoT Hub",
                "thermostat": "Smart Thermostat",
                "light": "Smart Light",
                "speaker": "Smart Speaker",
                "tv": "Smart TV"
            }
            
            for word, device_type in common_words.items():
                if word in hostname_lower:
                    return device_type
        
        # If we got all the way here without a match, make an attempt based on network location
        if hostname and hostname.endswith(".lan"):
            return "Local Network Device"
        
        return "Unknown Device"
    
    def identify_device(self, ip, mac, hostname=None, ports=None, health_data=None):
        """
        Identify a device based on IP, MAC, and possibly open ports
        
        Args:
            ip: IP address
            mac: MAC address
            hostname: Hostname (optional)
            ports: Dictionary of open ports (optional)
            health_data: Health check data (optional)
            
        Returns:
            Device information dictionary
        """
        # Get vendor information
        vendor = self.get_mac_vendor(mac)
        
        # Determine device type
        device_type = self.determine_device_type(vendor, ports, hostname)
        
        # Check if there's a custom label
        label = self.device_labels.get(ip)
        
        # Check device status (online/offline)
        status = "Unknown"
        if health_data:
            if health_data.get('status') in ['Good', 'Fair', 'Poor']:
                status = "Online"
            else:
                status = "Offline"
        else:
            # Attempt to perform a basic status check
            try:
                import ping3
                result = ping3.ping(ip, timeout=1)
                if result is not None:
                    status = "Online"
                else:
                    status = "Offline"
            except Exception as e:
                logger.error(f"Error pinging device {ip}: {str(e)}")
        
        # Build device info
        device_info = {
            'ip': ip,
            'mac': mac,
            'hostname': hostname or "Unknown",
            'vendor': vendor,
            'type': device_type,
            'device_type': device_type,  # For compatibility with both interfaces
            'status': status,
            'port_scan_available': self.nmap_available
        }
        
        # Add optional fields
        if label:
            device_info['label'] = label
        
        if ports:
            # Make sure the open ports are in both locations for compatibility
            device_info['open_ports'] = ports
            device_info['ports'] = ports
        
        # Add health information if provided
        if health_data:
            device_info['health_data'] = health_data
            
            # For compatibility with the existing health status system
            if 'status' in health_data:
                if health_data['status'] == 'Good':
                    device_info['health'] = 'healthy'
                elif health_data['status'] == 'Poor':
                    device_info['health'] = 'unhealthy'
                else:
                    device_info['health'] = 'unknown'
        
        return device_info
