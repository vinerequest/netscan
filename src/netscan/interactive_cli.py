#!/usr/bin/env python3

import os
import sys
import time
import re
import socket
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from rich.live import Live

from .network_discovery import get_network_info, discover_devices

# Configure logging
logger = logging.getLogger("netscan")

class InteractiveCLI:
    """Interactive CLI interface for the network scanner using Rich"""
    
    def __init__(self, display, identifier):
        """Initialize the interactive CLI"""
        self.display = display
        self.identifier = identifier
        self.console = Console()
        self.network_info = None
        self.devices = []
        
    def _clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def _display_header(self):
        """Display a header with network information"""
        if self.network_info:
            self.console.print(Panel.fit(
                f"[bold blue]Network:[/] {self.network_info['network_cidr']} | "
                f"[bold blue]Interface:[/] {self.network_info['interface']} | "
                f"[bold blue]Local IP:[/] {self.network_info['ip']}",
                title="[bold cyan]NetScan Interactive Mode[/]",
                border_style="cyan"
            ))
        else:
            self.console.print(Panel.fit(
                "[yellow]Network information not available yet[/]",
                title="[bold cyan]NetScan Interactive Mode[/]",
                border_style="cyan"
            ))
    
    def _display_menu(self):
        """Display the main menu options"""
        self.console.print("\n[bold cyan]Menu Options:[/]")
        menu_table = Table(show_header=False, box=None)
        menu_table.add_column("Key", style="cyan")
        menu_table.add_column("Action", style="white")
        
        menu_table.add_row("1", "Scan Network")
        menu_table.add_row("2", "View Devices")
        menu_table.add_row("3", "Manage Device Labels")
        menu_table.add_row("4", "Port Scan")
        menu_table.add_row("5", "Export Results")
        menu_table.add_row("q", "Quit")
        
        self.console.print(menu_table)
    
    def _scan_network(self):
        """Perform network scanning"""
        self._clear_screen()
        self.console.print(Panel("[bold]Network Scanning[/]", style="cyan"))
        
        # Get network info if not already available
        if not self.network_info:
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Getting network information...[/]"),
                transient=True,
            ) as progress:
                progress.add_task("", total=None)
                self.network_info = get_network_info()
        
        # Ask for network range or use default
        network_cidr = Prompt.ask(
            "[cyan]Network range to scan[/]", 
            default=self.network_info['network_cidr']
        )
        
        # Start scanning
        self.console.print(f"\n[bold cyan]Scanning network: [/]{network_cidr}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Scanning network...[/]"),
            transient=False,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            self.devices = discover_devices(
                network_cidr=network_cidr,
                check_health_status=True,
                interface=self.network_info['interface']
            )
            progress.update(task, completed=True)
        
        if not self.devices:
            self.console.print("[bold red]No devices found.[/]")
            return
        
        # Process device information
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Identifying devices...[/]"),
            transient=False,
        ) as progress:
            task = progress.add_task("Identifying...", total=len(self.devices))
            
            for device in self.devices:
                # Identify the device
                device_info = self.identifier.identify_device(
                    device['ip'], 
                    device['mac'], 
                    hostname=device.get('hostname')
                )
                
                # Add health info if it was collected
                if 'health' in device:
                    device_info['health'] = device.get('health')
                    
                # Add gateway flag if applicable
                if device.get('is_gateway', False):
                    device_info['is_gateway'] = True
                    
                # Update the device in the list with full identification
                for i, d in enumerate(self.devices):
                    if d['ip'] == device_info['ip']:
                        self.devices[i] = device_info
                        break
                
                progress.update(task, advance=1)
        
        # Display a summary
        self.console.print(f"\n[bold green]Found {len(self.devices)} devices.[/]")
        time.sleep(1)
    
    def _display_devices(self):
        """Display the list of discovered devices"""
        self._clear_screen()
        self.console.print(Panel("[bold]Device List[/]", style="cyan"))
        
        if not self.devices:
            self.console.print("[bold yellow]No devices have been discovered yet. Choose option 1 to scan the network.[/]")
            input("\nPress Enter to continue...")
            return
        
        table = Table(title=f"Discovered Devices ({len(self.devices)})")
        table.add_column("IP", style="cyan")
        table.add_column("MAC Address", style="green")
        table.add_column("Hostname", style="blue")
        table.add_column("Device Type", style="magenta")
        table.add_column("Vendor", style="yellow")
        table.add_column("Status", style="bold")
        table.add_column("Label", style="bold cyan")
        
        for device in self.devices:
            status_style = "green" if device.get('health', 'unknown') == 'healthy' else "red"
            status_text = device.get('health', 'unknown')
            if device.get('is_gateway', False):
                status_text += " (Gateway)"
                
            # Get the device label if it exists
            label = self.identifier.get_device_label(device['ip'])
            
            table.add_row(
                device['ip'],
                device['mac'],
                device.get('hostname', 'Unknown'),
                device.get('device_type', 'Unknown'),
                device.get('vendor', 'Unknown'),
                f"[{status_style}]{status_text}[/{status_style}]",
                label if label else ""
            )
        
        self.console.print(table)
        
        # Device details option
        while True:
            ip = Prompt.ask("\n[cyan]Enter IP to view details (or Enter to go back)[/]", default="")
            if not ip:
                break
                
            # Find the device
            device = next((d for d in self.devices if d['ip'] == ip), None)
            if not device:
                self.console.print("[bold red]Device not found.[/]")
                continue
                
            # Display device details
            self._display_device_details(device)
    
    def _display_device_details(self, device):
        """Display detailed information about a specific device"""
        self._clear_screen()
        self.console.print(Panel(f"[bold]Device: {device['ip']}[/]", style="cyan"))
        
        # Prepare device data
        device_copy = device.copy()
        
        # Check if we need to get status
        if 'status' not in device_copy or device_copy['status'] == 'Unknown':
            try:
                import ping3
                result = ping3.ping(device_copy['ip'], timeout=1)
                if result is not None:
                    device_copy['status'] = "Online"
                else:
                    device_copy['status'] = "Offline"
            except Exception as e:
                self.console.print(f"[yellow]Warning: Error checking device status: {str(e)}[/]")
                device_copy['status'] = "Unknown"
        
        # Check if we have a device type, get from 'type' if needed
        if not device_copy.get('device_type') or device_copy['device_type'] == 'Unknown':
            if device_copy.get('type') and device_copy['type'] != 'Unknown':
                device_copy['device_type'] = device_copy['type']
            elif device_copy.get('vendor') or device_copy.get('hostname'):
                # Try to determine based on vendor and hostname
                device_copy['device_type'] = self.identifier.determine_device_type(
                    device_copy.get('vendor', 'Unknown'),
                    device_copy.get('ports', {}),
                    device_copy.get('hostname')
                )
        
        # Create basic info table
        basic_info_table = Table(title="Basic Information", show_header=False)
        basic_info_table.add_column("Property", style="cyan")
        basic_info_table.add_column("Value", style="white")
        
        # Add properties in a specific order
        properties = [
            ("IP Address", device_copy['ip']),
            ("MAC Address", device_copy.get('mac', 'Unknown')),
            ("Hostname", device_copy.get('hostname', 'Unknown')),
            ("Device Type", device_copy.get('device_type', device_copy.get('type', 'Unknown'))),
            ("Vendor", device_copy.get('vendor', 'Unknown')),
            ("Status", device_copy.get('status', 'Unknown')),
            ("Gateway", "Yes" if device_copy.get('is_gateway') else "No"),
            ("Label", device_copy.get('label', 'No label'))
        ]
        
        for prop, value in properties:
            # Add styling for status
            if prop == "Status":
                if value == "Online":
                    value = f"[green]{value}[/green]"
                elif value == "Offline":
                    value = f"[red]{value}[/red]"
                else:
                    value = f"[yellow]{value}[/yellow]"
                    
            basic_info_table.add_row(prop, str(value))
        
        self.console.print(basic_info_table)
        
        # Display ports if available
        clean_ports = {}
        if 'ports' in device and device['ports'] and isinstance(device['ports'], dict):
            # Process port scan results for display
            raw_ports = device['ports']
            
            for port_key, port_info in raw_ports.items():
                # Skip non-port keys like 'detailed' or 'error'
                if port_key in ['detailed', 'error']:
                    continue
                    
                # Process different formats of port info
                if isinstance(port_info, dict):
                    # Extract name for display
                    if 'name' in port_info:
                        service_name = port_info['name']
                        if port_info.get('product'):
                            service_name += f" ({port_info['product']})"
                            if port_info.get('version'):
                                service_name += f" {port_info['version']}"
                        clean_ports[port_key] = service_name
                    else:
                        clean_ports[port_key] = "unknown"
                elif isinstance(port_info, str):
                    # Use the string directly
                    clean_ports[port_key] = port_info
                else:
                    # Fallback for any other data type
                    clean_ports[port_key] = str(port_info)
                    
            # Only create table if we have ports to show
            if clean_ports:
                ports_table = Table(title="Open Ports")
                ports_table.add_column("Port", style="cyan")
                ports_table.add_column("Service", style="green")
                ports_table.add_column("Information", style="yellow")
                
                port_applications = {
                    "22": "SSH - Secure Shell",
                    "80": "HTTP - Web Server",
                    "443": "HTTPS - Secure Web Server",
                    "21": "FTP - File Transfer",
                    "23": "Telnet - Remote Access (insecure)",
                    "25": "SMTP - Mail Server",
                    "53": "DNS - Domain Name System",
                    "3306": "MySQL Database",
                    "5432": "PostgreSQL Database",
                    "8080": "Web Server/Proxy",
                    "1433": "MS SQL Server",
                    "3389": "Remote Desktop Protocol",
                    "5900": "VNC Remote Access",
                    "139": "NetBIOS - Windows Networking",
                    "445": "SMB - Windows File Sharing"
                }
                
                for port, service in clean_ports.items():
                    app_info = port_applications.get(port, "")
                    ports_table.add_row(str(port), service, app_info)
                
                self.console.print(ports_table)
        
        if not clean_ports:
            self.console.print("\n[yellow]No port scan information available. Use the Port Scan option to scan for open ports.[/yellow]")
        
        input("\nPress Enter to go back...")
    
    def _manage_labels(self):
        """Manage device labels"""
        self._clear_screen()
        self.console.print(Panel("[bold]Manage Device Labels[/]", style="cyan"))
        
        while True:
            self.console.print("\n[bold cyan]Label Management Options:[/]")
            menu_table = Table(show_header=False, box=None)
            menu_table.add_column("Key", style="cyan")
            menu_table.add_column("Action", style="white")
            
            menu_table.add_row("1", "View All Labels")
            menu_table.add_row("2", "Add/Update Label")
            menu_table.add_row("3", "Remove Label")
            menu_table.add_row("b", "Back to Main Menu")
            
            self.console.print(menu_table)
            
            choice = Prompt.ask("\n[cyan]Choose an option[/]", choices=["1", "2", "3", "b"], default="b")
            
            if choice == "1":
                self._view_labels()
            elif choice == "2":
                self._add_label()
            elif choice == "3":
                self._remove_label()
            elif choice == "b":
                break
    
    def _view_labels(self):
        """View all device labels"""
        self._clear_screen()
        self.console.print(Panel("[bold]Device Labels[/]", style="cyan"))
        
        if not self.identifier.device_labels:
            self.console.print("[bold yellow]No device labels found.[/]")
            input("\nPress Enter to continue...")
            return
        
        table = Table(title="Saved Device Labels")
        table.add_column("IP Address", style="cyan")
        table.add_column("Label", style="green")
        
        for ip, label in self.identifier.device_labels.items():
            table.add_row(ip, label)
        
        self.console.print(table)
        input("\nPress Enter to continue...")
    
    def _add_label(self):
        """Add or update a device label"""
        self._clear_screen()
        self.console.print(Panel("[bold]Add/Update Device Label[/]", style="cyan"))
        
        # Show discovered devices if available
        if self.devices:
            table = Table(title="Discovered Devices")
            table.add_column("IP", style="cyan")
            table.add_column("Hostname", style="blue")
            table.add_column("Current Label", style="green")
            
            for device in self.devices:
                label = self.identifier.get_device_label(device['ip']) or ""
                table.add_row(
                    device['ip'],
                    device.get('hostname', 'Unknown'),
                    label
                )
            
            self.console.print(table)
        
        # Get IP and label
        ip = Prompt.ask("[cyan]IP address[/]")
        label = Prompt.ask("[cyan]Label[/]")
        
        if self.identifier.add_device_label(ip, label):
            self.console.print(f"\n[bold green]Added label '{label}' for device {ip}[/]")
        else:
            self.console.print(f"\n[bold red]Failed to add label for device {ip}[/]")
        
        input("\nPress Enter to continue...")
    
    def _remove_label(self):
        """Remove a device label"""
        self._clear_screen()
        self.console.print(Panel("[bold]Remove Device Label[/]", style="cyan"))
        
        if not self.identifier.device_labels:
            self.console.print("[bold yellow]No device labels found.[/]")
            input("\nPress Enter to continue...")
            return
        
        # Show existing labels
        table = Table(title="Saved Device Labels")
        table.add_column("IP Address", style="cyan")
        table.add_column("Label", style="green")
        
        for ip, label in self.identifier.device_labels.items():
            table.add_row(ip, label)
        
        self.console.print(table)
        
        # Get IP to remove
        ip = Prompt.ask("[cyan]IP address to remove label[/]")
        
        if self.identifier.remove_device_label(ip):
            self.console.print(f"\n[bold green]Removed label for device {ip}[/]")
        else:
            self.console.print(f"\n[bold red]Failed to remove label for device {ip} (label may not exist)[/]")
        
        input("\nPress Enter to continue...")
    
    def _port_scan(self):
        """Perform port scanning on a specific device"""
        self._clear_screen()
        self.console.print(Panel("[bold]Port Scanning[/]", style="cyan"))
        
        if not self.identifier.nmap_available:
            self.console.print("[bold red]Port scanning requires nmap, which is not installed.[/]")
            self.console.print(f"Install nmap with: [bold cyan]{'brew install nmap' if sys.platform == 'darwin' else 'apt install nmap'}[/]")
            input("\nPress Enter to continue...")
            return
        
        # Show discovered devices if available
        if self.devices:
            table = Table(title="Discovered Devices")
            table.add_column("IP", style="cyan")
            table.add_column("Hostname", style="blue")
            table.add_column("Device Type", style="green")
            
            for device in self.devices:
                table.add_row(
                    device['ip'],
                    device.get('hostname', 'Unknown'),
                    device.get('device_type', 'Unknown')
                )
            
            self.console.print(table)
        
        # Get IP to scan
        ip = Prompt.ask("[cyan]IP address to scan[/]")
        deep_scan = Confirm.ask("[cyan]Perform deep scan?[/]", default=False)
        
        # Define port range
        port_range = None
        if deep_scan:
            port_range = "1-1024,1433,1521,3000,3306,3389,5000,5432,5900,5901,6379,8000-8100,9000-9200,27017"
        
        # Perform scan
        self.console.print(f"\n[bold cyan]Scanning ports on {ip}...[/]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]Scanning ports on {ip}...[/]"),
            transient=False,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            scan_result = self.identifier.scan_ports(ip, ports=port_range)
            progress.update(task, completed=True)
        
        # Process scan results
        if not scan_result or (isinstance(scan_result, dict) and "error" in scan_result):
            error_message = scan_result.get("error", "Unknown error") if isinstance(scan_result, dict) else "No ports found"
            self.console.print(f"[bold red]Error scanning ports: {error_message}[/]")
            input("\nPress Enter to continue...")
            return
        
        # Clean up port data for display
        clean_ports = {}
        port_count = 0
        
        for port_key, port_info in scan_result.items():
            # Skip non-port keys like 'detailed' or 'error'
            if port_key in ['detailed', 'error']:
                continue
                
            port_count += 1
            
            # Handle different possible formats of port info
            if isinstance(port_info, dict):
                # Extract name for display
                if 'name' in port_info:
                    service_name = port_info['name']
                    if port_info.get('product'):
                        service_name += f" ({port_info['product']})"
                        if port_info.get('version'):
                            service_name += f" {port_info['version']}"
                    clean_ports[port_key] = service_name
                else:
                    clean_ports[port_key] = "unknown"
            elif isinstance(port_info, str):
                # Use the string directly
                clean_ports[port_key] = port_info
            else:
                # Fallback for any other data type
                clean_ports[port_key] = str(port_info)
        
        if not clean_ports:
            self.console.print("[bold yellow]No open ports found.[/]")
            input("\nPress Enter to continue...")
            return
        
        # Display results
        self.console.print(f"\n[bold green]Scan completed - {port_count} open ports found.[/]\n")
        
        # Create a table for the results
        scan_type = "Deep" if deep_scan else "Quick"
        ports_table = Table(title=f"Port Scan: {ip} - {scan_type} Scan")
        ports_table.add_column("Port", style="cyan")
        ports_table.add_column("Service", style="green")
        ports_table.add_column("Possible Applications", style="yellow")
        
        port_applications = {
            "22": "SSH, SFTP - Secure shell for remote access",
            "80": "HTTP, Web Server - Hypertext Transfer Protocol",
            "443": "HTTPS, Secure Web Server - Encrypted web traffic",
            "21": "FTP - File Transfer Protocol",
            "23": "Telnet - Remote terminal access (insecure)",
            "25": "SMTP, Mail Server - Email sending",
            "53": "DNS - Domain Name System",
            "110": "POP3 - Post Office Protocol (email retrieval)",
            "143": "IMAP - Internet Message Access Protocol (email)",
            "3306": "MySQL Database - Open source database",
            "5432": "PostgreSQL Database - Open source database",
            "8080": "Web Server, Proxy - Alternate HTTP port",
            "1433": "Microsoft SQL Server - Database",
            "3389": "Remote Desktop Protocol (RDP) - Windows remote access",
            "5900": "VNC Remote Access - Virtual Network Computing",
            "5901": "VNC Remote Access - Virtual Network Computing",
            "6379": "Redis - In-memory data structure store",
            "27017": "MongoDB - NoSQL database",
            "139": "SMB, Windows File Sharing - Server Message Block",
            "445": "SMB, Windows File Sharing - Server Message Block",
            "548": "AFP - Apple Filing Protocol for file sharing",
            "631": "IPP - Internet Printing Protocol",
            "5000": "UPnP - Universal Plug and Play / Flask apps",
            "8000": "Common web development port (Django, etc.)",
            "8888": "Jupyter Notebook - Web-based development"
        }
        
        for port, service in clean_ports.items():
            app_info = port_applications.get(port, "-")
            ports_table.add_row(port, service, app_info)
        
        self.console.print(ports_table)
        
        # Update device info if it exists
        device_updated = False
        for i, device in enumerate(self.devices):
            if device['ip'] == ip:
                # Store in both locations to ensure compatibility
                self.devices[i]['ports'] = scan_result
                self.devices[i]['open_ports'] = scan_result
                
                # Update device type if we found open ports
                if clean_ports and len(clean_ports) > 0:
                    device_type = self.identifier.determine_device_type(
                        device.get('vendor', 'Unknown'),
                        scan_result,
                        device.get('hostname')
                    )
                    self.devices[i]['device_type'] = device_type
                    self.devices[i]['type'] = device_type
                    
                self.console.print("[bold green]Device information updated.[/]")
                device_updated = True
                break
                
        # If device not in list, add a basic entry
        if not device_updated:
            self.console.print("[bold yellow]Device not in current scan list. Adding as new device.[/]")
            
            # Try to identify the device with the port information
            try:
                hostname = socket.getfqdn(ip)
                if hostname == ip:  # If hostname is the same as IP, resolution failed
                    hostname = 'Unknown'
            except Exception:
                hostname = 'Unknown'
            
            # Try to determine MAC address
            mac = 'Unknown'
            try:
                import subprocess
                try:
                    output = subprocess.check_output(['arp', '-n', ip], text=True)
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                    if mac_match:
                        mac = mac_match.group(0)
                except subprocess.SubprocessError:
                    pass  # Silently handle subprocess errors
            except Exception:
                pass  # Silently handle any other errors
            
            # Get vendor information
            vendor = 'Unknown'
            if mac != 'Unknown':
                vendor = self.identifier.get_mac_vendor(mac)
            
            # Determine device type based on ports
            device_type = self.identifier.determine_device_type(vendor, scan_result, hostname)
            
            new_device = {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'device_type': device_type,
                'type': device_type,
                'vendor': vendor,
                'status': 'Online',  # If we can scan ports, it's online
                'ports': scan_result,
                'open_ports': scan_result
            }
            self.devices.append(new_device)
            
        input("\nPress Enter to continue...")
    
    def _export_results(self):
        """Export scan results to a file"""
        self._clear_screen()
        self.console.print(Panel("[bold]Export Results[/]", style="cyan"))
        
        if not self.devices:
            self.console.print("[bold yellow]No devices have been discovered yet. Choose option 1 to scan the network.[/]")
            input("\nPress Enter to continue...")
            return
        
        # Ask for filename
        filename = Prompt.ask("[cyan]Enter filename to save results[/]", default="netscan_results.json")
        
        from .main import save_results
        if save_results(self.devices, filename):
            self.console.print(f"\n[bold green]Scan results saved to {filename}[/]")
        else:
            self.console.print(f"\n[bold red]Failed to save scan results to {filename}[/]")
        
        input("\nPress Enter to continue...")
    
    def run(self):
        """Run the interactive CLI interface"""
        try:
            while True:
                self._clear_screen()
                self._display_header()
                self._display_menu()
                
                choice = Prompt.ask("\n[cyan]Choose an option[/]", choices=["1", "2", "3", "4", "5", "q"], default="1")
                
                if choice == "1":
                    self._scan_network()
                elif choice == "2":
                    self._display_devices()
                elif choice == "3":
                    self._manage_labels()
                elif choice == "4":
                    self._port_scan()
                elif choice == "5":
                    self._export_results()
                elif choice == "q":
                    self.console.print("[bold cyan]Exiting...[/]")
                    return 0
        
        except KeyboardInterrupt:
            self.console.print("\n[bold cyan]Interrupted. Exiting...[/]")
            return 130
        except Exception as e:
            self.console.print(f"\n[bold red]Error: {str(e)}[/]")
            return 1