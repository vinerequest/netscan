#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import ipaddress
import socket
import netifaces
import ping3
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
from concurrent.futures import ThreadPoolExecutor
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("netscan")

def is_root():
    """Check if the script is running with root privileges"""
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False

def get_network_info(interface=None):
    """
    Get the local IP address, network CIDR, and default gateway
    
    Args:
        interface: Specific network interface to use (optional)
        
    Returns:
        Dictionary containing network information
    """
    try:
        # Get the default gateway and interface
        gateways = netifaces.gateways()
        if 'default' not in gateways or netifaces.AF_INET not in gateways['default']:
            logger.error("No default gateway found")
            return None
            
        default_gw = gateways['default'][netifaces.AF_INET]
        default_gateway = default_gw[0]
        default_interface = interface or default_gw[1]
        
        # Get address information for the interface
        addrs = netifaces.ifaddresses(default_interface)
        if netifaces.AF_INET not in addrs:
            logger.error(f"No IPv4 address found for interface {default_interface}")
            return None
            
        ip_info = addrs[netifaces.AF_INET][0]
        ip_address = ip_info['addr']
        netmask = ip_info['netmask']
        
        # Convert netmask to CIDR notation
        netmask_bits = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
        
        # Determine network CIDR
        ip_obj = ipaddress.IPv4Address(ip_address)
        network_obj = ipaddress.IPv4Network(f"{ip_address}/{netmask_bits}", strict=False)
        network_cidr = f"{network_obj.network_address}/{netmask_bits}"
        
        return {
            'ip_address': ip_address,
            'network_cidr': network_cidr,
            'default_gateway': default_gateway,
            'interface': default_interface
        }
    except Exception as e:
        logger.error(f"Error getting network information: {str(e)}")
        return None

def scan_network(network_cidr, timeout=2):
    """
    Scan the network to discover active devices using ARP
    
    Args:
        network_cidr: Network in CIDR notation (e.g., "192.168.1.0/24")
        timeout: Timeout for ARP responses in seconds
        
    Returns:
        List of dictionaries with discovered devices information
    """
    if not is_root():
        logger.error("Root privileges required for network scanning")
        return []
        
    try:
        # Create ARP request packet for all IPs in the network
        arp_request = ARP(pdst=network_cidr)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Send packets and capture responses
        logger.info(f"Scanning network {network_cidr}...")
        answered, _ = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)
        
        # Process responses
        devices = []
        for sent, received in answered:
            device = {
                'ip': received.psrc,
                'mac': received.hwsrc
            }
            devices.append(device)
            
        logger.info(f"Discovered {len(devices)} devices")
        return devices
    except Exception as e:
        logger.error(f"Error scanning network: {str(e)}")
        return []

def resolve_hostname(ip_address):
    """
    Resolve hostname for an IP address
    
    Args:
        ip_address: IP address to resolve
        
    Returns:
        Hostname or None if not resolvable
    """
    try:
        hostname = socket.getfqdn(ip_address)
        # If hostname is the same as IP, it wasn't resolved
        if hostname == ip_address:
            return None
        return hostname
    except Exception:
        return None

def check_health(ip_address, count=4, timeout=1):
    """
    Check device health using ping
    
    Args:
        ip_address: IP address to ping
        count: Number of pings to send
        timeout: Timeout for each ping in seconds
        
    Returns:
        Dictionary with latency and packet loss info
    """
    ping_results = {
        'latency_ms': None,
        'packet_loss_pct': 100,
        'status': 'Offline'
    }
    
    try:
        # Send multiple pings
        ping_times = []
        for _ in range(count):
            try:
                # ping3 returns time in seconds, convert to ms
                ping_time = ping3.ping(ip_address, timeout=timeout)
                if ping_time is not None:
                    ping_times.append(ping_time * 1000)  # Convert to ms
            except Exception:
                pass
                
        # Calculate statistics
        if ping_times:
            avg_latency = sum(ping_times) / len(ping_times)
            packet_loss = ((count - len(ping_times)) / count) * 100
            
            ping_results['latency_ms'] = round(avg_latency, 1)
            ping_results['packet_loss_pct'] = round(packet_loss, 1)
            
            # Determine status
            if avg_latency < 50 and packet_loss == 0:
                ping_results['status'] = 'Good'
            elif avg_latency > 100 or packet_loss > 10:
                ping_results['status'] = 'Poor'
            else:
                ping_results['status'] = 'Fair'
    except Exception as e:
        logger.error(f"Error checking health for {ip_address}: {str(e)}")
        
    return ping_results

def check_device_health(devices, max_workers=10):
    """
    Check health for all discovered devices in parallel
    
    Args:
        devices: List of device dictionaries
        max_workers: Maximum number of concurrent workers
        
    Returns:
        Devices list with health information added
    """
    if not devices:
        return devices
        
    with ThreadPoolExecutor(max_workers=min(max_workers, len(devices))) as executor:
        # Map IP addresses to futures
        future_to_ip = {executor.submit(check_health, device['ip']): device for device in devices}
        
        # Process results as they complete
        for future in future_to_ip:
            device = future_to_ip[future]
            try:
                health_result = future.result()
                device['health'] = health_result
            except Exception as e:
                logger.error(f"Health check error for {device['ip']}: {str(e)}")
                device['health'] = {
                    'latency_ms': None,
                    'packet_loss_pct': None,
                    'status': 'Error'
                }
                
    return devices

def discover_devices(network_cidr=None, check_health_status=True, interface=None):
    """
    Main function to discover and identify devices on the network
    
    Args:
        network_cidr: Network CIDR to scan (e.g., "192.168.1.0/24")
        check_health_status: Whether to check device health
        interface: Network interface to use
        
    Returns:
        List of discovered devices with their information
    """
    # Get network information if not provided
    if network_cidr is None:
        network_info = get_network_info(interface)
        if not network_info:
            logger.error("Failed to get network information")
            return []
        network_cidr = network_info.get('network_cidr')
        
    # Discover devices on the network
    devices = scan_network(network_cidr)
    
    # Get default gateway and ensure it's in the list
    network_info = get_network_info(interface)
    if network_info:
        gateway_ip = network_info.get('default_gateway')
        gateway_in_list = any(d['ip'] == gateway_ip for d in devices)
        
        if not gateway_in_list and gateway_ip:
            # Add gateway if not already in list
            devices.append({
                'ip': gateway_ip,
                'mac': 'Unknown',  # Will be updated later if possible
                'is_gateway': True
            })
    
    # Check device health if requested
    if check_health_status:
        devices = check_device_health(devices)
    
    # Resolve hostname for each device
    for device in devices:
        device['hostname'] = resolve_hostname(device['ip'])
    
    return devices
