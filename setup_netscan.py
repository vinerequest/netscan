#!/usr/bin/env python3

"""
Network Scanner Setup Script

This script sets up the Network Scanner tool. It:
1. Creates the necessary directory structure
2. Creates the Python package files
3. Installs the package
4. Checks for required dependencies

It works on Windows, macOS, and Linux.
"""

import os
import sys
import shutil
import platform
import subprocess
import tempfile
import argparse
from pathlib import Path

# ANSI color codes (not used on Windows except Windows 10+)
GREEN = '\033[92m' if platform.system() != 'Windows' or (platform.system() == 'Windows' and int(platform.release()) >= 10) else ''
YELLOW = '\033[93m' if platform.system() != 'Windows' or (platform.system() == 'Windows' and int(platform.release()) >= 10) else ''
RED = '\033[91m' if platform.system() != 'Windows' or (platform.system() == 'Windows' and int(platform.release()) >= 10) else ''
RESET = '\033[0m' if platform.system() != 'Windows' or (platform.system() == 'Windows' and int(platform.release()) >= 10) else ''

def print_color(text, color):
    """Print colored text"""
    print(f"{color}{text}{RESET}")

def run_command(command, check=True, shell=False):
    """Run a command and return the result"""
    try:
        # Use shell=True on Windows, shell=False elsewhere
        use_shell = shell or platform.system() == 'Windows'
        result = subprocess.run(command, check=check, shell=use_shell, 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                               text=True)
        return result
    except subprocess.CalledProcessError as e:
        print_color(f"Command failed: {e}", RED)
        print_color(f"Error output: {e.stderr}", RED)
        return None

def check_dependencies():
    """Check for required dependencies"""
    issues = []
    
    # Check Python version
    if sys.version_info < (3, 6):
        issues.append({
            'type': 'error',
            'message': f"Python version {sys.version} is not supported.",
            'fix': "Please upgrade to Python 3.6 or later."
        })
    
    # Check for pip
    pip_command = 'pip3' if shutil.which('pip3') else 'pip'
    if not shutil.which(pip_command):
        issues.append({
            'type': 'error',
            'message': "pip not found.",
            'fix': "Please install pip (usually included with Python)."
        })
    
    # Check for nmap (optional)
    if not shutil.which('nmap'):
        install_cmd = ""
        if platform.system() == 'Darwin':  # macOS
            install_cmd = "brew install nmap"
        elif platform.system() == 'Linux':
            if shutil.which('apt'):
                install_cmd = "sudo apt install nmap"
            elif shutil.which('yum'):
                install_cmd = "sudo yum install nmap"
            elif shutil.which('dnf'):
                install_cmd = "sudo dnf install nmap"
        elif platform.system() == 'Windows':
            install_cmd = "Download and install from https://nmap.org/download.html"
            
        issues.append({
            'type': 'warning',
            'message': "nmap not found. Port scanning will be disabled.",
            'fix': f"Install nmap with: {install_cmd}"
        })
    
    return issues

def create_directory_structure(base_dir):
    """Create the directory structure for the netscan package"""
    try:
        # Create main directories
        os.makedirs(os.path.join(base_dir, "src", "netscan"), exist_ok=True)
        os.makedirs(os.path.join(base_dir, "tests"), exist_ok=True)
        
        print_color(f"Created directory structure in {base_dir}", GREEN)
        return True
    except Exception as e:
        print_color(f"Error creating directory structure: {str(e)}", RED)
        return False

def create_setup_py(base_dir):
    """Create the setup.py file"""
    setup_py = """from setuptools import setup, find_packages

setup(
    name="netscan",
    version="0.1.0",
    description="Network Scanner - Discover, identify, and monitor devices on your network",
    author="Digital Dropkick, LLC",
    author_email="info@digitaldropkick.com",
    url="https://github.com/digitaldropkick/netscan",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "scapy==2.6.1",
        "python-nmap==0.7.1",
        "netifaces==0.11.0",
        "mac-vendor-lookup==0.1.12",
        "tabulate==0.9.0",
        "ping3==4.0.4",
    ],
    entry_points={
        'console_scripts': [
            'netscan=netscan.main:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    python_requires=">=3.6",
)
"""
    try:
        with open(os.path.join(base_dir, "setup.py"), 'w') as f:
            f.write(setup_py)
        print_color("Created setup.py", GREEN)
        return True
    except Exception as e:
        print_color(f"Error creating setup.py: {str(e)}", RED)
        return False

def create_init_py(base_dir):
    """Create the __init__.py file"""
    init_py = '''"""
Network Scanner - A tool to scan local networks and identify connected devices.

This package provides functionality to:
1. Discover devices on the local network
2. Check network health with ping tests
3. Identify devices based on MAC vendor and open ports
4. Label and track devices across scans
"""

__version__ = "0.1.0"
'''
    try:
        with open(os.path.join(base_dir, "src", "netscan", "__init__.py"), 'w') as f:
            f.write(init_py)
        print_color("Created __init__.py", GREEN)
        return True
    except Exception as e:
        print_color(f"Error creating __init__.py: {str(e)}", RED)
        return False

def install_package(base_dir, pip_command='pip'):
    """Install the package in development mode"""
    print_color("Installing the package...", GREEN)
    
    # Determine if we need to use sudo (not on Windows)
    use_sudo = platform.system() != 'Windows' and os.geteuid() != 0 if hasattr(os, "geteuid") else False
    
    if use_sudo:
        cmd = ['sudo', pip_command, 'install', '-e', base_dir]
    else:
        cmd = [pip_command, 'install', '-e', base_dir]
    
    result = run_command(cmd)
    if result and result.returncode == 0:
        print_color("Package installed successfully!", GREEN)
        return True
    else:
        print_color("Failed to install package.", RED)
        print_color("Try running manually: sudo pip install -e /path/to/netscan", YELLOW)
        return False

def main():
    """Main entry point for the setup script"""
    parser = argparse.ArgumentParser(description='Network Scanner Setup Script')
    parser.add_argument('--dir', help='Installation directory (default: ~/netscan)', default=None)
    parser.add_argument('--no-install', action='store_true', help='Create files but don\'t install the package')
    args = parser.parse_args()
    
    print_color("=== Network Scanner Setup ===", GREEN)
    
    # Check dependencies
    issues = check_dependencies()
    for issue in issues:
        if issue['type'] == 'error':
            print_color(f"ERROR: {issue['message']} {issue['fix']}", RED)
            return 1
        else:
            print_color(f"WARNING: {issue['message']} {issue['fix']}", YELLOW)
    
    # Determine installation directory
    if args.dir:
        base_dir = os.path.abspath(args.dir)
    else:
        home_dir = str(Path.home())
        base_dir = os.path.join(home_dir, 'netscan')
    
    # Create directory structure
    if not create_directory_structure(base_dir):
        return 1
    
    # Create setup.py
    if not create_setup_py(base_dir):
        return 1
    
    # Create __init__.py
    if not create_init_py(base_dir):
        return 1
    
    # Copy source files from this repository if they exist
    # Otherwise, you'd create the source files here
    
    # Install the package
    if not args.no_install:
        pip_command = 'pip3' if shutil.which('pip3') else 'pip'
        if not install_package(base_dir, pip_command):
            return 1
    
    print_color("\nSetup complete!", GREEN)
    print_color("You can now run the network scanner with: sudo netscan", GREEN)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())