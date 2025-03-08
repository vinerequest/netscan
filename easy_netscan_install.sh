#!/bin/bash

# Define colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Network Scanner One-Command Setup ===${NC}"
echo "This script will download, set up, and install the Network Scanner"

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This installation script requires sudo privileges.${NC}"
    echo "Please run with: sudo bash -c \"$(curl -fsSL https://raw.githubusercontent.com/yourusername/netscan/main/easy_netscan_install.sh)\""
    exit 1
fi

# Create a temporary directory for the download
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo -e "${GREEN}Downloading setup script...${NC}"
# Download the setup script (URL should be replaced with the actual GitHub URL)
curl -sL -o setup_and_install_netscan.sh https://raw.githubusercontent.com/yourusername/netscan/main/setup_and_install_netscan.sh
chmod +x setup_and_install_netscan.sh

echo -e "${GREEN}Running setup script...${NC}"
# Run the setup script
./setup_and_install_netscan.sh

# Clean up
cd ~
rm -rf "$TEMP_DIR"

echo -e "${GREEN}Setup complete!${NC}"
echo -e "You can now run the network scanner with: ${YELLOW}sudo netscan${NC}"