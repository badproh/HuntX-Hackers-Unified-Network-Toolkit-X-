#!/bin/bash

# Colors
GREEN='\033[92m'
RESET='\033[0m'
RED='\033[91m'

echo -e "${GREEN}[+] Starting HuntX Installer...${RESET}"

# 1. Check if running as root (needed for apt)
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[!] Please run as root (sudo ./install.sh)${RESET}"
  exit
fi

# 2. Update and Install System Tools (Matches Summary Requirements)
echo -e "${GREEN}[+] Installing System Dependencies (Nmap, Hydra, Netcat, Wafw00f, Wireshark)...${RESET}"
apt-get update -y
apt-get install -y python3 python3-pip nmap hydra netcat-openbsd wireshark wafw00f git

# 3. Install Python Dependencies
echo -e "${GREEN}[+] Installing Python Dependencies...${RESET}"
pip3 install -r requirements.txt --break-system-packages

# 4. Permission Handling
echo -e "${GREEN}[+] Setting execution permissions...${RESET}"
chmod +x huntx.py

echo -e "${GREEN}[+] Installation Complete! Run with: python3 huntx.py${RESET}"