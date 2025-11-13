#!/bin/bash

# AD Enumeration Tool Setup Script
# This script installs the required dependencies for the AD enumeration tool

echo "[+] AD Enumeration Tool Setup"
echo "[+] Installing required packages..."

# Update package list
sudo apt update

# Install Python dependencies
echo "[+] Installing Python packages..."
pip3 install --user asyncio

# Install enumeration tools
echo "[+] Installing enumeration tools..."

# Install nmap
sudo apt install -y nmap

# Install netexec (formerly CrackMapExec)
echo "[+] Installing netexec..."
pip3 install --user netexec

# Install gobuster for directory busting
sudo apt install -y gobuster

# Install nikto for web vulnerability scanning
sudo apt install -y nikto

# Install curl (usually pre-installed)
sudo apt install -y curl

# Install wordlists
echo "[+] Installing wordlists..."
sudo apt install -y seclists dirb

echo "[+] Setup complete!"
echo "[+] Make sure the following tools are in your PATH:"
echo "    - nmap"
echo "    - netexec"
echo "    - gobuster"
echo "    - nikto"
echo "    - curl"
echo ""
echo "[+] You can now run the AD enumeration tool with:"
echo "    python3 main.py --help"