#!/bin/bash
# ============================================================
#  ARIA - Tool Installer
#  Run this once to set up everything
# ============================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════╗"
echo "  ║   ARIA Tool Installer            ║"
echo "  ╚══════════════════════════════════╝"
echo -e "${RESET}"

# Create directories
echo -e "${GREEN}[+] Creating directories...${RESET}"
mkdir -p ~/aria_logs ~/aria_wordlists ~/aria_reports ~/aria_evidence

# Make all scripts executable
echo -e "${GREEN}[+] Setting permissions...${RESET}"
chmod +x ~/aria.sh ~/aria_chat.sh ~/aria_wordlist.sh
chmod +x ~/aria_rayhunter.py ~/aria_pineapple.py

# Install Python dependencies
echo -e "${GREEN}[+] Installing Python packages...${RESET}"
pip install --break-system-packages \
    ndjson \
    pandas \
    rich \
    colorama \
    scapy \
    hexdump 2>/dev/null

# Install system tools
echo -e "${GREEN}[+] Installing system tools...${RESET}"
sudo apt update -qq
sudo apt install -y \
    hashcat \
    john \
    tshark \
    nmap \
    jq \
    tmux \
    xxd \
    aircrack-ng \
    hcxtools \
    net-tools 2>/dev/null

# Add ARIA shortcut to .bashrc
if ! grep -q "alias aria=" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# ARIA Launcher" >> ~/.bashrc
    echo "alias aria='bash ~/aria.sh'" >> ~/.bashrc
    echo -e "${GREEN}[+] Added 'aria' command to shell${RESET}"
fi

# Create systemd service for ollama autostart
echo -e "${GREEN}[+] Enabling Ollama service...${RESET}"
sudo systemctl enable ollama 2>/dev/null
sudo systemctl start ollama 2>/dev/null

echo ""
echo -e "${CYAN}${BOLD}=== Installation Complete ===${RESET}"
echo ""
echo -e "  Start ARIA anytime with: ${GREEN}aria${RESET}"
echo -e "  Or directly:             ${GREEN}bash ~/aria.sh${RESET}"
echo ""
echo -e "${YELLOW}Run: source ~/.bashrc${RESET} to activate the aria command"
echo ""
