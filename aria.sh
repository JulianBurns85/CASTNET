#!/bin/bash
# ============================================================
#  ARIA - Master Launcher
#  Central menu for all ARIA tools
# ============================================================

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

clear
echo -e "${CYAN}${BOLD}"
cat << 'EOF'
  ╔═══════════════════════════════════════════════╗
  ║                                               ║
  ║    █████╗ ██████╗ ██╗ █████╗                 ║
  ║   ██╔══██╗██╔══██╗██║██╔══██╗                ║
  ║   ███████║██████╔╝██║███████║                ║
  ║   ██╔══██║██╔══██╗██║██╔══██║                ║
  ║   ██║  ██║██║  ██║██║██║  ██║                ║
  ║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝                ║
  ║                                               ║
  ║   Automated Recon & Investigation Assistant   ║
  ║   Offline Cybersecurity AI — Raspberry Pi 5   ║
  ╚═══════════════════════════════════════════════╝
EOF
echo -e "${RESET}"

# Check ollama is running
if ! pgrep -x "ollama" > /dev/null; then
    echo -e "${YELLOW}[*] Starting Ollama service...${RESET}"
    ollama serve &>/dev/null &
    sleep 2
fi

echo -e "${GREEN}[+] Ollama running${RESET}"
echo ""

show_menu() {
    echo -e "${BOLD}Select Tool:${RESET}"
    echo ""
    echo -e "  ${CYAN}1)${RESET} ARIA Chat            — Interactive AI assistant"
    echo -e "  ${CYAN}2)${RESET} Rayhunter Analyser   — Parse NDJSON/QMDL cellular logs"
    echo -e "  ${CYAN}3)${RESET} Pineapple Analyser   — Parse WiFi Pineapple recon logs"
    echo -e "  ${CYAN}4)${RESET} Wordlist Generator   — Hashcat wordlists and rules"
    echo -e "  ${CYAN}5)${RESET} Quick Query          — One-shot question to ARIA"
    echo -e "  ${CYAN}6)${RESET} Analyse a File       — Drop any file into ARIA"
    echo -e "  ${CYAN}7)${RESET} System Status        — Check models and resources"
    echo -e "  ${CYAN}8)${RESET} Update ARIA Model    — Rebuild ARIA with new Modelfile"
    echo -e "  ${CYAN}9)${RESET} Exit"
    echo ""
    echo -ne "${GREEN}Choice: ${RESET}"
}

quick_query() {
    echo ""
    echo -ne "${GREEN}Question: ${RESET}"
    read -r query
    echo ""
    echo -e "${YELLOW}ARIA:${RESET}"
    ollama run aria "$query"
}

analyse_file() {
    echo ""
    echo -ne "${GREEN}File path: ${RESET}"
    read -r filepath

    if [[ ! -f "$filepath" ]]; then
        echo -e "${RED}[-] File not found.${RESET}"
        return
    fi

    # Detect file type and route to right analyser
    ext="${filepath##*.}"
    case "$ext" in
        ndjson|json)
            echo -e "${CYAN}[*] Routing to Rayhunter analyser...${RESET}"
            python3 ~/aria_rayhunter.py "$filepath"
            ;;
        pcap|pcapng)
            echo -e "${CYAN}[*] Asking ARIA to analyse pcap summary...${RESET}"
            summary=$(tshark -r "$filepath" -q -z io,phs 2>/dev/null | head -50)
            ollama run aria "Analyse this Wireshark packet capture summary for cybersecurity anomalies:\n$summary"
            ;;
        log|txt)
            echo -e "${CYAN}[*] Injecting log into ARIA...${RESET}"
            content=$(head -100 "$filepath")
            ollama run aria "Analyse this log file for security anomalies:\n$content"
            ;;
        *)
            echo -e "${CYAN}[*] Sending to ARIA as raw text...${RESET}"
            content=$(head -100 "$filepath")
            ollama run aria "Analyse this file content:\n$content"
            ;;
    esac
}

system_status() {
    echo ""
    echo -e "${BOLD}=== ARIA System Status ===${RESET}"
    echo ""
    echo -e "${CYAN}Ollama Models:${RESET}"
    ollama list
    echo ""
    echo -e "${CYAN}System Resources:${RESET}"
    echo -n "  RAM: "; free -h | awk '/Mem:/ {print $3 " used / " $2 " total"}'
    echo -n "  SSD: "; df -h ~ | awk 'NR==2 {print $3 " used / " $2 " total"}'
    echo -n "  CPU: "; top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d. -f1
    echo -n "  Temp: "; vcgencmd measure_temp 2>/dev/null || echo "N/A"
    echo ""
}

update_aria() {
    echo -e "${YELLOW}[*] Rebuilding ARIA model from Modelfile...${RESET}"
    if [[ -f ~/Modelfile ]]; then
        ollama create aria -f ~/Modelfile
        echo -e "${GREEN}[+] ARIA updated.${RESET}"
    else
        echo -e "${RED}[-] No Modelfile found at ~/Modelfile${RESET}"
    fi
}

# Main loop
while true; do
    echo ""
    show_menu
    read -r choice

    case "$choice" in
        1) bash ~/aria_chat.sh ;;
        2)
            echo -ne "${GREEN}Path to NDJSON file: ${RESET}"; read -r f
            python3 ~/aria_rayhunter.py "$f"
            ;;
        3)
            echo -ne "${GREEN}Path to Pineapple log file: ${RESET}"; read -r f
            python3 ~/aria_pineapple.py "$f"
            ;;
        4) bash ~/aria_wordlist.sh ;;
        5) quick_query ;;
        6) analyse_file ;;
        7) system_status ;;
        8) update_aria ;;
        9) echo -e "${CYAN}Goodbye.${RESET}"; exit 0 ;;
        *) echo -e "${RED}Invalid choice.${RESET}" ;;
    esac
done
