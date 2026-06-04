#!/bin/bash
# ============================================================
#  ARIA - Enhanced Interactive Chat Loop
#  Features: conversation memory, context injection, logging
# ============================================================

MODEL="aria"
LOG_DIR="$HOME/aria_logs"
CONTEXT_FILE="$HOME/aria_context.txt"
SESSION_LOG="$LOG_DIR/session_$(date +%Y%m%d_%H%M%S).txt"

mkdir -p "$LOG_DIR"

# Colour codes
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

clear
echo -e "${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║   ARIA - Cyber Investigation Assistant ║"
echo "  ║   Model: qwen2.5-coder:7b              ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "${YELLOW}Commands: exit | save | clear | context | help${RESET}"
echo ""

# Load persistent context if it exists
if [[ -f "$CONTEXT_FILE" ]]; then
    echo -e "${GREEN}[+] Loaded persistent context from $CONTEXT_FILE${RESET}"
fi

conversation_context=""

show_help() {
    echo -e "${CYAN}"
    echo "  ARIA Commands:"
    echo "  exit       - Quit ARIA"
    echo "  save       - Save last response to file"
    echo "  clear      - Clear conversation context"
    echo "  context    - Show current context"
    echo "  help       - Show this help"
    echo "  !file <path> - Inject file contents into prompt"
    echo -e "${RESET}"
}

while true; do
    echo -ne "${GREEN}You: ${RESET}"
    read -r input

    # Empty input
    [[ -z "$input" ]] && continue

    # Commands
    case "$input" in
        exit|quit|bye)
            echo -e "${CYAN}ARIA: Closing session. Stay safe out there.${RESET}"
            break
            ;;
        help)
            show_help
            continue
            ;;
        clear)
            conversation_context=""
            echo -e "${YELLOW}[*] Context cleared.${RESET}"
            continue
            ;;
        context)
            echo -e "${YELLOW}Current context:${RESET}"
            echo "$conversation_context" | tail -20
            continue
            ;;
        save)
            if [[ -n "$last_response" ]]; then
                save_file="$LOG_DIR/output_$(date +%Y%m%d_%H%M%S).txt"
                echo "$last_response" > "$save_file"
                echo -e "${GREEN}[+] Saved to $save_file${RESET}"
            else
                echo -e "${RED}[-] Nothing to save yet.${RESET}"
            fi
            continue
            ;;
        !file\ *)
            filepath="${input#!file }"
            if [[ -f "$filepath" ]]; then
                file_content=$(cat "$filepath")
                input="Analyse this file content:\n$file_content"
                echo -e "${GREEN}[+] Injecting file: $filepath${RESET}"
            else
                echo -e "${RED}[-] File not found: $filepath${RESET}"
                continue
            fi
            ;;
    esac

    # Build prompt with context
    if [[ -n "$conversation_context" ]]; then
        full_prompt="Previous conversation:\n$conversation_context\n\nUser: $input"
    else
        full_prompt="$input"
    fi

    echo -e "${YELLOW}ARIA is thinking...${RESET}"
    echo ""

    response=$(ollama run "$MODEL" "$full_prompt" 2>/dev/null)
    last_response="$response"

    echo -e "${CYAN}ARIA: ${RESET}$response"
    echo ""

    # Update context (keep last 6 exchanges to avoid token overflow)
    conversation_context=$(echo -e "$conversation_context\nUser: $input\nARIA: $response" | tail -50)

    # Log session
    echo "$(date '+%H:%M:%S') You: $input" >> "$SESSION_LOG"
    echo "$(date '+%H:%M:%S') ARIA: $response" >> "$SESSION_LOG"
    echo "---" >> "$SESSION_LOG"

done

echo -e "${GREEN}[+] Session saved to: $SESSION_LOG${RESET}"
