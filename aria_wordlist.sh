#!/bin/bash
# ============================================================
#  ARIA - Hashcat Wordlist & Rule Generator
#  Uses ARIA to generate targeted wordlists and hashcat rules
# ============================================================

MODEL="aria"
OUTPUT_DIR="$HOME/aria_wordlists"
mkdir -p "$OUTPUT_DIR"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║   ARIA - Hashcat Wordlist Generator  ║"
    echo "  ╚══════════════════════════════════════╝"
    echo -e "${RESET}"
}

show_menu() {
    echo -e "${BOLD}Select wordlist type:${RESET}"
    echo "  1) Target-specific wordlist (person/org)"
    echo "  2) WiFi network wordlist (SSID-based)"
    echo "  3) Australian common passwords"
    echo "  4) Custom keyword expansion"
    echo "  5) Generate hashcat rules file"
    echo "  6) Generate hashcat mask attack"
    echo "  7) Combine and deduplicate wordlists"
    echo "  8) Exit"
    echo ""
    echo -ne "${GREEN}Choice: ${RESET}"
}

generate_target_wordlist() {
    echo ""
    echo -ne "${GREEN}Target name/org: ${RESET}"; read target_name
    echo -ne "${GREEN}Keywords (comma separated, e.g. dog,street,year): ${RESET}"; read keywords
    echo -ne "${GREEN}Known dates (e.g. 1985,2010): ${RESET}"; read dates
    echo ""

    outfile="$OUTPUT_DIR/target_${target_name// /_}_$(date +%Y%m%d).txt"

    prompt="Generate a comprehensive hashcat wordlist for a target named '$target_name'. 
Keywords associated with target: $keywords
Known dates: $dates

Generate variations including:
- Name combinations (firstname, lastname, initials)
- Keyword + number combinations
- Date variations (DDMMYYYY, YYYY, DD/MM/YY formats)
- Common substitutions (a=@, e=3, i=1, o=0, s=\$)
- Common suffixes (123, !, 2024, 2025, #1)
- Mixed case variations
- Concatenations of keywords

Output ONLY the wordlist, one password per line, no explanations, no numbering."

    echo -e "${YELLOW}[*] ARIA generating wordlist...${RESET}"
    ollama run "$MODEL" "$prompt" > "$outfile"

    # Clean up — remove blank lines and any commentary
    grep -v '^$' "$outfile" | grep -v '^[[:space:]]*#' | sort -u > "${outfile}.clean"
    mv "${outfile}.clean" "$outfile"

    count=$(wc -l < "$outfile")
    echo -e "${GREEN}[+] Generated $count passwords → $outfile${RESET}"
}

generate_wifi_wordlist() {
    echo ""
    echo -ne "${GREEN}SSID name: ${RESET}"; read ssid
    echo -ne "${GREEN}ISP/Router brand (e.g. Telstra, TPG, Optus): ${RESET}"; read isp
    echo ""

    outfile="$OUTPUT_DIR/wifi_${ssid// /_}_$(date +%Y%m%d).txt"

    prompt="Generate a hashcat wordlist targeting the WiFi network SSID: '$ssid' from ISP: '$isp' in Australia.

Include:
- Default router password formats for $isp routers
- SSID-based variations
- Common Australian WiFi passwords
- Default Telstra/TPG/Optus gateway passwords (format examples: serial numbers, MAC-based)
- Number sequences appended to SSID
- Common household passwords used in Australia

Output ONLY passwords, one per line, no explanations."

    echo -e "${YELLOW}[*] ARIA generating WiFi wordlist...${RESET}"
    ollama run "$MODEL" "$prompt" > "$outfile"

    grep -v '^$' "$outfile" | sort -u > "${outfile}.clean"
    mv "${outfile}.clean" "$outfile"

    count=$(wc -l < "$outfile")
    echo -e "${GREEN}[+] Generated $count passwords → $outfile${RESET}"
}

generate_aus_wordlist() {
    outfile="$OUTPUT_DIR/australian_common_$(date +%Y%m%d).txt"

    prompt="Generate a wordlist of common Australian passwords including:
- Australian slang terms
- AFL team names and variations  
- Australian place names (cities, suburbs, states)
- Common Australian names (male and female top 50)
- Australian sports teams
- Common phrases with Aus spelling (colour, harbour, etc)
- Australian events (Australia Day, Anzac, Melbourne Cup)
- Common patterns: Summer2024!, Winter2025!, etc
- Telco names: Telstra, Optus, Vodafone + number combos

Output ONLY passwords one per line, no explanations, 500+ entries."

    echo -e "${YELLOW}[*] ARIA generating Australian wordlist...${RESET}"
    ollama run "$MODEL" "$prompt" > "$outfile"

    grep -v '^$' "$outfile" | sort -u > "${outfile}.clean"
    mv "${outfile}.clean" "$outfile"

    count=$(wc -l < "$outfile")
    echo -e "${GREEN}[+] Generated $count passwords → $outfile${RESET}"
}

generate_keyword_expansion() {
    echo ""
    echo -ne "${GREEN}Enter keywords (comma separated): ${RESET}"; read keywords
    outfile="$OUTPUT_DIR/keywords_$(date +%Y%m%d_%H%M%S).txt"

    prompt="Expand these keywords into a comprehensive password wordlist: $keywords

For each keyword generate:
- Original word
- Capitalised version
- ALL CAPS
- l33t speak substitutions (a=@, e=3, i=1, o=0, s=\$)
- Add common suffixes: 1, 12, 123, 1234, !, !1, 2024, 2025, #
- Add common prefixes: 1, 123, the, my
- Reversed word
- Doubled word (e.g. wordword)
- Combined pairs of keywords

Output ONLY the wordlist, one per line."

    echo -e "${YELLOW}[*] ARIA expanding keywords...${RESET}"
    ollama run "$MODEL" "$prompt" > "$outfile"

    grep -v '^$' "$outfile" | sort -u > "${outfile}.clean"
    mv "${outfile}.clean" "$outfile"

    count=$(wc -l < "$outfile")
    echo -e "${GREEN}[+] Generated $count entries → $outfile${RESET}"
}

generate_rules() {
    outfile="$OUTPUT_DIR/aria_rules_$(date +%Y%m%d).rule"

    prompt="Generate a hashcat rules file (.rule format) for password cracking.

Include rules for:
- Case modifications (uppercase first, all caps, toggle case)
- Common character substitutions (a→@, e→3, i→1, o→0, s→\$)
- Append common suffixes (1, 12, 123, 1234, !, !!, 2024, 2025)
- Prepend common prefixes (1, 123, !)
- Duplicate word
- Reverse word
- Common Australian patterns

Use valid hashcat rule syntax only. Output ONLY the rules file content, one rule per line, with # comments for sections."

    echo -e "${YELLOW}[*] ARIA generating rules file...${RESET}"
    ollama run "$MODEL" "$prompt" > "$outfile"

    echo -e "${GREEN}[+] Rules saved → $outfile${RESET}"
    echo -e "${CYAN}    Usage: hashcat -a 0 -r $outfile hash.txt wordlist.txt${RESET}"
}

generate_mask() {
    echo ""
    echo -e "${BOLD}Common mask charsets:${RESET}"
    echo "  ?l = lowercase  ?u = uppercase  ?d = digit  ?s = special"
    echo ""
    echo -ne "${GREEN}Describe the password pattern (e.g. 'Australian mobile numbers', '8 char alphanumeric'): ${RESET}"
    read pattern

    outfile="$OUTPUT_DIR/masks_$(date +%Y%m%d_%H%M%S).hcmask"

    prompt="Generate hashcat mask attack patterns (.hcmask format) for: $pattern

Use hashcat mask syntax:
- ?l = lowercase letter
- ?u = uppercase letter  
- ?d = digit
- ?s = special character
- ?a = all printable

Output ONLY valid .hcmask format, one mask per line.
Example format: ?u?l?l?l?l?d?d?d
Include 10-20 relevant masks."

    echo -e "${YELLOW}[*] ARIA generating masks...${RESET}"
    ollama run "$MODEL" "$prompt" > "$outfile"

    echo -e "${GREEN}[+] Masks saved → $outfile${RESET}"
    echo -e "${CYAN}    Usage: hashcat -a 3 hash.txt $outfile${RESET}"
}

combine_wordlists() {
    echo ""
    echo -e "${GREEN}Wordlists in $OUTPUT_DIR:${RESET}"
    ls "$OUTPUT_DIR"/*.txt 2>/dev/null || echo "  None found"
    echo ""
    echo -ne "${GREEN}Enter paths to combine (space separated): ${RESET}"
    read -a files

    outfile="$OUTPUT_DIR/combined_$(date +%Y%m%d_%H%M%S).txt"

    cat "${files[@]}" 2>/dev/null | sort -u > "$outfile"
    count=$(wc -l < "$outfile")
    echo -e "${GREEN}[+] Combined $count unique passwords → $outfile${RESET}"
}

# Main loop
banner

while true; do
    show_menu
    read -r choice

    case "$choice" in
        1) generate_target_wordlist ;;
        2) generate_wifi_wordlist ;;
        3) generate_aus_wordlist ;;
        4) generate_keyword_expansion ;;
        5) generate_rules ;;
        6) generate_mask ;;
        7) combine_wordlists ;;
        8) echo -e "${CYAN}Exiting.${RESET}"; break ;;
        *) echo -e "${RED}Invalid choice.${RESET}" ;;
    esac

    echo ""
done
