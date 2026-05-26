#!/bin/bash
# =============================================================================
# CASTNET Unified Deployment Script v1.0
# Civilian IMSI Catcher Detection Network
# =============================================================================
# Supports: Raspberry Pi (Debian/Raspbian), Ubuntu, Termux/Android
# Usage: bash setup.sh
# =============================================================================

set -e

GREEN='\033[92m'
RED='\033[91m'
AMBER='\033[93m'
CYAN='\033[96m'
RESET='\033[0m'
BOLD='\033[1m'

IS_TERMUX=false
IS_PI=false
IS_LINUX=false

if [ -n "$TERMUX_VERSION" ] || echo "$HOME" | grep -q "com.termux"; then
    IS_TERMUX=true
    ENV_NAME="Termux/Android"
elif grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
    IS_PI=true
    ENV_NAME="Raspberry Pi"
else
    IS_LINUX=true
    ENV_NAME="Linux"
fi

echo -e "${CYAN}${BOLD}"
echo "  CASTNET -- Unified Deployment Script v1.0"
echo "  Civilian IMSI Catcher Detection Network"
echo "  Because Stingrays are fish too."
echo -e "${RESET}"
echo "  Detected environment: ${ENV_NAME}"
echo ""

ok()   { echo -e "  ${GREEN}[OK]${RESET} $1"; }
warn() { echo -e "  ${AMBER}[WARN]${RESET} $1"; }
err()  { echo -e "  ${RED}[ERR]${RESET} $1"; }
info() { echo -e "  ${CYAN}[INFO]${RESET} $1"; }
step() { echo -e "\n${BOLD}-- $1 --${RESET}"; }

deploy_termux() {
    step "Installing Termux dependencies"
    pkg update -y
    pkg install -y python termux-api curl git
    pip install requests --quiet
    ok "Termux dependencies installed"

    step "Configuring field node"
    mkdir -p ~/castnet
    cd ~/castnet

    info "Pulling latest castnet_node.py from GitHub..."
    curl -sf -o castnet_node.py \
        "https://raw.githubusercontent.com/JulianBurns85/CASTNET/main/castnet_node.py?$(date +%s)"
    ok "castnet_node.py downloaded"

    echo ""
    echo -e "${BOLD}  Node Configuration${RESET}"
    read -p "  Enter your node name (e.g. grapher): " NODE_ID
    read -p "  Enter your CASTNET API key: " API_KEY
    read -p "  Enter Pi Tailscale IP [100.68.146.48]: " PI_IP
    PI_IP=${PI_IP:-100.68.146.48}
    read -p "  Enter communal operator key (leave blank to skip): " COMMUNAL_KEY

    grep -v "CASTNET_NODE_ID\|CASTNET_API_KEY\|CASTNET_API\|CASTNET_COMMUNAL" ~/.bashrc > /tmp/bashrc_clean && mv /tmp/bashrc_clean ~/.bashrc

    cat >> ~/.bashrc << ENVEOF

# CASTNET Field Node Configuration
export CASTNET_NODE_ID="${NODE_ID}"
export CASTNET_API_KEY="${API_KEY}"
export CASTNET_API="http://${PI_IP}:5000/api/v1/report"
export CASTNET_COMMUNAL_API="http://${PI_IP}:5001/api/v1/report"
export CASTNET_COMMUNAL_KEY="${COMMUNAL_KEY}"
ENVEOF

    source ~/.bashrc
    ok "Environment variables saved to ~/.bashrc"

    echo ""
    ok "Termux node setup complete!"
    echo ""
    echo "  To start your node:"
    echo "    termux-wake-lock"
    echo "    python ~/castnet/castnet_node.py"
    echo ""
    echo "  Remember:"
    echo "  1. Set Termux and Termux:API battery to Unrestricted in Android settings"
    echo "  2. Enable Location in Android quick settings"
}

deploy_pi() {
    step "Checking system dependencies"

    if command -v python3 &>/dev/null; then
        ok "python3 found: $(python3 --version)"
    else
        sudo apt-get update -qq
        sudo apt-get install -y python3 python3-pip
        ok "python3 installed"
    fi

    if python3 -c "import flask" 2>/dev/null; then
        ok "flask found"
    else
        pip3 install flask --break-system-packages --quiet
        ok "flask installed"
    fi

    command -v git &>/dev/null && ok "git found" || sudo apt-get install -y git
    command -v curl &>/dev/null && ok "curl found" || sudo apt-get install -y curl

    step "Setting up CASTNET directory"
    CASTNET_DIR="$HOME/castnet"

    if [ -d "$CASTNET_DIR/.git" ]; then
        info "Git repo found -- pulling latest..."
        cd "$CASTNET_DIR"
        git pull origin main
        ok "Repository updated"
    else
        info "Initialising git repo..."
        mkdir -p "$CASTNET_DIR"
        cd "$CASTNET_DIR"
        git init
        git remote add origin https://github.com/JulianBurns85/CASTNET.git 2>/dev/null || true
        git fetch origin main
        git checkout -b main --track origin/main 2>/dev/null || git checkout main
        ok "Repository ready"
    fi

    step "Generating security keys"

    if [ -z "$CASTNET_ADMIN_KEY" ]; then
        ADMIN_KEY=$(openssl rand -hex 32)
        info "Generated new admin key"
    else
        ADMIN_KEY="$CASTNET_ADMIN_KEY"
        info "Using existing admin key"
    fi

    if ! grep -q "CASTNET_ADMIN_KEY" ~/.bashrc; then
        echo "" >> ~/.bashrc
        echo "# CASTNET Server Configuration" >> ~/.bashrc
        echo "export CASTNET_ADMIN_KEY=${ADMIN_KEY}" >> ~/.bashrc
        ok "Admin key saved to ~/.bashrc"
    fi

    step "Deploying systemd services"

    sudo tee /etc/systemd/system/castnet-local.service > /dev/null << SERVICE
[Unit]
Description=CASTNET Local Aggregation API
After=network.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${CASTNET_DIR}
ExecStart=/usr/bin/python3 ${CASTNET_DIR}/castnet_api.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE
    ok "castnet-local.service written (port 5000)"

    sudo tee /etc/systemd/system/castnet-communal.service > /dev/null << SERVICE
[Unit]
Description=CASTNET Communal Aggregation API
After=network.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${CASTNET_DIR}
Environment=CASTNET_ADMIN_KEY=${ADMIN_KEY}
Environment=CASTNET_PORT=5001
ExecStart=/usr/bin/python3 ${CASTNET_DIR}/castnet_communal_api.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE
    ok "castnet-communal.service written (port 5001)"

    sudo systemctl daemon-reload
    sudo systemctl enable castnet-local castnet-communal
    sudo systemctl restart castnet-local castnet-communal
    sleep 3

    sudo systemctl is-active --quiet castnet-local && ok "castnet-local running" || err "castnet-local failed -- check: journalctl -u castnet-local"
    sudo systemctl is-active --quiet castnet-communal && ok "castnet-communal running" || err "castnet-communal failed -- check: journalctl -u castnet-communal"

    step "Registering default operator"
    sleep 2

    OPERATOR_RESPONSE=$(curl -sf -X POST http://localhost:5001/admin/operators/register \
        -H "Content-Type: application/json" \
        -H "X-Castnet-Admin: ${ADMIN_KEY}" \
        -d "{\"handle\": \"${USER}_au\", \"region\": \"$(hostname)\"}" 2>/dev/null || echo "failed")

    if echo "$OPERATOR_RESPONSE" | grep -q "api_key"; then
        OPERATOR_KEY=$(echo "$OPERATOR_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
        ok "Operator registered: ${USER}_au"
        echo ""
        echo "  SAVE THESE KEYS -- shown once only:"
        echo "  Admin key:    ${ADMIN_KEY}"
        echo "  Operator key: ${OPERATOR_KEY}"
        echo ""
        if ! grep -q "CASTNET_OPERATOR_KEY" ~/.bashrc; then
            echo "export CASTNET_OPERATOR_KEY=${OPERATOR_KEY}" >> ~/.bashrc
        fi
    else
        warn "Auto-registration failed -- register manually after setup"
    fi

    step "Health checks"

    curl -sf http://localhost:5000/health | grep -q "ok" && ok "Local API healthy (port 5000)" || err "Local API not responding"
    curl -sf http://localhost:5001/health | grep -q "ok" && ok "Communal API healthy (port 5001)" || err "Communal API not responding"

    STATS=$(curl -sf http://localhost:5001/community/stats 2>/dev/null)
    if echo "$STATS" | grep -q "confirmed_cids"; then
        CONFIRMED=$(echo "$STATS" | python3 -c "import sys,json; print(json.load(sys.stdin)['confirmed_cids'])")
        ok "Community CID database: ${CONFIRMED} confirmed rogue CIDs loaded"
    fi

    echo ""
    echo "  CASTNET deployment complete!"
    echo ""
    echo "  Local API:     http://localhost:5000"
    echo "  Communal API:  http://localhost:5001"
    echo "  Map dashboard: http://localhost:5000/map"
    echo ""
    echo "  sudo systemctl status castnet-local castnet-communal"
    echo "  journalctl -u castnet-local -f"
    echo ""
    echo "  Because Stingrays are fish too."
}

if $IS_TERMUX; then
    deploy_termux
else
    deploy_pi
fi
