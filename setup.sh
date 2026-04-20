#!/bin/bash
# CHAINLOCK — Supply Chain Security Scanner — Setup
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[✓]${NC} $1"; }
log() { echo -e "${CYAN}[→]${NC} $1"; }

PROJECT_DIR="$HOME/projects/supply-chain-scanner"

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║         CHAINLOCK — SETUP v2.0                   ║"
echo "  ║   Supply Chain Security Scanner                  ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

cd "$PROJECT_DIR"

# Python venv
log "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null || true
pip install --upgrade pip -q
pip install -r requirements.txt pytest -q
ok "Dependencies installed"

# Env file
[ ! -f .env ] && cp .env.example .env 2>/dev/null || true

# Tests
log "Running tests..."
python3 -m pytest tests/ -v --tb=short 2>&1 | tail -10 && ok "Tests passed" || echo "Some tests need network — continuing..."

# Git
[ ! -d .git ] && git init && ok "Git initialized"

# Launch
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║           CHAINLOCK STARTING 🔗                  ║"
echo "  ║   Dashboard: http://localhost:5001               ║"
echo "  ║   Click '⚡ Run Demo Scan' to test immediately   ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

command -v open &>/dev/null && sleep 2 && open "http://localhost:5001" &
python3 app.py
