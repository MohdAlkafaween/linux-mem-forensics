#!/usr/bin/env bash
# install.sh — One-shot setup for linux-mem-forensics + memhunter
# ==============================================================
# Installs:
#   1. Build tools and kernel headers (for memdump.ko)
#   2. Volatility 3 (for memory analysis)
#   3. Python dependencies (rich, etc.)
#   4. Companion tools (bulk_extractor, binwalk, foremost)
#
# Usage:
#   chmod +x install.sh
#   sudo ./install.sh
# ==============================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Detect distro ──────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
else
    warn "Unknown package manager. Install dependencies manually."
    PKG_MGR="unknown"
fi

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   linux-mem-forensics  ·  Setup Script       ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# ── 1. System packages ─────────────────────────────────────────────────────
info "Installing system packages …"
case $PKG_MGR in
    apt)
        apt-get update -qq
        apt-get install -y -qq \
            build-essential \
            "linux-headers-$(uname -r)" \
            python3 python3-pip python3-venv \
            git curl wget \
            binwalk foremost \
            bulk-extractor \
            libssl-dev \
            2>/dev/null || true
        ;;
    dnf)
        dnf install -y -q \
            gcc make \
            "kernel-devel-$(uname -r)" \
            python3 python3-pip \
            git curl wget \
            openssl-devel \
            2>/dev/null || true
        ;;
    pacman)
        pacman -Sy --noconfirm --quiet \
            base-devel linux-headers python python-pip git curl wget \
            2>/dev/null || true
        ;;
esac
success "System packages done."

# ── 2. Python dependencies ─────────────────────────────────────────────────
info "Installing Python dependencies …"
pip3 install --quiet --upgrade pip
pip3 install --quiet rich yara-python pycryptodome
success "Python dependencies done."

# ── 3. Volatility 3 ────────────────────────────────────────────────────────
VOL_DIR="$HOME/volatility3"
if [[ -d "$VOL_DIR" ]]; then
    info "Volatility 3 already cloned — pulling latest …"
    git -C "$VOL_DIR" pull --quiet
else
    info "Cloning Volatility 3 …"
    git clone --quiet https://github.com/volatilityfoundation/volatility3.git "$VOL_DIR"
fi

info "Installing Volatility 3 Python package …"
pip3 install --quiet -e "$VOL_DIR"
success "Volatility 3 installed: $VOL_DIR"

# ── 4. Symbol packs ────────────────────────────────────────────────────────
SYM_DIR="$VOL_DIR/volatility3/symbols"
mkdir -p "$SYM_DIR"
info "Downloading Linux symbol pack …"
if [[ ! -f "$SYM_DIR/linux.zip" ]]; then
    curl -L -o "$SYM_DIR/linux.zip" \
        "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip" \
        --silent --show-error || warn "Could not download linux.zip (continue without it)"
    success "Linux symbol pack downloaded."
else
    info "linux.zip already present — skipping."
fi

# ── 5. Make memhunter.py executable ────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/memhunter.py"

# Symlink so it's on PATH
if [[ -d "$HOME/.local/bin" ]]; then
    ln -sf "$SCRIPT_DIR/memhunter.py" "$HOME/.local/bin/memhunter"
    success "Created symlink: ~/.local/bin/memhunter"
fi

# ── 6. Build memdump.ko (optional) ─────────────────────────────────────────
if [[ -d "/lib/modules/$(uname -r)/build" ]]; then
    info "Building memdump.ko kernel module …"
    make -C "$SCRIPT_DIR" --quiet 2>&1 | tail -5 || warn "Kernel module build failed (non-fatal)"
    [[ -f "$SCRIPT_DIR/memdump.ko" ]] && success "memdump.ko built successfully."
else
    warn "Kernel headers not found — skipping memdump.ko build."
    warn "Install with: apt install linux-headers-\$(uname -r)"
fi

# ── Done ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Setup complete!                                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Run the interactive tool:"
echo "    python3 memhunter.py"
echo "    python3 memhunter.py /path/to/dump.raw"
echo ""
echo "  Build cheat sheet reference:"
echo "    python3 memhunter.py  →  options cs1–cs4"
echo ""
