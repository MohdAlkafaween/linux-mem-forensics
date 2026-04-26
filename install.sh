#!/usr/bin/env bash
# install.sh — One-shot setup for memhunter
# ==============================================================
# Installs:
#   1. Build tools and kernel headers  (for memdump.ko)
#   2. Volatility 3                    (for memory analysis)
#   3. Python dependencies             (rich, yara-python, etc.)
#   4. Companion tools                 (bulk_extractor, binwalk, foremost)
#
# Handles Kali / Debian "externally-managed-environment" (PEP 668)
# by preferring apt packages → venv fallback → --break-system-packages.
#
# Usage:
#   chmod +x install.sh && sudo ./install.sh
# ==============================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   memhunter  ·  Setup Script                  ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# ── Detect distro ──────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then   PKG_MGR="apt"
elif command -v dnf &>/dev/null;   then   PKG_MGR="dnf"
elif command -v pacman &>/dev/null; then  PKG_MGR="pacman"
else warn "Unknown package manager — install dependencies manually."; PKG_MGR="unknown"; fi

# ── Detect externally-managed Python (PEP 668) by checking the marker file ─
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if [[ -f "/usr/lib/python${PYTHON_VERSION}/EXTERNALLY-MANAGED" ]] || \
   [[ -f "/usr/lib/python3/EXTERNALLY-MANAGED" ]]; then
    warn "Detected externally-managed Python (PEP 668) — will use venv."
    EXTERNALLY_MANAGED=1
else
    EXTERNALLY_MANAGED=0
fi

# ===========================================================================
# 1. System packages
# ===========================================================================
info "Installing system packages …"
case $PKG_MGR in
    apt)
        apt-get update -qq
        # Core build tools
        apt-get install -y -qq \
            build-essential git curl wget \
            python3 python3-pip python3-venv python3-dev \
            libssl-dev libffi-dev \
            2>/dev/null || true

        # Kernel headers (non-fatal if unavailable)
        apt-get install -y -qq "linux-headers-$(uname -r)" 2>/dev/null \
            || warn "Kernel headers not available for $(uname -r) — skipping."

        # Companion forensics tools (non-fatal)
        apt-get install -y -qq binwalk foremost bulk-extractor 2>/dev/null || true

        # Try to get rich via apt first (avoids PEP 668 entirely)
        apt-get install -y -qq python3-rich 2>/dev/null \
            && success "rich installed via apt." || true
        ;;
    dnf)
        dnf install -y -q gcc make "kernel-devel-$(uname -r)" \
            python3 python3-pip python3-devel git curl wget openssl-devel 2>/dev/null || true
        ;;
    pacman)
        pacman -Sy --noconfirm --quiet \
            base-devel linux-headers python python-pip git curl wget 2>/dev/null || true
        ;;
esac
success "System packages done."

# ===========================================================================
# 2. Python environment — venv on externally-managed systems, pip elsewhere
# ===========================================================================
pip_install() {
    # Usage: pip_install <package> [<package> ...]
    if [[ $EXTERNALLY_MANAGED -eq 1 ]]; then
        # Install inside the dedicated venv
        "$VENV_DIR/bin/pip" install --quiet "$@"
    else
        pip3 install --quiet "$@"
    fi
}

# Resolve the real user even when called via sudo
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
VENV_DIR="${REAL_HOME}/.venv/memhunter"
VOL_DIR="${REAL_HOME}/volatility3"

if [[ $EXTERNALLY_MANAGED -eq 1 ]]; then
    info "Creating Python venv at ${VENV_DIR} …"
    mkdir -p "$(dirname "$VENV_DIR")"
    python3 -m venv "$VENV_DIR" --system-site-packages
    # Hand ownership back to the real user
    chown -R "$REAL_USER":"$REAL_USER" "$VENV_DIR"
    success "Venv created."
fi

info "Installing Python dependencies …"
pip_install --upgrade pip
pip_install rich yara-python pycryptodome
success "Python dependencies done."

# ===========================================================================
# 3. Volatility 3 — clone or update
# ===========================================================================
if [[ -d "$VOL_DIR/.git" ]]; then
    info "Volatility 3 already cloned — pulling latest …"
    git -C "$VOL_DIR" pull --quiet || warn "git pull failed (using existing version)."
else
    info "Cloning Volatility 3 from GitHub …"
    git clone --quiet https://github.com/volatilityfoundation/volatility3.git "$VOL_DIR" \
        || error "Failed to clone Volatility 3. Check your internet connection."
fi

info "Installing Volatility 3 into Python environment …"
pip_install -e "$VOL_DIR"
success "Volatility 3 installed: $VOL_DIR"

# ── Create a wrapper script so 'vol' works regardless of venv ──────────────
LOCAL_BIN="${REAL_HOME}/.local/bin"
mkdir -p "$LOCAL_BIN"
VOL_WRAPPER="${LOCAL_BIN}/vol"
if [[ $EXTERNALLY_MANAGED -eq 1 ]]; then
    cat > "$VOL_WRAPPER" <<EOF
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python3" "${VOL_DIR}/vol.py" "\$@"
EOF
else
    cat > "$VOL_WRAPPER" <<EOF
#!/usr/bin/env bash
exec python3 "${VOL_DIR}/vol.py" "\$@"
EOF
fi
chmod +x "$VOL_WRAPPER"
chown "$REAL_USER":"$REAL_USER" "$VOL_WRAPPER"
success "Created vol wrapper: $VOL_WRAPPER"

# ===========================================================================
# 4. Volatility symbol packs
# ===========================================================================
SYM_DIR="$VOL_DIR/volatility3/symbols"
mkdir -p "$SYM_DIR"
info "Downloading Linux symbol pack …"
if [[ ! -f "$SYM_DIR/linux.zip" ]]; then
    curl -L --silent --show-error \
        -o "$SYM_DIR/linux.zip" \
        "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip" \
        && success "Linux symbol pack downloaded." \
        || warn "Could not download linux.zip — re-run or download manually."
else
    info "linux.zip already present — skipping download."
fi

# ===========================================================================
# 5. memhunter.py wrapper
# ===========================================================================
chmod +x "$SCRIPT_DIR/memhunter.py"
HUNTER_LINK="${LOCAL_BIN}/memhunter"

if [[ $EXTERNALLY_MANAGED -eq 1 ]]; then
    cat > "$HUNTER_LINK" <<EOF
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python3" "${SCRIPT_DIR}/memhunter.py" "\$@"
EOF
else
    ln -sf "$SCRIPT_DIR/memhunter.py" "$HUNTER_LINK"
fi
chmod +x "$HUNTER_LINK"
chown "$REAL_USER":"$REAL_USER" "$HUNTER_LINK"
success "Created memhunter command: $HUNTER_LINK"

# Ensure ~/.local/bin is on PATH this session
export PATH="${LOCAL_BIN}:$PATH"

# ===========================================================================
# 6. Build memdump.ko (optional)
# ===========================================================================
if [[ -d "/lib/modules/$(uname -r)/build" ]]; then
    info "Building memdump.ko kernel module …"
    make -C "$SCRIPT_DIR" --quiet 2>&1 | tail -3 \
        && success "memdump.ko built successfully." \
        || warn "Kernel module build failed (non-fatal — memhunter.py still works)."
else
    warn "Kernel headers not found — skipping memdump.ko build."
fi

# ===========================================================================
# Done
# ===========================================================================
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Setup complete!                                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Analyse a dump (interactive):"
echo "    memhunter /path/to/dump.raw"
echo "    # or: python3 $SCRIPT_DIR/memhunter.py /path/to/dump.raw"
echo ""
echo "  Test with the built-in sample dump:"
echo "    memhunter $SCRIPT_DIR/test_dump.raw"
echo ""
echo "  Run Volatility directly:"
echo "    vol -f dump.raw linux.pslist"
echo ""
if [[ $EXTERNALLY_MANAGED -eq 1 ]]; then
    echo "  Python venv location (if you need it):"
    echo "    $VENV_DIR"
    echo ""
fi
echo "  Reload PATH if 'memhunter' / 'vol' aren't found:"
echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
echo "    # add that line to ~/.bashrc to make it permanent"
echo ""
