#!/usr/bin/env python3
"""
memhunter.py — Interactive Linux Memory Forensics Tool for CTF Competitions
============================================================================
Wraps Volatility 3 with guided workflows, built-in cheat sheets, and
CTF-specific hunting techniques. All output is saved to a timestamped
results directory so nothing is lost between sessions.

Usage:
    python3 memhunter.py                       # prompts for dump path
    python3 memhunter.py /path/to/dump.raw     # load dump directly
    python3 memhunter.py --install             # install Volatility 3
"""

import argparse
import base64 as _b64
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Rich is the only non-stdlib dependency (pre-installed on Kali).
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich import box
    from rich.markdown import Markdown
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH = True
except ImportError:
    RICH = False
    print("[!] 'rich' not found — pip3 install rich   (falling back to plain output)")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
VERSION   = "2.0.0"
DUMP_PATH = None          # set after argument parsing / menu selection
OUT_DIR   = None          # timestamped output directory
VOL_CMD   = None          # path to vol / vol3 / python3 vol.py

console = Console(highlight=False) if RICH else None


# ---------------------------------------------------------------------------
# Resolve real user home even when launched with sudo
# ---------------------------------------------------------------------------
def _real_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def _is_externally_managed() -> bool:
    """Return True if pip is blocked by PEP 668 on this system."""
    import sys as _sys
    ver = f"{_sys.version_info.major}.{_sys.version_info.minor}"
    return (
        Path(f"/usr/lib/python{ver}/EXTERNALLY-MANAGED").exists()
        or Path("/usr/lib/python3/EXTERNALLY-MANAGED").exists()
    )


def _venv_dir() -> Path:
    return _real_home() / ".venv" / "memhunter"


def _pip_cmd() -> list:
    """Return the pip command to use — venv pip or system pip3."""
    venv_pip = _venv_dir() / "bin" / "pip"
    if venv_pip.exists():
        return [str(venv_pip)]
    if _is_externally_managed():
        return []          # no usable pip yet
    return [sys.executable, "-m", "pip"]


# ===========================================================================
# I/O helpers
# ===========================================================================

def cprint(msg: str, style: str = "") -> None:
    if RICH:
        console.print(msg, style=style)
    else:
        print(msg)


def header(title: str) -> None:
    if RICH:
        console.print(Panel(Text(title, justify="center", style="bold cyan"),
                            border_style="cyan"))
    else:
        print(f"\n{'='*60}\n  {title}\n{'='*60}")


def banner() -> None:
    art = r"""
  __  __                _   _             _
 |  \/  | ___ _ __ ___ | | | |_   _ _ __ | |_ ___ _ __
 | |\/| |/ _ \ '_ ` _ \| |_| | | | | '_ \| __/ _ \ '__|
 | |  | |  __/ | | | | |  _  | |_| | | | | ||  __/ |
 |_|  |_|\___|_| |_| |_|_| |_|\__,_|_| |_|\__\___|_|
    """
    if RICH:
        console.print(art, style="bold green")
        console.print(
            Panel(
                "[bold white]Linux Memory Forensics — CTF Edition[/bold white]\n"
                f"[dim]v{VERSION}  |  Powered by Volatility 3[/dim]",
                border_style="green",
            )
        )
    else:
        print(art)
        print(f"  Linux Memory Forensics — CTF Edition  v{VERSION}\n")


def ask(prompt: str, default: str = "") -> str:
    if RICH:
        return Prompt.ask(prompt, default=default)
    val = input(f"{prompt} [{default}]: ").strip()
    return val if val else default


def confirm(prompt: str, default: bool = True) -> bool:
    if RICH:
        return Confirm.ask(prompt, default=default)
    ans = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if not ans:
        return default
    return ans.startswith("y")


# ===========================================================================
# Volatility 3 discovery & installation
# ===========================================================================

def find_volatility() -> str | None:
    """Return the command string to invoke Volatility 3, or None."""
    real_home = _real_home()

    # 1. Wrapper scripts on PATH or in ~/.local/bin
    for name in ("vol3", "vol", "volatility3", "volatility"):
        if shutil.which(name):
            return name

    for name in ("vol3", "vol"):
        p = real_home / ".local" / "bin" / name
        if p.exists():
            return str(p)

    # 2. venv python + vol.py
    venv_python = _venv_dir() / "bin" / "python3"
    for vol_py in (
        real_home / "volatility3" / "vol.py",
        Path("/opt/volatility3/vol.py"),
        Path("/tools/volatility3/vol.py"),
        Path.cwd() / "volatility3" / "vol.py",
    ):
        if vol_py.exists():
            py = str(venv_python) if venv_python.exists() else "python3"
            return f"{py} {vol_py}"

    return None


def install_volatility() -> bool:
    """Clone and install Volatility 3, using a venv if PEP 668 is active."""
    cprint("\n[*] Installing Volatility 3 …", "yellow")

    real_home = _real_home()
    target    = real_home / "volatility3"
    venv      = _venv_dir()
    ext_mgd   = _is_externally_managed()

    # ── Step 1: create venv if needed ──────────────────────────────────────
    if ext_mgd and not (venv / "bin" / "pip").exists():
        cprint(f"  → Creating Python venv at {venv} …", "dim")
        r = subprocess.run(
            [sys.executable, "-m", "venv", str(venv), "--system-site-packages"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            cprint(f"[!] venv creation failed:\n{r.stderr[:300]}", "red")
            return False
        cprint("  [+] Venv created.", "dim")

    # Choose the right pip
    if ext_mgd:
        pip_exe = [str(venv / "bin" / "pip")]
        py_exe  = str(venv / "bin" / "python3")
    else:
        pip_exe = [sys.executable, "-m", "pip"]
        py_exe  = sys.executable

    # ── Step 2: clone or update ────────────────────────────────────────────
    if (target / ".git").exists():
        cprint(f"  → Updating existing clone at {target} …", "dim")
        r = subprocess.run(["git", "-C", str(target), "pull", "--quiet"],
                           capture_output=True, text=True)
        cprint(r.stdout.strip() or "  Already up to date.", "dim")
    else:
        cprint("  → Cloning Volatility 3 …", "dim")
        r = subprocess.run(
            ["git", "clone", "--quiet",
             "https://github.com/volatilityfoundation/volatility3.git",
             str(target)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            cprint(f"[!] git clone failed:\n{r.stderr[:400]}", "red")
            return False

    # ── Step 3: pip install into correct environment ───────────────────────
    cprint("  → Installing Python package …", "dim")
    r = subprocess.run(
        pip_exe + ["install", "-e", str(target), "--quiet"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        cprint(f"[!] pip install failed:\n{r.stderr[:400]}", "red")
        return False

    # ── Step 4: create ~/.local/bin/vol wrapper ────────────────────────────
    local_bin = real_home / ".local" / "bin"
    local_bin.mkdir(parents=True, exist_ok=True)
    vol_wrapper = local_bin / "vol"
    vol_wrapper.write_text(
        f"#!/usr/bin/env bash\nexec \"{py_exe}\" \"{target}/vol.py\" \"$@\"\n"
    )
    vol_wrapper.chmod(0o755)
    cprint(f"  [+] Wrapper created: {vol_wrapper}", "dim")

    # ── Step 5: symbol packs ───────────────────────────────────────────────
    sym_dir = target / "volatility3" / "symbols"
    sym_dir.mkdir(exist_ok=True)
    cprint("  → Downloading Linux symbol pack …", "dim")
    dest = sym_dir / "linux.zip"
    if not dest.exists():
        r = subprocess.run(
            ["curl", "-L", "--silent", "--show-error", "-o", str(dest),
             "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip"],
            capture_output=True,
        )
        if r.returncode == 0:
            cprint("  [+] linux.zip downloaded.", "dim")
        else:
            cprint("  [!] Could not download linux.zip (non-fatal).", "yellow")
    else:
        cprint("  [skip] linux.zip already present.", "dim")

    cprint(f"[+] Volatility 3 installed → {target}", "bold green")
    return True


def ensure_volatility() -> str:
    """Find or offer to install Volatility 3; return command string."""
    global VOL_CMD
    VOL_CMD = find_volatility()
    if VOL_CMD:
        cprint(f"[+] Volatility 3 found: {VOL_CMD}", "green")
        return VOL_CMD

    cprint("[!] Volatility 3 not found on this system.", "yellow")
    if confirm("Install it now from GitHub?"):
        if install_volatility():
            VOL_CMD = find_volatility() or \
                      f"python3 {Path.home()/'volatility3/vol.py'}"
            return VOL_CMD
    cprint("[!] Continuing without Volatility 3 — some features unavailable.", "red")
    return ""


# ===========================================================================
# Output directory management
# ===========================================================================

def setup_output_dir(dump_path: str) -> Path:
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = Path(dump_path).stem
    out  = Path(f"results_{name}_{ts}")
    out.mkdir(exist_ok=True)
    cprint(f"[+] Output directory: {out.resolve()}", "green")
    return out


def save_result(filename: str, content: str) -> None:
    if OUT_DIR is None:
        return
    p = OUT_DIR / filename
    with open(p, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
        f.write(f"{'='*60}\n")
        f.write(content)
        f.write("\n")


# ===========================================================================
# Volatility runner
# ===========================================================================

def run_vol(plugin: str, extra_args: str = "", save_as: str = "") -> str:
    """Run a Volatility 3 plugin against the current dump."""
    if not VOL_CMD:
        cprint("[!] Volatility 3 not available. Use option [i] to install it.", "red")
        return ""
    if not DUMP_PATH:
        cprint("[!] No dump loaded. Use option [d] to select a file.", "red")
        return ""

    cmd = f"{VOL_CMD} -f \"{DUMP_PATH}\" {plugin} {extra_args}".strip()
    cprint(f"\n[>] {cmd}", "dim")

    if RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(f"Running {plugin} …", total=None)
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=300
                )
            except subprocess.TimeoutExpired:
                cprint("[!] Plugin timed out after 5 minutes.", "red")
                return ""
    else:
        print(f"[>] Running {plugin} …")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=300
            )
        except subprocess.TimeoutExpired:
            print("[!] Plugin timed out.")
            return ""

    output = result.stdout
    errors = result.stderr.strip()

    if errors and "Volatility" not in errors and "WARNING" not in errors:
        cprint(f"[stderr] {errors[:400]}", "dim")

    if output:
        cprint(output)
        if save_as:
            save_result(save_as, f"Command: {cmd}\n\n{output}")
    else:
        cprint("[!] No output returned.", "yellow")

    return output


# ===========================================================================
# Cheat sheets
# ===========================================================================

CHEATSHEET_VOL3 = """
# Volatility 3 — Quick Reference

## Identify OS / kernel info
    banners.Banners              → kernel banner (Linux/Mac)
    linux.info                   → basic OS / profile info
    windows.info                 → (Windows dumps)

## Process listing
    linux.pslist                 → simple flat list
    linux.pstree                 → parent/child tree
    linux.psaux                  → list with full argv
    linux.cmdline                → command line per PID

## Process memory inspection
    linux.proc.Maps --pid <PID>  → virtual memory map
    linux.dump_map  --pid <PID>  → dump writable regions
    linux.malfind                → find injected / unsigned pages

## Environment variables  ← CTF goldmine
    linux.envars                 → all vars for all processes
    linux.envars --pid <PID>     → vars for one process

## Network
    linux.netstat                → active TCP/UDP connections
    linux.sockstat               → socket statistics
    linux.check_afinfo           → AF hook detection

## File system artefacts
    linux.find_file --find /path → locate a file in VFS cache
    linux.inode_cache            → inode cache (finds deleted files)
    linux.recover_filesystem     → attempt FS reconstruction

## Shell history
    linux.bash                   → .bash_history per process

## Kernel / rootkit checks
    linux.lsmod                  → loaded modules
    linux.check_modules          → compare module lists
    linux.check_syscall          → syscall table hooks
    linux.check_idt              → interrupt descriptor table
    linux.tty_check              → TTY op pointer hooks
    linux.kernel_log             → kernel ring buffer (dmesg)

## Credentials
    linux.credentials            → UID/GID per process

## Symbol packs (needed for profile resolution)
    Download: https://github.com/volatilityfoundation/volatility3/releases
    Place .zip in: volatility3/volatility3/symbols/
"""

CHEATSHEET_CTF = """
# CTF Memory Forensics — Workflow & Hunting Guide

## Step 1 — Orient yourself (always first)
    linux.banners        → kernel version string
    linux.pslist         → running processes
    linux.lsmod          → loaded kernel modules
    linux.netstat        → open connections

## Step 2 — Flag hunting locations

### a) Environment variables  ← most common CTF path
    vol linux.envars
    # look for:  FLAG=, CTF_FLAG=, SECRET=, KEY=, TOKEN=

### b) Bash history
    vol linux.bash
    # commands typed by users — may reveal flag location or credentials

### c) Raw dump strings
    strings dump.raw | grep -iP "flag\\{[^}]+\\}"
    strings -el dump.raw | grep -iP "flag\\{[^}]+\\}"    # Unicode

### d) Files on disk (VFS cache)
    vol linux.find_file --find /root
    vol linux.find_file --find /home
    vol linux.find_file --find /tmp
    vol linux.find_file --find /var/tmp
    vol linux.find_file --find /dev/shm          # common malware hiding spot

### e) Process memory of interesting PIDs
    vol linux.proc.Maps --pid <PID>
    vol linux.dump_map  --pid <PID>
    strings pid_dump.dmp | grep -i flag

### f) Network (exfiltration / C2 path)
    vol linux.netstat
    # unusual outbound connections → investigate the owner PID

## Step 3 — Suspicious process checklist
    ✓ PID 1 = init / systemd
    ✓ PID 2 = kthreadd
    □ Processes running from /tmp, /dev/shm, /var/tmp
    □ Processes with PPID=1 that aren't system daemons
    □ Names with spaces, dots, or hidden characters
    □ Processes with "(deleted)" in their Maps
    □ Processes visible in netstat but not pslist (hiding)

## Step 4 — Rootkit indicators
    □ Module visible in memory but absent from lsmod → check_modules
    □ Syscall table entry outside kernel .text section → check_syscall
    □ IDT entry pointing to unknown address → check_idt
    □ Process in netstat/files but NOT in pslist → process hiding

## Step 5 — String grep patterns (copy-paste ready)
    grep -aP  'flag\\{[^}]+\\}'     strings.txt   # generic
    grep -aP  'HTB\\{[^}]+\\}'      strings.txt   # HackTheBox
    grep -aP  'picoCTF\\{[^}]+\\}'  strings.txt   # picoCTF
    grep -aP  'THM\\{[^}]+\\}'      strings.txt   # TryHackMe
    grep -aP  'DUCTF\\{[^}]+\\}'    strings.txt   # Down Under CTF
    grep -aP  '[A-Za-z0-9+/]{40,}={0,2}' strings.txt  # base64
    grep -aP  'password\\s*[=:]\\s*\\S+' strings.txt   # passwords
    grep -aP  'ssh-[rd]sa [A-Za-z0-9+/]+' strings.txt  # SSH keys
    grep -aP  'BEGIN .{0,30}PRIVATE KEY' strings.txt   # PEM keys

## Step 6 — Tool chaining workflow
    1) pslist  → identify interesting PIDs
    2) cmdline → confirm what process is running
    3) proc.Maps <PID> → locate writable heap/stack regions
    4) dump_map <PID>  → dump them
    5) strings <dump>  → grep for flag

## Tip — Volatility symbol packs
    If vol fails with "No suitable address space", you need a symbol pack.
    Download from: https://github.com/volatilityfoundation/volatility3/releases
    Place in: ~/volatility3/volatility3/symbols/
    Then retry your command.
"""

CHEATSHEET_STRINGS = """
# Strings & grep — Analysis Without Volatility

## Extract all printable strings
    strings -n 8 dump.raw > strings.txt          # ASCII, min 8 chars
    strings -el dump.raw >> strings.txt          # little-endian UTF-16

## Flag patterns
    grep -aP 'flag\\{[^}]+\\}'    strings.txt
    grep -aiP 'htb\\{[^}]+\\}'    strings.txt
    grep -aiP 'picoctf\\{[^}]+\\}' strings.txt
    grep -aiP 'thm\\{[^}]+\\}'    strings.txt

## Credentials
    grep -aiP 'password\\s*[=:]\\s*\\S+'  strings.txt | head -50
    grep -aiP 'passwd\\s*[=:]\\s*\\S+'    strings.txt | head -30
    grep -aiP 'secret\\s*[=:]\\s*\\S+'    strings.txt | head -30
    grep -aiP 'token\\s*[=:]\\s*\\S+'     strings.txt | head -30

## SSH & crypto keys
    grep -aP 'ssh-[rd]sa [A-Za-z0-9+/]+' strings.txt
    grep -aP 'BEGIN .{0,30}PRIVATE KEY'   strings.txt
    grep -aP 'BEGIN CERTIFICATE'           strings.txt

## Network artefacts
    grep -oP '\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b' strings.txt | sort -u
    grep -oiP 'https?://[^\\s"<>]+' strings.txt | sort -u

## Hashes
    grep -oP '[0-9a-f]{32}\\b'  strings.txt   # MD5
    grep -oP '[0-9a-f]{40}\\b'  strings.txt   # SHA-1
    grep -oP '[0-9a-f]{64}\\b'  strings.txt   # SHA-256

## Base64
    grep -oP '[A-Za-z0-9+/]{40,}={0,2}' strings.txt | sort -u
    # Decode a candidate:
    echo "BASE64HERE" | base64 -d

## Direct dump grep (byte-offset aware, no strings needed)
    grep -boa -P '[\\x20-\\x7e]{8,}' dump.raw | grep -iP 'flag\\{'

## Bulk extractor (automatic artefact carving)
    bulk_extractor -o be_out/ dump.raw
    # Creates: email.txt, url.txt, domain.txt, telephone.txt, json.txt, etc.
"""

CHEATSHEET_TOOLS = """
# Companion Tools for Memory Forensics

## Volatility 3  (primary analysis framework)
    pip3 install volatility3
    # OR: git clone https://github.com/volatilityfoundation/volatility3 && pip3 install -e .
    vol -f dump.raw <plugin>

## LiME — Linux Memory Extractor  (live acquisition from running system)
    git clone https://github.com/504ensicsLabs/LiME
    cd LiME/src && make
    sudo insmod lime.ko "path=/tmp/dump.lime format=lime"
    # format options: raw | lime | padded

## This module (memdump.ko)  — kernel-level raw acquisition
    make && sudo insmod memdump.ko dump_path="/tmp/dump.raw"
    dmesg | grep memdump   # check SHA-256 and progress

## bulk_extractor  — fast parallel string/artefact extraction
    sudo apt install bulk-extractor
    bulk_extractor -o out_dir/ dump.raw
    # Produces: email, url, credit_card, domain, json, histogram files

## binwalk  — embedded file detection & carving
    binwalk -e dump.raw

## foremost  — file carving by magic bytes
    foremost -o carved/ dump.raw

## Hex viewers
    xxd dump.raw | less
    hexyl dump.raw | less          # colourised
    ghex dump.raw                  # GUI

## YARA scanning
    pip3 install yara-python
    # Write a rule, then:
    yara -r my_rules.yar dump.raw

## radare2  — binary analysis / scripted memory search
    r2 dump.raw
    [0x00000000]> /i flag{         # case-insensitive search
    [0x00000000]> ps @ hit0_0      # print string at hit

## pypykatz  — credential extraction (Windows dumps, LSASS)
    pip3 install pypykatz
    pypykatz lsa minidump lsass.dmp

## Rekall  (legacy, Volatility 2 fork)
    pip3 install rekall
    rekal -f dump.raw pslist

## VM memory acquisition
    # VMware: copy .vmem file directly — it IS the dump
    # VirtualBox:
        vboxmanage debugvm <VM_NAME> dumpguestcore --filename dump.elf
    # QEMU/KVM:
        virsh dump <domain> dump.raw --memory-only
    # Hyper-V: use vm2dmp or ProcDump

## Autopsy / Sleuth Kit  (GUI case management)
    autopsy                        # web UI → http://localhost:9999

## Online resources
    Volatility docs:   https://volatility3.readthedocs.io
    Symbol packs:      https://github.com/volatilityfoundation/volatility3/releases
    CTF writeups:      https://github.com/search?q=volatility+CTF+writeup
    MemLabs (practice): https://github.com/stuxnet999/MemLabs
"""


def show_cheatsheet(name: str) -> None:
    sheets = {
        "vol3":    (CHEATSHEET_VOL3,    "Volatility 3 Quick Reference"),
        "ctf":     (CHEATSHEET_CTF,     "CTF Memory Forensics Workflow"),
        "strings": (CHEATSHEET_STRINGS, "Strings & grep Without Volatility"),
        "tools":   (CHEATSHEET_TOOLS,   "Companion Tools"),
    }
    content, title = sheets.get(name, (None, None))
    if not content:
        cprint("[!] Unknown cheat sheet.", "red")
        return

    header(f"Cheat Sheet — {title}")
    if RICH:
        console.print(Markdown(content))
    else:
        print(content)

    if OUT_DIR and confirm("\nSave cheat sheet to results directory?", False):
        save_result(f"cheatsheet_{name}.txt", content)
        cprint(f"[+] Saved to {OUT_DIR}/cheatsheet_{name}.txt", "green")


# ===========================================================================
# Menu system
# ===========================================================================

MAIN_MENU = [
    ("1",  "Quick Triage",           "Auto-run essential plugins in one shot"),
    ("2",  "Process Analysis",       "pslist, pstree, cmdline, envars"),
    ("3",  "Network Analysis",       "netstat, sockstat, connection forensics"),
    ("4",  "File System Hunting",    "find_file, inode cache, VFS artefacts"),
    ("5",  "Credential & Flag Hunt", "bash history, env vars, raw strings"),
    ("6",  "Kernel / Rootkit Check", "lsmod, syscall table, IDT hooks"),
    ("7",  "Strings Search",         "Grep raw dump without Volatility"),
    ("8",  "Custom Plugin",          "Run any Volatility plugin manually"),
    ("",   "",                       ""),
    ("cs1","Cheat Sheet: Volatility 3","Full plugin reference"),
    ("cs2","Cheat Sheet: CTF Workflow","Flag hunting strategies & tips"),
    ("cs3","Cheat Sheet: Strings/grep","No-Volatility string analysis"),
    ("cs4","Cheat Sheet: Tools",       "Companion forensics tools"),
    ("",   "",                         ""),
    ("i",  "Install / Update Volatility 3", "Clone & pip-install from GitHub"),
    ("d",  "Change dump file",         "Load a different memory image"),
    ("q",  "Quit",                     "Exit memhunter"),
]


def print_main_menu() -> None:
    if RICH:
        t = Table(title="[bold cyan]Main Menu[/bold cyan]",
                  box=box.ROUNDED, border_style="cyan",
                  show_header=True, header_style="bold cyan")
        t.add_column("Key",    style="bold yellow", width=6)
        t.add_column("Action", style="white",       width=32)
        t.add_column("Description", style="dim",    width=42)
        for key, action, desc in MAIN_MENU:
            t.add_row(key, action, desc)
        console.print(t)
    else:
        print(f"\n{'─'*65}")
        for key, action, desc in MAIN_MENU:
            if key:
                print(f"  [{key:>4}]  {action:<30}  {desc}")
        print(f"{'─'*65}")


# ===========================================================================
# Workflow modules
# ===========================================================================

def quick_triage() -> None:
    header("Quick Triage — Essential Plugins")
    cprint("[*] Running a first-look set of plugins. This may take a few minutes …\n",
           "yellow")

    plugins = [
        ("banners.Banners",     "",  "banners.txt"),
        ("linux.pslist",        "",  "pslist.txt"),
        ("linux.pstree",        "",  "pstree.txt"),
        ("linux.lsmod",         "",  "lsmod.txt"),
        ("linux.netstat",       "",  "netstat.txt"),
        ("linux.bash",          "",  "bash_history.txt"),
        ("linux.envars",        "",  "envars.txt"),
        ("linux.credentials",   "",  "credentials.txt"),
        ("linux.check_modules", "",  "check_modules.txt"),
        ("linux.check_syscall", "",  "check_syscall.txt"),
    ]

    for plugin, args, outfile in plugins:
        cprint(f"\n{'─'*50}", "dim")
        cprint(f"  Plugin: {plugin}", "bold cyan")
        run_vol(plugin, args, outfile)

    cprint("\n[+] Quick triage complete.", "bold green")
    if OUT_DIR:
        cprint(f"[+] All results saved in: {OUT_DIR.resolve()}", "green")


def process_analysis() -> None:
    header("Process Analysis")
    opts = [
        ("1", "pslist      — simple process list"),
        ("2", "pstree      — parent/child tree"),
        ("3", "psaux       — processes with full argv"),
        ("4", "cmdline     — command lines for all PIDs"),
        ("5", "envars      — environment variables  [FLAG goldmine]"),
        ("6", "envars grep — search envars for a keyword"),
        ("7", "proc.Maps   — memory maps for a specific PID"),
        ("8", "malfind     — detect injected / unsigned pages"),
        ("b", "Back"),
    ]
    _submenu(opts, {
        "1": lambda: run_vol("linux.pslist",  "", "pslist.txt"),
        "2": lambda: run_vol("linux.pstree",  "", "pstree.txt"),
        "3": lambda: run_vol("linux.psaux",   "", "psaux.txt"),
        "4": lambda: run_vol("linux.cmdline", "", "cmdline.txt"),
        "5": lambda: run_vol("linux.envars",  "", "envars.txt"),
        "6": _envars_grep,
        "7": _proc_maps,
        "8": lambda: run_vol("linux.malfind", "", "malfind.txt"),
    })


def _envars_grep() -> None:
    kw = ask("Keyword to search in envars (e.g. FLAG, pass, secret)", "FLAG")
    out = run_vol("linux.envars", "", "envars.txt")
    if out:
        hits = [l for l in out.splitlines() if kw.lower() in l.lower()]
        if hits:
            cprint(f"\n[+] {len(hits)} line(s) containing '{kw}':", "bold green")
            for h in hits:
                cprint(f"  {h}", "yellow")
            save_result("envars_filtered.txt", "\n".join(hits))
        else:
            cprint(f"[!] No lines containing '{kw}'", "yellow")


def _proc_maps() -> None:
    pid = ask("Enter PID")
    if pid.isdigit():
        run_vol("linux.proc.Maps", f"--pid {pid}", f"maps_pid{pid}.txt")
    else:
        cprint("[!] Invalid PID — must be a number.", "red")


def network_analysis() -> None:
    header("Network Analysis")
    opts = [
        ("1", "netstat     — active TCP/UDP connections + owning PIDs"),
        ("2", "sockstat    — socket statistics"),
        ("3", "check_afinfo — address family hook detection"),
        ("b", "Back"),
    ]
    _submenu(opts, {
        "1": lambda: run_vol("linux.netstat",     "", "netstat.txt"),
        "2": lambda: run_vol("linux.sockstat",    "", "sockstat.txt"),
        "3": lambda: run_vol("linux.check_afinfo","", "check_afinfo.txt"),
    })


def file_hunting() -> None:
    header("File System Hunting")
    opts = [
        ("1", "find_file  — search for a specific path"),
        ("2", "inode_cache — cached inodes (finds recently deleted files)"),
        ("3", "find /tmp  — list /tmp contents"),
        ("4", "find /root — list /root contents"),
        ("5", "find /home — list /home contents"),
        ("6", "find /dev/shm — shared memory (common malware staging area)"),
        ("b", "Back"),
    ]
    _submenu(opts, {
        "1": _find_file_prompt,
        "2": lambda: run_vol("linux.inode_cache", "", "inode_cache.txt"),
        "3": lambda: run_vol("linux.find_file", "--find /tmp",     "find_tmp.txt"),
        "4": lambda: run_vol("linux.find_file", "--find /root",    "find_root.txt"),
        "5": lambda: run_vol("linux.find_file", "--find /home",    "find_home.txt"),
        "6": lambda: run_vol("linux.find_file", "--find /dev/shm", "find_devshm.txt"),
    })


def _find_file_prompt() -> None:
    path = ask("Enter file or directory path", "/etc/passwd")
    run_vol("linux.find_file", f"--find {path}", "find_custom.txt")


def credential_flag_hunt() -> None:
    header("Credential & Flag Hunt")
    cprint("[*] Targets the most common CTF flag and credential locations.\n", "yellow")
    opts = [
        ("1", "bash history      — .bash_history per process"),
        ("2", "envars full       — dump ALL environment variables"),
        ("3", "envars → flag{    — grep envars for flag patterns"),
        ("4", "strings → flags   — grep raw dump for flag{...}"),
        ("5", "strings → base64  — find & decode base64 blobs"),
        ("6", "strings → creds   — grep for password/secret/key/token"),
        ("7", "credentials plugin— UID/GID per process"),
        ("b", "Back"),
    ]
    _submenu(opts, {
        "1": lambda: run_vol("linux.bash",        "", "bash_history.txt"),
        "2": lambda: run_vol("linux.envars",      "", "envars.txt"),
        "3": _hunt_flags_envars,
        "4": _hunt_flags_strings,
        "5": _hunt_base64,
        "6": _hunt_creds_strings,
        "7": lambda: run_vol("linux.credentials", "", "credentials.txt"),
    })


def _hunt_flags_envars() -> None:
    out = run_vol("linux.envars", "", "envars.txt")
    if not out:
        return
    patterns = [r"flag\{", r"HTB\{", r"picoCTF\{", r"ctf\{", r"CTF\{",
                r"THM\{", r"DUCTF\{", r"FLAG=", r"SECRET="]
    found = False
    for pat in patterns:
        hits = [l for l in out.splitlines() if re.search(pat, l, re.I)]
        if hits:
            found = True
            cprint(f"\n[+] Pattern '{pat}':", "bold green")
            for h in hits:
                cprint(f"  {h}", "yellow")
    if not found:
        cprint("[!] No flag patterns found in envars.", "yellow")
        cprint("[>] Tip: try option 2 to dump all envars and review manually.", "dim")


def _hunt_flags_strings() -> None:
    if not DUMP_PATH:
        return
    cprint("[*] Running strings against the dump — may take a minute …", "yellow")
    patterns = [
        r"flag\{[^}]+\}",
        r"HTB\{[^}]+\}",
        r"picoCTF\{[^}]+\}",
        r"ctf\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"THM\{[^}]+\}",
        r"DUCTF\{[^}]+\}",
    ]
    combined = "|".join(patterns)

    # ASCII
    cmd = f'strings -n 6 "{DUMP_PATH}" | grep -oiP "{combined}"'
    r1 = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
    # Unicode (wide chars)
    cmd2 = f'strings -el "{DUMP_PATH}" | grep -oiP "{combined}"'
    r2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True, timeout=300)

    output = (r1.stdout + r2.stdout).strip()
    if output:
        # deduplicate
        hits = sorted(set(output.splitlines()))
        cprint(f"\n[+] Found {len(hits)} unique flag string(s):", "bold green")
        for h in hits:
            cprint(f"  {h}", "bold yellow")
        save_result("flag_hits.txt", "\n".join(hits))
    else:
        cprint("[!] No flag patterns found in raw strings.", "yellow")
        cprint("[>] Try option 5 (base64) — the flag might be encoded.", "dim")


def _hunt_base64() -> None:
    if not DUMP_PATH:
        return
    cprint("[*] Hunting base64 blobs (≥40 chars) …", "yellow")
    cmd = (f'strings -n 6 "{DUMP_PATH}" | '
           f'grep -oP "[A-Za-z0-9+/]{{40,}}={{0,2}}" | sort -u | head -80')
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
    output = result.stdout.strip()
    if not output:
        cprint("[!] No base64 blobs found.", "yellow")
        return

    candidates = output.splitlines()
    cprint(f"\n[+] {len(candidates)} base64 candidate(s):", "yellow")
    for line in candidates[:20]:
        cprint(f"  {line}", "dim")

    save_result("base64_candidates.txt", output)

    if confirm(f"\nDecode up to 20 candidates?", True):
        cprint("\n[*] Decoding …", "cyan")
        for line in candidates[:20]:
            try:
                # Pad to multiple of 4
                padded = line + "=" * (-len(line) % 4)
                decoded = _b64.b64decode(padded).decode("utf-8", errors="replace")
                printable = re.sub(r"[^\x20-\x7e]", ".", decoded)
                if len([c for c in decoded if c.isprintable()]) > len(decoded) * 0.6:
                    cprint(f"  [decode] {printable[:100]}", "green")
            except Exception:
                pass


def _hunt_creds_strings() -> None:
    if not DUMP_PATH:
        return
    cprint("[*] Searching for credential artefacts in strings …", "yellow")
    patterns = [
        (r"(?i)password\s*[=:]\s*\S+",   "passwords"),
        (r"(?i)passwd\s*[=:]\s*\S+",     "passwd refs"),
        (r"(?i)secret\s*[=:]\s*\S+",     "secrets"),
        (r"(?i)token\s*[=:]\s*\S+",      "tokens"),
        (r"(?i)api[_\-]?key\s*[=:]\s*\S+", "API keys"),
        (r"ssh-[rd]sa [A-Za-z0-9+/]+",   "SSH public keys"),
        (r"BEGIN .{0,30}PRIVATE KEY",     "private keys (PEM)"),
    ]
    any_found = False
    for pat, label in patterns:
        cmd = f'strings -n 6 "{DUMP_PATH}" | grep -oiP "{pat}" | head -20'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        if result.stdout.strip():
            any_found = True
            cprint(f"\n[+] {label}:", "bold yellow")
            cprint(result.stdout.strip(), "yellow")
            save_result("credential_hits.txt", f"=== {label} ===\n{result.stdout}")

    if not any_found:
        cprint("[!] No credential patterns found.", "yellow")


def kernel_rootkit_check() -> None:
    header("Kernel / Rootkit Detection")
    opts = [
        ("1", "lsmod          — list loaded kernel modules"),
        ("2", "check_modules  — compare against in-memory module list"),
        ("3", "check_syscall  — verify syscall table integrity"),
        ("4", "check_idt      — inspect interrupt descriptor table"),
        ("5", "tty_check      — TTY operation pointer hooks"),
        ("6", "kernel_log     — kernel ring buffer (dmesg equivalent)"),
        ("b", "Back"),
    ]
    _submenu(opts, {
        "1": lambda: run_vol("linux.lsmod",         "", "lsmod.txt"),
        "2": lambda: run_vol("linux.check_modules",  "", "check_modules.txt"),
        "3": lambda: run_vol("linux.check_syscall",  "", "check_syscall.txt"),
        "4": lambda: run_vol("linux.check_idt",      "", "check_idt.txt"),
        "5": lambda: run_vol("linux.tty_check",      "", "tty_check.txt"),
        "6": lambda: run_vol("linux.kernel_log",     "", "kernel_log.txt"),
    })


def strings_search() -> None:
    header("Strings Search — No Volatility Required")
    opts = [
        ("1", "Custom pattern search"),
        ("2", "Extract all strings to file"),
        ("3", "Flag pattern sweep (flag{, HTB{, THM{, …)"),
        ("4", "Network artefacts (IPs, URLs, emails)"),
        ("5", "Base64 hunt & decode"),
        ("b", "Back"),
    ]
    _submenu(opts, {
        "1": _strings_custom,
        "2": _strings_extract_all,
        "3": _hunt_flags_strings,
        "4": _strings_network,
        "5": _hunt_base64,
    })


def _strings_custom() -> None:
    if not DUMP_PATH:
        return
    pat = ask("Regex pattern (grep -oiP syntax, e.g. flag\\{[^}]+\\})")
    if not pat:
        return
    cmd = f'strings -n 6 "{DUMP_PATH}" | grep -oiP "{pat}" | sort -u | head -100'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
    if result.stdout.strip():
        cprint(result.stdout, "yellow")
        save_result("custom_strings.txt", f"Pattern: {pat}\n{result.stdout}")
    else:
        cprint("[!] No matches found.", "yellow")


def _strings_extract_all() -> None:
    if not DUMP_PATH or not OUT_DIR:
        return
    out_file = OUT_DIR / "all_strings.txt"
    cprint(f"[*] Extracting ASCII strings to {out_file} …", "yellow")
    subprocess.run(f'strings -n 6 "{DUMP_PATH}" > "{out_file}"',
                   shell=True, timeout=600)
    cprint("[*] Appending Unicode (wide) strings …", "yellow")
    subprocess.run(f'strings -el "{DUMP_PATH}" >> "{out_file}"',
                   shell=True, timeout=300)
    size_kb = out_file.stat().st_size // 1024
    cprint(f"[+] Saved {size_kb:,} KB → {out_file}", "bold green")
    cprint("[>] Tip: grep -aP 'flag\\{' all_strings.txt", "dim")


def _strings_network() -> None:
    if not DUMP_PATH:
        return
    cprint("[*] Extracting network artefacts …", "yellow")
    patterns = [
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",         "IPv4 addresses"),
        (r"https?://[^\s\"'<>]+",                             "HTTP/HTTPS URLs"),
        (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-z]{2,}",  "Email addresses"),
        (r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b", "IPv6 addresses"),
    ]
    any_found = False
    for pat, label in patterns:
        cmd = (f'strings -n 6 "{DUMP_PATH}" | '
               f'grep -oiP "{pat}" | sort -u | head -40')
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=300)
        if result.stdout.strip():
            any_found = True
            cprint(f"\n[+] {label}:", "bold cyan")
            cprint(result.stdout.strip(), "cyan")
            save_result("network_artefacts.txt",
                        f"=== {label} ===\n{result.stdout}")
    if not any_found:
        cprint("[!] No network artefacts found.", "yellow")


def custom_plugin() -> None:
    header("Custom Volatility Plugin")
    cprint("Enter a plugin name and optional arguments.", "dim")
    cprint("Examples:", "dim")
    cprint("  linux.pslist --pid 1234", "dim")
    cprint("  linux.find_file --find /etc/shadow", "dim")
    cprint("  linux.proc.Maps --pid 42\n", "dim")
    plugin_input = ask("Plugin [args]")
    if not plugin_input.strip():
        return
    parts = plugin_input.strip().split(None, 1)
    plugin = parts[0]
    args   = parts[1] if len(parts) > 1 else ""
    run_vol(plugin, args, f"custom_{plugin.replace('.','_')}.txt")


# ===========================================================================
# Generic submenu helper
# ===========================================================================

def _submenu(opts: list, actions: dict) -> None:
    while True:
        if RICH:
            t = Table(box=box.SIMPLE, border_style="blue", show_header=False)
            t.add_column("Key",  style="bold yellow", width=6)
            t.add_column("Item", style="white")
            for key, desc in opts:
                t.add_row(key, desc)
            console.print(t)
        else:
            for key, desc in opts:
                if key:
                    print(f"  [{key}]  {desc}")

        choice = ask("\nChoice", "b").strip().lower()
        if choice == "b":
            return
        action = actions.get(choice)
        if action:
            action()
        else:
            cprint("[!] Invalid choice.", "red")


# ===========================================================================
# Dump file selection
# ===========================================================================

def select_dump() -> str | None:
    cprint("\n[*] Enter the path to a memory dump file.", "yellow")
    cprint("    Supported: .raw .lime .elf .core .vmem .bin .dmp", "dim")
    path = ask("Dump file path")
    path = path.strip().strip('"').strip("'")
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        cprint(f"[!] File not found: {path}", "red")
        return None
    size_mb = p.stat().st_size // (1024 * 1024)
    cprint(f"[+] Loaded: {path}  ({size_mb:,} MB)", "bold green")
    return str(p.resolve())


# ===========================================================================
# Main entry point
# ===========================================================================

def main() -> None:
    global DUMP_PATH, OUT_DIR, VOL_CMD

    parser = argparse.ArgumentParser(
        description="memhunter — Interactive Linux Memory Forensics for CTF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("dump", nargs="?", help="Memory dump file to analyse")
    parser.add_argument("--install", action="store_true",
                        help="Install/update Volatility 3 from GitHub and exit")
    args = parser.parse_args()

    banner()

    if args.install:
        install_volatility()
        sys.exit(0)

    # Ensure Volatility 3 is available
    ensure_volatility()

    # Load dump file
    if args.dump:
        p = Path(args.dump)
        if p.exists():
            DUMP_PATH = str(p.resolve())
            size_mb = p.stat().st_size // (1024 * 1024)
            cprint(f"[+] Loaded: {DUMP_PATH}  ({size_mb:,} MB)", "bold green")
        else:
            cprint(f"[!] File not found: {args.dump}", "red")

    if not DUMP_PATH:
        DUMP_PATH = select_dump()

    if DUMP_PATH:
        OUT_DIR = setup_output_dir(DUMP_PATH)

    # Main interactive loop
    while True:
        print_main_menu()

        if DUMP_PATH:
            cprint(f"  Dump : [cyan]{DUMP_PATH}[/cyan]", "dim") if RICH else \
            print(f"  Dump : {DUMP_PATH}")
            cprint(f"  Out  : [cyan]{OUT_DIR.resolve() if OUT_DIR else 'none'}[/cyan]\n",
                   "dim") if RICH else \
            print(f"  Out  : {OUT_DIR.resolve() if OUT_DIR else 'none'}\n")
        else:
            cprint("\n  [!] No dump loaded — use option [d] to select a file\n", "yellow")

        choice = ask("Choice", "q").strip().lower()

        if   choice == "q":   cprint("\n[*] Goodbye.\n", "cyan"); sys.exit(0)
        elif choice == "1":   quick_triage()
        elif choice == "2":   process_analysis()
        elif choice == "3":   network_analysis()
        elif choice == "4":   file_hunting()
        elif choice == "5":   credential_flag_hunt()
        elif choice == "6":   kernel_rootkit_check()
        elif choice == "7":   strings_search()
        elif choice == "8":   custom_plugin()
        elif choice == "cs1": show_cheatsheet("vol3")
        elif choice == "cs2": show_cheatsheet("ctf")
        elif choice == "cs3": show_cheatsheet("strings")
        elif choice == "cs4": show_cheatsheet("tools")
        elif choice == "i":
            install_volatility()
            VOL_CMD = find_volatility() or VOL_CMD
        elif choice == "d":
            new_dump = select_dump()
            if new_dump:
                DUMP_PATH = new_dump
                OUT_DIR   = setup_output_dir(DUMP_PATH)
        else:
            cprint("[!] Unknown option.", "red")


if __name__ == "__main__":
    main()
