#!/usr/bin/env python3
"""
memhunter.py — Interactive Memory Forensics Tool for CTF Competitions
=====================================================================
Wraps Volatility 3 with guided workflows, built-in cheat sheets, and
CTF-specific hunting techniques for both Linux and Windows memory dumps.
All output is saved to a timestamped results directory so nothing is lost
between sessions.

Usage:
    python3 memhunter.py                       # prompts for dump path
    python3 memhunter.py /path/to/dump.raw     # load dump directly
    python3 memhunter.py --install             # install Volatility 3
"""

import argparse
import base64 as _b64
import concurrent.futures
import json
import os
import re
import shlex
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
VERSION     = "2.1.0"
DUMP_PATH   = None          # set after argument parsing / menu selection
OUT_DIR     = None          # timestamped output directory
VOL_CMD     = None          # path to vol / vol3 / python3 vol.py
OS_TYPE     = "linux"       # "linux" or "windows" — chosen at startup
FLAG_FORMAT = ""            # user-supplied flag regex (e.g. flag\{[^}]+\})
HITS_JSON   = []            # accumulated structured hits for --json export


# ---------------------------------------------------------------------------
# Linux → Windows Volatility plugin mapping.
# None means the plugin has no Windows equivalent and should be skipped.
# ---------------------------------------------------------------------------
PLUGIN_MAP_WINDOWS = {
    "linux.info":           "windows.info",
    "linux.pslist":         "windows.pslist",
    "linux.pstree":         "windows.pstree",
    "linux.psaux":          "windows.cmdline",
    "linux.cmdline":        "windows.cmdline",
    "linux.envars":         "windows.envars",
    "linux.malfind":        "windows.malfind",
    "linux.proc.Maps":      "windows.vadinfo",
    "linux.netstat":        "windows.netstat",
    "linux.sockstat":       "windows.netscan",
    "linux.check_afinfo":   None,
    "linux.find_file":      "windows.filescan",
    "linux.inode_cache":    None,
    "linux.lsmod":          "windows.modules",
    "linux.check_modules":  "windows.modscan",
    "linux.check_syscall":  "windows.ssdt",
    "linux.check_idt":      None,
    "linux.tty_check":      None,
    "linux.kernel_log":     None,
    "linux.credentials":    "windows.hashdump",
    "linux.bash":           None,
}


def _p(plugin: str):
    """Translate a linux.* plugin to the active OS. Returns None if unavailable."""
    if OS_TYPE == "linux" or not plugin.startswith("linux."):
        return plugin
    return PLUGIN_MAP_WINDOWS.get(plugin)

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
                "[bold white]memhunter — Memory Forensics for CTFs[/bold white]\n"
                f"[dim]v{VERSION}  |  Linux + Windows  |  Powered by Volatility 3[/dim]",
                border_style="green",
            )
        )
    else:
        print(art)
        print(f"  memhunter — Memory Forensics for CTFs  v{VERSION}  (Linux + Windows)\n")


def ask(prompt: str, default: str = "") -> str:
    if RICH:
        return Prompt.ask(prompt, default=default)
    val = input(f"{prompt} [{default}]: ").strip()
    return val if val else default


DEFAULT_FLAG_PATTERN = r"(?:flag|HTB|picoCTF|THM|DUCTF|CTF|pwn|sun|KCTF)\{[^}]{1,200}\}"


def _ensure_flag_format() -> str:
    """Return the flag regex to use — fully optional, never prompts.

    If the user has set FLAG_FORMAT via the [f] menu, that's used. Otherwise
    the default multi-CTF pattern is returned silently so flag hunts always
    work without requiring the user to configure anything.
    """
    return FLAG_FORMAT or DEFAULT_FLAG_PATTERN


def _prompt_flag_format() -> str:
    """Interactively ask the user for a custom flag regex ([f] menu).

    Empty input clears any override so the default is used.
    """
    global FLAG_FORMAT
    cprint("\n[*] Enter a flag format for this CTF (Python/grep regex).", "yellow")
    cprint("    Optional — press Enter to clear and use the default multi-CTF pattern.", "dim")
    cprint("    Examples:", "dim")
    cprint(r"      flag\{[^}]+\}        HTB\{[^}]+\}        picoCTF\{[^}]+\}", "dim")
    cprint(r"      THM\{[^}]+\}         DUCTF\{[^}]+\}      CTF\{[a-f0-9]{32}\}", "dim")
    while True:
        pat = ask("Flag regex (blank = default)").strip()
        if not pat:
            FLAG_FORMAT = ""
            cprint(f"[+] Cleared — using default flag pattern: {DEFAULT_FLAG_PATTERN}", "green")
            return DEFAULT_FLAG_PATTERN
        try:
            re.compile(pat)
        except re.error as e:
            cprint(f"[!] Invalid regex: {e}", "red")
            continue
        FLAG_FORMAT = pat
        cprint(f"[+] Flag format set to: {pat}", "green")
        return FLAG_FORMAT


def _select_os() -> None:
    """Ask the user whether the dump is Linux or Windows."""
    global OS_TYPE
    cprint("\n[*] What OS is this memory dump from?", "yellow")
    cprint("    [1] Linux    [2] Windows", "dim")
    while True:
        choice = ask("Choice", "1").strip().lower()
        if choice in ("1", "l", "linux"):
            OS_TYPE = "linux"
            break
        if choice in ("2", "w", "win", "windows"):
            OS_TYPE = "windows"
            break
        cprint("[!] Enter 1 or 2.", "red")
    cprint(f"[+] OS set to: {OS_TYPE}", "green")


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


def run_shell(cmd: str, timeout: int = 300) -> subprocess.CompletedProcess | None:
    """Run a shell pipeline, catching timeouts and common failures.

    Returns the CompletedProcess on success, or None if the command timed out
    or failed to start. Callers should check `.stdout` / `.returncode`.
    """
    try:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        cprint(f"[!] Command timed out after {timeout}s.", "yellow")
        return None
    except FileNotFoundError as e:
        cprint(f"[!] Required tool missing: {e}", "red")
        return None
    except Exception as e:
        cprint(f"[!] Shell error: {e}", "red")
        return None


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

    mapped = _p(plugin)
    if mapped is None:
        cprint(f"[!] '{plugin}' has no equivalent on {OS_TYPE} — skipping.", "yellow")
        return ""
    plugin = mapped

    # windows.filescan doesn't accept --find <path>; strip it so the map
    # from linux.find_file still produces a usable command.
    if plugin == "windows.filescan" and "--find" in extra_args:
        extra_args = ""

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

    # Detect the "no symbol table / unsatisfied requirement" failure and
    # give the user an actionable hint instead of a silent empty result.
    VOL_FAIL_HINTS = (
        "Unsatisfied requirement",
        "A translation layer requirement was not fulfilled",
        "A symbol table requirement was not fulfilled",
    )
    has_real_data = len([ln for ln in output.splitlines() if ln.strip()]) > 1
    if not has_real_data and any(h in output or h in errors for h in VOL_FAIL_HINTS):
        cprint("\n[!] Volatility could not parse this dump.", "bold red")
        cprint("    Possible reasons:", "yellow")
        cprint("    1. The dump is truncated, synthetic, or from an unsupported kernel.", "yellow")
        if OS_TYPE == "windows":
            cprint("    2. PDB symbol download failed — Volatility needs internet access", "yellow")
            cprint("       to fetch Windows kernel symbols from Microsoft's symbol server.", "yellow")
            cprint("       Check connectivity and retry, or pre-seed ~/.cache/volatility3.", "dim")
        else:
            cprint("    2. The Linux symbol pack is missing for this kernel.", "yellow")
            cprint("       Download from: https://github.com/volatilityfoundation/volatility3/releases", "dim")
        cprint("\n    Use strings-based analysis instead (no Volatility needed):", "bold cyan")
        cprint("    → Option [5] → [4]  :  flag pattern sweep", "cyan")
        cprint("    → Option [5] → [5]  :  base64 hunt & decode", "cyan")
        cprint("    → Option [5] → [6]  :  credential strings", "cyan")
        cprint("    → Option [7]        :  full strings search menu", "cyan")
        return output

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
    ("r",  "Report (MD/HTML)",       "Stitch all results_*.txt into report.md"),
    ("y",  "YARA scan",              "Run yara rules against the dump"),
    ("be", "bulk_extractor",         "One-click artefact carving"),
    ("pk", "pypykatz (LSASS)",       "Dump LSASS via memmap + pypykatz (Windows)"),
    ("j",  "Export hits to JSON",    "Save structured flag/cred hits to hits.json"),
    ("h",  "Health check",           "Re-run dependency/version checks"),
    ("?",  "Help",                   "Usage tips + full Volatility plugin list"),
    ("",   "",                       ""),
    ("cs1","Cheat Sheet: Volatility 3","Full plugin reference"),
    ("cs2","Cheat Sheet: CTF Workflow","Flag hunting strategies & tips"),
    ("cs3","Cheat Sheet: Strings/grep","No-Volatility string analysis"),
    ("cs4","Cheat Sheet: Tools",       "Companion forensics tools"),
    ("",   "",                         ""),
    ("i",  "Install / Update Volatility 3", "Clone & pip-install from GitHub"),
    ("iy", "Install YARA",                "apt install yara"),
    ("d",  "Change dump file",         "Load a different memory image"),
    ("o",  "Change OS (linux/windows)","Re-select the target OS for plugin mapping"),
    ("f",  "Change flag format",       "Enter a new flag regex for this CTF"),
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
    header(f"Quick Triage ({OS_TYPE}) — Parallel Plugin Sweep + Strings")

    if OS_TYPE == "windows":
        plugins = [
            ("windows.info",                "", "info.txt"),
            ("windows.pslist",              "", "pslist.txt"),
            ("windows.pstree",              "", "pstree.txt"),
            ("windows.cmdline",             "", "cmdline.txt"),
            ("windows.svcscan",             "", "svcscan.txt"),
            ("windows.netscan",             "", "netscan.txt"),
            ("windows.malfind",             "", "malfind.txt"),
            ("windows.hashdump",            "", "hashdump.txt"),
            ("windows.registry.hivelist",   "", "hivelist.txt"),
            ("windows.mftscan",             "", "mftscan.txt"),
        ]
    else:
        plugins = [
            ("banners.Banners",     "", "banners.txt"),
            ("linux.pslist",        "", "pslist.txt"),
            ("linux.pstree",        "", "pstree.txt"),
            ("linux.lsmod",         "", "lsmod.txt"),
            ("linux.netstat",       "", "netstat.txt"),
            ("linux.bash",          "", "bash_history.txt"),
            ("linux.envars",        "", "envars.txt"),
            ("linux.credentials",   "", "credentials.txt"),
            ("linux.check_modules", "", "check_modules.txt"),
            ("linux.check_syscall", "", "check_syscall.txt"),
        ]

    cprint("[*] Phase 1: running Volatility plugins in parallel (4 workers) …\n",
           "yellow")

    vol_worked = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {
            ex.submit(run_vol_quiet, p, a): outfile
            for p, a, outfile in plugins
        }
        for fut in concurrent.futures.as_completed(futs):
            outfile = futs[fut]
            try:
                plugin_name, output = fut.result()
            except Exception as e:
                cprint(f"  [x] worker error: {e}", "red")
                continue
            if output and "Unsatisfied requirement" not in output:
                vol_worked = True
                save_result(outfile, f"Plugin: {plugin_name}\n\n{output}")
                cprint(f"  [+] {plugin_name:<32} "
                       f"{len(output.splitlines()):>5} lines", "green")
            else:
                cprint(f"  [-] {plugin_name:<32}  (no output / failed)", "dim")

    # ── Phase 2: strings-based flag sweep (only if user set a flag format) ─
    if FLAG_FORMAT:
        cprint(f"\n{'─'*50}", "dim")
        cprint("\n[*] Phase 2: Strings-based flag sweep …\n", "yellow")
        _hunt_flags_strings()
    else:
        cprint(f"\n{'─'*50}", "dim")
        cprint("\n[*] Phase 2: Skipping flag sweep — no flag format set ([f] to set one).", "dim")

    cprint(f"\n{'─'*50}", "dim")
    cprint("\n[*] Phase 3: Credential strings sweep …\n", "yellow")
    _hunt_creds_strings()

    cprint("\n[+] Quick triage complete.", "bold green")
    if OUT_DIR:
        cprint(f"[+] All results saved in: {OUT_DIR.resolve()}", "green")

    _triage_summary()

    if not vol_worked:
        cprint("\n[!] Volatility plugins produced no output.", "bold yellow")
        cprint("    For a real dump: run install.sh to get symbol packs.", "yellow")
        cprint("    For this test dump: use options [5] and [7] for full strings analysis.", "yellow")


def process_analysis() -> None:
    header(f"Process Analysis ({OS_TYPE})")
    if OS_TYPE == "windows":
        opts = [
            ("1", "pslist       — simple process list"),
            ("2", "pstree       — parent/child tree"),
            ("3", "cmdline      — command lines for all PIDs"),
            ("4", "pslist --pid <PID>"),
            ("5", "vadinfo --pid <PID>  — VAD regions for a PID"),
            ("6", "dumpfiles --pid <PID> — carve files owned by PID"),
            ("7", "malfind      — detect injected / unsigned pages"),
            ("b", "Back"),
        ]
        _submenu(opts, {
            "1": lambda: run_vol("windows.pslist",  "", "pslist.txt"),
            "2": lambda: run_vol("windows.pstree",  "", "pstree.txt"),
            "3": lambda: run_vol("windows.cmdline", "", "cmdline.txt"),
            "4": lambda: _win_pid_plugin("windows.pslist"),
            "5": lambda: _win_pid_plugin("windows.vadinfo"),
            "6": lambda: _win_pid_plugin("windows.dumpfiles"),
            "7": lambda: run_vol("windows.malfind", "", "malfind.txt"),
        })
        return

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
    if not kw:
        return
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
    cprint("    [vol] = needs Volatility + real dump   [str] = works on any dump\n", "dim")
    opts = [
        ("1", "bash history      [vol] — .bash_history per process"),
        ("2", "envars full       [vol] — dump ALL environment variables"),
        ("3", "envars → flag     [vol] — grep envars for your flag format"),
        ("4", "strings → flags   [str] — grep raw dump for your flag format  ← START HERE"),
        ("5", "strings → base64  [str] — find & decode base64 blobs"),
        ("6", "strings → creds   [str] — grep for password/secret/key/token"),
        ("7", "credentials plugin[vol] — UID/GID per process"),
        ("b", "Back"),
    ]
    _submenu(opts, {
        "1": _run_bash_history,
        "2": _run_envars_full,
        "3": _hunt_flags_envars,
        "4": _hunt_flags_strings,
        "5": _hunt_base64,
        "6": _hunt_creds_strings,
        "7": lambda: run_vol("linux.credentials", "", "credentials.txt"),
    })


def _vol_failed(output: str) -> bool:
    """Return True if Volatility output indicates a parse/symbol failure."""
    has_real_data = len([ln for ln in output.splitlines() if ln.strip()]) > 1
    if has_real_data:
        return False
    return (not output) or any(x in output for x in (
        "Unsatisfied requirement", "A translation layer requirement",
        "A symbol table requirement"))


def _run_bash_history() -> None:
    out = run_vol("linux.bash", "", "bash_history.txt")
    if _vol_failed(out):
        if OS_TYPE == "windows":
            cprint("\n[!] No shell-history plugin for Windows — scanning raw strings …", "yellow")
            pattern = r"(powershell|cmd\.exe|wget|curl|Invoke-|IEX |DownloadString|bitsadmin|certutil)"
        else:
            cprint("\n[!] Volatility bash plugin failed — scanning raw strings for shell history …", "yellow")
            pattern = r"(bash|history|sudo|wget|curl|chmod|python|nc |ncat|sh -i)"
        if not DUMP_PATH:
            return
        dump = shlex.quote(DUMP_PATH)
        pat  = shlex.quote(pattern)
        cmd  = f"strings -n 6 {dump} | grep -iP {pat} | head -40"
        r = run_shell(cmd)
        if r and r.stdout.strip():
            cprint(r.stdout, "yellow")
            save_result("bash_strings.txt", r.stdout)
        else:
            cprint("[!] No shell command strings found.", "yellow")


def _run_envars_full() -> None:
    out = run_vol("linux.envars", "", "envars.txt")
    if _vol_failed(out):
        cprint("\n[!] Volatility envars failed — scanning raw strings for env-style KEY=VALUE pairs …", "yellow")
        if not DUMP_PATH:
            return
        dump = shlex.quote(DUMP_PATH)
        pat  = shlex.quote(r"[A-Z_]{2,30}=\S+")
        cmd  = f"strings -n 6 {dump} | grep -oP {pat} | sort -u | head -60"
        r = run_shell(cmd)
        if r and r.stdout.strip():
            cprint(r.stdout, "yellow")
            save_result("envars_strings.txt", r.stdout)
        else:
            cprint("[!] No KEY=VALUE env strings found.", "yellow")


def _hunt_flags_envars() -> None:
    pat = _ensure_flag_format()
    out = run_vol("linux.envars", "", "envars.txt")

    if _vol_failed(out):
        cprint("\n[!] Volatility envars failed — falling back to raw strings scan …", "yellow")
        _hunt_flags_strings()
        return

    hits = [l for l in out.splitlines() if re.search(pat, l, re.I)]
    if hits:
        cprint(f"\n[+] Pattern '{pat}' in envars:", "bold green")
        for h in hits:
            cprint(f"  {h}", "yellow")
        save_result("flag_envars.txt", "\n".join(hits))
    else:
        cprint(f"[!] Flag format '{pat}' not found in envars.", "yellow")
        cprint("[>] Falling back to raw strings scan …", "dim")
        _hunt_flags_strings()


def _hunt_flags_strings() -> None:
    if not DUMP_PATH:
        return
    pat = _ensure_flag_format()
    cprint(f"[*] Running strings against the dump for /{pat}/ — may take a minute …", "yellow")

    dump = shlex.quote(DUMP_PATH)
    qpat = shlex.quote(pat)

    # ASCII
    r1 = run_shell(f"strings -n 6 {dump} | grep -oiP {qpat}")
    # Unicode (wide chars) — common on Windows dumps
    r2 = run_shell(f"strings -el {dump} | grep -oiP {qpat}")

    out1 = r1.stdout if r1 else ""
    out2 = r2.stdout if r2 else ""
    output = (out1 + out2).strip()
    if output:
        hits = sorted(set(output.splitlines()))
        cprint(f"\n[+] Found {len(hits)} unique flag string(s):", "bold green")
        for h in hits:
            cprint(f"  {h}", "bold yellow")
            _record_hit("flag", h, "strings")
        save_result("flag_hits.txt", "\n".join(hits))
    else:
        cprint(f"[!] Flag format '{pat}' not found in raw strings.", "yellow")
        cprint("[>] Try option 5 (base64) — the flag might be encoded.", "dim")


def _hunt_base64() -> None:
    if not DUMP_PATH:
        return
    cprint("[*] Hunting base64 blobs (≥40 chars) …", "yellow")
    dump = shlex.quote(DUMP_PATH)
    pat  = shlex.quote(r"[A-Za-z0-9+/]{40,}={0,2}")
    cmd  = f"strings -n 6 {dump} | grep -oP {pat} | sort -u | head -80"
    result = run_shell(cmd)
    output = result.stdout.strip() if result else ""
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
    dump = shlex.quote(DUMP_PATH)
    any_found = False
    for pat, label in patterns:
        qpat = shlex.quote(pat)
        cmd  = f"strings -n 6 {dump} | grep -oiP {qpat} | head -20"
        result = run_shell(cmd, timeout=120)
        if result and result.stdout.strip():
            any_found = True
            cprint(f"\n[+] {label}:", "bold yellow")
            cprint(result.stdout.strip(), "yellow")
            save_result("credential_hits.txt", f"=== {label} ===\n{result.stdout}")
            for ln in result.stdout.strip().splitlines():
                _record_hit("credential", ln, label)

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
        ("3", "Flag pattern sweep (uses the flag format you enter)"),
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
    try:
        re.compile(pat)
    except re.error as e:
        cprint(f"[!] Invalid regex: {e}", "red")
        return
    dump = shlex.quote(DUMP_PATH)
    qpat = shlex.quote(pat)
    cmd  = f"strings -n 6 {dump} | grep -oiP {qpat} | sort -u | head -100"
    result = run_shell(cmd)
    if result and result.stdout.strip():
        cprint(result.stdout, "yellow")
        save_result("custom_strings.txt", f"Pattern: {pat}\n{result.stdout}")
    else:
        cprint("[!] No matches found.", "yellow")


def _strings_extract_all() -> None:
    if not DUMP_PATH or not OUT_DIR:
        return
    out_file = OUT_DIR / "all_strings.txt"
    dump = shlex.quote(DUMP_PATH)
    qout = shlex.quote(str(out_file))
    cprint(f"[*] Extracting ASCII strings to {out_file} …", "yellow")
    if run_shell(f"strings -n 6 {dump} > {qout}", timeout=600) is None:
        return
    cprint("[*] Appending Unicode (wide) strings …", "yellow")
    run_shell(f"strings -el {dump} >> {qout}", timeout=300)
    try:
        size_kb = out_file.stat().st_size // 1024
        cprint(f"[+] Saved {size_kb:,} KB → {out_file}", "bold green")
    except OSError as e:
        cprint(f"[!] Could not stat output file: {e}", "red")
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
    dump = shlex.quote(DUMP_PATH)
    any_found = False
    for pat, label in patterns:
        qpat = shlex.quote(pat)
        cmd  = f"strings -n 6 {dump} | grep -oiP {qpat} | sort -u | head -40"
        result = run_shell(cmd)
        if result and result.stdout.strip():
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
# Health check
# ===========================================================================

def health_check() -> None:
    header("Health Check")
    # Volatility 3 version
    if VOL_CMD:
        # Volatility only prints its framework banner when a plugin actually
        # runs — probe against /dev/null to capture it cheaply.
        r = run_shell(f"{VOL_CMD} -f /dev/null banners.Banners", timeout=30)
        blob = ((r.stdout if r else "") + (r.stderr if r else ""))
        m = re.search(r"Volatility\s*3\s*Framework\s*([\d.]+)", blob)
        if m:
            cprint(f"  [+] Volatility 3 Framework {m.group(1)}", "green")
        else:
            cprint("  [+] Volatility: present (version unknown)", "green")
            cprint("  [!] Could not confirm Volatility 3.x banner.", "yellow")
    else:
        cprint("  [!] Volatility 3 not found (option [i] to install).", "red")

    # strings
    if shutil.which("strings"):
        cprint("  [+] strings: OK", "green")
    else:
        cprint("  [!] strings missing (sudo apt install binutils).", "red")

    # grep -P (PCRE)
    r = subprocess.run("echo test | grep -P test", shell=True,
                       capture_output=True)
    if r.returncode == 0:
        cprint("  [+] grep -P (PCRE): OK", "green")
    else:
        cprint("  [!] grep lacks PCRE (-P) support.", "yellow")

    # Symbol cache
    cache = _real_home() / ".cache" / "volatility3"
    if cache.exists():
        cprint(f"  [+] Symbol cache: {cache}", "green")
    else:
        cprint(f"  [-] Symbol cache not created yet: {cache}", "dim")

    # Optional tools
    for t in ("yara", "bulk_extractor", "pypykatz"):
        if shutil.which(t):
            cprint(f"  [+] {t}: installed", "green")
        else:
            cprint(f"  [-] {t}: not installed (optional)", "dim")


# ===========================================================================
# OS auto-detect (banners.Banners once)
# ===========================================================================

def _auto_detect_os() -> None:
    global OS_TYPE
    if not (VOL_CMD and DUMP_PATH):
        _select_os()
        return
    cprint("\n[*] Auto-detecting OS via banners.Banners …", "yellow")
    r = run_shell(f"{VOL_CMD} -f \"{DUMP_PATH}\" banners.Banners", timeout=240)
    blob = ((r.stdout if r else "") + (r.stderr if r else "")) if r else ""
    if "Linux version" in blob:
        OS_TYPE = "linux"
        cprint("[+] Detected: Linux", "bold green")
    elif re.search(r"Windows|ntoskrnl|NT Kernel|Microsoft", blob):
        OS_TYPE = "windows"
        cprint("[+] Detected: Windows", "bold green")
    else:
        cprint("[!] Auto-detect inconclusive — please select manually.", "yellow")
        _select_os()


# ===========================================================================
# Quiet parallel Volatility runner (no Rich progress — thread-safe)
# ===========================================================================

def run_vol_quiet(plugin: str, extra_args: str = "", timeout: int = 300) -> tuple:
    if not (VOL_CMD and DUMP_PATH):
        return plugin, ""
    mapped = _p(plugin)
    if mapped is None:
        return plugin, ""
    plugin = mapped
    if plugin == "windows.filescan" and "--find" in extra_args:
        extra_args = ""
    cmd = f"{VOL_CMD} -f \"{DUMP_PATH}\" {plugin} {extra_args}".strip()
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return plugin, (r.stdout or "")
    except subprocess.TimeoutExpired:
        return plugin, ""
    except Exception:
        return plugin, ""


# ===========================================================================
# Report generator, YARA, bulk_extractor, pypykatz, JSON export
# ===========================================================================

_CATEGORY_MAP = {
    "process":    {"pslist", "pstree", "psaux", "cmdline", "envars",
                   "envars_filtered", "malfind", "vadinfo", "dumpfiles",
                   "proc_maps", "maps"},
    "network":    {"netstat", "netscan", "sockstat", "check_afinfo",
                   "network_artefacts"},
    "filesystem": {"filescan", "find_file", "inode_cache", "mftscan",
                   "hivelist"},
    "credentials":{"credential_hits", "hashdump", "credentials",
                   "pypykatz", "flag_hits", "flag_envars", "base64_candidates"},
    "kernel":     {"lsmod", "modules", "modscan", "check_modules",
                   "check_syscall", "check_idt", "ssdt", "tty_check",
                   "kernel_log"},
    "services":   {"svcscan"},
    "yara":       {"yara_hits", "yara"},
    "strings":    {"custom_strings", "strings"},
    "other":      set(),
}

_CATEGORY_LABELS = {
    "process":     ("Processes",     "fa-microchip"),
    "network":     ("Network",       "fa-network-wired"),
    "filesystem":  ("File System",   "fa-folder-open"),
    "credentials": ("Credentials",   "fa-key"),
    "kernel":      ("Kernel",        "fa-skull-crossbones"),
    "services":    ("Services",      "fa-cogs"),
    "yara":        ("YARA",          "fa-biohazard"),
    "strings":     ("Strings",       "fa-font"),
    "other":       ("Other",         "fa-file-alt"),
}


def _file_to_category(name: str) -> str:
    stem = re.sub(r'_pid\d+', '', Path(name).stem).lower()
    for cat, kws in _CATEGORY_MAP.items():
        if cat == "other":
            continue
        if stem in kws or any(kw in stem for kw in kws):
            return cat
    return "other"


def _classify_file(name: str) -> tuple[str, str, str]:
    """Return (severity, label, css_class) for a result filename."""
    n = name.lower()
    rootkit_markers = ("malfind", "check_modules", "check_syscall",
                       "check_idt", "rootkit")
    suspect_markers = ("credential", "hashdump", "envars",
                       "netstat", "netscan", "svcscan", "cmdline",
                       "base64", "pypykatz", "yara")
    if "flag" in n:
        return ("CRITICAL", "FLAG", "sev-flag")
    if any(m in n for m in rootkit_markers):
        return ("HIGH", "ROOTKIT?", "sev-rootkit")
    if any(m in n for m in suspect_markers):
        return ("MEDIUM", "SUSPECT", "sev-suspect")
    return ("LOW", "info", "sev-info")


def _parse_processes(files: list) -> dict:
    """Parse pslist/pstree/cmdline/netscan/malfind and group data by PID."""
    procs: dict[str, dict] = {}

    for tf in files:
        if tf.stem.lower() not in ("pslist", "pstree"):
            continue
        try:
            raw = tf.read_text(errors="replace")
        except OSError:
            continue
        for line in raw.splitlines():
            line = line.lstrip("* ")
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            pid = parts[0].strip()
            if not pid.isdigit():
                continue
            name = parts[2].strip() if len(parts) > 2 else "?"
            ppid = parts[1].strip() if len(parts) > 1 else "?"
            if pid not in procs:
                procs[pid] = {"pid": pid, "ppid": ppid, "name": name,
                              "cmdline": "", "network": [], "malfind": [],
                              "other": []}

    for tf in files:
        if tf.stem.lower() != "cmdline":
            continue
        try:
            raw = tf.read_text(errors="replace")
        except OSError:
            continue
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            pid = parts[0].strip()
            if pid in procs:
                procs[pid]["cmdline"] = parts[2].strip() if len(parts) > 2 else ""

    for tf in files:
        stem = tf.stem.lower()
        if stem not in ("netscan", "netstat", "sockstat"):
            continue
        try:
            raw = tf.read_text(errors="replace")
        except OSError:
            continue
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) < 8:
                continue
            pid = parts[7].strip() if len(parts) > 7 else ""
            if pid in procs:
                procs[pid]["network"].append(line.strip())

    for tf in files:
        if tf.stem.lower() != "malfind":
            continue
        try:
            raw = tf.read_text(errors="replace")
        except OSError:
            continue
        chunk: list[str] = []
        chunk_pid = ""
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0].strip().isdigit():
                if chunk and chunk_pid in procs:
                    procs[chunk_pid]["malfind"].append("\n".join(chunk))
                chunk_pid = parts[0].strip()
                chunk = [line]
            elif chunk_pid:
                chunk.append(line)
        if chunk and chunk_pid in procs:
            procs[chunk_pid]["malfind"].append("\n".join(chunk))

    return procs


def generate_report() -> None:
    if not OUT_DIR:
        cprint("[!] No output directory.", "red")
        return
    header("Report Generator")
    files = sorted(p for p in OUT_DIR.glob("*.txt") if p.name != "report.md")
    if not files:
        cprint("[!] No result files yet.", "yellow")
        return

    md = OUT_DIR / "report.md"
    with md.open("w") as f:
        f.write("# memhunter Report\n\n")
        f.write(f"- **Dump:** `{DUMP_PATH}`\n")
        f.write(f"- **OS:** {OS_TYPE}\n")
        f.write(f"- **Flag format:** `{FLAG_FORMAT or 'n/a'}`\n")
        f.write(f"- **Generated:** {datetime.now().isoformat()}\n\n")
        f.write("## Contents\n\n")
        for tf in files:
            f.write(f"- [{tf.name}](#{tf.stem.lower()})\n")
        f.write("\n---\n\n")
        for tf in files:
            try:
                content = tf.read_text(errors="replace")
            except OSError:
                continue
            hits = len(content.splitlines())
            f.write(f"## {tf.stem}\n\n")
            f.write(f"*{tf.name} — {hits} lines*\n\n")
            f.write("```\n")
            f.write(content[:12000])
            if len(content) > 12000:
                f.write("\n... [truncated] ...\n")
            f.write("\n```\n\n")
    cprint(f"[+] Markdown report -> {md}", "bold green")

    import html as _h

    categorized: dict[str, list[tuple[Path, str, str, str]]] = {}
    for tf in files:
        cat = _file_to_category(tf.name)
        sev, label, css = _classify_file(tf.name)
        categorized.setdefault(cat, []).append((tf, sev, label, css))

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for cat_files in categorized.values():
        for _, sev, _, _ in cat_files:
            sev_counts[sev] += 1

    procs = _parse_processes(files)

    # --- sidebar nav ---
    sidebar_items = ""
    sidebar_items += (
        '<a class="nav-item nav-dashboard active" data-page="dashboard" '
        'onclick="showPage(\'dashboard\')">'
        '<i class="fas fa-tachometer-alt"></i><span>Dashboard</span></a>\n'
    )
    sidebar_items += (
        '<a class="nav-item nav-processes" data-page="processes" '
        'onclick="showPage(\'processes\')">'
        '<i class="fas fa-microchip"></i><span>Process Explorer</span></a>\n'
    )
    sidebar_items += (
        '<a class="nav-item" data-page="proctree" '
        'onclick="showPage(\'proctree\')">'
        '<i class="fas fa-project-diagram"></i><span>Process Tree</span></a>\n'
    )
    sidebar_items += (
        '<a class="nav-item" data-page="netmap" '
        'onclick="showPage(\'netmap\')">'
        '<i class="fas fa-globe-americas"></i><span>Network Map</span></a>\n'
    )
    cat_order = ["process", "network", "filesystem", "credentials",
                 "kernel", "services", "yara", "strings", "other"]
    for cat in cat_order:
        if cat not in categorized:
            continue
        lbl, icon = _CATEGORY_LABELS[cat]
        n = len(categorized[cat])
        has_alert = any(s in ("CRITICAL", "HIGH") for _, s, _, _ in categorized[cat])
        alert_dot = '<span class="alert-dot"></span>' if has_alert else ''
        sidebar_items += (
            f'<a class="nav-item" data-page="cat-{cat}" '
            f'onclick="showPage(\'cat-{cat}\')">'
            f'<i class="fas {icon}"></i><span>{lbl} ({n})</span>{alert_dot}</a>\n'
        )
    sidebar_plugins = ""
    for cat in cat_order:
        if cat not in categorized:
            continue
        sidebar_plugins += f'<div class="plugin-group" data-cat="{cat}">\n'
        for tf, sev, label, css in categorized[cat]:
            sidebar_plugins += (
                f'<a class="nav-plugin {css}" data-page="plugin-{tf.stem.lower()}" '
                f'onclick="showPage(\'plugin-{tf.stem.lower()}\')">'
                f'<span class="badge-sm {css}">{label}</span> {_h.escape(tf.stem)}</a>\n'
            )
        sidebar_plugins += '</div>\n'

    # --- category pages ---
    cat_pages = ""
    for cat in cat_order:
        if cat not in categorized:
            continue
        lbl, icon = _CATEGORY_LABELS[cat]
        cards = ""
        for tf, sev, label, css in categorized[cat]:
            try:
                content = tf.read_text(errors="replace")
            except OSError:
                continue
            lines = len(content.splitlines())
            cards += (
                f'<div class="cat-card {css}" onclick="showPage(\'plugin-{tf.stem.lower()}\')">'
                f'<div class="cat-card-head"><span class="badge {css}">{label}</span>'
                f'<span class="cat-card-name">{_h.escape(tf.stem)}</span></div>'
                f'<div class="cat-card-meta">{lines} lines</div></div>\n'
            )
        cat_pages += (
            f'<div class="page" id="page-cat-{cat}">'
            f'<h1 class="page-title"><i class="fas {icon}"></i> {lbl}</h1>'
            f'<div class="cat-grid">{cards}</div></div>\n'
        )

    # --- plugin pages (each line is clickable for evidence) ---
    plugin_pages = ""
    for cat in cat_order:
        if cat not in categorized:
            continue
        for tf, sev, label, css in categorized[cat]:
            try:
                content = tf.read_text(errors="replace")
            except OSError:
                continue
            lines_list = content.splitlines()
            total = len(lines_list)
            if len(lines_list) > 3000:
                lines_list = lines_list[:3000]
            line_divs = ""
            for i, ln in enumerate(lines_list):
                esc = _h.escape(ln)
                line_divs += (
                    f'<div class="code-line" data-src="{_h.escape(tf.stem)}" '
                    f'data-ln="{i+1}" onclick="selectLine(event,this)" '
                    f'title="Click to select, Shift+Click for range">'
                    f'<span class="ln-num">{i+1}</span>'
                    f'<span class="ln-text">{esc}</span></div>\n'
                )
            trunc = ""
            if total > 3000:
                trunc = (
                    '<div class="truncated">'
                    f'Showing 3000 of {total} lines</div>'
                )
            plugin_pages += (
                f'<div class="page" id="page-plugin-{tf.stem.lower()}">'
                f'<h1 class="page-title"><span class="badge {css}">{label}</span> '
                f'{_h.escape(tf.stem)}</h1>'
                f'<p class="plugin-meta">{_h.escape(tf.name)} | {total} lines | '
                f'Category: {_file_to_category(tf.name)}</p>'
                f'<p class="collect-hint"><i class="fas fa-crosshairs"></i> '
                f'Click to select lines &bull; Shift+Click to select a range '
                f'&bull; press Confirm to add as one result</p>'
                f'<div class="output-block">'
                f'<div class="confirm-bar" id="cb-{tf.stem.lower()}">'
                f'<span><i class="fas fa-layer-group"></i> '
                f'<span class="cb-count">0</span> lines selected</span>'
                f'<span class="cb-btn cb-confirm" '
                f'onclick="confirmSelection(\'{_h.escape(tf.stem)}\')">'
                f'<i class="fas fa-check"></i> Confirm</span>'
                f'<span class="cb-btn cb-cancel" '
                f'onclick="cancelSelection(\'{_h.escape(tf.stem)}\')">'
                f'<i class="fas fa-times"></i> Cancel</span>'
                f'</div>'
                f'<div class="code-lines">'
                f'{line_divs}</div>{trunc}</div></div>\n'
            )

    # --- process explorer page ---
    proc_rows = ""
    proc_detail_pages = ""
    for pid in sorted(procs.keys(), key=int):
        p = procs[pid]
        has_mal = len(p["malfind"]) > 0
        has_net = len(p["network"]) > 0
        row_cls = "proc-row-danger" if has_mal else ""
        indicators = ""
        if has_mal:
            indicators += '<span class="badge sev-rootkit">MALFIND</span> '
        if has_net:
            indicators += '<span class="badge sev-info">NET</span> '
        proc_rows += (
            f'<tr class="{row_cls}" onclick="showPage(\'proc-{pid}\')" '
            f'style="cursor:pointer">'
            f'<td>{_h.escape(pid)}</td>'
            f'<td>{_h.escape(p["name"])}</td>'
            f'<td>{_h.escape(p["ppid"])}</td>'
            f'<td class="cmdline-cell">{_h.escape(p["cmdline"][:120])}</td>'
            f'<td>{indicators}</td></tr>\n'
        )
        net_section = ""
        if p["network"]:
            net_lines = _h.escape("\n".join(p["network"]))
            net_section = (
                f'<div class="proc-section"><h3><i class="fas fa-network-wired">'
                f'</i> Network Connections ({len(p["network"])})</h3>'
                f'<pre><code>{net_lines}</code></pre></div>'
            )
        mal_section = ""
        if p["malfind"]:
            mal_lines = _h.escape("\n\n".join(p["malfind"]))
            mal_section = (
                f'<div class="proc-section proc-danger"><h3>'
                f'<i class="fas fa-exclamation-triangle"></i> '
                f'Malfind Hits ({len(p["malfind"])})</h3>'
                f'<pre><code>{mal_lines}</code></pre></div>'
            )
        pid_files_html = ""
        for tf in files:
            if f"pid{pid}" in tf.name.lower():
                try:
                    fc = tf.read_text(errors="replace")[:20000]
                except OSError:
                    continue
                pid_files_html += (
                    f'<div class="proc-section"><h3>{_h.escape(tf.stem)}</h3>'
                    f'<pre><code>{_h.escape(fc)}</code></pre></div>'
                )

        proc_detail_pages += (
            f'<div class="page" id="page-proc-{pid}">'
            f'<h1 class="page-title proc-title">'
            f'<i class="fas fa-microchip"></i> {_h.escape(p["name"])} '
            f'<span class="pid-tag">PID {pid}</span></h1>'
            f'<div class="proc-info-grid">'
            f'<div class="proc-info-item"><span class="lbl">PPID</span>'
            f'<span class="val">{_h.escape(p["ppid"])}</span></div>'
            f'<div class="proc-info-item"><span class="lbl">Command</span>'
            f'<span class="val mono">{_h.escape(p["cmdline"] or "N/A")}</span></div>'
            f'<div class="proc-info-item"><span class="lbl">Net Conns</span>'
            f'<span class="val">{len(p["network"])}</span></div>'
            f'<div class="proc-info-item"><span class="lbl">Malfind</span>'
            f'<span class="val {"danger-val" if has_mal else ""}">'
            f'{len(p["malfind"])}</span></div></div>'
            f'{mal_section}{net_section}{pid_files_html}</div>\n'
        )

    # --- process tree visual page ---
    def _build_tree_html(pid: str, children_map: dict, procs: dict, depth: int = 0) -> str:
        p = procs.get(pid, {})
        name = _h.escape(p.get("name", "?"))
        has_mal = len(p.get("malfind", [])) > 0
        has_net = len(p.get("network", [])) > 0
        node_cls = "tree-node"
        if has_mal:
            node_cls += " tree-danger"
        elif has_net:
            node_cls += " tree-net"
        badges = ""
        if has_mal:
            badges += '<span class="badge sev-rootkit" style="font-size:.55em">MALFIND</span> '
        if has_net:
            badges += '<span class="badge sev-info" style="font-size:.55em">NET</span> '
        kids = children_map.get(pid, [])
        child_html = ""
        if kids:
            child_items = ""
            for cpid in sorted(kids, key=int):
                child_items += _build_tree_html(cpid, children_map, procs, depth + 1)
            child_html = f'<div class="tree-children">{child_items}</div>'
        return (
            f'<div class="{node_cls}">'
            f'<div class="tree-label" onclick="showPage(\'proc-{_h.escape(pid)}\')" '
            f'title="Click to view process details">'
            f'<span class="tree-pid">{_h.escape(pid)}</span>'
            f'<span class="tree-name">{name}</span>{badges}</div>'
            f'{child_html}</div>'
        )

    children_map: dict[str, list[str]] = {}
    all_pids = set(procs.keys())
    for pid, p in procs.items():
        ppid = p.get("ppid", "0")
        if ppid not in children_map:
            children_map[ppid] = []
        children_map[ppid].append(pid)

    roots = []
    for pid in sorted(procs.keys(), key=int):
        ppid = procs[pid].get("ppid", "0")
        if ppid not in all_pids:
            roots.append(pid)

    tree_nodes_html = ""
    for rpid in roots:
        tree_nodes_html += _build_tree_html(rpid, children_map, procs, 0)

    proc_tree_page = (
        f'<div class="page" id="page-proctree">'
        f'<h1 class="page-title"><i class="fas fa-project-diagram"></i> Process Tree</h1>'
        f'<p class="plugin-meta">Visual parent-child hierarchy &bull; '
        f'Click any node to view process details</p>'
        f'<div class="proc-tree">{tree_nodes_html}</div></div>\n'
    )

    # --- network map page ---
    SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6666, 6667, 8443, 9001, 9090, 1234, 12345}
    net_connections = []
    for tf in files:
        if tf.stem.lower() not in ("netscan", "netstat", "sockstat"):
            continue
        try:
            raw = tf.read_text(errors="replace")
        except OSError:
            continue
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) < 8:
                continue
            pid = parts[7].strip() if len(parts) > 7 else ""
            if not pid.isdigit():
                continue
            proto = parts[1].strip() if len(parts) > 1 else "?"
            local_addr = parts[2].strip() if len(parts) > 2 else "?"
            local_port = parts[3].strip() if len(parts) > 3 else "?"
            foreign_addr = parts[4].strip() if len(parts) > 4 else "?"
            foreign_port = parts[5].strip() if len(parts) > 5 else "?"
            state = parts[6].strip() if len(parts) > 6 else "?"
            owner = parts[8].strip() if len(parts) > 8 else "?"
            try:
                fp = int(foreign_port)
            except ValueError:
                fp = 0
            try:
                lp = int(local_port)
            except ValueError:
                lp = 0
            suspicious = fp in SUSPICIOUS_PORTS or lp in SUSPICIOUS_PORTS
            net_connections.append({
                "proto": proto, "localAddr": local_addr, "localPort": local_port,
                "foreignAddr": foreign_addr, "foreignPort": foreign_port,
                "state": state, "pid": pid, "owner": owner, "suspicious": suspicious,
            })

    import json as _json
    net_json = _json.dumps(net_connections)

    netmap_page = (
        f'<div class="page" id="page-netmap">'
        f'<h1 class="page-title"><i class="fas fa-globe-americas"></i> Network Map</h1>'
        f'<p class="plugin-meta">Interactive connection graph &bull; '
        f'Drag nodes to rearrange &bull; Hover for details &bull; '
        f'Red edges = suspicious ports</p>'
        f'<div class="netmap-controls">'
        f'<button class="nm-btn" onclick="nmResetLayout()"><i class="fas fa-redo"></i> Reset</button>'
        f'<button class="nm-btn" onclick="nmToggleLabels()"><i class="fas fa-tags"></i> Labels</button>'
        f'<label class="nm-filter"><input type="checkbox" id="nm-sus-only" onchange="nmFilter()"> '
        f'Suspicious only</label>'
        f'</div>'
        f'<div class="netmap-container" id="netmap-container">'
        f'<svg id="netmap-svg"></svg>'
        f'</div>'
        f'<div class="netmap-tooltip" id="nm-tooltip"></div>'
        f'<div class="netmap-legend">'
        f'<span class="nm-legend-item"><span class="nm-dot nm-dot-local"></span> Local IP</span>'
        f'<span class="nm-legend-item"><span class="nm-dot nm-dot-remote"></span> Remote IP</span>'
        f'<span class="nm-legend-item"><span class="nm-dot nm-dot-proc"></span> Process</span>'
        f'<span class="nm-legend-item"><span class="nm-line nm-line-normal"></span> Connection</span>'
        f'<span class="nm-legend-item"><span class="nm-line nm-line-sus"></span> Suspicious</span>'
        f'</div>'
        f'</div>\n'
    )

    # --- hits section ---
    hits_html = ""
    if HITS_JSON:
        hit_rows = ""
        for h in HITS_JSON:
            cat = h.get("category", "")
            val = _h.escape(str(h.get("value", "")))
            src = _h.escape(str(h.get("source", "")))
            cat_css = "sev-flag" if cat == "flag" else (
                "sev-rootkit" if cat == "yara" else "sev-suspect")
            hit_rows += (
                f'<tr class="{cat_css}">'
                f'<td><span class="badge {cat_css}">{_h.escape(cat)}</span></td>'
                f'<td class="mono">{val}</td><td>{src}</td></tr>\n'
            )
        hits_html = (
            f'<div class="hits-block"><h2>Recorded Hits ({len(HITS_JSON)})</h2>'
            f'<table class="data-table"><thead><tr>'
            f'<th>Category</th><th>Value</th><th>Source</th>'
            f'</tr></thead><tbody>{hit_rows}</tbody></table></div>'
        )

    ts_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    dump_esc = _h.escape(str(DUMP_PATH) if DUMP_PATH else 'n/a')
    os_esc = _h.escape(OS_TYPE or 'n/a')
    flag_esc = _h.escape(FLAG_FORMAT or 'n/a')

    page = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MEMHUNTER // FALCON Report</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

:root {{
  --bg: #05060a; --bg2: #080a10; --surface: #0c0e18;
  --surface2: #12152a; --border: #1e2248;
  --neon-cyan: #00f0ff; --neon-magenta: #ff00e5; --neon-yellow: #f0ff00;
  --neon-green: #00ff88; --neon-red: #ff2244; --neon-orange: #ff8800;
  --neon-blue: #4488ff; --neon-purple: #b44aff;
  --text: #c8cce0; --text-dim: #555880; --text-bright: #f0f2ff;
  --glow-cyan: 0 0 8px rgba(0,240,255,.4), 0 0 30px rgba(0,240,255,.15);
  --glow-magenta: 0 0 8px rgba(255,0,229,.4), 0 0 30px rgba(255,0,229,.15);
  --glow-red: 0 0 8px rgba(255,34,68,.5), 0 0 25px rgba(255,34,68,.2);
  --glow-green: 0 0 8px rgba(0,255,136,.4), 0 0 25px rgba(0,255,136,.15);
  --sidebar-w: 260px;
  --evidence-w: 340px;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
html {{ scrollbar-width: thin; scrollbar-color: var(--neon-cyan) var(--bg); }}
body {{
  font-family: 'Rajdhani', 'Segoe UI', sans-serif;
  background: var(--bg); color: var(--text);
  display: flex; min-height: 100vh; overflow-x: hidden;
}}

/* === ANIMATED BG === */
body::before {{
  content: ''; position: fixed; inset: 0; z-index: -2;
  background:
    radial-gradient(circle at 15% 85%, rgba(0,240,255,.04) 0%, transparent 40%),
    radial-gradient(circle at 85% 15%, rgba(255,0,229,.04) 0%, transparent 40%),
    radial-gradient(circle at 50% 50%, rgba(180,74,255,.03) 0%, transparent 50%);
  animation: bgShift 20s ease-in-out infinite alternate;
}}
@keyframes bgShift {{
  0% {{ filter: hue-rotate(0deg); }}
  100% {{ filter: hue-rotate(30deg); }}
}}
body::after {{
  content: ''; position: fixed; inset: 0; z-index: -1; pointer-events: none;
  background:
    repeating-linear-gradient(0deg, transparent 0, transparent 2px,
      rgba(0,240,255,.015) 2px, rgba(0,240,255,.015) 4px),
    repeating-linear-gradient(90deg, transparent 0, transparent 100px,
      rgba(0,240,255,.008) 100px, rgba(0,240,255,.008) 101px);
  animation: scanDrift 8s linear infinite;
}}
@keyframes scanDrift {{ 0% {{ transform: translateY(0); }} 100% {{ transform: translateY(4px); }} }}

/* === SIDEBAR === */
.sidebar {{
  width: var(--sidebar-w); min-height: 100vh;
  background: linear-gradient(180deg, var(--bg2) 0%, rgba(8,10,16,.98) 100%);
  border-right: 1px solid var(--border);
  position: fixed; top:0; left:0; z-index: 100;
  display: flex; flex-direction: column;
  overflow-y: auto; overflow-x: hidden;
  backdrop-filter: blur(10px);
}}
.sidebar-brand {{
  padding: 1.5em 1em; text-align: center;
  border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, rgba(0,240,255,.05) 0%, transparent 100%);
  position: relative;
}}
.sidebar-brand::after {{
  content: ''; position: absolute; bottom: -1px; left: 10%; right: 10%;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--neon-cyan), transparent);
  box-shadow: var(--glow-cyan);
}}
.sidebar-brand h1 {{
  font-family: 'Orbitron', monospace; font-size: 1.2em;
  font-weight: 900; letter-spacing: .2em;
  background: linear-gradient(90deg, var(--neon-cyan), var(--neon-magenta), var(--neon-cyan));
  background-size: 200% 100%;
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  animation: shimmer 3s linear infinite;
}}
@keyframes shimmer {{ 0% {{ background-position: 100% 0; }} 100% {{ background-position: -100% 0; }} }}
.sidebar-brand .sub {{
  font-family: 'Share Tech Mono', monospace; font-size: .6em;
  color: var(--neon-cyan); letter-spacing: .3em; margin-top: .4em;
  opacity: .6;
}}
.sidebar-brand .author {{
  font-family: 'Share Tech Mono', monospace; font-size: .55em;
  color: var(--neon-magenta); letter-spacing: .15em; margin-top: .2em;
  opacity: .5;
}}
.nav-section {{
  padding: .8em 1em .3em; font-family: 'Orbitron', monospace;
  font-size: .55em; color: var(--neon-cyan); letter-spacing: .25em;
  text-transform: uppercase; opacity: .5;
}}
.nav-item {{
  display: flex; align-items: center; gap: .6em;
  padding: .55em 1.2em; color: var(--text);
  text-decoration: none; font-size: .88em; font-weight: 600;
  border-left: 3px solid transparent;
  transition: all .2s; position: relative; cursor: pointer;
}}
.nav-item:hover {{
  background: rgba(0,240,255,.06);
  border-left-color: var(--neon-cyan); color: var(--neon-cyan);
}}
.nav-item.active {{
  background: linear-gradient(90deg, rgba(0,240,255,.12) 0%, transparent 100%);
  border-left-color: var(--neon-cyan); color: var(--neon-cyan);
  text-shadow: var(--glow-cyan);
}}
.nav-item i {{ width: 18px; text-align: center; font-size: .85em; }}
.alert-dot {{
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--neon-red); box-shadow: var(--glow-red);
  position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
  animation: pulse-dot 1.5s ease-in-out infinite;
}}
@keyframes pulse-dot {{
  0%,100% {{ opacity:1; transform: translateY(-50%) scale(1); }}
  50% {{ opacity:.4; transform: translateY(-50%) scale(.7); }}
}}
.plugin-group {{ display:none; padding-left: .5em; }}
.plugin-group.open {{ display:block; }}
.nav-plugin {{
  display: flex; align-items: center; gap: .5em;
  padding: .35em 1em .35em 2.2em; color: var(--text-dim);
  text-decoration: none; font-size: .76em; font-family: 'Share Tech Mono', monospace;
  border-left: 2px solid transparent;
  cursor: pointer; transition: all .15s;
}}
.nav-plugin:hover {{ color: var(--neon-cyan); border-left-color: var(--neon-cyan); background: rgba(0,240,255,.04); }}
.nav-plugin.active {{ color: var(--neon-cyan); border-left-color: var(--neon-cyan); }}
.badge-sm {{
  font-size: .55em; padding: 1px 5px; border-radius: 3px;
  font-weight: 700; text-transform: uppercase; letter-spacing: .05em;
}}
.badge-sm.sev-flag {{ background: rgba(0,255,136,.12); color: var(--neon-green); }}
.badge-sm.sev-rootkit {{ background: rgba(255,34,68,.12); color: var(--neon-red); }}
.badge-sm.sev-suspect {{ background: rgba(255,136,0,.12); color: var(--neon-orange); }}
.badge-sm.sev-info {{ background: rgba(68,136,255,.1); color: var(--neon-blue); }}

/* === MAIN CONTENT === */
.main {{
  margin-left: var(--sidebar-w); flex: 1;
  padding: 2em; min-height: 100vh;
  transition: margin-right .3s;
}}
.main.evidence-open {{ margin-right: var(--evidence-w); }}
.page {{ display: none; animation: fadeIn .35s ease; }}
.page.active {{ display: block; }}
@keyframes fadeIn {{ from {{ opacity:0; transform:translateY(12px); }} to {{ opacity:1; transform:translateY(0); }} }}

.page-title {{
  font-family: 'Orbitron', monospace; font-size: 1.4em;
  font-weight: 700; margin-bottom: 1em;
  background: linear-gradient(90deg, var(--neon-cyan), var(--neon-purple));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}}
.page-title i {{ margin-right: .4em; }}
.page-title .badge {{ font-size: .55em; vertical-align: middle; }}

/* === DASHBOARD === */
.dash-grid {{
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 1em; margin-bottom: 2em;
}}
.stat-card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 1.3em; text-align: center;
  position: relative; overflow: hidden;
  transition: transform .2s, box-shadow .2s;
}}
.stat-card:hover {{ transform: translateY(-3px); }}
.stat-card::before {{
  content: ''; position: absolute; top:0; left:0; right:0; height: 2px;
}}
.stat-card::after {{
  content: ''; position: absolute; inset: 0;
  border-radius: 10px; opacity: 0; transition: opacity .3s;
}}
.stat-card.sc-flag::before {{ background: var(--neon-green); box-shadow: 0 0 20px var(--neon-green); }}
.stat-card.sc-flag:hover::after {{ opacity:1; box-shadow: inset 0 0 30px rgba(0,255,136,.06); }}
.stat-card.sc-rootkit::before {{ background: var(--neon-red); box-shadow: 0 0 20px var(--neon-red); }}
.stat-card.sc-rootkit:hover::after {{ opacity:1; box-shadow: inset 0 0 30px rgba(255,34,68,.06); }}
.stat-card.sc-suspect::before {{ background: var(--neon-orange); box-shadow: 0 0 20px var(--neon-orange); }}
.stat-card.sc-suspect:hover::after {{ opacity:1; box-shadow: inset 0 0 30px rgba(255,136,0,.06); }}
.stat-card.sc-info::before {{ background: var(--neon-blue); box-shadow: 0 0 20px var(--neon-blue); }}
.stat-card.sc-info:hover::after {{ opacity:1; box-shadow: inset 0 0 30px rgba(68,136,255,.06); }}
.stat-card .num {{
  font-family: 'Orbitron', monospace; font-size: 2.8em; font-weight: 900;
}}
.sc-flag .num {{ color: var(--neon-green); text-shadow: 0 0 25px rgba(0,255,136,.5); }}
.sc-rootkit .num {{ color: var(--neon-red); text-shadow: 0 0 25px rgba(255,34,68,.5); }}
.sc-suspect .num {{ color: var(--neon-orange); text-shadow: 0 0 25px rgba(255,136,0,.5); }}
.sc-info .num {{ color: var(--neon-blue); text-shadow: 0 0 25px rgba(68,136,255,.5); }}
.stat-card .stat-label {{
  font-family: 'Orbitron', monospace; font-size: .6em;
  color: var(--text-dim); text-transform: uppercase; letter-spacing: .18em;
  margin-top: .3em;
}}
.meta-bar {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: .8em; margin-bottom: 2em;
}}
.meta-chip {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: .7em 1em;
  position: relative; overflow: hidden;
}}
.meta-chip::before {{
  content: ''; position: absolute; top:0; left:0; bottom:0; width: 2px;
  background: var(--neon-cyan); opacity: .4;
}}
.meta-chip .mc-label {{
  font-size: .65em; color: var(--text-dim); text-transform: uppercase;
  font-family: 'Orbitron', monospace; letter-spacing: .12em;
}}
.meta-chip .mc-val {{
  font-family: 'Share Tech Mono', monospace; color: var(--neon-cyan);
  font-size: .85em; word-break: break-all;
}}

/* === DATA TABLE === */
.data-table {{
  width: 100%; border-collapse: collapse; margin-top: .5em;
}}
.data-table th {{
  text-align: left; font-family: 'Orbitron', monospace;
  font-size: .6em; color: var(--neon-cyan); letter-spacing: .12em;
  text-transform: uppercase; padding: .7em .5em;
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; background: var(--surface); z-index: 2;
}}
.data-table td {{
  padding: .5em; border-bottom: 1px solid rgba(30,34,72,.5);
  font-size: .85em;
}}
.data-table tbody tr {{ transition: background .1s; }}
.data-table tbody tr:hover {{ background: rgba(0,240,255,.04); }}
tr.sev-flag {{ background: rgba(0,255,136,.04); }}
tr.sev-rootkit {{ background: rgba(255,34,68,.06); }}
tr.sev-suspect {{ background: rgba(255,136,0,.04); }}
.mono {{ font-family: 'Share Tech Mono', monospace; }}

/* === BADGES === */
.badge {{
  display: inline-block; padding: 2px 10px; border-radius: 3px;
  font-family: 'Orbitron', monospace;
  font-size: .6em; font-weight: 700; text-transform: uppercase;
  letter-spacing: .08em;
}}
.badge.sev-flag {{ background: rgba(0,255,136,.12); color: var(--neon-green);
  border: 1px solid rgba(0,255,136,.25); text-shadow: var(--glow-green); }}
.badge.sev-rootkit {{ background: rgba(255,34,68,.12); color: var(--neon-red);
  border: 1px solid rgba(255,34,68,.25); text-shadow: var(--glow-red); }}
.badge.sev-suspect {{ background: rgba(255,136,0,.12); color: var(--neon-orange);
  border: 1px solid rgba(255,136,0,.25); }}
.badge.sev-info {{ background: rgba(68,136,255,.1); color: var(--neon-blue);
  border: 1px solid rgba(68,136,255,.2); }}

/* === CATEGORY GRID === */
.cat-grid {{
  display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1em;
}}
.cat-card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 1.1em; cursor: pointer;
  transition: all .25s; border-left: 3px solid var(--border);
  position: relative; overflow: hidden;
}}
.cat-card::after {{
  content: ''; position: absolute; inset: 0;
  background: linear-gradient(135deg, transparent 60%, rgba(0,240,255,.03) 100%);
  opacity: 0; transition: opacity .3s;
}}
.cat-card:hover {{ transform: translateY(-3px); box-shadow: 0 6px 25px rgba(0,0,0,.5); }}
.cat-card:hover::after {{ opacity: 1; }}
.cat-card.sev-flag {{ border-left-color: var(--neon-green); }}
.cat-card.sev-rootkit {{ border-left-color: var(--neon-red); }}
.cat-card.sev-suspect {{ border-left-color: var(--neon-orange); }}
.cat-card.sev-info {{ border-left-color: var(--neon-blue); }}
.cat-card-head {{ display: flex; align-items: center; gap: .5em; margin-bottom: .3em; position: relative; z-index: 1; }}
.cat-card-name {{
  font-family: 'Share Tech Mono', monospace; font-weight: 600; font-size: .95em;
}}
.cat-card-meta {{ font-size: .75em; color: var(--text-dim); position: relative; z-index: 1; }}

/* === OUTPUT BLOCK (plugin pages) === */
.output-block {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; overflow: hidden;
}}
.code-lines {{
  background: #04050a; padding: .4em 0;
  max-height: 80vh; overflow-y: auto; overflow-x: auto;
  font-family: 'Share Tech Mono', monospace;
  font-size: .78em; line-height: 1.55;
}}
.code-line {{
  display: flex; padding: 1px .8em; cursor: pointer;
  transition: background .1s; border-left: 3px solid transparent;
  min-height: 1.55em;
}}
.code-line:hover {{
  background: rgba(0,240,255,.06);
  border-left-color: var(--neon-cyan);
}}
.code-line.collected {{
  background: rgba(255,0,229,.08);
  border-left-color: var(--neon-magenta);
}}
.code-line.collected .ln-num {{ color: var(--neon-magenta); }}
.ln-num {{
  width: 45px; min-width: 45px; text-align: right;
  color: var(--text-dim); padding-right: .8em;
  user-select: none; opacity: .5; font-size: .9em;
}}
.ln-text {{ white-space: pre-wrap; word-break: break-all; color: #b8bcd0; }}
.collect-hint {{
  font-size: .78em; color: var(--neon-magenta); margin-bottom: .8em;
  font-family: 'Share Tech Mono', monospace; opacity: .7;
}}
.collect-hint i {{ margin-right: .3em; }}
/* Multi-select */
.code-line.selected {{
  background: rgba(0,240,255,.12);
  border-left-color: var(--neon-cyan);
}}
.code-line.selected .ln-num {{ color: var(--neon-cyan); }}
.confirm-bar {{
  display: none; position: sticky; top: 0; z-index: 10;
  background: linear-gradient(90deg, rgba(0,240,255,.15), rgba(180,74,255,.15));
  border-bottom: 1px solid var(--neon-cyan);
  padding: .5em 1em; text-align: center;
  font-family: 'Orbitron', monospace; font-size: .7em;
  color: var(--neon-cyan); backdrop-filter: blur(6px);
}}
.confirm-bar.visible {{ display: flex; align-items: center; justify-content: center; gap: 1em; }}
.confirm-bar .cb-count {{ color: var(--text-bright); }}
.cb-btn {{
  padding: .3em .8em; border-radius: 4px; cursor: pointer;
  font-family: 'Orbitron', monospace; font-size: 1em;
  letter-spacing: .08em; text-transform: uppercase; border: 1px solid;
  transition: all .15s;
}}
.cb-confirm {{ background: rgba(0,255,136,.15); border-color: var(--neon-green);
  color: var(--neon-green); }}
.cb-confirm:hover {{ background: rgba(0,255,136,.3); box-shadow: var(--glow-green); }}
.cb-cancel {{ background: rgba(255,34,68,.1); border-color: var(--neon-red);
  color: var(--neon-red); opacity: .7; }}
.cb-cancel:hover {{ opacity: 1; }}
.plugin-meta {{
  font-size: .78em; color: var(--text-dim); margin-bottom: .5em;
  font-family: 'Share Tech Mono', monospace;
}}
.truncated {{
  background: rgba(255,136,0,.08); color: var(--neon-orange);
  text-align: center; padding: .6em;
  font-family: 'Orbitron', monospace; font-size: .7em;
  letter-spacing: .1em;
}}

/* === PROCESS EXPLORER === */
.proc-search {{
  width: 100%; padding: .6em 1em;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text);
  font-family: 'Share Tech Mono', monospace; font-size: .85em;
  margin-bottom: 1em; outline: none;
  transition: border-color .2s, box-shadow .2s;
}}
.proc-search:focus {{ border-color: var(--neon-cyan); box-shadow: var(--glow-cyan); }}
.proc-search::placeholder {{ color: var(--text-dim); }}
.proc-row-danger {{ background: rgba(255,34,68,.06) !important; }}
.proc-row-danger:hover {{ background: rgba(255,34,68,.1) !important; }}
.cmdline-cell {{
  font-family: 'Share Tech Mono', monospace; font-size: .78em;
  max-width: 350px; overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap;
}}
.proc-title {{ display: flex; align-items: center; gap: .5em; flex-wrap: wrap; }}
.pid-tag {{
  font-family: 'Orbitron', monospace; font-size: .45em;
  background: rgba(0,240,255,.08); color: var(--neon-cyan);
  border: 1px solid rgba(0,240,255,.25); border-radius: 4px;
  padding: 2px 10px;
}}
.proc-info-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr));
  gap: .8em; margin-bottom: 1.5em;
}}
.proc-info-item {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 6px; padding: .6em .8em;
}}
.proc-info-item .lbl {{
  font-size: .6em; color: var(--text-dim); text-transform: uppercase;
  font-family: 'Orbitron', monospace; letter-spacing: .1em; display: block;
}}
.proc-info-item .val {{ font-size: .9em; font-weight: 600; }}
.proc-info-item .val.mono {{ font-family: 'Share Tech Mono', monospace; font-size: .78em; }}
.danger-val {{ color: var(--neon-red) !important; text-shadow: var(--glow-red); }}
.proc-section {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; margin-bottom: 1em; overflow: hidden;
}}
.proc-section h3 {{
  padding: .8em 1em; font-size: .95em;
  border-bottom: 1px solid var(--border);
}}
.proc-section h3 i {{ margin-right: .4em; color: var(--neon-cyan); }}
.proc-section pre {{
  background: #04050a; padding: 1em;
  font-family: 'Share Tech Mono', monospace;
  font-size: .76em; line-height: 1.5;
  overflow-x: auto; white-space: pre-wrap; word-break: break-word;
  max-height: 50vh; overflow-y: auto;
}}
.proc-section pre code {{ background: transparent; color: inherit; }}
.proc-danger {{ border-color: rgba(255,34,68,.25); }}
.proc-danger h3 {{ color: var(--neon-red); }}
.proc-danger h3 i {{ color: var(--neon-red); }}

/* process tree */
.proc-tree {{ padding: .5em 0; }}
.tree-node {{
  position: relative; margin-left: 1.4em;
  border-left: 1px solid var(--border);
}}
.tree-node::before {{
  content: ''; position: absolute; left: 0; top: .85em;
  width: 1em; height: 0; border-top: 1px solid var(--border);
}}
.tree-node:last-child {{ border-left-color: transparent; }}
.tree-node:last-child::before {{
  border-left: 1px solid var(--border);
  height: .85em; top: 0;
}}
.tree-label {{
  display: inline-flex; align-items: center; gap: .4em;
  padding: .25em .6em; margin: .15em 0 .15em 1em;
  background: var(--surface2); border: 1px solid var(--border);
  border-radius: 4px; cursor: pointer;
  transition: border-color .15s, background .15s;
  font-size: .82em;
}}
.tree-label:hover {{
  border-color: var(--neon-cyan); background: rgba(0,255,255,.04);
}}
.tree-pid {{
  font-family: 'Orbitron', monospace; font-size: .7em;
  color: var(--neon-magenta); min-width: 3em;
}}
.tree-name {{
  font-family: 'Share Tech Mono', monospace;
  color: var(--text);
}}
.tree-danger > .tree-label {{
  border-color: rgba(255,34,68,.4); background: rgba(255,34,68,.06);
}}
.tree-danger > .tree-label:hover {{
  border-color: var(--neon-red); background: rgba(255,34,68,.12);
}}
.tree-net > .tree-label {{
  border-color: rgba(0,255,136,.25); background: rgba(0,255,136,.04);
}}
.tree-children {{ margin-left: 0; }}

/* network map */
.netmap-controls {{
  display: flex; gap: .6em; align-items: center;
  margin-bottom: .8em; flex-wrap: wrap;
}}
.nm-btn {{
  background: var(--surface2); border: 1px solid var(--border);
  color: var(--text); font-family: 'Rajdhani', sans-serif;
  font-size: .8em; padding: .3em .8em; border-radius: 4px;
  cursor: pointer; transition: border-color .15s;
}}
.nm-btn:hover {{ border-color: var(--neon-cyan); }}
.nm-btn i {{ margin-right: .3em; }}
.nm-filter {{
  font-family: 'Rajdhani', sans-serif; font-size: .8em;
  color: var(--text-dim); display: flex; align-items: center; gap: .3em;
  cursor: pointer;
}}
.nm-filter input {{ accent-color: var(--neon-magenta); cursor: pointer; }}
.netmap-container {{
  width: 100%; height: 65vh; background: var(--bg);
  border: 1px solid var(--border); border-radius: 6px;
  position: relative; overflow: hidden;
}}
#netmap-svg {{ width: 100%; height: 100%; }}
.netmap-tooltip {{
  display: none; position: fixed; z-index: 9000;
  background: var(--surface); border: 1px solid var(--neon-cyan);
  border-radius: 4px; padding: .5em .8em;
  font-family: 'Share Tech Mono', monospace; font-size: .72em;
  color: var(--text); pointer-events: none;
  box-shadow: 0 0 12px rgba(0,255,255,.15);
  max-width: 300px;
}}
.netmap-tooltip.visible {{ display: block; }}
.netmap-legend {{
  display: flex; gap: 1.2em; padding: .6em 0; flex-wrap: wrap;
  font-family: 'Rajdhani', sans-serif; font-size: .75em; color: var(--text-dim);
}}
.nm-legend-item {{ display: flex; align-items: center; gap: .3em; }}
.nm-dot {{
  width: 10px; height: 10px; border-radius: 50%; display: inline-block;
}}
.nm-dot-local {{ background: #00ff88; }}
.nm-dot-remote {{ background: #ff00e5; }}
.nm-dot-proc {{ background: #00e5ff; }}
.nm-line {{
  width: 20px; height: 2px; display: inline-block;
}}
.nm-line-normal {{ background: rgba(255,255,255,.3); }}
.nm-line-sus {{ background: #ff2244; }}

/* hits block */
.hits-block {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 1.2em; margin-top: 1.5em;
}}
.hits-block h2 {{
  font-family: 'Orbitron', monospace; font-size: .85em;
  color: var(--neon-magenta); margin-bottom: .8em;
  text-shadow: var(--glow-magenta);
}}

/* === EVIDENCE PANEL === */
.evidence-toggle {{
  position: fixed; right: 0; top: 50%; transform: translateY(-50%);
  z-index: 200; background: var(--surface2);
  border: 1px solid var(--neon-magenta); border-right: none;
  border-radius: 8px 0 0 8px; padding: .6em .5em;
  color: var(--neon-magenta); cursor: pointer;
  font-size: 1.1em; transition: right .3s ease, background .2s;
  box-shadow: var(--glow-magenta);
}}
.evidence-toggle.shifted {{ right: var(--evidence-w); }}
.evidence-toggle:hover {{ background: rgba(255,0,229,.15); }}
.evidence-toggle .ev-count {{
  position: absolute; top: -6px; left: -6px;
  background: var(--neon-magenta); color: #000;
  font-family: 'Orbitron', monospace; font-size: .5em;
  font-weight: 900; width: 18px; height: 18px;
  border-radius: 50%; display: flex; align-items: center;
  justify-content: center; box-shadow: var(--glow-magenta);
}}
.evidence-panel {{
  position: fixed; top: 0; right: 0; width: var(--evidence-w);
  height: 100vh; background: var(--bg2);
  border-left: 1px solid var(--neon-magenta);
  z-index: 150; transform: translateX(100%);
  transition: transform .3s ease;
  display: flex; flex-direction: column;
  box-shadow: -5px 0 30px rgba(255,0,229,.1);
}}
.evidence-panel.open {{ transform: translateX(0); }}
.ev-header {{
  padding: 1em; border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, rgba(255,0,229,.06) 0%, transparent 100%);
}}
.ev-header h2 {{
  font-family: 'Orbitron', monospace; font-size: .85em;
  color: var(--neon-magenta); letter-spacing: .15em;
  text-shadow: var(--glow-magenta);
}}
.ev-header .ev-sub {{
  font-family: 'Share Tech Mono', monospace; font-size: .6em;
  color: var(--text-dim); margin-top: .2em;
}}
.ev-actions {{
  display: flex; gap: .4em; padding: .6em .8em;
  border-bottom: 1px solid var(--border); flex-wrap: wrap;
}}
.ev-btn {{
  flex: 1; padding: .45em .3em; border: 1px solid var(--border);
  border-radius: 5px; background: var(--surface);
  color: var(--text); font-family: 'Orbitron', monospace;
  font-size: .55em; letter-spacing: .06em;
  cursor: pointer; transition: all .2s; text-align: center;
  text-transform: uppercase; min-width: 0;
}}
.ev-btn:hover {{ border-color: var(--neon-cyan); color: var(--neon-cyan); }}
.ev-btn.ev-new {{
  border-color: var(--neon-green); color: var(--neon-green);
}}
.ev-btn.ev-new:hover {{ background: rgba(0,255,136,.1); box-shadow: var(--glow-green); }}
.ev-btn.ev-pdf {{
  background: linear-gradient(135deg, rgba(255,0,229,.12), rgba(0,240,255,.12));
  border-color: var(--neon-magenta); color: var(--neon-magenta);
}}
.ev-btn.ev-pdf:hover {{
  background: linear-gradient(135deg, rgba(255,0,229,.22), rgba(0,240,255,.22));
  box-shadow: var(--glow-magenta);
}}
.ev-btn.ev-clear {{ border-color: var(--neon-red); color: var(--neon-red); opacity: .5; }}
.ev-btn.ev-clear:hover {{ opacity: 1; }}
.ev-list {{
  flex: 1; overflow-y: auto; padding: .5em;
}}
/* IOC folder */
.ioc-folder {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 6px; margin-bottom: .6em; overflow: hidden;
  animation: evSlideIn .3s ease;
}}
@keyframes evSlideIn {{ from {{ opacity:0; transform:translateX(20px); }} to {{ opacity:1; transform:translateX(0); }} }}
.ioc-folder.active {{ border-color: var(--neon-green); box-shadow: 0 0 8px rgba(0,255,136,.15); }}
.ioc-folder-head {{
  display: flex; align-items: center; gap: .4em;
  padding: .5em .7em; cursor: pointer;
  background: rgba(0,0,0,.2); border-bottom: 1px solid var(--border);
  transition: background .15s;
}}
.ioc-folder-head:hover {{ background: rgba(0,240,255,.04); }}
.ioc-folder.active .ioc-folder-head {{ background: rgba(0,255,136,.06); }}
.ioc-folder-icon {{
  color: var(--neon-magenta); font-size: .8em; width: 16px; text-align: center;
  transition: transform .2s;
}}
.ioc-folder.expanded .ioc-folder-icon {{ transform: rotate(90deg); }}
.ioc-folder.active .ioc-folder-icon {{ color: var(--neon-green); }}
.ioc-folder-title {{
  flex: 1; font-family: 'Share Tech Mono', monospace; font-size: .75em;
  color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}}
.ioc-folder-plugins {{
  display: flex; gap: .2em; flex-wrap: wrap;
}}
.ioc-plugin-tag {{
  font-family: 'Orbitron', monospace; font-size: .45em;
  padding: 1px 4px; border-radius: 2px;
  background: rgba(0,240,255,.1); color: var(--neon-cyan);
  border: 1px solid rgba(0,240,255,.2); text-transform: uppercase;
}}
.ioc-folder-count {{
  font-family: 'Orbitron', monospace; font-size: .5em;
  color: var(--text-dim); min-width: 20px; text-align: right;
}}
.ioc-folder-actions {{
  display: flex; gap: .3em; align-items: center;
}}
.ioc-folder-btn {{
  background: none; border: none; color: var(--text-dim);
  cursor: pointer; font-size: .7em; padding: 2px; transition: color .15s;
}}
.ioc-folder-btn:hover {{ color: var(--neon-red); }}
.ioc-folder-btn.ioc-activate {{  }}
.ioc-folder-btn.ioc-activate:hover {{ color: var(--neon-green); }}
.ioc-folder-body {{
  display: none; padding: .3em .5em .5em;
}}
.ioc-folder.expanded .ioc-folder-body {{ display: block; }}
.ioc-folder-note {{
  margin-bottom: .4em;
}}
.ioc-folder-note input {{
  width: 100%; background: rgba(0,240,255,.04);
  border: 1px solid var(--border); border-radius: 3px;
  color: var(--neon-yellow); font-family: 'Share Tech Mono', monospace;
  font-size: .68em; padding: .3em .5em; outline: none;
}}
.ioc-folder-note input:focus {{ border-color: var(--neon-yellow); }}
.ioc-folder-note input::placeholder {{ color: var(--text-dim); }}
.ioc-result {{
  border-left: 2px solid var(--neon-magenta); margin-bottom: .4em;
  background: rgba(0,0,0,.15); border-radius: 0 4px 4px 0;
  overflow: hidden; position: relative;
}}
.ioc-result-head {{
  display: flex; align-items: center; justify-content: space-between;
  padding: .2em .4em; background: rgba(255,0,229,.06);
}}
.ioc-result-plugin {{
  font-family: 'Orbitron', monospace; font-size: .45em;
  color: var(--neon-cyan); text-transform: uppercase; letter-spacing: .05em;
}}
.ioc-result-goto {{
  color: var(--neon-cyan); cursor: pointer; font-size: .55em;
  padding: 2px 4px; transition: color .1s; margin-right: auto; margin-left: .3em;
}}
.ioc-result-goto:hover {{ color: var(--neon-green); }}
.ioc-result-rm {{
  color: var(--text-dim); cursor: pointer; font-size: .6em;
  padding: 2px; transition: color .1s;
}}
.ioc-result-rm:hover {{ color: var(--neon-red); }}
.ioc-result-text {{
  font-family: 'Share Tech Mono', monospace; font-size: .68em;
  color: var(--text); word-break: break-all; line-height: 1.4;
  padding: .3em .5em; white-space: pre-wrap; cursor: pointer;
  transition: background .15s;
}}
.ioc-result-text:hover {{
  background: rgba(0,255,136,.06);
}}
.ioc-result.dragging {{
  opacity: .4; border-left-color: var(--neon-cyan);
}}
.ioc-folder.drag-over {{
  outline: 2px dashed var(--neon-green);
  outline-offset: -2px;
  background: rgba(0,255,136,.04);
}}
.ioc-result[draggable="true"] {{
  cursor: grab;
}}
.ioc-result[draggable="true"]:active {{
  cursor: grabbing;
}}
.ev-empty {{
  text-align: center; padding: 2.5em 1em;
  color: var(--text-dim); font-family: 'Share Tech Mono', monospace;
  font-size: .75em;
}}
.ev-empty i {{ display: block; font-size: 2em; margin-bottom: .5em; color: var(--border); }}
/* Active IOC indicator on code lines */
.code-line.collected {{
  background: rgba(255,0,229,.08);
  border-left-color: var(--neon-magenta);
}}
.code-line.collected .ln-num {{ color: var(--neon-magenta); }}
@keyframes gotoFlash {{
  0%,100% {{ background: rgba(0,255,136,.05); }}
  50% {{ background: rgba(0,255,136,.35); }}
}}
.code-line.goto-highlight {{
  animation: gotoFlash .6s ease 3;
  border-left-color: var(--neon-green) !important;
}}
.active-ioc-banner {{
  padding: .4em .8em; background: rgba(0,255,136,.08);
  border-bottom: 1px solid rgba(0,255,136,.2);
  font-family: 'Orbitron', monospace; font-size: .55em;
  color: var(--neon-green); letter-spacing: .08em; text-align: center;
}}
.active-ioc-banner strong {{ color: var(--neon-green); }}

/* Footer */
.footer {{
  text-align: center; color: var(--text-dim); font-size: .72em;
  padding: 3em 0 1em;
  font-family: 'Share Tech Mono', monospace;
  border-top: 1px solid var(--border); margin-top: 3em;
}}
.footer strong {{ color: var(--neon-cyan); }}
.footer .falcon {{ color: var(--neon-magenta); }}

/* Responsive */
@media (max-width: 900px) {{
  .sidebar {{ width: 55px; }} .sidebar span, .nav-section, .plugin-group, .author {{ display:none!important; }}
  .main {{ margin-left: 55px; }}
  .sidebar-brand h1 {{ font-size: .65em; letter-spacing: .05em; }}
  .sidebar-brand .sub {{ display:none; }}
  .dash-grid {{ grid-template-columns: repeat(2,1fr); }}
  .evidence-panel {{ width: 280px; }}
}}
</style>
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar">
  <div class="sidebar-brand">
    <h1>MEMHUNTER</h1>
    <div class="sub">Memory Forensics</div>
    <div class="author">by FALCON</div>
  </div>
  <div class="nav-section">Navigation</div>
  {sidebar_items}
  <div class="nav-section">Plugins</div>
  {sidebar_plugins}
</nav>

<!-- EVIDENCE TOGGLE -->
<div class="evidence-toggle" id="ev-toggle-btn" onclick="toggleEvidence()" title="Evidence Board">
  <i class="fas fa-crosshairs"></i>
  <div class="ev-count" id="ev-count">0</div>
</div>

<!-- EVIDENCE PANEL -->
<div class="evidence-panel" id="evidence-panel">
  <div class="ev-header">
    <h2><i class="fas fa-crosshairs"></i> Evidence Board</h2>
    <div class="ev-sub">Group indicators into IOC folders</div>
  </div>
  <div class="ev-actions">
    <button class="ev-btn ev-new" onclick="createIOC()">
      <i class="fas fa-folder-plus"></i> New IOC
    </button>
    <button class="ev-btn ev-pdf" onclick="exportPDF()">
      <i class="fas fa-file-pdf"></i> Export PDF
    </button>
    <button class="ev-btn ev-clear" onclick="clearAllIOCs()">
      <i class="fas fa-trash"></i> Clear
    </button>
  </div>
  <div class="ev-list" id="ev-list">
    <div class="ev-empty" id="ev-empty">
      <i class="fas fa-folder-plus"></i>
      Create an IOC folder, then click lines in plugin outputs to add them
    </div>
  </div>
</div>

<!-- MAIN -->
<div class="main" id="main-content">

  <!-- Dashboard -->
  <div class="page active" id="page-dashboard">
    <h1 class="page-title"><i class="fas fa-tachometer-alt"></i> Dashboard</h1>
    <div class="meta-bar">
      <div class="meta-chip">
        <div class="mc-label">Memory Dump</div>
        <div class="mc-val">{dump_esc}</div>
      </div>
      <div class="meta-chip">
        <div class="mc-label">OS</div>
        <div class="mc-val">{os_esc}</div>
      </div>
      <div class="meta-chip">
        <div class="mc-label">Flag Format</div>
        <div class="mc-val">{flag_esc}</div>
      </div>
      <div class="meta-chip">
        <div class="mc-label">Generated</div>
        <div class="mc-val">{ts_now}</div>
      </div>
    </div>
    <div class="dash-grid">
      <div class="stat-card sc-flag">
        <div class="num">{sev_counts['CRITICAL']}</div>
        <div class="stat-label">Flags</div>
      </div>
      <div class="stat-card sc-rootkit">
        <div class="num">{sev_counts['HIGH']}</div>
        <div class="stat-label">Rootkit</div>
      </div>
      <div class="stat-card sc-suspect">
        <div class="num">{sev_counts['MEDIUM']}</div>
        <div class="stat-label">Suspicious</div>
      </div>
      <div class="stat-card sc-info">
        <div class="num">{sev_counts['LOW']}</div>
        <div class="stat-label">Info</div>
      </div>
    </div>
    {hits_html}
  </div>

  <!-- Process Explorer -->
  <div class="page" id="page-processes">
    <h1 class="page-title"><i class="fas fa-microchip"></i> Process Explorer</h1>
    <input class="proc-search" type="text" placeholder="Search processes by name or PID..."
           oninput="filterProcs(this.value)">
    <div style="overflow-x:auto">
    <table class="data-table" id="proc-table">
      <thead><tr><th>PID</th><th>Name</th><th>PPID</th><th>Command Line</th><th>Indicators</th></tr></thead>
      <tbody>{proc_rows}</tbody>
    </table>
    </div>
  </div>

  {proc_detail_pages}
  {proc_tree_page}
  {netmap_page}
  {cat_pages}
  {plugin_pages}

  <div class="footer">
    <strong>MEMHUNTER</strong> // by <span class="falcon">FALCON</span> //
    Report generated {ts_now}
  </div>
</div>

<script>
// ========== Navigation ==========
function showPage(id) {{
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item, .nav-plugin').forEach(n => n.classList.remove('active'));
  const pg = document.getElementById('page-' + id);
  if (pg) pg.classList.add('active');
  const nav = document.querySelector('[data-page="' + id + '"]');
  if (nav) nav.classList.add('active');
  if (id.startsWith('cat-')) {{
    const cat = id.replace('cat-', '');
    document.querySelectorAll('.plugin-group').forEach(g => {{
      g.classList.toggle('open', g.dataset.cat === cat);
    }});
  }}
  window.scrollTo(0, 0);
}}

function filterProcs(q) {{
  const rows = document.querySelectorAll('#proc-table tbody tr');
  const ql = q.toLowerCase();
  rows.forEach(r => {{
    r.style.display = r.textContent.toLowerCase().includes(ql) ? '' : 'none';
  }});
}}

document.querySelectorAll('.nav-item').forEach(item => {{
  item.addEventListener('click', () => {{
    const page = item.dataset.page;
    if (page && page.startsWith('cat-')) {{
      const cat = page.replace('cat-', '');
      document.querySelectorAll('.plugin-group').forEach(g => {{
        if (g.dataset.cat === cat) g.classList.toggle('open');
        else g.classList.remove('open');
      }});
    }}
  }});
}});

// ========== Evidence Board (IOC Folders + Multi-select) ==========
// Data model: iocFolders[].results[] = {{ plugin, text, keys:['src:ln',...] }}
// "plugin" is shown only for single-line results. Multi-line = merged text, no plugin label.
let iocFolders = [];
let nextIocId = 1;
let lastClickedLine = null;
const evList = document.getElementById('ev-list');
const evCount = document.getElementById('ev-count');
const evPanel = document.getElementById('evidence-panel');
const evToggle = document.getElementById('ev-toggle-btn');
const mainEl = document.getElementById('main-content');

function toggleEvidence() {{
  evPanel.classList.toggle('open');
  mainEl.classList.toggle('evidence-open');
  document.getElementById('ev-toggle-btn').classList.toggle('shifted');
}}

function escHtml(s) {{
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}}
function escAttr(s) {{
  return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}

// --- Selection ---
function getSelectedLines(src) {{
  return [...document.querySelectorAll('.code-line.selected[data-src="' + src + '"]')];
}}

function updateConfirmBar(src) {{
  const bar = document.getElementById('cb-' + src.toLowerCase());
  if (!bar) return;
  const sel = getSelectedLines(src);
  if (sel.length > 0) {{
    bar.classList.add('visible');
    bar.querySelector('.cb-count').textContent = sel.length;
  }} else {{
    bar.classList.remove('visible');
  }}
}}

function selectLine(ev, el) {{
  const src = el.dataset.src || '?';
  const ln = parseInt(el.dataset.ln) || 0;

  if (ev.shiftKey && lastClickedLine && lastClickedLine.src === src) {{
    const fromLn = lastClickedLine.ln;
    const minLn = Math.min(fromLn, ln);
    const maxLn = Math.max(fromLn, ln);
    document.querySelectorAll('.code-line[data-src="' + src + '"]').forEach(line => {{
      const n = parseInt(line.dataset.ln) || 0;
      if (n >= minLn && n <= maxLn) line.classList.add('selected');
    }});
  }} else {{
    el.classList.toggle('selected');
  }}

  lastClickedLine = {{ src, ln }};
  updateConfirmBar(src);
}}

function confirmSelection(src) {{
  const sel = getSelectedLines(src);
  if (sel.length === 0) return;

  let activeIOC = iocFolders.find(f => f.active);
  if (!activeIOC) {{
    createIOC();
    activeIOC = iocFolders.find(f => f.active);
  }}

  // Merge all selected lines into one result
  const texts = [];
  const keys = [];
  sel.forEach(el => {{
    const text = el.querySelector('.ln-text').textContent;
    const ln = el.dataset.ln || '0';
    const key = src + ':' + ln;
    if (text.trim()) {{
      texts.push(text);
      keys.push(key);
    }}
    el.classList.add('collected');
    el.classList.remove('selected');
  }});

  if (texts.length > 0) {{
    activeIOC.results.push({{
      plugin: src,
      text: texts.join('\\n'),
      keys: keys
    }});
  }}

  activeIOC.expanded = true;
  updateConfirmBar(src);
  renderEvidence();
  if (!evPanel.classList.contains('open')) toggleEvidence();
}}

function cancelSelection(src) {{
  getSelectedLines(src).forEach(el => el.classList.remove('selected'));
  updateConfirmBar(src);
}}

// --- IOC Folder management ---
function createIOC() {{
  iocFolders.forEach(f => f.active = false);
  const ioc = {{ id: nextIocId++, note: '', results: [], expanded: true, active: true }};
  iocFolders.push(ioc);
  renderEvidence();
  if (!evPanel.classList.contains('open')) toggleEvidence();
}}

function activateIOC(id) {{
  iocFolders.forEach(f => f.active = (f.id === id));
  renderEvidence();
}}

function toggleIOCExpand(id) {{
  const f = iocFolders.find(f => f.id === id);
  if (f) f.expanded = !f.expanded;
  renderEvidence();
}}

function deleteIOC(id) {{
  const f = iocFolders.find(f => f.id === id);
  if (f) {{
    f.results.forEach(r => {{
      r.keys.forEach(k => {{
        const parts = k.split(':');
        const el = document.querySelector(
          '.code-line[data-src="' + parts[0] + '"][data-ln="' + parts[1] + '"]');
        if (el) el.classList.remove('collected');
      }});
    }});
  }}
  iocFolders = iocFolders.filter(ff => ff.id !== id);
  renderEvidence();
}}

function removeResult(iocId, rIdx) {{
  const f = iocFolders.find(ff => ff.id === iocId);
  if (!f) return;
  const r = f.results[rIdx];
  if (r) {{
    r.keys.forEach(k => {{
      const parts = k.split(':');
      const el = document.querySelector(
        '.code-line[data-src="' + parts[0] + '"][data-ln="' + parts[1] + '"]');
      if (el) el.classList.remove('collected');
    }});
  }}
  f.results.splice(rIdx, 1);
  renderEvidence();
}}

function updateIOCNote(id, val) {{
  const f = iocFolders.find(ff => ff.id === id);
  if (f) f.note = val;
}}

function gotoResult(iocId, rIdx) {{
  const f = iocFolders.find(ff => ff.id === iocId);
  if (!f || !f.results[rIdx]) return;
  const r = f.results[rIdx];
  if (r.keys.length === 0) return;
  const firstKey = r.keys[0];
  const src = firstKey.split(':')[0];
  showPage('plugin-' + src.toLowerCase());
  setTimeout(() => {{
    document.querySelectorAll('.code-line.goto-highlight').forEach(
      el => el.classList.remove('goto-highlight'));
    r.keys.forEach(k => {{
      const parts = k.split(':');
      const el = document.querySelector(
        '.code-line[data-src="' + parts[0] + '"][data-ln="' + parts[1] + '"]');
      if (el) el.classList.add('goto-highlight');
    }});
    const firstParts = firstKey.split(':');
    const firstEl = document.querySelector(
      '.code-line[data-src="' + firstParts[0] + '"][data-ln="' + firstParts[1] + '"]');
    if (firstEl) firstEl.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
    setTimeout(() => {{
      document.querySelectorAll('.code-line.goto-highlight').forEach(
        el => el.classList.remove('goto-highlight'));
    }}, 3000);
  }}, 100);
}}

function clearAllIOCs() {{
  document.querySelectorAll('.code-line.collected,.code-line.selected').forEach(
    el => {{ el.classList.remove('collected'); el.classList.remove('selected'); }});
  iocFolders = [];
  renderEvidence();
  document.querySelectorAll('.confirm-bar').forEach(b => b.classList.remove('visible'));
}}

// ========== Drag & Drop ==========
let dragData = null;

function onDragStart(e, iocId, rIdx) {{
  dragData = {{ fromIoc: iocId, rIdx: rIdx }};
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', '');
  e.target.closest('.ioc-result').classList.add('dragging');
}}

function onDragOver(e) {{
  if (!dragData) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  const folder = e.target.closest('.ioc-folder');
  if (folder) folder.classList.add('drag-over');
}}

function onDragLeave(e) {{
  const folder = e.target.closest('.ioc-folder');
  if (folder && !folder.contains(e.relatedTarget)) {{
    folder.classList.remove('drag-over');
  }}
}}

function onDrop(e, targetIocId) {{
  e.preventDefault();
  document.querySelectorAll('.ioc-folder.drag-over').forEach(
    el => el.classList.remove('drag-over'));
  if (!dragData || dragData.fromIoc === targetIocId) {{
    dragData = null;
    return;
  }}
  const src = iocFolders.find(f => f.id === dragData.fromIoc);
  const dst = iocFolders.find(f => f.id === targetIocId);
  if (!src || !dst || !src.results[dragData.rIdx]) {{
    dragData = null;
    return;
  }}
  const result = src.results.splice(dragData.rIdx, 1)[0];
  dst.results.push(result);
  dst.expanded = true;
  dragData = null;
  renderEvidence();
}}

document.addEventListener('dragend', () => {{
  dragData = null;
  document.querySelectorAll('.ioc-result.dragging').forEach(
    el => el.classList.remove('dragging'));
  document.querySelectorAll('.ioc-folder.drag-over').forEach(
    el => el.classList.remove('drag-over'));
}});

function getIOCPlugins(ioc) {{
  const all = [];
  ioc.results.forEach(r => {{
    if (r.plugin) all.push(r.plugin);
    else r.keys.forEach(k => all.push(k.split(':')[0]));
  }});
  return [...new Set(all)];
}}

function getTotalResults() {{
  return iocFolders.reduce((s, f) => s + f.results.length, 0);
}}

function renderEvidence() {{
  evCount.textContent = getTotalResults();
  if (iocFolders.length === 0) {{
    evList.innerHTML = '<div class="ev-empty">' +
      '<i class="fas fa-folder-plus"></i>' +
      'Create an IOC folder, then select lines<br>and press Confirm to add them</div>';
    return;
  }}
  let html = '';
  const activeIOC = iocFolders.find(f => f.active);
  if (activeIOC) {{
    html += '<div class="active-ioc-banner">' +
      '<i class="fas fa-bullseye"></i> Collecting into: <strong>IOC-' +
      activeIOC.id + '</strong> (' + activeIOC.results.length + ' result' +
      (activeIOC.results.length !== 1 ? 's' : '') + ')</div>';
  }}
  iocFolders.forEach(f => {{
    const plugins = getIOCPlugins(f);
    const pluginTags = plugins.map(p =>
      '<span class="ioc-plugin-tag">' + escHtml(p) + '</span>'
    ).join('');
    const expandedCls = f.expanded ? ' expanded' : '';
    const activeCls = f.active ? ' active' : '';

    html += '<div class="ioc-folder' + expandedCls + activeCls + '" ' +
      'data-ioc-id="' + f.id + '" ' +
      'ondragover="onDragOver(event)" ondragleave="onDragLeave(event)" ' +
      'ondrop="onDrop(event,' + f.id + ')">';

    html += '<div class="ioc-folder-head" onclick="toggleIOCExpand(' + f.id + ')">' +
      '<span class="ioc-folder-icon"><i class="fas fa-chevron-right"></i></span>' +
      '<span class="ioc-folder-title">IOC-' + f.id + '</span>' +
      '<div class="ioc-folder-plugins">' + pluginTags + '</div>' +
      '<span class="ioc-folder-count">' + f.results.length + '</span>' +
      '<div class="ioc-folder-actions">' +
      '<span class="ioc-folder-btn ioc-activate" onclick="event.stopPropagation();activateIOC(' + f.id + ')" title="Set as active target">' +
      '<i class="fas fa-bullseye"></i></span>' +
      '<span class="ioc-folder-btn" onclick="event.stopPropagation();deleteIOC(' + f.id + ')" title="Delete IOC">' +
      '<i class="fas fa-trash-alt"></i></span>' +
      '</div></div>';

    html += '<div class="ioc-folder-body">' +
      '<div class="ioc-folder-note">' +
      '<input type="text" placeholder="Analyst note for this IOC..." ' +
      'value="' + escAttr(f.note) + '" ' +
      'oninput="updateIOCNote(' + f.id + ', this.value)" ' +
      'onclick="event.stopPropagation()">' +
      '</div>';

    f.results.forEach((r, ri) => {{
      const pluginLabel = r.plugin
        ? '<span class="ioc-result-plugin">' + escHtml(r.plugin) + '</span>'
        : '';
      html += '<div class="ioc-result" draggable="true" ' +
        'ondragstart="onDragStart(event,' + f.id + ',' + ri + ')">' +
        '<div class="ioc-result-head">' + pluginLabel +
        '<span class="ioc-result-goto" onclick="event.stopPropagation();gotoResult(' + f.id + ',' + ri + ')" title="Go to source">' +
        '<i class="fas fa-external-link-alt"></i></span>' +
        '<span class="ioc-result-rm" onclick="removeResult(' + f.id + ',' + ri + ')" title="Remove">' +
        '<i class="fas fa-times"></i></span></div>' +
        '<div class="ioc-result-text" onclick="gotoResult(' + f.id + ',' + ri + ')" ' +
        'title="Click to go to source">' + escHtml(r.text) + '</div>' +
        '</div>';
    }});

    if (f.results.length === 0) {{
      html += '<div style="padding:.5em;color:var(--text-dim);font-size:.7em;text-align:center;">' +
        'Select lines in plugin outputs, then press Confirm</div>';
    }}

    html += '</div></div>';
  }});
  evList.innerHTML = html;
}}

// ========== Network Map ==========
(function() {{
  const NET_DATA = {net_json};
  const svg = document.getElementById('netmap-svg');
  const container = document.getElementById('netmap-container');
  const tooltip = document.getElementById('nm-tooltip');
  if (!svg || !container || NET_DATA.length === 0) return;

  let showLabels = true;
  let susOnly = false;

  const nodeMap = {{}};
  const edges = [];

  function addNode(id, type, label) {{
    if (!nodeMap[id]) {{
      nodeMap[id] = {{ id, type, label, x: 0, y: 0, vx: 0, vy: 0, conns: 0 }};
    }}
    nodeMap[id].conns++;
    return nodeMap[id];
  }}

  NET_DATA.forEach(c => {{
    const localId = 'ip:' + c.localAddr;
    const procId = 'proc:' + c.pid + ':' + c.owner;

    addNode(localId, 'local', c.localAddr);
    addNode(procId, 'proc', c.owner + ' (' + c.pid + ')');

    edges.push({{
      from: procId, to: localId,
      label: c.proto + ' :' + c.localPort,
      suspicious: c.suspicious, state: c.state, conn: c,
      type: 'proc-local'
    }});

    if (c.foreignAddr && c.foreignAddr !== '0.0.0.0' &&
        c.foreignAddr !== '::' && c.foreignAddr !== '*') {{
      const foreignId = 'ip:' + c.foreignAddr;
      addNode(foreignId, 'remote', c.foreignAddr);
      edges.push({{
        from: localId, to: foreignId,
        label: ':' + c.foreignPort + ' ' + c.state,
        suspicious: c.suspicious, state: c.state, conn: c,
        type: 'net'
      }});
    }}
  }});

  const nodes = Object.values(nodeMap);
  const W = () => container.clientWidth || 800;
  const H = () => container.clientHeight || 500;

  nodes.forEach((n, i) => {{
    const angle = (2 * Math.PI * i) / nodes.length;
    const r = Math.min(W(), H()) * 0.35;
    n.x = W() / 2 + r * Math.cos(angle);
    n.y = H() / 2 + r * Math.sin(angle);
  }});

  const ns = 'http://www.w3.org/2000/svg';

  function typeColor(type) {{
    if (type === 'local') return '#00ff88';
    if (type === 'remote') return '#ff00e5';
    return '#00e5ff';
  }}

  function typeRadius(n) {{
    const base = n.type === 'proc' ? 8 : 10;
    return base + Math.min(n.conns * 1.5, 8);
  }}

  let edgeEls = [];
  let edgeLabelEls = [];
  let nodeEls = [];
  let nodeLabelEls = [];
  let dragNode = null;

  function render() {{
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    edgeEls = []; edgeLabelEls = []; nodeEls = []; nodeLabelEls = [];

    const visibleEdges = susOnly ? edges.filter(e => e.suspicious) : edges;
    const visNodeIds = new Set();
    visibleEdges.forEach(e => {{ visNodeIds.add(e.from); visNodeIds.add(e.to); }});
    const visNodes = susOnly ? nodes.filter(n => visNodeIds.has(n.id)) : nodes;

    const defs = document.createElementNS(ns, 'defs');
    const marker = document.createElementNS(ns, 'marker');
    marker.setAttribute('id', 'arrow');
    marker.setAttribute('viewBox', '0 0 10 6');
    marker.setAttribute('refX', '10'); marker.setAttribute('refY', '3');
    marker.setAttribute('markerWidth', '8'); marker.setAttribute('markerHeight', '6');
    marker.setAttribute('orient', 'auto');
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('d', 'M0,0 L10,3 L0,6 Z');
    path.setAttribute('fill', 'rgba(255,255,255,.3)');
    marker.appendChild(path);
    defs.appendChild(marker);
    svg.appendChild(defs);

    visibleEdges.forEach((e, i) => {{
      const line = document.createElementNS(ns, 'line');
      line.setAttribute('stroke', e.suspicious ? '#ff2244' : 'rgba(255,255,255,.2)');
      line.setAttribute('stroke-width', e.suspicious ? '2' : '1');
      line.setAttribute('marker-end', 'url(#arrow)');
      line.dataset.idx = i;
      line.addEventListener('mouseenter', ev => showEdgeTip(ev, e));
      line.addEventListener('mouseleave', hideTip);
      svg.appendChild(line);
      edgeEls.push({{ el: line, edge: e }});

      const lbl = document.createElementNS(ns, 'text');
      lbl.textContent = e.label;
      lbl.setAttribute('fill', e.suspicious ? '#ff4466' : 'rgba(255,255,255,.35)');
      lbl.setAttribute('font-size', '9');
      lbl.setAttribute('font-family', 'Share Tech Mono, monospace');
      lbl.setAttribute('text-anchor', 'middle');
      lbl.setAttribute('display', showLabels ? '' : 'none');
      svg.appendChild(lbl);
      edgeLabelEls.push({{ el: lbl, edge: e }});
    }});

    visNodes.forEach(n => {{
      const r = typeRadius(n);
      const g = document.createElementNS(ns, 'g');
      g.style.cursor = 'grab';

      const glow = document.createElementNS(ns, 'circle');
      glow.setAttribute('r', r + 4);
      glow.setAttribute('fill', 'none');
      glow.setAttribute('stroke', typeColor(n.type));
      glow.setAttribute('stroke-opacity', '0.15');
      glow.setAttribute('stroke-width', '4');
      g.appendChild(glow);

      const circle = document.createElementNS(ns, 'circle');
      circle.setAttribute('r', r);
      circle.setAttribute('fill', typeColor(n.type));
      circle.setAttribute('fill-opacity', '0.2');
      circle.setAttribute('stroke', typeColor(n.type));
      circle.setAttribute('stroke-width', '1.5');
      g.appendChild(circle);

      const lbl = document.createElementNS(ns, 'text');
      lbl.textContent = n.label;
      lbl.setAttribute('fill', '#fff');
      lbl.setAttribute('font-size', '10');
      lbl.setAttribute('font-family', 'Share Tech Mono, monospace');
      lbl.setAttribute('text-anchor', 'middle');
      lbl.setAttribute('dy', r + 14);
      lbl.setAttribute('display', showLabels ? '' : 'none');
      g.appendChild(lbl);
      nodeLabelEls.push(lbl);

      g.addEventListener('mouseenter', ev => showNodeTip(ev, n));
      g.addEventListener('mouseleave', hideTip);
      g.addEventListener('mousedown', ev => startDrag(ev, n));

      if (n.type === 'proc') {{
        g.addEventListener('dblclick', () => {{
          const pid = n.id.split(':')[1];
          showPage('proc-' + pid);
        }});
        g.style.cursor = 'pointer';
      }}

      svg.appendChild(g);
      nodeEls.push({{ el: g, node: n, circle, glow }});
    }});

    updatePositions();
  }}

  function updatePositions() {{
    edgeEls.forEach(({{ el, edge }}) => {{
      const from = nodeMap[edge.from];
      const to = nodeMap[edge.to];
      if (!from || !to) return;
      const r = typeRadius(to);
      const dx = to.x - from.x; const dy = to.y - from.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      el.setAttribute('x1', from.x); el.setAttribute('y1', from.y);
      el.setAttribute('x2', to.x - (dx / dist) * r);
      el.setAttribute('y2', to.y - (dy / dist) * r);
    }});
    edgeLabelEls.forEach(({{ el, edge }}) => {{
      const from = nodeMap[edge.from];
      const to = nodeMap[edge.to];
      if (!from || !to) return;
      el.setAttribute('x', (from.x + to.x) / 2);
      el.setAttribute('y', (from.y + to.y) / 2 - 4);
    }});
    nodeEls.forEach(({{ el, node }}) => {{
      el.setAttribute('transform', 'translate(' + node.x + ',' + node.y + ')');
    }});
  }}

  // Force simulation
  function simulate() {{
    const repulsion = 2500;
    const attraction = 0.005;
    const damping = 0.85;
    const centerPull = 0.01;
    const cx = W() / 2; const cy = H() / 2;

    nodes.forEach(a => {{
      nodes.forEach(b => {{
        if (a === b) return;
        const dx = a.x - b.x; const dy = a.y - b.y;
        const d2 = dx * dx + dy * dy + 1;
        const f = repulsion / d2;
        const dist = Math.sqrt(d2);
        a.vx += (dx / dist) * f;
        a.vy += (dy / dist) * f;
      }});
    }});

    edges.forEach(e => {{
      const a = nodeMap[e.from]; const b = nodeMap[e.to];
      if (!a || !b) return;
      const dx = b.x - a.x; const dy = b.y - a.y;
      a.vx += dx * attraction;
      a.vy += dy * attraction;
      b.vx -= dx * attraction;
      b.vy -= dy * attraction;
    }});

    nodes.forEach(n => {{
      n.vx += (cx - n.x) * centerPull;
      n.vy += (cy - n.y) * centerPull;
      n.vx *= damping; n.vy *= damping;
      if (n !== dragNode) {{
        n.x += n.vx; n.y += n.vy;
        n.x = Math.max(20, Math.min(W() - 20, n.x));
        n.y = Math.max(20, Math.min(H() - 20, n.y));
      }}
    }});

    updatePositions();
  }}

  let simTimer = null;
  function startSim() {{
    let ticks = 0;
    if (simTimer) clearInterval(simTimer);
    simTimer = setInterval(() => {{
      simulate();
      ticks++;
      if (ticks > 300) clearInterval(simTimer);
    }}, 16);
  }}

  // Drag
  function startDrag(ev, node) {{
    ev.preventDefault();
    dragNode = node;
    const onMove = (e) => {{
      const rect = svg.getBoundingClientRect();
      node.x = e.clientX - rect.left;
      node.y = e.clientY - rect.top;
      updatePositions();
    }};
    const onUp = () => {{
      dragNode = null;
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }};
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }}

  // Tooltips
  function showNodeTip(ev, n) {{
    const conns = edges.filter(e => e.from === n.id || e.to === n.id);
    let html = '<strong>' + escHtml(n.label) + '</strong><br>';
    html += '<span style="color:' + typeColor(n.type) + '">' + n.type.toUpperCase() + '</span><br>';
    html += conns.length + ' connection' + (conns.length !== 1 ? 's' : '');
    const susCount = conns.filter(e => e.suspicious).length;
    if (susCount > 0) html += '<br><span style="color:#ff2244">' + susCount + ' suspicious</span>';
    tooltip.innerHTML = html;
    tooltip.classList.add('visible');
    positionTip(ev);
  }}

  function showEdgeTip(ev, e) {{
    const c = e.conn;
    let html = '<strong>' + escHtml(c.owner) + '</strong> (PID ' + c.pid + ')<br>';
    html += c.proto + ' ' + c.localAddr + ':' + c.localPort +
      ' → ' + c.foreignAddr + ':' + c.foreignPort + '<br>';
    html += 'State: ' + c.state;
    if (e.suspicious) html += '<br><span style="color:#ff2244">⚠ SUSPICIOUS PORT</span>';
    tooltip.innerHTML = html;
    tooltip.classList.add('visible');
    positionTip(ev);
  }}

  function positionTip(ev) {{
    tooltip.style.left = (ev.clientX + 12) + 'px';
    tooltip.style.top = (ev.clientY + 12) + 'px';
  }}

  function hideTip() {{
    tooltip.classList.remove('visible');
  }}

  // Controls
  window.nmResetLayout = function() {{
    nodes.forEach((n, i) => {{
      const angle = (2 * Math.PI * i) / nodes.length;
      const r = Math.min(W(), H()) * 0.35;
      n.x = W() / 2 + r * Math.cos(angle);
      n.y = H() / 2 + r * Math.sin(angle);
      n.vx = 0; n.vy = 0;
    }});
    render();
    startSim();
  }};

  window.nmToggleLabels = function() {{
    showLabels = !showLabels;
    const disp = showLabels ? '' : 'none';
    edgeLabelEls.forEach(e => e.el.setAttribute('display', disp));
    nodeLabelEls.forEach(e => e.setAttribute('display', disp));
  }};

  window.nmFilter = function() {{
    susOnly = document.getElementById('nm-sus-only').checked;
    render();
    startSim();
  }};

  // Init on page show
  const origShowPage = window.showPage;
  window.showPage = function(id) {{
    origShowPage(id);
    if (id === 'netmap' && nodes.length > 0) {{
      setTimeout(() => {{ render(); startSim(); }}, 50);
    }}
  }};

  if (nodes.length === 0) {{
    const noData = document.createElement('div');
    noData.style.cssText = 'text-align:center;padding:3em;color:var(--text-dim);font-size:.9em;';
    noData.innerHTML = '<i class="fas fa-globe-americas" style="font-size:2em;opacity:.3;display:block;margin-bottom:.5em"></i>No network connections found';
    container.appendChild(noData);
  }}
}})();

// ========== PDF Export ==========
function exportPDF() {{
  const totalResults = getTotalResults();
  if (iocFolders.length === 0 || totalResults === 0) {{
    alert('No evidence collected. Create an IOC folder and click lines in plugin outputs.');
    return;
  }}

  const printWin = window.open('', '_blank');
  if (!printWin) {{
    alert('Pop-up blocked. Please allow pop-ups for this page and try again.');
    return;
  }}

  let iocHtml = '';
  iocFolders.forEach(f => {{
    if (f.results.length === 0) return;

    const noteHtml = f.note
      ? '<div class="ioc-note">Analyst Note: ' + escHtml(f.note) + '</div>'
      : '';

    let resultsHtml = '';
    f.results.forEach(r => {{
      const pluginLabel = r.plugin
        ? '<div class="ioc-result-plugin">' + escHtml(r.plugin) + '</div>'
        : '';
      resultsHtml += '<div class="ioc-result-row">' +
        pluginLabel +
        '<pre class="ioc-result-text">' + escHtml(r.text) + '</pre></div>';
    }});

    iocHtml += '<div class="ioc-block">' +
      '<div class="ioc-block-head">' +
      '<span class="ioc-block-id">IOC-' + f.id + '</span>' +
      '</div>' +
      '<div class="ioc-block-body">' + resultsHtml + '</div>' +
      noteHtml +
      '</div>';
  }});

  const html = '<!DOCTYPE html><html><head><meta charset="utf-8">' +
    '<title>MEMHUNTER Evidence Report - FALCON</title>' +
    '<style>' +
    '@page {{ size: A4; margin: 15mm; }}' +
    'body {{ font-family: Arial, Helvetica, sans-serif; color: #1a1a2e; background: #fff; margin:0; padding:0; }}' +
    '.pdf-header {{ border-bottom: 3px solid #0a0a18; padding-bottom: 12px; margin-bottom: 20px; }}' +
    '.pdf-header h1 {{ font-size: 26px; margin:0; color: #0a0a18; letter-spacing: 4px; }}' +
    '.pdf-header h1 span {{ color: #8a2be2; font-size: 13px; letter-spacing: 1px; margin-left: 10px; font-weight: normal; }}' +
    '.pdf-header .subtitle {{ font-size: 10px; color: #555; margin-top: 4px; letter-spacing: 1px; }}' +
    '.case-info {{ background: #f4f4f8; border: 1px solid #d0d0e0; border-radius: 6px; padding: 12px 16px; margin-bottom: 22px; }}' +
    '.case-info h2 {{ font-size: 11px; color: #0a0a18; text-transform: uppercase; letter-spacing: 2px; margin: 0 0 8px; border-bottom: 1px solid #d0d0e0; padding-bottom: 5px; }}' +
    '.case-row {{ display: flex; margin-bottom: 3px; font-size: 9px; }}' +
    '.case-label {{ width: 130px; font-weight: bold; color: #444; }}' +
    '.case-val {{ color: #0a0a18; font-family: Courier New, monospace; word-break: break-all; }}' +
    '.section-title {{ font-size: 12px; color: #0a0a18; text-transform: uppercase; letter-spacing: 2px; border-bottom: 2px solid #8a2be2; padding-bottom: 4px; margin: 22px 0 14px; }}' +
    '.ioc-block {{ border: 1px solid #d0d0e0; border-left: 4px solid #8a2be2; border-radius: 4px; margin-bottom: 14px; page-break-inside: avoid; overflow: hidden; }}' +
    '.ioc-block-head {{ background: #f0f0f6; padding: 6px 12px; border-bottom: 1px solid #e0e0e8; }}' +
    '.ioc-block-id {{ font-weight: bold; font-size: 11px; color: #8a2be2; }}' +
    '.ioc-block-meta {{ font-size: 8px; color: #666; margin-left: 10px; }}' +
    '.ioc-block-body {{ padding: 8px 12px; }}' +
    '.ioc-result-row {{ margin-bottom: 6px; font-size: 8.5px; line-height: 1.5; }}' +
    '.ioc-result-plugin {{ font-family: Courier New, monospace; color: #8a2be2; font-size: 7.5px; font-weight: bold; margin-bottom: 2px; }}' +
    '.ioc-result-text {{ font-family: Courier New, monospace; color: #1a1a2e; word-break: break-all; white-space: pre-wrap; margin: 0; font-size: 8px; }}' +
    '.ioc-note {{ padding: 5px 12px; background: #fffde6; border-top: 1px solid #e8e0a0; font-size: 8.5px; font-style: italic; color: #7a6e00; }}' +
    '.pdf-footer {{ margin-top: 28px; padding-top: 8px; border-top: 2px solid #0a0a18; font-size: 7.5px; color: #888; display: flex; justify-content: space-between; }}' +
    '.pdf-footer strong {{ color: #0a0a18; }}' +
    '.pdf-footer .falcon {{ color: #8a2be2; }}' +
    '</style></head><body>' +
    '<div class="pdf-header">' +
    '<h1>MEMHUNTER <span>by FALCON</span></h1>' +
    '<div class="subtitle">INDICATORS OF COMPROMISE REPORT</div>' +
    '</div>' +
    '<div class="case-info">' +
    '<h2>Case Information</h2>' +
    '<div class="case-row"><span class="case-label">Memory Dump:</span><span class="case-val">{dump_esc}</span></div>' +
    '<div class="case-row"><span class="case-label">Operating System:</span><span class="case-val">{os_esc}</span></div>' +
    '<div class="case-row"><span class="case-label">Flag Format:</span><span class="case-val">{flag_esc}</span></div>' +
    '<div class="case-row"><span class="case-label">Report Generated:</span><span class="case-val">{ts_now}</span></div>' +
    '<div class="case-row"><span class="case-label">IOC Groups:</span><span class="case-val">' + iocFolders.filter(f=>f.results.length>0).length + '</span></div>' +
    '<div class="case-row"><span class="case-label">Total Indicators:</span><span class="case-val">' + totalResults + '</span></div>' +
    '</div>' +
    '<div class="section-title">Collected Indicators</div>' +
    iocHtml +
    '<div class="pdf-footer">' +
    '<div><strong>MEMHUNTER</strong> by <span class="falcon">FALCON</span> | Confidential Forensic Report</div>' +
    '<div>{ts_now}</div>' +
    '</div>' +
    '<script>window.onload=function(){{window.print();}};<\\/script>' +
    '</body></html>';

  printWin.document.write(html);
  printWin.document.close();
}}
</script>
</body>
</html>"""

    html_path = OUT_DIR / "report.html"
    html_path.write_text(page)
    cprint(f"[+] HTML report     -> {html_path}", "bold green")


def _install_yara_rules() -> None:
    dest = Path("~/yara-rules").expanduser()
    if dest.exists() and any(dest.rglob("*.yar*")):
        cprint(f"[+] YARA rules already present at {dest}", "green")
        return
    if not shutil.which("git"):
        cprint("[!] git not installed — cannot clone rule set.", "red")
        return
    repos = [
        ("1", "Neo23x0/signature-base  (Florian Roth, curated APT/malware)",
         "https://github.com/Neo23x0/signature-base.git"),
        ("2", "Yara-Rules/rules         (large community collection)",
         "https://github.com/Yara-Rules/rules.git"),
    ]
    cprint("[*] Available YARA rule sets:", "cyan")
    for k, label, _ in repos:
        cprint(f"  {k}) {label}", "yellow")
    cprint("  s) Skip", "dim")
    choice = ask("Select rule set [1/2/s]", "1").strip().lower()
    repo = next((r for r in repos if r[0] == choice), None)
    if not repo:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", "1", repo[2], str(dest)]
    cprint(f"[>] {' '.join(shlex.quote(c) for c in cmd)}", "dim")
    try:
        rc = subprocess.run(cmd, timeout=1800).returncode
    except subprocess.TimeoutExpired:
        cprint("[!] git clone timed out after 30 min.", "red")
        return
    except Exception as e:
        cprint(f"[!] git clone error: {e}", "red")
        return
    if rc != 0:
        cprint(f"[!] git clone failed (exit {rc}).", "red")
        return
    n = sum(1 for _ in dest.rglob("*.yar")) + sum(1 for _ in dest.rglob("*.yara"))
    if n:
        cprint(f"[+] Cloned {n} rule file(s) to {dest}", "bold green")
    else:
        cprint(f"[!] Clone succeeded but no .yar/.yara files found under {dest}.", "yellow")


def install_yara() -> None:
    header("Install YARA")
    if shutil.which("yara"):
        cprint(f"[+] yara already installed at {shutil.which('yara')}", "green")
        r = run_shell("yara --version")
        if r and r.stdout.strip():
            cprint(f"    version: {r.stdout.strip()}", "dim")
    else:
        cprint("[*] Installing yara via apt (requires sudo) …", "yellow")
        cmd = "sudo apt update && sudo apt install -y yara"
        cprint(f"[>] {cmd}", "dim")
        run_shell(cmd, timeout=600)
        if shutil.which("yara"):
            cprint("[+] yara installed successfully.", "bold green")
        else:
            cprint("[!] yara install failed — install manually: sudo apt install yara", "red")
            return
    if ask("Download a YARA rule set now? [Y/n]", "y").strip().lower() in ("", "y", "yes"):
        _install_yara_rules()


def _find_yara_rules() -> list[Path]:
    """Auto-discover YARA rule files/dirs in common locations."""
    candidates = [
        "/usr/share/yara",
        "/usr/share/yara-rules",
        "/var/lib/yara",
        "/opt/yara-rules",
        "/opt/yara",
        "~/yara-rules",
        "~/.yara",
        "~/rules",
    ]
    found: list[Path] = []
    for c in candidates:
        p = Path(c).expanduser()
        if not p.exists():
            continue
        if p.is_file() and p.suffix in (".yar", ".yara"):
            found.append(p)
        elif p.is_dir():
            if any(p.rglob("*.yar")) or any(p.rglob("*.yara")):
                found.append(p)
    return found


def yara_scan() -> None:
    header("YARA Scan")
    if not shutil.which("yara"):
        cprint("[!] yara not installed.", "red")
        if ask("Install yara now? [y/N]").strip().lower() == "y":
            install_yara()
        if not shutil.which("yara"):
            return
    if not DUMP_PATH:
        return

    discovered = _find_yara_rules()
    if discovered:
        cprint("[*] Auto-detected YARA rule locations:", "cyan")
        for i, d in enumerate(discovered, 1):
            kind = "dir" if d.is_dir() else "file"
            cprint(f"  {i}) [{kind}] {d}", "yellow")
        cprint("  m) Enter path manually", "dim")
        choice = ask(f"Select [1-{len(discovered)}/m]", "1").strip().lower()
        if choice == "m":
            rules = ask("Path to YARA rule file or rules directory")
        elif choice.isdigit() and 1 <= int(choice) <= len(discovered):
            rules = str(discovered[int(choice) - 1])
        else:
            cprint("[!] Invalid selection.", "red")
            return
    else:
        cprint("[*] No YARA rules auto-detected in common locations.", "dim")
        rules = ask("Path to YARA rule file or rules directory")

    if not rules:
        return
    rp = Path(rules).expanduser()
    if not rp.exists():
        cprint(f"[!] Not found: {rp}", "red")
        return
    index_file: Path | None = None
    if rp.is_dir():
        all_files = sorted({*rp.rglob("*.yar"), *rp.rglob("*.yara")})
        rule_files = [
            f for f in all_files
            if "index" not in f.name.lower()
            and "deprecated" not in {p.lower() for p in f.parts}
        ]
        skipped = len(all_files) - len(rule_files)
        if not rule_files:
            cprint(f"[!] No .yar/.yara files under {rp}", "red")
            return
        cprint(f"[*] Found {len(rule_files)} rule file(s) under {rp}"
               + (f" (skipped {skipped} index/deprecated)" if skipped else ""), "cyan")
        index_file = (OUT_DIR / "_yara_index.yar") if OUT_DIR else Path("/tmp/_yara_index.yar")
        index_file.write_text("".join(f'include "{f}"\n' for f in rule_files))
        rules_arg = shlex.quote(str(index_file))
    else:
        rules_arg = shlex.quote(str(rp))
    cmd = f"yara -w -s {rules_arg} {shlex.quote(DUMP_PATH)}"
    cprint(f"[>] {cmd}", "dim")
    r = run_shell(cmd, timeout=1200)
    if r is None:
        return
    if r.returncode != 0:
        cprint(f"[!] yara exited with code {r.returncode}.", "red")
        if r.stderr.strip():
            err = r.stderr.strip().splitlines()
            cprint("[!] yara stderr (first 20 lines):", "red")
            for line in err[:20]:
                cprint(f"    {line}", "dim")
            if len(err) > 20:
                cprint(f"    ... ({len(err) - 20} more lines suppressed)", "dim")
            if OUT_DIR:
                save_result("yara_errors.txt", r.stderr)
                cprint(f"[*] Full errors saved to {OUT_DIR}/yara_errors.txt", "dim")
        cprint("[*] Tip: Yara-Rules/rules has many rules requiring external modules "
               "(pe, cuckoo) or vars (filename) that fail to compile. Try "
               "Neo23x0/signature-base instead — it's curated and compiles cleanly.", "cyan")
        return
    if r.stdout.strip():
        cprint(r.stdout, "yellow")
        save_result("yara_hits.txt", r.stdout)
        for line in r.stdout.splitlines():
            if line.strip() and not line.startswith("0x"):
                _record_hit("yara", line.strip(), "yara_scan")
    else:
        cprint("[!] No YARA hits.", "yellow")
        if r.stderr.strip() and OUT_DIR:
            save_result("yara_errors.txt", r.stderr)
            cprint(f"[*] yara emitted warnings — see {OUT_DIR}/yara_errors.txt", "dim")


def bulk_extractor_run() -> None:
    header("bulk_extractor")
    if not shutil.which("bulk_extractor"):
        cprint("[!] bulk_extractor not installed (sudo apt install bulk-extractor).", "red")
        return
    if not (DUMP_PATH and OUT_DIR):
        return
    be_out = OUT_DIR / "bulk_extractor"
    if be_out.exists():
        cprint(f"[!] Output dir exists: {be_out} — remove it first.", "yellow")
        return
    cmd = f"bulk_extractor -o {shlex.quote(str(be_out))} {shlex.quote(DUMP_PATH)}"
    cprint(f"[>] {cmd}", "dim")
    r = run_shell(cmd, timeout=1800)
    if r is None or not be_out.exists():
        cprint("[!] bulk_extractor failed.", "red")
        return
    cprint(f"[+] Done → {be_out}", "bold green")
    for fp in sorted(be_out.glob("*.txt")):
        try:
            sz = fp.stat().st_size
            if sz > 0:
                cprint(f"  {fp.name:<28} {sz:>10,} bytes", "cyan")
        except OSError:
            pass


def pypykatz_run() -> None:
    header("pypykatz — LSASS Credentials")
    if OS_TYPE != "windows":
        cprint("[!] pypykatz targets Windows LSASS dumps only.", "yellow")
        return
    if not shutil.which("pypykatz"):
        cprint("[!] pypykatz not installed (pipx install pypykatz).", "red")
        return
    if not (DUMP_PATH and OUT_DIR):
        return
    pid = ask("LSASS PID (use Quick Triage → pslist to find it)")
    if not pid.isdigit():
        cprint("[!] Invalid PID.", "red")
        return
    dump_dir = OUT_DIR / f"lsass_pid{pid}"
    dump_dir.mkdir(exist_ok=True)
    cprint("[*] Dumping LSASS memory via windows.memmap …", "yellow")
    cmd = (f"cd {shlex.quote(str(dump_dir))} && "
           f"{VOL_CMD} -f \"{DUMP_PATH}\" windows.memmap --dump --pid {pid}")
    r = run_shell(cmd, timeout=900)
    if r is None:
        return
    dmps = list(dump_dir.glob("*.dmp"))
    if not dmps:
        cprint("[!] No .dmp file produced by memmap.", "red")
        return
    for d in dmps:
        cprint(f"[*] pypykatz lsa minidump {d.name} …", "yellow")
        r2 = run_shell(f"pypykatz lsa minidump {shlex.quote(str(d))}", timeout=300)
        if r2 and r2.stdout:
            cprint(r2.stdout, "yellow")
            save_result(f"pypykatz_pid{pid}.txt", r2.stdout)
            _record_hit("pypykatz", f"lsass pid {pid} parsed", d.name)


def _record_hit(category: str, value: str, source: str = "") -> None:
    HITS_JSON.append({
        "category": category,
        "value": value,
        "source": source,
        "timestamp": datetime.now().isoformat(),
    })


def export_json() -> None:
    if not OUT_DIR:
        cprint("[!] No output directory.", "red")
        return
    p = OUT_DIR / "hits.json"
    payload = {
        "dump": DUMP_PATH,
        "os": OS_TYPE,
        "flag_format": FLAG_FORMAT,
        "generated": datetime.now().isoformat(),
        "hits": HITS_JSON,
    }
    p.write_text(json.dumps(payload, indent=2))
    cprint(f"[+] {len(HITS_JSON)} hit(s) → {p}", "bold green")


def _triage_summary() -> None:
    if not OUT_DIR:
        return
    cprint("\n── Severity Summary ──", "bold cyan")
    rootkit_markers = ("malfind", "check_modules", "check_syscall",
                       "check_idt", "rootkit")
    suspect_markers = ("credential", "hashdump", "envars",
                       "netstat", "netscan", "svcscan", "cmdline")
    for tf in sorted(OUT_DIR.glob("*.txt")):
        try:
            content = tf.read_text(errors="replace").strip()
        except OSError:
            continue
        if not content:
            continue
        name = tf.name.lower()
        if "flag" in name:
            cprint(f"  [FLAG]     {tf.name}", "bold green")
        elif any(m in name for m in rootkit_markers):
            cprint(f"  [ROOTKIT?] {tf.name}", "bold red")
        elif any(m in name for m in suspect_markers):
            cprint(f"  [SUSPECT]  {tf.name}", "yellow")
        else:
            cprint(f"  [info]     {tf.name}", "dim")


def show_help() -> None:
    """In-app help: usage tips + full Volatility 3 plugin list."""
    header("memhunter — Help")
    tips = """
## Workflow at a glance

  1. Load a dump (argv, or menu `d`)
  2. memhunter auto-detects OS — confirms Linux or Windows
  3. Enter your flag regex when prompted (e.g. `flag\\{[^}]+\\}`)
  4. Run **[1] Quick Triage** — parallel plugin sweep + flag/cred strings
  5. Inspect `results_*/` — severity summary flags the interesting files
  6. **[r]** Report  — stitch everything into `report.md` / `report.html`
  7. **[j]** JSON    — export structured `hits.json` for scoreboards
  8. **[q]** Quit    — `--json` on the CLI auto-exports on exit

## Menu keys

  [1] Quick Triage — the fastest way to see everything in one shot
  [2] Process Analysis — drill into a PID (Linux: envars/Maps; Windows: vadinfo/dumpfiles)
  [3] Network Analysis — who was talking to whom
  [4] File System Hunting — find files in VFS/MFT cache
  [5] Credential & Flag Hunt — most CTF flags live here
  [6] Kernel / Rootkit Check — module/syscall/IDT integrity
  [7] Strings Search — works on *any* dump, no Volatility required
  [8] Custom Plugin — run any Volatility plugin verbatim
  [r] Report (MD/HTML)      [y]  YARA scan
  [be] bulk_extractor       [pk] pypykatz LSASS (Windows)
  [j] Export hits → JSON    [h]  Health check
  [cs1-4] Cheat sheets      [i]  Install Volatility 3
  [d] Change dump           [o]  Change OS        [f] Change flag format

## Tips

  * `[str]` labels mean strings-only → works even if Volatility can't
    parse the dump (missing symbol pack, truncated image, etc).
  * `[vol]` labels mean the option invokes a Volatility plugin.
  * Every command's output is saved automatically to `results_*/`.
  * `[8] Custom Plugin` is the escape hatch — try any plugin listed below.
"""
    if RICH:
        console.print(Markdown(tips))
    else:
        print(tips)

    if not VOL_CMD:
        cprint("\n[!] Volatility 3 not available — plugin list omitted.", "yellow")
        return

    cprint("\n── Available Volatility 3 plugins ──", "bold cyan")
    r = run_shell(f"{VOL_CMD} --help", timeout=60)
    blob = (r.stdout if r else "") + (r.stderr if r else "")
    # vol --help lists plugins at the bottom after a "Plugins" header, or
    # inline with the choices list. Grab lines that look like plugin names.
    plugins = sorted(set(re.findall(
        r"\b((?:linux|windows|mac|frameworkinfo|banners|isfinfo|configwriter|timeliner|layerwriter|yarascan|vmscan|regexscan)"
        r"(?:\.[A-Za-z][A-Za-z0-9_]*)*)\b",
        blob)))
    if plugins:
        cols = 2
        for i in range(0, len(plugins), cols):
            row = plugins[i:i + cols]
            cprint("  " + "  ".join(f"{p:<42}" for p in row), "cyan")
        cprint(f"\n  Total: {len(plugins)} plugins", "bold green")
        cprint("  Use [8] Custom Plugin to run any of these by name.", "dim")
    else:
        cprint("  (Could not parse plugin list — run `vol --help` manually.)",
               "yellow")


def _win_pid_plugin(plugin: str) -> None:
    pid = ask("Enter PID")
    if not pid.isdigit():
        cprint("[!] Invalid PID.", "red")
        return
    run_vol(plugin, f"--pid {pid}",
            f"{plugin.replace('.','_')}_pid{pid}.txt")


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
        description="memhunter — Interactive Memory Forensics for CTF (Linux + Windows)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("dump", nargs="?", help="Memory dump file to analyse")
    parser.add_argument("--install", action="store_true",
                        help="Install/update Volatility 3 from GitHub and exit")
    parser.add_argument("--json", action="store_true",
                        help="After analysis, export accumulated hits to hits.json on exit")
    args = parser.parse_args()

    banner()

    if args.install:
        install_volatility()
        sys.exit(0)

    # Ensure Volatility 3 is available
    ensure_volatility()

    # Startup health check
    health_check()

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
        _auto_detect_os()

    # Main interactive loop
    while True:
        print_main_menu()

        if DUMP_PATH:
            cprint(f"  Dump : [cyan]{DUMP_PATH}[/cyan]", "dim") if RICH else \
            print(f"  Dump : {DUMP_PATH}")
            cprint(f"  Out  : [cyan]{OUT_DIR.resolve() if OUT_DIR else 'none'}[/cyan]",
                   "dim") if RICH else \
            print(f"  Out  : {OUT_DIR.resolve() if OUT_DIR else 'none'}")
            cprint(f"  OS   : [cyan]{OS_TYPE}[/cyan]    Flag : [cyan]{FLAG_FORMAT or '(not set)'}[/cyan]\n",
                   "dim") if RICH else \
            print(f"  OS   : {OS_TYPE}    Flag : {FLAG_FORMAT or '(not set)'}\n")
        else:
            cprint("\n  [!] No dump loaded — use option [d] to select a file\n", "yellow")

        choice = ask("Choice", "q").strip().lower()

        if   choice == "q":
            if args.json:
                export_json()
            cprint("\n[*] Goodbye.\n", "cyan"); sys.exit(0)
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
        elif choice == "r":   generate_report()
        elif choice == "y":   yara_scan()
        elif choice == "iy":  install_yara()
        elif choice == "be":  bulk_extractor_run()
        elif choice == "pk":  pypykatz_run()
        elif choice == "j":   export_json()
        elif choice == "h":   health_check()
        elif choice in ("?", "help"): show_help()
        elif choice == "d":
            new_dump = select_dump()
            if new_dump:
                DUMP_PATH = new_dump
                OUT_DIR   = setup_output_dir(DUMP_PATH)
                _auto_detect_os()
        elif choice == "o":
            _select_os()
        elif choice == "f":
            _prompt_flag_format()
        else:
            cprint("[!] Unknown option.", "red")


if __name__ == "__main__":
    main()
