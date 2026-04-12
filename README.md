# memhunter

Interactive memory forensics toolkit for CTF competitions — works on both
**Linux** and **Windows** memory dumps.

| Component | Purpose |
|---|---|
| **`memhunter.py`** | Interactive CLI — memory dump *analysis* (CTF-focused, Linux + Windows) |
| **`memdump.ko`** | Linux LKM — forensic-grade physical memory *acquisition* |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/MohdAlkafaween/memhunter
cd memhunter

# 2. One-shot setup (installs Volatility 3 + deps)
chmod +x install.sh
sudo ./install.sh

# 3. Analyse a memory dump interactively
python3 memhunter.py /path/to/dump.raw
```

On startup, memhunter:

1. Runs a **health check** (Volatility 3 version, `strings`, `grep -P`,
   symbol cache, optional tools like YARA / bulk_extractor / pypykatz).
2. **Auto-detects the OS** of the dump via `banners.Banners` — falls back to
   a manual Linux/Windows prompt only when detection is inconclusive. The
   chosen OS picks the right Volatility 3 plugin family (`linux.*` vs
   `windows.*`).
3. Asks for the **flag format** for the CTF you're playing — as a Python/grep
   regex. Every flag-hunting option uses that regex, so you get the right
   hits for your specific event (HTB, picoCTF, THM, DUCTF, custom, …). No
   hardcoded flag patterns.

---

## memhunter.py — Interactive Analysis Tool

```
  __  __                _   _             _
 |  \/  | ___ _ __ ___ | | | |_   _ _ __ | |_ ___ _ __
 | |\/| |/ _ \ '_ ` _ \| |_| | | | | '_ \| __/ _ \ '__|
 | |  | |  __/ | | | | |  _  | |_| | | | | ||  __/ |
 |_|  |_|\___|_| |_| |_|_| |_|\__,_|_| |_|\__\___|_|

  memhunter — Memory Forensics for CTFs  v2.1.0  (Linux + Windows)
```

### Features

- **Linux + Windows support** — automatic `linux.*` → `windows.*` plugin mapping
- **OS auto-detect** — `banners.Banners` at startup, manual fallback on ambiguity
- **Startup health check** — Volatility 3 version, `strings`, `grep -P`, symbol cache, optional tools
- **User-defined flag format** — you enter the regex, memhunter validates and uses it everywhere
- **Guided menus** — no need to memorise plugin names
- **Parallel Quick Triage** — 4-worker thread pool runs essential plugins concurrently, then a strings sweep, with an OS-specific plugin set (Linux: pslist/pstree/bash/envars/credentials/check_modules/…; Windows: pslist/pstree/cmdline/svcscan/netscan/malfind/hashdump/hivelist/mftscan)
- **Severity-coloured summary** — post-triage summary marks files `[FLAG]` / `[ROOTKIT?]` / `[SUSPECT]` / `[info]`
- **Process / Network / File / Kernel analysis** sections (Windows branch adds `pslist`/`vadinfo`/`dumpfiles` per-PID)
- **Flag & credential hunter** — sweeps envars, history, raw strings
- **Base64 decoder** — finds and decodes blobs inline
- **Raw strings search** — flag patterns, IPs, URLs, SSH keys without Volatility
- **Report generator** — stitches every `results_*/*.txt` into `report.md` (and `report.html` when `python3-markdown` is installed)
- **YARA menu** — point at a rules file or directory, scan the dump, save hits
- **bulk_extractor one-click** — carves emails, URLs, domains, JSON, histograms
- **pypykatz bridge (Windows)** — dumps LSASS via `windows.memmap` and runs `pypykatz lsa minidump` automatically
- **JSON export (`--json` / menu `j`)** — structured `hits.json` with category, source, and timestamps for scoreboard / Obsidian integration
- **Built-in cheat sheets** — Volatility 3 reference, CTF workflow, tools guide
- **Auto-save** — every result written to a timestamped `results_*/` directory
- **Volatility 3 installer** — clones and installs with symbol packs in one step

### Usage

```bash
python3 memhunter.py                        # interactive, prompts for dump
python3 memhunter.py dump.raw               # load dump on startup
python3 memhunter.py dump.raw --json        # auto-export hits.json on exit
python3 memhunter.py --install              # install/update Volatility 3
```

### Menu Overview

```
  [  1]  Quick Triage            Parallel plugin sweep + strings (OS-aware)
  [  2]  Process Analysis        pslist, pstree, cmdline, envars / vadinfo
  [  3]  Network Analysis        netstat, sockstat, connection forensics
  [  4]  File System Hunting     find_file / filescan, VFS artefacts
  [  5]  Credential & Flag Hunt  history, env vars, raw strings
  [  6]  Kernel / Rootkit Check  modules, syscall table, IDT hooks
  [  7]  Strings Search          Grep raw dump without Volatility
  [  8]  Custom Plugin           Run any Volatility plugin manually

  [  r]  Report (MD/HTML)        Stitch all results_*.txt into report.md
  [  y]  YARA scan               Run yara rules against the dump
  [ be]  bulk_extractor          One-click artefact carving
  [ pk]  pypykatz (LSASS)        Dump LSASS via memmap + pypykatz (Windows)
  [  j]  Export hits to JSON     Save structured hits to hits.json
  [  h]  Health check            Re-run dependency / version checks

  [cs1]  Cheat Sheet: Volatility 3
  [cs2]  Cheat Sheet: CTF Workflow
  [cs3]  Cheat Sheet: Strings/grep
  [cs4]  Cheat Sheet: Tools

  [  i]  Install / Update Volatility 3
  [  d]  Change dump file
  [  o]  Change OS (linux/windows)
  [  f]  Change flag format
  [  q]  Quit
```

### Flag format examples

The first time you run a flag-hunting option you'll be asked for a regex:

```
  flag\{[^}]+\}          generic
  HTB\{[^}]+\}           HackTheBox
  picoCTF\{[^}]+\}       picoCTF
  THM\{[^}]+\}           TryHackMe
  DUCTF\{[^}]+\}         Down Under CTF
  CTF\{[a-f0-9]{32}\}    custom fixed-length hex flag
```

Invalid regexes are rejected and you're prompted again.

### Requirements

**Required**

- Python 3.10+
- [`rich`](https://github.com/Textualize/rich) — `pip3 install rich` (pre-installed on Kali)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3) — installed by `install.sh` or option `[i]`
- `strings`, `grep -P` — standard Linux utilities (always present)

**Optional** (enable extra menu items — the health check reports what's missing)

- [`yara`](https://github.com/VirusTotal/yara) — `sudo apt install yara`
- [`bulk_extractor`](https://github.com/simsong/bulk_extractor) — `sudo apt install bulk-extractor`
- [`pypykatz`](https://github.com/skelsec/pypykatz) — `pipx install pypykatz` (Windows LSASS)
- `python3-markdown` — `sudo apt install python3-markdown` (HTML report export)

---

## memdump.ko — Physical Memory Acquisition Module (Linux)

A Linux Loadable Kernel Module that performs forensic-grade physical memory
acquisition, producing a raw dump suitable for Volatility 3, Rekall, or any
hex editor. For Windows acquisition use tools like
[DumpIt](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/),
WinPMEM, or FTK Imager.

### Why a Kernel Module?

User-space tools can read `/dev/mem` or `/proc/kcore`, but modern kernels
restrict both (`CONFIG_STRICT_DEVMEM`, `CONFIG_LOCKDOWN_LSM`). An LKM runs at
ring 0 and safely maps physical memory through `ioremap_cache()` — bypassing
these restrictions while remaining read-only.

### Features

| Feature | Detail |
|---|---|
| **Read-only access** | Never modifies kernel structures or physical pages |
| **System RAM only** | Skips MMIO, ACPI, PCI — only dumps real DRAM |
| **SHA-256 integrity** | Hash computed during acquisition, printed to dmesg |
| **Error-tolerant** | Unmappable pages replaced with zeroes (offsets stay aligned) |
| **Configurable path** | `dump_path=` parameter at load time |

### Prerequisites

```bash
# Debian / Ubuntu / Kali
sudo apt-get install build-essential linux-headers-$(uname -r)

# RHEL / CentOS / Fedora
sudo dnf install gcc make kernel-devel-$(uname -r)

# Arch
sudo pacman -S base-devel linux-headers
```

### Build

```bash
make
# Cross-compile / custom kernel:
make KDIR=/path/to/kernel/build
```

### Acquire Memory

```bash
# Default output: /tmp/memdump.raw
sudo insmod memdump.ko

# Custom path
sudo insmod memdump.ko dump_path="/evidence/case42/physmem.raw"

# Monitor progress
dmesg | grep memdump

# Unload when done
sudo rmmod memdump
```

### Analyse the Dump

```bash
# With memhunter.py (interactive)
python3 memhunter.py /tmp/memdump.raw

# Direct Volatility 3
vol -f /tmp/memdump.raw linux.pslist
vol -f /tmp/memdump.raw linux.bash
vol -f /tmp/memdump.raw linux.envars

# Verify integrity
sha256sum /tmp/memdump.raw    # should match dmesg output
```

---

## Repository Structure

```
memhunter/
├── memdump.c       LKM source — physical memory acquisition (Linux)
├── Makefile        Kbuild out-of-tree module build
├── memhunter.py    Interactive analysis tool (Linux + Windows dumps)
├── install.sh      One-shot setup script
└── README.md       This file
```

---

## Security Considerations

- **Root required** — `insmod` needs `CAP_SYS_MODULE`
- **Secure Boot** — module must be signed with an enrolled MOK key, or SB disabled
- **Kernel lockdown** — use `lockdown=integrity` or `lockdown=none` if `ioremap_cache` is blocked
- **Output file** — created mode `0600`; move to encrypted storage immediately

## License

GPL-2.0 — required for modules that reference GPL-only kernel symbols.
