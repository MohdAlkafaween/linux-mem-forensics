# memhunter

Interactive memory forensics toolkit — works on both **Linux** and **Windows**
memory dumps. Built for incident response, malware analysis, and forensic
investigations.

| Component | Purpose |
|---|---|
| **`memhunter.py`** | Interactive CLI — memory dump *analysis* (Linux + Windows) |
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
3. Optionally set a **string search pattern** via `[f]` — a Python/grep regex
   used by all string-hunting options to find specific indicators across the
   dump (credentials, IOCs, custom patterns).

---

## memhunter.py — Interactive Analysis Tool

```
  __  __                _   _             _
 |  \/  | ___ _ __ ___ | | | |_   _ _ __ | |_ ___ _ __
 | |\/| |/ _ \ '_ ` _ \| |_| | | | | '_ \| __/ _ \ '__|
 | |  | |  __/ | | | | |  _  | |_| | | | | ||  __/ |
 |_|  |_|\___|_| |_| |_|_| |_|\__,_|_| |_|\__\___|_|

  memhunter — Memory Forensics Toolkit  v3.0.0  (Linux + Windows)
```

### Features

#### Analysis Engine
- **Linux + Windows support** — automatic `linux.*` / `windows.*` plugin mapping
- **OS auto-detect** — `banners.Banners` at startup, manual fallback on ambiguity
- **Startup health check** — Volatility 3 version, `strings`, `grep -P`, symbol cache, optional tools
- **String search pattern** — user-defined regex applied across all string-hunting operations
- **Guided menus** — no need to memorise plugin names
- **Parallel Quick Triage** — 4-worker thread pool runs essential plugins concurrently, then a strings sweep, with an OS-specific plugin set (Linux: pslist/pstree/bash/envars/credentials/check_modules/...; Windows: pslist/pstree/cmdline/svcscan/netscan/malfind/hashdump/hivelist/mftscan)
- **Severity-coloured summary** — post-triage summary marks files `[CRITICAL]` / `[ROOTKIT?]` / `[SUSPECT]` / `[info]`
- **Process / Network / File / Kernel analysis** sections (Windows branch adds `pslist`/`vadinfo`/`dumpfiles` per-PID)
- **Credential & string hunter** — sweeps envars, history, raw strings for user-defined patterns
- **Base64 decoder** — finds and decodes blobs inline
- **Raw strings search** — custom patterns, IPs, URLs, SSH keys without Volatility
- **YARA menu** — point at a rules file or directory, scan the dump, save hits
- **bulk_extractor one-click** — carves emails, URLs, domains, JSON, histograms
- **pypykatz bridge (Windows)** — dumps LSASS via `windows.memmap` and runs `pypykatz lsa minidump` automatically
- **JSON export (`--json` / menu `j`)** — structured `hits.json` with category, source, and timestamps
- **Built-in cheat sheets** — Volatility 3 reference, forensic workflow, tools guide
- **Auto-save** — every result written to a timestamped `results_*/` directory
- **Volatility 3 installer** — clones and installs with symbol packs in one step

#### Interactive HTML Report (Cyberpunk UI)

The `[r] Report` option generates both a Markdown summary and a fully interactive
single-page HTML report with a cyberpunk-themed interface:

- **Sidebar navigation** — dashboard, categories (process, network, filesystem, credentials, kernel, services, YARA, strings), and per-plugin pages
- **Dashboard** — stat cards showing dump info, OS, plugin counts, and severity breakdown
- **Process Explorer** — searchable process table with per-process detail pages showing network connections, malfind hits, and command lines
- **Process Tree** — visual parent-child hierarchy with connecting lines; click any node to view process details; colour-coded nodes (red = malfind, green = network activity)
- **Network Map** — interactive force-directed SVG graph showing local IPs, remote IPs, and processes as nodes with connection edges; drag to rearrange, hover for tooltips, filter to suspicious ports only, double-click process nodes to jump to details
- **Per-plugin pages** — clickable output lines with shift+click range selection for evidence collection
- **Evidence Board** — IOC folder system for building indicator groups:
  - Click or shift+click lines in any plugin output to select, then Confirm to add as a single merged result
  - Plugin name tags on every result
  - Click any result to navigate back to its source line (highlighted with a flash animation)
  - Drag and drop results between IOC folders to reorganise
  - Analyst notes per IOC folder
  - PDF export with FALCON branding via browser print-to-PDF
- **Severity badges** — every plugin output is classified (CRITICAL / HIGH / MEDIUM / LOW) with colour-coded badges throughout the UI

### Usage

```bash
python3 memhunter.py                        # interactive, prompts for dump
python3 memhunter.py dump.raw               # load dump on startup
python3 memhunter.py dump.raw --json        # auto-export hits.json on exit
python3 memhunter.py --install              # install/update Volatility 3
```

### Menu Overview

```
  [  1]  Quick Triage              Parallel plugin sweep + strings (OS-aware)
  [  2]  Process Analysis          pslist, pstree, cmdline, envars / vadinfo
  [  3]  Network Analysis          netstat, sockstat, connection forensics
  [  4]  File System Hunting       find_file / filescan, VFS artefacts
  [  5]  Credential & String Hunt  history, env vars, raw strings
  [  6]  Kernel / Rootkit Check    modules, syscall table, IDT hooks
  [  7]  Strings Search            Grep raw dump without Volatility
  [  8]  Custom Plugin             Run any Volatility plugin manually

  [  r]  Report (MD/HTML)          Generate Markdown + interactive HTML report
  [  y]  YARA scan                 Run yara rules against the dump
  [ be]  bulk_extractor            One-click artefact carving
  [ pk]  pypykatz (LSASS)          Dump LSASS via memmap + pypykatz (Windows)
  [  j]  Export hits to JSON       Save structured hits to hits.json
  [  h]  Health check              Re-run dependency / version checks

  [cs1]  Cheat Sheet: Volatility 3
  [cs2]  Cheat Sheet: Forensic Workflow
  [cs3]  Cheat Sheet: Strings/grep
  [cs4]  Cheat Sheet: Tools

  [  i]  Install / Update Volatility 3
  [  d]  Change dump file
  [  o]  Change OS (linux/windows)
  [  f]  Change string search
  [  q]  Quit
```

### String search examples

Use `[f]` to set a custom search regex — applied across all string-hunting operations:

```
  password|secret|key          credential patterns
  admin.*login                 authentication strings
  https?://[^\s]+              URLs in memory
  [A-Za-z0-9+/]{40,}          base64-encoded blobs
  \.exe$|\.dll$                executable references
  C:\\Windows\\Temp            suspicious paths
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
├── README.md       This file
└── results_*/      Auto-generated output directories (gitignored)
    ├── *.txt       Individual plugin outputs
    ├── report.md   Markdown summary report
    └── report.html Interactive HTML report (cyberpunk UI)
```

---

## Security Considerations

- **Root required** — `insmod` needs `CAP_SYS_MODULE`
- **Secure Boot** — module must be signed with an enrolled MOK key, or SB disabled
- **Kernel lockdown** — use `lockdown=integrity` or `lockdown=none` if `ioremap_cache` is blocked
- **Output file** — created mode `0600`; move to encrypted storage immediately

## License

GPL-2.0 — required for modules that reference GPL-only kernel symbols.
