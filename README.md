# linux-mem-forensics

A two-part Linux memory forensics toolkit:

| Component | Purpose |
|---|---|
| **`memdump.ko`** | Linux LKM — forensic-grade physical memory *acquisition* |
| **`memhunter.py`** | Interactive CLI — memory dump *analysis* (CTF-focused) |

---

## Quick Start (CTF / Analysis)

```bash
# 1. Clone
git clone https://github.com/MohdAlkafaween/linux-mem-forensics
cd linux-mem-forensics

# 2. One-shot setup (installs Volatility 3 + deps)
chmod +x install.sh
sudo ./install.sh

# 3. Analyse a memory dump interactively
python3 memhunter.py /path/to/dump.raw
```

---

## memhunter.py — Interactive Analysis Tool

```
  __  __                _   _             _
 |  \/  | ___ _ __ ___ | | | |_   _ _ __ | |_ ___ _ __
 | |\/| |/ _ \ '_ ` _ \| |_| | | | | '_ \| __/ _ \ '__|
 | |  | |  __/ | | | | |  _  | |_| | | | | ||  __/ |
 |_|  |_|\___|_| |_| |_|_| |_|\__,_|_| |_|\__\___|_|

  Linux Memory Forensics — CTF Edition  v2.0.0
```

### Features

- **Guided menus** — no need to memorise plugin names
- **Quick Triage** — 10 essential plugins in one shot
- **Process / Network / File / Kernel analysis** sections
- **Flag & credential hunter** — sweeps envars, bash history, raw strings
- **Base64 decoder** — finds and decodes blobs inline
- **Raw strings search** — flag patterns, IPs, URLs, SSH keys without Volatility
- **Built-in cheat sheets** — Volatility 3 reference, CTF workflow, tools guide
- **Auto-save** — every result written to a timestamped `results_*/` directory
- **Volatility 3 installer** — clones and installs with symbol packs in one step

### Usage

```bash
python3 memhunter.py                        # interactive, prompts for dump
python3 memhunter.py dump.raw               # load dump on startup
python3 memhunter.py --install              # install/update Volatility 3
```

### Menu Overview

```
  [  1]  Quick Triage            Auto-run essential plugins in one shot
  [  2]  Process Analysis        pslist, pstree, cmdline, envars
  [  3]  Network Analysis        netstat, sockstat, connection forensics
  [  4]  File System Hunting     find_file, inode cache, VFS artefacts
  [  5]  Credential & Flag Hunt  bash history, env vars, raw strings
  [  6]  Kernel / Rootkit Check  lsmod, syscall table, IDT hooks
  [  7]  Strings Search          Grep raw dump without Volatility
  [  8]  Custom Plugin           Run any Volatility plugin manually

  [cs1]  Cheat Sheet: Volatility 3
  [cs2]  Cheat Sheet: CTF Workflow
  [cs3]  Cheat Sheet: Strings/grep
  [cs4]  Cheat Sheet: Tools

  [  i]  Install / Update Volatility 3
  [  d]  Change dump file
  [  q]  Quit
```

### Requirements

- Python 3.10+
- [`rich`](https://github.com/Textualize/rich) — `pip3 install rich` (pre-installed on Kali)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3) — installed by `install.sh` or option `[i]`
- `strings`, `grep` — standard Linux utilities (always present)

---

## memdump.ko — Physical Memory Acquisition Module

A Linux Loadable Kernel Module that performs forensic-grade physical memory
acquisition, producing a raw dump suitable for Volatility 3, Rekall, or any
hex editor.

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

## CTF Quick-Reference

### Common Flag Locations

```bash
# Environment variables (most common CTF path)
vol -f dump.raw linux.envars | grep -i flag

# Bash history
vol -f dump.raw linux.bash

# Raw strings
strings dump.raw | grep -oiP 'flag\{[^}]+\}'
strings -el dump.raw | grep -oiP 'flag\{[^}]+\}'   # Unicode

# Files
vol -f dump.raw linux.find_file --find /root
vol -f dump.raw linux.find_file --find /tmp
```

### Suspicious Process Indicators

- Running from `/tmp`, `/dev/shm`, `/var/tmp`
- PPID=1 for non-system processes
- Name contains spaces or hidden chars
- Maps show `(deleted)` executable

### Rootkit Indicators

- Module absent from `lsmod` → `linux.check_modules`
- Syscall table entry outside kernel `.text` → `linux.check_syscall`
- IDT entry pointing to unknown address → `linux.check_idt`

---

## Repository Structure

```
linux-mem-forensics/
├── memdump.c       LKM source — physical memory acquisition
├── Makefile        Kbuild out-of-tree module build
├── memhunter.py    Interactive analysis tool (CTF-focused)
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
