# linux-mem-forensics

A Linux Loadable Kernel Module (LKM) that performs forensic-grade physical memory acquisition. It produces a raw dump of System RAM suitable for analysis with tools such as [Volatility 3](https://github.com/volatilityfoundation/volatility3), [Rekall](https://github.com/google/rekall), or any hex editor.

## Why a Kernel Module?

User-space tools can read `/dev/mem` or `/proc/kcore`, but modern kernels restrict both by default (`CONFIG_STRICT_DEVMEM`, `CONFIG_LOCKDOWN_LSM`). A loadable kernel module runs at ring 0 and can safely map physical memory through `ioremap_cache()` — the same primitive the kernel itself uses — bypassing these restrictions while remaining read-only.

## Features

| Feature | Detail |
|---|---|
| **Read-only access** | The module never modifies kernel structures or physical pages. |
| **System RAM awareness** | Only dumps ranges reported as "System RAM" in `/proc/iomem`, skipping MMIO, ACPI, and PCI regions. |
| **SHA-256 integrity hash** | A running hash is computed during acquisition and printed to `dmesg` on completion, providing a chain-of-custody anchor. |
| **Error-tolerant** | Unmappable pages are replaced with zeroes so file offsets stay aligned to physical addresses. |
| **Minimal footprint** | Uses a single page-sized bounce buffer — no large allocations. |
| **Configurable output path** | Pass `dump_path=` at load time. |

## Prerequisites

You need a Linux system with:

- **Kernel headers** for your running kernel
- **Build toolchain** (`make`, `gcc`)

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install build-essential linux-headers-$(uname -r)
```

### RHEL / CentOS / Fedora

```bash
sudo dnf install gcc make kernel-devel-$(uname -r)
```

### Arch Linux

```bash
sudo pacman -S base-devel linux-headers
```

## Compilation

```bash
cd linux-mem-forensics
make
```

This produces `memdump.ko` in the current directory. To target a different kernel version or a cross-compile build tree:

```bash
make KDIR=/path/to/kernel/build
```

## Usage

### 1. Load the Module (Start Acquisition)

The dump runs entirely during module insertion, so `insmod` will block until the acquisition is complete.

**Default output** (`/tmp/memdump.raw`):

```bash
sudo insmod memdump.ko
```

**Custom output path:**

```bash
sudo insmod memdump.ko dump_path="/evidence/case42/physmem.raw"
```

> **Tip:** Make sure the target directory exists and has enough free space to hold the full physical memory image.

### 2. Monitor Progress

```bash
dmesg | grep memdump
```

Sample output:

```
memdump: module loaded — target file: /evidence/case42/physmem.raw
memdump: opened /evidence/case42/physmem.raw for writing
memdump: starting physical memory dump …
memdump: dumping range 0x100000 – 0x7fffffff (2047 MiB)
memdump: progress: 256 MiB written
memdump: progress: 512 MiB written
...
memdump: dump complete — 2147483648 bytes (2048 MiB) written
memdump: SHA-256 of dump: a1b2c3d4e5f6...
```

Record the SHA-256 hash in your case notes for chain-of-custody purposes.

### 3. Unload the Module

```bash
sudo rmmod memdump
```

### 4. Analyse the Dump

```bash
# Volatility 3 example
vol -f /evidence/case42/physmem.raw linux.pslist
vol -f /evidence/case42/physmem.raw linux.bash

# Verify integrity
sha256sum /evidence/case42/physmem.raw
```

## File Structure

```
linux-mem-forensics/
├── Makefile        # Kbuild out-of-tree module Makefile
├── memdump.c       # LKM source (heavily commented)
└── README.md       # This file
```

## Security Considerations

- **Root required.** `insmod` needs `CAP_SYS_MODULE` (effectively root).
- **Secure Boot.** If Secure Boot is enabled the module must be signed with an enrolled MOK key, or Secure Boot must be disabled during acquisition.
- **Kernel lockdown.** In `confidentiality` lockdown mode, `ioremap_cache()` on RAM ranges may be blocked. Boot with `lockdown=integrity` or `lockdown=none` if needed.
- **Output file permissions.** The dump is created with mode `0600`. Move it to encrypted storage as soon as practical.

## Limitations

- The dump is a snapshot of physical RAM at acquisition time; processes continue to run and may change memory while the dump is in progress. For the most consistent results, acquire from a system with minimal activity or from a paused VM.
- Kernel code and data that are not backed by "System RAM" resources (e.g., firmware tables, UEFI runtime regions) are intentionally excluded.
- Only tested on x86_64. ARM64 and other architectures may require changes to the `ioremap_cache` path.

## License

GPL-2.0 — required for modules that reference GPL-only kernel symbols.
