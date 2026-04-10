# ============================================================================
# Makefile — Linux Kernel Module build for memdump.ko
#
# This Makefile uses the standard Kbuild out-of-tree module build system.
# It invokes the kernel's own build infrastructure so that compiler flags,
# symbol versioning, and module metadata are all handled correctly.
# ============================================================================

# Name of the module (without .ko extension)
obj-m += memdump.o

# Path to the running kernel's build tree.  Override on the command line
# if you are cross-compiling or targeting a different kernel version:
#   make KDIR=/path/to/kernel/build
KDIR ?= /lib/modules/$(shell uname -r)/build

# Current working directory (where this Makefile lives)
PWD := $(shell pwd)

# Default target — build the kernel module
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Remove all build artefacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Convenience targets for loading / unloading during development
load:
	sudo insmod memdump.ko

unload:
	sudo rmmod memdump

# Show the last kernel log lines related to this module
dmesg:
	dmesg | grep memdump

.PHONY: all clean load unload dmesg
