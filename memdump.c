/*
 * memdump.c — Linux Loadable Kernel Module for Physical Memory Acquisition
 *
 * Purpose
 * -------
 * This LKM performs a linear dump of the system's physical RAM to a file on
 * disk.  It is designed for Digital Forensics & Incident Response (DFIR) work
 * where an examiner needs a bit-for-bit copy of volatile memory for offline
 * analysis (e.g., with Volatility, Rekall, or similar frameworks).
 *
 * Forensic Safeguards
 * -------------------
 *  1. READ-ONLY access — the module never writes to, or modifies, any kernel
 *     data structure or physical memory page.  All access goes through the
 *     kernel's own ioremap / memcpy_fromio helpers.
 *  2. Minimal footprint — the module allocates only a small page-sized bounce
 *     buffer; it does NOT map the entire physical address space at once.
 *  3. /proc/iomem awareness — we walk the "System RAM" resources reported by
 *     the kernel so that we only read regions that actually back real DRAM,
 *     skipping MMIO holes, reserved firmware areas, and PCI BARs.
 *  4. Error tolerance — if a single page cannot be read (e.g., hardware-
 *     reserved region that slipped through), we write a zero-filled page
 *     instead, keeping offsets aligned for downstream tools.
 *  5. SHA-256 integrity hash — after the dump completes the module logs a
 *     running SHA-256 digest of every byte written so the examiner has an
 *     integrity anchor without needing to touch the output file again.
 *
 * Usage
 * -----
 *  # Compile
 *  make
 *
 *  # Load — dumps RAM to the given path (default: /tmp/memdump.raw)
 *  sudo insmod memdump.ko dump_path="/evidence/physmem.raw"
 *
 *  # Check kernel log for progress and final SHA-256
 *  dmesg | grep memdump
 *
 *  # Unload
 *  sudo rmmod memdump
 *
 * License : GPL-2.0 (required for access to kernel symbols)
 * Author  : Mohd Alkafaween
 */

#include <linux/module.h>       /* MODULE_*, module_init, module_exit       */
#include <linux/kernel.h>       /* pr_info, pr_err, printk                 */
#include <linux/init.h>         /* __init, __exit macros                   */
#include <linux/fs.h>           /* filp_open, filp_close, kernel_write     */
#include <linux/mm.h>           /* page / memory helpers                   */
#include <linux/io.h>           /* ioremap, iounmap, memcpy_fromio         */
#include <linux/slab.h>         /* kmalloc, kfree                          */
#include <linux/ioport.h>       /* iomem_resource, struct resource         */
#include <linux/crypto.h>       /* crypto_alloc_shash, etc.                */
#include <crypto/hash.h>        /* shash descriptor helpers                */
#include <linux/string.h>       /* memset, sprintf                         */
#include <linux/version.h>      /* LINUX_VERSION_CODE                      */

/* -----------------------------------------------------------------------
 * Module parameters — configurable at load time via insmod / modprobe
 * -------------------------------------------------------------------- */

/* Path where the physical memory image will be written. */
static char *dump_path = "/tmp/memdump.raw";
module_param(dump_path, charp, 0444);   /* read-only after load */
MODULE_PARM_DESC(dump_path,
    "Output file path for the physical memory dump (default: /tmp/memdump.raw)");

/* -----------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------- */
#define MEMDUMP_TAG      "memdump: "          /* prefix for pr_info/pr_err */
#define CHUNK_SIZE       PAGE_SIZE             /* read one page at a time  */
#define PROGRESS_EVERY   (256ULL * 1024 * 1024) /* log every 256 MiB      */

/* -----------------------------------------------------------------------
 * Helper: open a file for writing from kernel space
 *
 * We use filp_open() which is the standard kernel VFS helper.  The file
 * is created with mode 0600 (owner read/write only) to protect the dump.
 * -------------------------------------------------------------------- */
static struct file *open_output_file(const char *path)
{
    struct file *fp;

    fp = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0600);
    if (IS_ERR(fp)) {
        pr_err(MEMDUMP_TAG "failed to open %s (err %ld)\n",
               path, PTR_ERR(fp));
        return NULL;
    }

    pr_info(MEMDUMP_TAG "opened %s for writing\n", path);
    return fp;
}

/* -----------------------------------------------------------------------
 * Helper: write a buffer to the output file at the current position
 *
 * kernel_write() is the in-kernel equivalent of the write(2) syscall.
 * It advances *pos automatically.
 * -------------------------------------------------------------------- */
static int write_chunk(struct file *fp, const void *buf, size_t len,
                       loff_t *pos)
{
    ssize_t ret;

    ret = kernel_write(fp, buf, len, pos);
    if (ret < 0) {
        pr_err(MEMDUMP_TAG "write error at offset 0x%llx (err %zd)\n",
               *pos, ret);
        return (int)ret;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Helper: compute and log SHA-256 over the dump file contents
 *
 * We use the kernel crypto API (shash — synchronous hash) so the examiner
 * gets an integrity value in dmesg without needing user-space tools.
 * -------------------------------------------------------------------- */
static void log_sha256(const u8 *running_hash, unsigned int digest_len)
{
    char hex[65];   /* 32 bytes * 2 hex chars + NUL */
    int i;

    if (digest_len != 32) {
        pr_err(MEMDUMP_TAG "unexpected digest length %u, expected 32\n",
               digest_len);
        return;
    }
    for (i = 0; i < (int)digest_len; i++)
        snprintf(&hex[i * 2], 3, "%02x", running_hash[i]);
    hex[64] = '\0';

    pr_info(MEMDUMP_TAG "SHA-256 of dump: %s\n", hex);
}

/* -----------------------------------------------------------------------
 * Core: walk "System RAM" resources and dump each range
 *
 * The kernel exposes physical address ranges through the iomem_resource
 * tree (the same data visible via /proc/iomem).  We iterate only over
 * top-level children whose name is "System RAM" — this ensures we never
 * attempt to read MMIO or firmware-reserved space.
 *
 * For each page in a System RAM range we:
 *   1. ioremap_cache() the physical page into kernel virtual address space.
 *   2. memcpy_fromio() into our bounce buffer (safe, read-only copy).
 *   3. iounmap() immediately — minimal mapping lifetime.
 *   4. Write the bounce buffer to the output file.
 *   5. Feed the buffer into the running SHA-256 context.
 *
 * If ioremap fails for a particular page we substitute a zeroed page so
 * that the dump file stays correctly aligned.
 * -------------------------------------------------------------------- */
static int dump_physical_memory(void)
{
    struct file *fp = NULL;
    void *bounce = NULL;                 /* page-sized bounce buffer      */
    void __iomem *mapped = NULL;         /* ioremap return                */
    struct resource *res;
    loff_t file_pos = 0;
    u64 total_written = 0;
    u64 next_progress = PROGRESS_EVERY;
    int ret = 0;

    /* --- SHA-256 context setup ---------------------------------------- */
    struct crypto_shash *sha256_tfm = NULL;
    struct shash_desc *sha256_desc  = NULL;
    u8 digest[32];                       /* SHA-256 is 256 bits = 32 B    */

    sha256_tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256_tfm)) {
        pr_err(MEMDUMP_TAG "SHA-256 algorithm not available\n");
        sha256_tfm = NULL;
        /* Non-fatal: we can still dump, just without the hash. */
    }

    if (sha256_tfm) {
        sha256_desc = kmalloc(sizeof(*sha256_desc) +
                              crypto_shash_descsize(sha256_tfm),
                              GFP_KERNEL);
        if (!sha256_desc) {
            pr_err(MEMDUMP_TAG "failed to allocate hash descriptor\n");
            crypto_free_shash(sha256_tfm);
            sha256_tfm = NULL;
        } else {
            sha256_desc->tfm = sha256_tfm;
            crypto_shash_init(sha256_desc);
        }
    }

    /* --- Allocate bounce buffer --------------------------------------- */
    bounce = kmalloc(CHUNK_SIZE, GFP_KERNEL);
    if (!bounce) {
        pr_err(MEMDUMP_TAG "failed to allocate bounce buffer\n");
        ret = -ENOMEM;
        goto out;
    }

    /* --- Open output file --------------------------------------------- */
    fp = open_output_file(dump_path);
    if (!fp) {
        ret = -EIO;
        goto out;
    }

    pr_info(MEMDUMP_TAG "starting physical memory dump …\n");

    /*
     * Walk the top-level iomem_resource children.  Each child whose name
     * matches "System RAM" represents a contiguous range of physical DRAM.
     *
     * NOTE: we hold no locks on the resource tree beyond what the kernel
     * provides for read-side iteration; this is safe because the tree is
     * essentially static after boot.
     */
    for (res = iomem_resource.child; res; res = res->sibling) {
        resource_size_t addr, end;

        /* Only dump real DRAM — skip ACPI, PCI, MMIO, etc. */
        if (strcmp(res->name, "System RAM") != 0)
            continue;

        addr = res->start;
        end  = res->end;

        pr_info(MEMDUMP_TAG "dumping range 0x%llx – 0x%llx (%llu MiB)\n",
                (unsigned long long)addr,
                (unsigned long long)end,
                (unsigned long long)(end - addr + 1) >> 20);

        /*
         * Iterate through the range one page at a time.  Using a small
         * mapping window keeps our virtual address footprint minimal and
         * avoids problems with regions that are not fully contiguous at
         * the CPU page-table level.
         */
        while (addr <= end) {
            size_t to_read = CHUNK_SIZE;

            /* Clamp the last read if the range isn't page-aligned. */
            if (addr + to_read - 1 > end)
                to_read = (size_t)(end - addr + 1);

            /*
             * ioremap_cache: map the physical page as cacheable memory.
             * This is the safest read-only mapping method available in
             * the kernel for regular DRAM.
             */
            mapped = ioremap_cache(addr, to_read);
            if (mapped) {
                /*
                 * memcpy_fromio: the correct way to copy from an
                 * I/O-remapped region.  Under the hood this is a plain
                 * memcpy on most architectures but it satisfies the
                 * kernel's abstraction requirements.
                 */
                memcpy_fromio(bounce, mapped, to_read);
                iounmap(mapped);
                mapped = NULL;
            } else {
                /*
                 * If we cannot map this page, fill with zeroes.  This
                 * keeps the output file correctly aligned so that
                 * downstream analysis tools can still index by physical
                 * address.
                 */
                pr_warn(MEMDUMP_TAG "ioremap failed at 0x%llx, "
                        "writing zeroes\n",
                        (unsigned long long)addr);
                memset(bounce, 0, to_read);
            }

            /* Write the page to the output file. */
            ret = write_chunk(fp, bounce, to_read, &file_pos);
            if (ret)
                goto out;

            /* Feed into the running hash. */
            if (sha256_desc)
                crypto_shash_update(sha256_desc, bounce, to_read);

            total_written += to_read;
            addr          += to_read;

            /* Periodic progress report so the operator knows we're alive */
            if (total_written >= next_progress) {
                pr_info(MEMDUMP_TAG "progress: %llu MiB written\n",
                        (unsigned long long)(total_written >> 20));
                next_progress += PROGRESS_EVERY;
            }

            /* Yield the CPU briefly to avoid soft-lockup warnings. */
            cond_resched();
        }
    }

    pr_info(MEMDUMP_TAG "dump complete — %llu bytes (%llu MiB) written to %s\n",
            (unsigned long long)total_written,
            (unsigned long long)(total_written >> 20),
            dump_path);

    /* Finalize and log the SHA-256 digest. */
    if (sha256_desc) {
        crypto_shash_final(sha256_desc, digest);
        log_sha256(digest, sizeof(digest));
    }

out:
    if (fp && !IS_ERR(fp))
        filp_close(fp, NULL);
    kfree(bounce);
    if (sha256_desc)
        kfree(sha256_desc);
    if (sha256_tfm)
        crypto_free_shash(sha256_tfm);

    return ret;
}

/* -----------------------------------------------------------------------
 * Module entry point
 *
 * The dump runs entirely within module_init so that by the time insmod
 * returns the acquisition is already complete.  This is intentional:
 * there is no persistent runtime footprint once the dump finishes.
 * -------------------------------------------------------------------- */
static int __init memdump_init(void)
{
    pr_info(MEMDUMP_TAG "module loaded — target file: %s\n", dump_path);
    return dump_physical_memory();
}

/* -----------------------------------------------------------------------
 * Module exit — nothing to clean up; the dump file is already closed.
 * -------------------------------------------------------------------- */
static void __exit memdump_exit(void)
{
    pr_info(MEMDUMP_TAG "module unloaded\n");
}

module_init(memdump_init);
module_exit(memdump_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mohd Alkafaween");
MODULE_DESCRIPTION("Physical memory acquisition module for forensic imaging");
MODULE_VERSION("1.0.0");
