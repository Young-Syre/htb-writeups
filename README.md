# Hack The Box — Retired Machine Writeups

![Machines](https://img.shields.io/badge/Machines-24-blue?style=flat-square) ![Status](https://img.shields.io/badge/All%20machines-Retired-success?style=flat-square) ![Flags](https://img.shields.io/badge/Flags-Omitted-lightgrey?style=flat-square) ![License](https://img.shields.io/badge/License-CC%20BY%204.0-informational?style=flat-square)

Writeups for 24 retired Hack The Box machines, by **David Nichols** ([Young-Syre](https://github.com/Young-Syre), HTB handle `YoungSyre`). These were written while solving the machines rather than reconstructed afterwards, so they keep the real shape of the work: the version fingerprint that pointed at the CVE, the payload that didn't fire on the first attempt, and the dead ends that were worth the time to rule out. Every machine here is retired, and flag values are deliberately omitted in line with HTB's policy on publishing solutions.

## At a Glance

**24 machines** — 17 Linux, 7 Windows — released between **17 December 2022** and **30 May 2026**.

| Difficulty | Count |
|---|---|
| Easy | 8 |
| Medium | 13 |
| Hard | 3 |

| OS | Count |
|---|---|
| Linux | 17 |
| Windows | 7 |

The work is concentrated in HTB Seasons 8.5 through 10 (September 2025 onward), with three earlier Easy machines included.

## Index

Newest first.

<details open>
<summary><b>2026</b> — 13 machines</summary>

| Machine | OS | Difficulty | Released | Key techniques |
|---|---|---|---|---|
| [DevHub](machines/DevHub/README.md) | Linux | Medium | 2026-05-30 | MCPJam Inspector RCE, Jupyter token in process args, hidden MCP tool file-read as root |
| [Reactor](machines/Reactor/README.md) | Linux | Easy | 2026-05-23 | CVE-2025-55182 React2Shell, Node `--inspect` CDP privesc, ws-free WebSocket client |
| [SmartHire](machines/SmartHire/README.md) | Linux | Medium | 2026-05-16 | CVE-2024-37054 MLflow pickle RCE, `site.addsitedir()` `.pth` execution |
| [Logging](machines/Logging/README.md) | Windows | Medium | 2026-04-18 | Shadow Credentials on a gMSA, DLL sideload via scheduled task, `mimikatz vault::cred`, Protected Users |
| [DevArea](machines/DevArea/README.md) | Linux | Medium | 2026-03-28 | CVE-2022-46364 MTOM XOP SSRF, Hoverfly middleware RCE, world-writable `/usr/bin/bash` |
| [VariaType](machines/VariaType/README.md) | Linux | Medium | 2026-03-14 | fonttools varLib PHP injection, FontForge ZIP filename injection, setuptools `%2F` traversal |
| [CCTV](machines/CCTV/README.md) | Linux | Easy | 2026-03-07 | ZoneMinder default creds, bcrypt crack, CVE-2025-60787 MotionEye injection as root |
| [Interpreter](machines/Interpreter/README.md) | Linux | Medium | 2026-02-21 | CVE-2023-43208 Mirth XStream RCE, Python f-string injection as root |
| [WingData](machines/WingData/README.md) | Linux | Easy | 2026-02-14 | CVE-2025-47812 null-byte Lua injection, salted SHA-256 crack, CVE-2025-4517 tarfile bypass |
| [Pterodactyl](machines/Pterodactyl/README.md) | Linux | Medium | 2026-02-07 | CVE-2025-49132 LFI, `pearcmd.php` argv injection, CVE-2025-6018 + CVE-2025-6019 udisks2 chain |
| [Facts](machines/Facts/README.md) | Linux | Easy | 2026-01-31 | CVE-2024-46987 Camaleon path traversal, SSH key passphrase crack, `sudo facter` custom fact |
| [Overwatch](machines/Overwatch/README.md) | Windows | Medium | 2026-01-24 | ADIDNS poisoning, SQL linked-server credential capture, SOAP command injection |
| [Browsed](machines/Browsed/README.md) | Linux | Medium | 2026-01-10 | Malicious Chrome extension to reach localhost, bash arithmetic injection, `.pyc` cache poisoning |

</details>

<details open>
<summary><b>2025</b> — 8 machines</summary>

| Machine | OS | Difficulty | Released | Key techniques |
|---|---|---|---|---|
| [Gavel](machines/Gavel/README.md) | Linux | Medium | 2025-11-29 | Exposed `.git`, PHP rule-injection RCE, YAML code execution, `disable_functions` bypass |
| [Fries](machines/Fries/README.md) | Windows | Hard | 2025-11-22 | NFS GID spoofing, Docker TLS CN authz bypass, PWM LDAP downgrade capture, ADCS ESC6 + ESC16 |
| [Eighteen](machines/Eighteen/README.md) | Windows | Easy | 2025-11-15 | MSSQL hash crack, ligolo-ng tunnel, BadSuccessor dMSA escalation, DCSync |
| [NanoCorp](machines/NanoCorp/README.md) | Windows | Hard | 2025-11-08 | bloodyAD password reset, CVE-2024-0670 CheckMK PID brute-force, DFSCoerce NTLM relay |
| [Breach](machines/Breach/README.md) | Windows | Medium | 2025-10-09 | SCF hash capture on a writable share, Kerberoasting, Silver Ticket, GodPotato |
| [Bamboo](machines/Bamboo/README.md) | Linux | Medium | 2025-10-07 | Squid proxy pivoting, CVE-2023-27350 PaperCut auth bypass + RCE, writable `PATH` directory |
| [DarkZero](machines/DarkZero/README.md) | Windows | Hard | 2025-10-04 | MSSQL linked-server sysadmin, CVE-2024-30088 kernel LPE, unconstrained delegation TGT capture |
| [HackNet](machines/HackNet/README.md) | Linux | Medium | 2025-09-13 | Django SSTI data exposure, pickle cache poisoning, GPG passphrase crack |

</details>

<details>
<summary><b>2023</b> — 2 machines</summary>

| Machine | OS | Difficulty | Released | Key techniques |
|---|---|---|---|---|
| [Sau](machines/Sau/README.md) | Linux | Easy | 2023-07-08 | CVE-2023-27163 Request Baskets SSRF, Maltrail command injection, `less` pager escape |
| [PC](machines/PC/README.md) | Linux | Easy | 2023-05-20 | gRPC enumeration, UNION SQL injection over gRPC, CVE-2023-0297 Js2Py sandbox escape |

</details>

<details>
<summary><b>2022</b> — 1 machine</summary>

| Machine | OS | Difficulty | Released | Key techniques |
|---|---|---|---|---|
| [Soccer](machines/Soccer/README.md) | Linux | Easy | 2022-12-17 | Tiny File Manager default creds, WebSocket blind SQLi, `doas` dstat plugin injection |

</details>

## How These Are Written

Each page opens with the machine's verified metadata and a short summary of the actual path, then follows the engagement in order: reconnaissance, the foothold, lateral movement, and privilege escalation.

A few conventions worth knowing before you read one:

- **Commands are the ones that were actually run.** Where a payload needed two attempts, or a tool needed patching to work, the writeup says so rather than presenting a clean version that never existed.
- **Dead ends are documented.** Most pages carry an explicit dead-ends section. Ruling a path out is a result, and on several of these machines — the ADCS template on Logging, the MinIO buckets on Facts — the excluded path was the more obvious-looking one.
- **Root causes over recipes.** Where a bug has an interesting mechanism (`site.addsitedir()` executing `.pth` imports, `realpath()` giving up past `PATH_MAX`, PHP's argv splitting on `+`), the writeup explains why it works, not just which PoC to clone.
- **Credentials, hashes and keys belonging to the machines are kept**, because they are part of the technical narrative and the machines are retired. Flag values are not.
- **Lab IP addresses are left as they were** (`10.10.x.x`, `10.129.x.x`). They are reassigned on every spawn and mean nothing outside a live session.

## Ethics and Policy

- **Every machine listed here is retired.** Each was verified as retired against the Hack The Box API before publication. Nothing in this repository describes an active machine.
- **Flag values are deliberately omitted.** Where a flag appeared in captured output it has been replaced with `[flag redacted]`. HTB flags are per-spawn or per-user anyway, so a published value is worthless to a reader and against the spirit of the platform either way.
- **None of this applies to active machines.** Publishing a path through a machine that is still in rotation spoils it for everyone currently working on it. If you are looking at an active box, the writeups here are the wrong resource.
- **These are deliberately vulnerable lab targets.** The techniques are documented for learning and for defensive context. Running any of them against a system you do not own or have written authorisation to test is unlawful in most jurisdictions.

## License

Prose and documentation in this repository are licensed under [Creative Commons Attribution 4.0 International](LICENSE) (CC BY 4.0) — © 2026 David Nichols. Third-party exploits and tools referenced by link remain under their own licenses.
