# Sentinel: Artifact Integrity Monitoring

**Sentinel** is a Windows file integrity and tamper-detection tool that alerts users when files or build artifacts have changed without authorization. By signing baselines with HMAC-SHA256 and maintaining a hash-chained audit log, Sentinel ensures that an attacker cannot alter or clear historical logs without detection. It integrates natively into CI/CD pipelines via a custom GitHub Action to safeguard critical software supply chain components.

---

## Key Features

* **File Integrity Monitoring:** Records file path, size, modification time, and SHA-256 hashes to detect modified, deleted, added, and moved files.
* **Anti-Tampering Controls:** Protects the trusted baseline using an HMAC-SHA256 signature and records scans in a sequential, hash-chained audit log.
* **Supply Chain Security:** Integrates with GitHub Actions to audit workflow definitions, Dockerfiles, and lockfiles, failing builds automatically on unexpected variations.
* **Web UI Dashboard:** Features a local web-based dashboard built with Vue and backed by Python to visually inspect configurations and run scans.
* **Flexible Alerting:** Generates results as console logs, JSON files, structured HTML reports, or real-time Slack and Discord webhook alerts.

---

## Commands

* **`INIT`** - Registers a target folder and builds the initial cryptographically signed baseline.
* **`VERIFY`** - Scans the folder structure against the baseline to discover tampered or updated items.
* **`ACCEPT`** - Approves legitimate file mutations and signs a new authoritative baseline.

---

## CLI Quick Start

1. **Install or run from source** (Python 3.11+):

   ```bash
   pip install -e .
   # Or run without installing: PYTHONPATH=src python -m sentinel --help
   ```

2. **Configure `SENTINEL_HMAC_KEY`** (base64 key >= 16 raw bytes, stored outside the monitored folder):

   ```powershell
   # PowerShell
   $env:SENTINEL_HMAC_KEY = python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
   ```

   ```bash
   # bash / zsh
   export SENTINEL_HMAC_KEY="$(python3 -c 'import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
   ```

3. **Initialize, verify, and accept changes**:

   ```bash
   # Create the initial signed baseline
   sentinel init ./my-app

   # Verify directory integrity (optionally export JSON/HTML reports)
   sentinel verify ./my-app --json-out ./scan-result.json --html-out ./scan-report.html

   # Approve legitimate changes as the new signed baseline
   sentinel accept ./my-app --yes
   ```

4. **Exit codes**:
   * `0` — `CLEAN` (`verify`) or successful `init` / `accept`
   * `1` — `CHANGED` (one or more changes detected by `verify`)
   * `2` — `ERROR` / `BASELINE_INVALID` (tampered/missing baseline, invalid key, filesystem/argument error)

For full command flags, `.sentinelignore` syntax, move detection notes, and troubleshooting, see [docs/cli-usage.md](docs/cli-usage.md) and the schema examples in [docs/samples/](docs/samples/) ([sample-baseline.json](docs/samples/sample-baseline.json), [sample-scan-result.json](docs/samples/sample-scan-result.json)).

---


