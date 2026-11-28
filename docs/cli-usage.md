# Sentinel CLI Usage & Core Engine Notes

This guide covers installing and running the Sentinel CLI, configuring `SENTINEL_HMAC_KEY`, writing `.sentinelignore` rules, integrating exit codes into CI/CD pipelines, and understanding the Person 1 Core Engine design.

---

## 1. Installation

Sentinel requires **Python 3.11 or newer** (`pyproject.toml`).

### Option A: Editable install (recommended)

Installing the package registers the `sentinel` console script (`sentinel.cli:main`):

```bash
pip install -e .
sentinel --help
```

### Option B: Run directly from source without installing

If you are running straight from a cloned repository without `pip install -e .`:

**bash / zsh:**

```bash
PYTHONPATH=src python -m sentinel --help
```

**PowerShell:**

```powershell
$env:PYTHONPATH = "src"
python -m sentinel --help
```

> Both `sentinel <command> ...` and `python -m sentinel <command> ...` invoke the exact same CLI entry point.

---

## 2. Environment Configuration

Sentinel reads runtime secrets and default storage paths from environment variables.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `SENTINEL_HMAC_KEY` | Yes | None | Base64-encoded secret key (**minimum 16 raw bytes**, 32 bytes recommended) used to sign and verify `baseline.json` with HMAC-SHA256. |
| `SENTINEL_STATE_DIR` | No | `~/.sentinel` | Directory storing the default `baseline.json` and `audit.jsonl` files outside the monitored root. |

### Generating `SENTINEL_HMAC_KEY`

Generate a cryptographically random 32-byte (256-bit) base64 key and store it **outside** the monitored directory (never commit it to Git or place it next to monitored files).

**PowerShell (Windows):**

```powershell
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:SENTINEL_HMAC_KEY = [Convert]::ToBase64String($bytes)
```

Or using Python in PowerShell:

```powershell
$env:SENTINEL_HMAC_KEY = python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

**bash / zsh (Linux / macOS / Git Bash):**

```bash
export SENTINEL_HMAC_KEY="$(python3 -c 'import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
```

Or with `openssl`:

```bash
export SENTINEL_HMAC_KEY="$(openssl rand -base64 32)"
```

> **Security Note:** Never reuse the same key across unrelated environments, never write the key inside the monitored folder, and never use a short or guessable key. Keys decoding to fewer than 16 raw bytes are rejected.

### Optional State Directory Override

By default, Sentinel stores state in `~/.sentinel/baseline.json` and `~/.sentinel/audit.jsonl`. To keep separate state per project:

**PowerShell:**

```powershell
$env:SENTINEL_STATE_DIR = "C:/SentinelState/MyApp"
```

**bash / zsh:**

```bash
export SENTINEL_STATE_DIR="./.sentinel-state"
```

(Or pass `--state-dir PATH` on the command line.)

---

## 3. CLI Reference

```text
sentinel <subcommand> [root_path] [options]
python -m sentinel <subcommand> [root_path] [options]
```

If `root_path` is omitted, it defaults to `.` (the current working directory).

### Shared Options (All Subcommands)

| Flag | Default | Description |
| --- | --- | --- |
| `--state-dir PATH` | `SENTINEL_STATE_DIR` or `~/.sentinel` | Directory containing default `baseline.json` and `audit.jsonl`. |
| `--baseline PATH` | `<state_dir>/baseline.json` | Custom path for the signed baseline JSON file. |
| `--audit-log PATH` | `<state_dir>/audit.jsonl` | Custom path for the hash-chained audit log (`.jsonl`). |
| `--ignore-file PATH`, `--ignore PATH` | `<root>/.sentinelignore` (if present) | Custom ignore file overriding `<root>/.sentinelignore`. |
| `--chunk-size BYTES` | `1048576` (1 MiB) | Read buffer size in bytes for streamed SHA-256 file hashing. |
| `--json` | Off | Print machine-readable JSON output to `stdout`. |

---

### `init [root_path]`

Scans the target directory, builds a baseline of all included files, signs it with HMAC-SHA256 using `SENTINEL_HMAC_KEY`, writes the signed baseline envelope, and appends an `INIT` event to the audit log.

```bash
sentinel init C:/Projects/MyApp
```

With custom paths and JSON output:

```bash
sentinel init ./my-app --state-dir ./sentinel-state --ignore-file ./custom.sentinelignore --json
```

---

### `verify [root_path]`

Verifies the existing signed baseline's HMAC-SHA256 signature, scans the target directory, compares current file snapshots against the baseline to detect `ADDED`, `MODIFIED`, `DELETED`, and `MOVED` changes, classifies severities (`LOW`, `MEDIUM`, `HIGH`), and appends a `VERIFY_COMPLETED` event to the audit log.

**Additional `verify` flags:**

| Flag | Description |
| --- | --- |
| `--json-out PATH` | Write the canonical `ScanResult` JSON report to `PATH`. |
| `--html-out PATH` | Write an HTML report generated from the `ScanResult` to `PATH`. |

**Examples:**

```bash
# Basic verification against current directory
sentinel verify

# Verify a specific folder and export JSON + HTML reports
sentinel verify C:/Projects/MyApp \
  --json-out ./reports/scan-result.json \
  --html-out ./reports/scan-report.html

# Print canonical ScanResult JSON directly to stdout
sentinel verify ./my-app --json
```

---

### `accept [root_path]`

Approves the current directory state as the new authoritative signed baseline and logs an `ACCEPT` event to the audit log.

`accept` is **blocked** (exiting non-zero without overwriting the baseline) if:
- The existing baseline is missing or fails HMAC signature verification (`BASELINE_INVALID`).
- The current directory scan encounters filesystem errors (e.g., unreadable files).

**Additional `accept` flags:**

| Flag | Description |
| --- | --- |
| `--scan-id ID` | Optional scan UUID/ID to associate with the acceptance audit record. |
| `--yes`, `-y` | Non-interactive confirmation flag (recommended for scripts and automation). |

**Examples:**

```bash
# Interactive confirmation or scripted approval
sentinel accept ./my-app --yes

# Associate acceptance with a specific verification scan ID
sentinel accept C:/Projects/MyApp --scan-id 7f3c9e2a-4b1d-4e8a-9c6b-2a1d5f8e3b04 -y
```

---

## 4. `.sentinelignore` Rules

By default, Sentinel loads `<root>/.sentinelignore` when present, or the file supplied via `--ignore-file` / `--ignore`.

### Syntax

- UTF-8 text file, one pattern per line.
- Blank lines and lines starting with `#` are ignored.
- Paths are matched using forward slashes (`/`) relative to `root_path` (even on Windows).
- Trailing `/` matches directories and everything inside them (e.g., `node_modules/`).
- Wildcards (`*`, `?`) match filenames or relative paths (e.g., `*.pyc`, `*.log`).

### Example `.sentinelignore`

```gitignore
# Sentinel ignore rules
# One pattern per line. Blank lines and lines starting with # are ignored.
node_modules/
__pycache__/
*.pyc
.env
*.log
dist/
build/
```

---

## 5. Exit Codes & CI/CD Integration

Sentinel uses predictable process exit codes so shell scripts and CI pipelines can distinguish clean runs, integrity drift, and operational/security failures:

| Exit Code | Outcome | Meaning |
| --- | --- | --- |
| `0` | Clean / Success | `verify` finished with status `CLEAN`, or `init` / `accept` succeeded. |
| `1` | Changes Detected | `verify` finished with status `CHANGED` (`ADDED`, `MODIFIED`, `DELETED`, or `MOVED` items found). |
| `2` | Error | `ERROR`, `BASELINE_INVALID` (missing/corrupt/tampered baseline or wrong key), missing/invalid `SENTINEL_HMAC_KEY`, missing `root_path`, or invalid CLI arguments. |

### CI/CD Pipeline Example (bash)

```bash
set +e
sentinel verify ./my-app --json-out ./scan-result.json --html-out ./scan-report.html
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -eq 0 ]; then
  echo "Integrity check passed (CLEAN)."
elif [ "$EXIT_CODE" -eq 1 ]; then
  echo "File changes detected (CHANGED). Review scan-report.html."
  exit 1
else
  echo "Sentinel failed to verify integrity (exit code $EXIT_CODE)."
  exit 2
fi
```

---

## 6. Person 1 Core Module Technical Notes

The Core Engine lives under `src/sentinel/core/` and provides importable, side-effect-free building blocks shared by the CLI, FastAPI backend, and GitHub Action.

### Module Layout & Public Interfaces

| Module | Public Functions / Types | Responsibility |
| --- | --- | --- |
| `src/sentinel/core/models.py` | `FileSnapshot`, `ScanError`, `ChangeRecord`, `BaselineData`, `ScanResult`, `ChangeStatus`, `SeverityLevel`, `ScanStatus` | Canonical dataclasses, status/severity string enums, path normalization helpers, and deterministic JSON dict serializers. |
| `src/sentinel/core/ignore.py` | Ignore rule loader and path matcher | Parses `.sentinelignore` rules and filters relative paths during traversal. |
| `src/sentinel/core/scanner.py` | `scan_directory(root, ignore_file=None, chunk_size=1_048_576) -> tuple[list[FileSnapshot], list[ScanError]]` | Walks `root`, applies ignore rules, collects `size_bytes` and `mtime_ns`, and computes streamed SHA-256 digests while capturing I/O errors separately. |
| `src/sentinel/core/baseline.py` | `build_baseline(root, snapshots) -> BaselineData` | Constructs a `BaselineData` payload (`schema_version=1`, UTC ISO-8601 `created_at`, `hash_algorithm="sha256"`, normalized `root_path`, and keyed `FileSnapshot` map). |
| `src/sentinel/core/diff.py` | `compare_snapshots(baseline, current_snapshots, scan_errors=None) -> ScanResult` | Compares baseline entries against current snapshots, detects `ADDED`, `MODIFIED`, `DELETED`, and `MOVED` files, populates summary counts, and prevents `CLEAN` status when errors exist. |
| `src/sentinel/cli.py` | `main()` | Parses CLI arguments, loads `AppSettings`, invokes `application.initialize` / `verify` / `accept`, formats output, and maps outcomes to exit codes `0`, `1`, `2`. |

### Streamed / Chunked SHA-256 Hashing

- Files are read sequentially in binary mode using `chunk_size` (default `1,048,576` bytes = 1 MiB, configurable via `--chunk-size`).
- Hashing never loads an entire large artifact into memory at once, keeping memory usage bounded even for multi-gigabyte build artifacts or disk images.

### Path Normalization & Windows Case Handling

- Stored relative `path` values always use forward slashes (`/`), even on Windows (e.g., `src/main.py`), and never store leading `./` or absolute paths inside `files`.
- `root_path` is normalized with forward slashes (e.g., `C:/Projects/MyApp`).
- Original display casing is preserved, while Windows-style roots/paths are compared case-insensitively and case-only collisions are surfaced explicitly rather than silently collapsing two files into one snapshot.

### Move Detection Heuristic

During `compare_snapshots`:

1. Files present in both the baseline and current scan are compared by content (`sha256`) and metadata; unchanged hashes produce no change record, while differing hashes produce `MODIFIED`.
2. Remaining paths present only in the baseline are initial `DELETED` candidates, and paths present only in the current scan are initial `ADDED` candidates.
3. Unmatched `DELETED` and `ADDED` candidates are grouped by `(size_bytes, sha256)` and paired 1-to-1 into `MOVED` records.
4. When multiple files share the same `(size_bytes, sha256)` (such as identical `__init__.py` or placeholder files), move pairing prioritizes exact `mtime_ns` + basename matches, then exact `mtime_ns`, then matching basename with nearest `mtime_ns`; any extra unmatched entries remain `DELETED` or `ADDED`.
5. Each `MOVED` record sets `path` and `new_path` to the destination path and preserves the source path in `old_path`.

### Error Handling & Incomplete Scans

- Permission errors (`FILE_ACCESS_DENIED`), unreadable files, and path collision errors are captured as `ScanError` objects rather than silently ignored.
- Any scan with `errors` cannot report `status: "CLEAN"`.
- `accept` refuses to sign a new baseline whenever the scan produces errors or the existing baseline fails verification.

---

## 7. Sample Artifacts

Reference JSON files matching Sections 7.1–7.5 of `SENTINEL_GLOBAL_RULES.md` are available under `docs/samples/`:

- [`docs/samples/sample-baseline.json`](samples/sample-baseline.json) — Canonical signed baseline envelope (`schema_version: 1`, `hash_algorithm: "sha256"`, `signature.algorithm: "hmac-sha256"`).
- [`docs/samples/sample-scan-result.json`](samples/sample-scan-result.json) — Canonical `ScanResult` demonstrating `ADDED`, `MODIFIED`, `DELETED`, and `MOVED` change records against the sample baseline.

For documentation/testing only, `sample-baseline.json` was signed over canonical UTF-8 JSON (`sort_keys=True, separators=(",", ":"), ensure_ascii=False`) using the non-secret example key:

- Raw bytes: `b"example-sample-key-for-docs-only"` (32 bytes)
- Base64 (`SENTINEL_HMAC_KEY`): `ZXhhbXBsZS1zYW1wbGUta2V5LWZvci1kb2NzLW9ubHk=`

> **Warning:** Never use this sample key for real directories or deployments.

---

## 8. Troubleshooting

| Symptom | Cause | Resolution |
| --- | --- | --- |
| `SENTINEL_HMAC_KEY is not set` (exit code `2`) | Environment variable missing in the current shell session. | Export `SENTINEL_HMAC_KEY` with a valid base64-encoded key (>= 16 raw bytes). |
| `SENTINEL_HMAC_KEY is not valid base64` or key too short (exit code `2`) | Malformed base64 string or decoded key shorter than 16 bytes. | Regenerate a 32-byte key using the commands in Section 2. |
| `BASELINE_INVALID` (exit code `2`) | Baseline file is missing, was modified outside `init`/`accept`, or you are using the wrong `SENTINEL_HMAC_KEY`. | Verify you pointed to the right `--baseline` / `--state-dir` and `SENTINEL_HMAC_KEY`; investigate potential baseline tampering before re-initializing. |
| `accept` blocked (`filesystem errors` or `baseline invalid`) | Unreadable files during scan or invalid existing baseline. | Resolve file permission issues or verify the active key/baseline before retrying `sentinel accept`. |
| `ERROR` with `FILE_ACCESS_DENIED` (exit code `2`) | Locked or unreadable file inside `root_path`. | Check file permissions/locks or add temporary/unreadable system artifacts to `.sentinelignore` if appropriate. |
| `sentinel: command not found` | Package not installed in the active environment, or venv `bin`/`Scripts` not on `PATH`. | Run `pip install -e .` inside your active virtual environment, or invoke `PYTHONPATH=src python -m sentinel ...`. |
