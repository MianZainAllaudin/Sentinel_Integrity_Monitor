# Sentinel: Artifact Integrity Monitoring

Sentinel is a Windows file integrity and tamper-detection tool. Register a trusted folder, build a signed baseline of file paths, sizes, modification times, and SHA-256 hashes, then verify the folder later to detect modified, deleted, added, and moved files. The baseline is protected with HMAC-SHA256 signatures and every scan is recorded in a hash-chained audit log. Results are delivered through a console CLI, a local Vue 3 dashboard backed by FastAPI, JSON and HTML reports, and webhook alerts. A GitHub Action integrates Sentinel into CI/CD pipelines.

Built by a three-person team under SENTINEL_GLOBAL_RULES.md. Python 3.11+, FastAPI, Vue 3 + Vite, JavaScript.

## Repository Structure

```
sentinel-project/
|-- src/sentinel/            Python package (shared engine, API, reporting, config)
|-- frontend/                Vue 3 + Vite dashboard
|-- tests/                   Unit and integration tests (pytest)
|-- docs/                    Architecture, API contract, CLI usage, threat model, security analysis
|-- .github/workflows/       GitHub Action for CI integrity checks
|-- ci/                      CI ignore rules
|-- pyproject.toml           Package metadata and console script entry point
|-- requirements.txt         Python dependencies
|-- .gitignore
|-- .sentinelignore
`-- README.md
```

## Prerequisites

- Python 3.11 or newer
- Node.js and npm (for the frontend dashboard)
- Git (optional, for version control)

## Installation

### 1. Clone or open the project

Open the folder containing this README in your terminal.

### 2. Install Python dependencies

```powershell
pip install -r requirements.txt
pip install -e .
```

The editable install registers the `sentinel` console command. You can also run without installing:

```powershell
PYTHONPATH=src python -m sentinel --help
```

### 3. Install frontend dependencies

```powershell
cd frontend
npm install
cd ..
```

## Configuration

### Generate an HMAC key

Sentinel requires `SENTINEL_HMAC_KEY`, a Base64-encoded secret key (minimum 16 raw bytes, 32 bytes recommended). Store it outside the monitored folder and never commit it to Git.

PowerShell:

```powershell
$env:SENTINEL_HMAC_KEY = python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

bash / zsh:

```bash
export SENTINEL_HMAC_KEY="$(python3 -c 'import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
```

### Optional: state directory

By default, baseline and audit log files are stored in `~/.sentinel/`. Override with:

```powershell
$env:SENTINEL_STATE_DIR = "C:/SentinelState/MyApp"
```

## Running the Backend (FastAPI)

```powershell
python -m sentinel.api.main
```

or with uvicorn:

```powershell
uvicorn sentinel.api.main:app --reload --port 8000
```

The API binds to `127.0.0.1:8000` by default. Endpoints are under `/api/v1`:

- `GET /api/v1/health` — health check
- `POST /api/v1/scans` — body `{ "root_path": "..." }`, starts a verify scan
- `GET /api/v1/scans` — list recent scans
- `GET /api/v1/scans/{scan_id}` — one scan result
- `POST /api/v1/accept` — body `{ "scan_id": "...", "confirm": true }`

## Running the Frontend (Vue 3 Dashboard)

```powershell
cd frontend
npm run dev
```

Open http://localhost:5173. The dashboard calls the FastAPI backend at `http://localhost:8000` by default. Override with the `VITE_API_BASE` environment variable if needed.

To build for production:

```powershell
cd frontend
npm run build
```

## Using the CLI

```powershell
# Initialize a signed baseline for a folder
sentinel init C:/Projects/MyApp

# Verify the folder against the baseline (export JSON and HTML reports)
sentinel verify C:/Projects/MyApp --json-out ./scan-result.json --html-out ./scan-report.html

# Approve legitimate changes as the new baseline
sentinel accept C:/Projects/MyApp --yes
```

Exit codes:

- `0` — clean or successful operation
- `1` — changes detected
- `2` — invalid arguments, missing key, baseline invalid, or filesystem error

## Running Tests

```powershell
python -m pytest
```

All tests must pass before considering a change complete. Frontend tests are not required; the frontend is verified by `npm run build`.

## End-to-End Test Flow (use a temp folder, never your real project)

```powershell
# 1. Create a temp test folder
New-Item -ItemType Directory -Path "C:\temp\sentinel-test"
Set-Location "C:\temp\sentinel-test"

# 2. Add a file
New-Item -ItemType File -Path "hello.txt" -Value "initial content"

# 3. Initialize the baseline
sentinel init .

# 4. Verify (expect CLEAN, exit 0)
sentinel verify .

# 5. Modify the file
Add-Content -Path "hello.txt" -Value "tampered content"

# 6. Verify again (expect CHANGED / MODIFIED, exit 1)
sentinel verify .

# 7. Accept the change as the new baseline
sentinel accept . --yes

# 8. Verify again (expect CLEAN against the new baseline, exit 0)
sentinel verify .
```

## Dashboard Test Flow

1. Start the backend (`python -m sentinel.api.main`).
2. Start the frontend (`cd frontend && npm run dev`).
3. Open http://localhost:5173.
4. Enter a folder path in the Dashboard view.
5. Click Verify. You should see a status badge (CLEAN/CHANGED/ERROR/BASELINE_INVALID), summary counts, and a change table.
6. Make a change to a file in the monitored folder, then click Verify again.
7. Click Accept Changes and confirm in the dialog to approve the change.
8. Switch to History to view scan records and details.

## .sentinelignore Rules

Create a `.sentinelignore` file in the monitored root. One pattern per line. Blank lines and `#` comments are ignored. Example:

```
node_modules/
__pycache__/
*.pyc
.env
*.log
dist/
build/
```

## Documentation

- `docs/architecture.md` — full project architecture and data flow
- `docs/api-contract.md` — FastAPI endpoint reference
- `docs/cli-usage.md` — CLI flags and `.sentinelignore` syntax
- `docs/threat-model.md` — threat model and limitations
- `docs/security_analysis.md` — security findings, performance, and lessons
- `docs/samples/sample-baseline.json` — example signed baseline
- `docs/samples/sample-scan-result.json` — example scan result

## Out of Scope

Real-time monitoring, ACL tracking, GitHub API commit checks, built-in scheduler, and email alerts are not part of this project.
