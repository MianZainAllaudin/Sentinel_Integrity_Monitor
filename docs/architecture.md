# Sentinel Project Architecture

This document describes the full architecture of the Sentinel artifact integrity monitoring tool, including all modules, data flow, and component relationships.

## Overview

Sentinel is a Windows-focused file integrity and tamper-detection application. It monitors a trusted folder for unauthorized changes by recording a cryptographic baseline (file paths, sizes, modification times, and SHA-256 hashes), then verifying the folder against that baseline on demand. Changes are classified by severity and reported through a console CLI, a FastAPI backend, a Vue 3 dashboard, JSON/HTML reports, and webhook alerts. The baseline is protected by HMAC-SHA256 signatures, and every scan is recorded in a hash-chained audit log.

The system is built by three team members, each owning distinct modules:

- Person 1: Core Engine and CLI (scanning, hashing, baseline creation, diff, ignore rules)
- Person 2: Security and CI/CD (HMAC signing, audit log, severity classification, GitHub Action, exit codes)
- Person 3: Backend, Vue Dashboard, Reports and Integration (FastAPI API, Vue frontend, reports, webhooks, integration)

## Module Layout

```
sentinel-project/
|-- src/sentinel/
|   |-- __init__.py          Package entry and version
|   |-- __main__.py          python -m sentinel support
|   |-- cli.py               Person 1: command-line interface (init/verify/accept)
|   |-- application.py       Person 3: INIT/VERIFY/ACCEPT orchestration layer
|   |
|   |-- core/                Person 1: pure engine, no imports from higher layers
|   |   |-- __init__.py
|   |   |-- models.py        Shared dataclasses and canonical serializers
|   |   |-- scanner.py       Directory traversal, streamed SHA-256, ignore rules
|   |   |-- baseline.py      BaselineData construction, atomic JSON save/load
|   |   |-- diff.py          Change detection (ADDED/MODIFIED/DELETED/MOVED)
|   |   `-- ignore.py        Gitignore-style .sentinelignore matcher
|   |
|   |-- security/            Person 2: baseline signing and audit chain
|   |   |-- __init__.py
|   |   |-- baseline_signer.py  HMAC-SHA256 sign/verify of baseline envelope
|   |   `-- audit_log.py   Hash-chained JSONL audit log append/verify
|   |
|   |-- integrations/        Person 2: severity classification
|   |   |-- __init__.py
|   |   `-- severity.py    classify_change/apply_severity with sensitive-path patterns
|   |
|   |-- reporting/           Person 3: report generation and webhook delivery
|   |   |-- __init__.py
|   |   |-- json_report.py  Canonical ScanResult JSON export
|   |   |-- html_report.py  HTML report with user-string escaping
|   |   `-- webhook.py      Discord/Slack alert sender (safe failure)
|   |
|   |-- api/                 Person 3: FastAPI backend
|   |   |-- __init__.py
|   |   |-- main.py         FastAPI app with CORS
|   |   |-- routes.py       /api/v1 endpoint definitions
|   |   |-- schemas.py      Pydantic request/response models
|   |   `-- services.py     Thin wrappers calling application layer
|   |
|   `-- config/              Person 3: settings
|       |-- __init__.py
|       `-- settings.py     AppSettings, load_settings from environment
|-- frontend/                Person 3: Vue 3 dashboard
|   |-- src/
|   |   |-- api/client.js   Single HTTP client for all API calls
|   |   |-- components/     (empty, reserved for future components)
|   |   |-- views/
|   |   |   |-- Dashboard.vue   Verify/init/accept panel + change table
|   |   |   `-- History.vue     Scan history list and detail view
|   |   |-- App.vue           Shell with navigation
|   |   `-- main.js           Vue app mount point
|   |-- package.json
|   `-- vite.config.js
|-- tests/
|   |-- unit/core/           Person 1 tests (scanner, baseline, diff, models, ignore)
|   |-- unit/security/       Person 2 tests (signer, audit log, severity, ci_runner)
|   |-- unit/reporting/      Person 3 tests (json/html/webhook reports)
|   `-- integration/         Shared end-to-end tests (api, security flow)
|-- docs/
|   |-- architecture.md      This file
|   |-- api-contract.md      Endpoint and schema reference
|   |-- cli-usage.md         CLI flags and `.sentinelignore` syntax
|   |-- security_and_ci.md   Security setup, exit codes, CI design
|   |-- threat-model.md      Threat model and limitations
|   `-- samples/             Canonical JSON examples (baseline, scan result)
|-- .github/
|   `-- workflows/
|       `-- sentinel.yml     GitHub Action for push/PR integrity checks
|-- ci/
|   `-- sentinel-ci.ignore   CI ignore rules sourced from trusted base tree
|-- pyproject.toml           Package metadata and console script entry point
|-- requirements.txt         Python dependencies
`-- README.md
```

## Architecture Diagram

The diagram below shows the logical layers and how data flows between them. Boxes with the same owner color belong to the same team member. Arrows show dependency direction (lower layers never import higher layers).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         USER / DEVELOPER / CI PIPELINE                      │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
      ┌──────────────▼──────────────┐
      │         CLI (Person 1)      │  sentinel init / verify / accept
      │   src/sentinel/cli.py       │
      └──────────────┬──────────────┘
                     │ calls
      ┌──────────────▼──────────────┐
      │  FastAPI Backend (Person 3) │  POST /api/v1/scans
      │   src/sentinel/api/         │  POST /api/v1/accept
      └──────────────┬──────────────┘
                     │ calls
      ┌──────────────▼──────────────┐
      │  Application Layer (Person 3)│
      │  src/sentinel/application.py│  initialize / verify / accept
      └──────────────┬──────────────┘
                     │
      ┌──────────────┼──────────────┐
      │              │              │
      ▼              ▼              ▼
┌───────────┐  ┌─────────────┐ ┌──────────────┐
│ Core Engine│ │  Security   │ │  Reporting   │
│ (Person 1) │ │  (Person 2) │ │  (Person 3)  │
│            │ │             │ │              │
│ scanner.py │ │ signer.py   │ │ json_report.py│
│ baseline.py│ │ audit_log.py│ │ html_report.py│
│ diff.py    │ │ severity.py │ │ webhook.py   │
│ ignore.py  │ │             │ │              │
│ models.py  │ └──────┬──────┘ └──────┬──────┘
└──────┬─────┘           │             │
      │                   │             │
      └───────────────────┴─────────────┘
              │
      ┌───────▼───────┐
      │   FILE SYSTEM │  Monitored root directory
      │   (target)    │  Scanned, hashed, compared
      └───────────────┘

External connections:

FastAPI Backend (127.0.0.1:8000) <--HTTP--> Vue Dashboard (localhost:5173)
                                            frontend/src/api/client.js

GitHub Action (ubuntu-latest)
  -> checkout trusted base commit
  -> checkout tree under test
  -> install Sentinel from base commit only
  -> run ci_runner (exit code mapping)
  -> upload evidence artifacts

State directory (outside monitored root):
  baseline.json   Signed baseline envelope (HMAC-SHA256)
  audit.jsonl     Hash-chained append-only audit log
```

## Data Flow

### INIT (create baseline)

1. User runs `sentinel init --root <path>` or POST `/api/v1/scans` from the dashboard.
2. CLI or API calls `application.initialize(root, settings)`.
3. `scan_directory` walks the root, applies `.sentinelignore` rules, streams each file through SHA-256 in 1 MiB chunks, and returns snapshots plus any access errors.
4. `build_baseline` validates snapshots, rejects path collisions, sorts paths, and produces `BaselineData` with UTC timestamp and schema version 1.
5. `sign_baseline` canonicalizes the payload JSON (sorted keys, compact separators, UTF-8) and computes HMAC-SHA256 over those bytes. The signature is stored in an envelope next to the payload, never inside it.
6. The envelope is written atomically to `baseline.json` (temp file then replace).
7. An `INIT` event is appended to `audit.jsonl` with a chained hash.
8. Exit code 0 on success, 2 on configuration or path error.

### VERIFY (detect changes)

1. User runs `sentinel verify --root <path>` or clicks Verify in the dashboard.
2. `application.verify` loads and verifies the baseline signature first. If invalid, returns `BASELINE_INVALID` and stops.
3. `scan_directory` re-scans the root and returns current snapshots plus scan errors.
4. `compare_snapshots` matches baseline against current files:
   - Same path, same hash and size: no change.
   - Same path, different hash or size: MODIFIED.
   - In baseline only: DELETED candidate.
   - In current only: ADDED candidate.
   - DELETED + ADDED with same `(size_bytes, sha256)` are paired into MOVED records using mtime and basename heuristics.
5. `apply_severity` classifies each change as HIGH, MEDIUM, or LOW based on sensitive-path patterns owned by Person 2.
6. A `VERIFY_COMPLETED` event is appended to the audit log.
7. Exit code 0 for CLEAN, 1 for CHANGED, 2 for ERROR or BASELINE_INVALID.
8. Optional `--json-out` and `--html-out` write reports from the same `ScanResult`.

### ACCEPT (approve changes)

1. User runs `sentinel accept --root <path>` or confirms in the dashboard dialog.
2. `application.accept` verifies the existing baseline signature first. If invalid, accept is blocked and the baseline is never overwritten.
3. The directory is re-scanned immediately before writing to reduce the window for late changes.
4. If the scan has errors, accept is blocked.
5. A new baseline is built from current snapshots, signed with HMAC-SHA256, and written atomically.
6. An `ACCEPT` event is appended to the audit log.
7. Exit code 0 on success, 2 on blocked accept.

## Layer Rules (contract section 3.3)

- Core code never imports FastAPI, Vue, HTML templates, GitHub Actions, or webhook code.
- Security code may use core data models, but core never depends on security.
- Reporting code consumes a completed `ScanResult`; it never re-scans or invents changes.
- The API calls shared services; it does not duplicate CLI business logic.
- The Vue frontend calls only the API; it never reads baseline files, audit logs, HMAC keys, or arbitrary local files.
- The GitHub Action invokes the Sentinel CLI/package; it does not contain a second scanner.
- Lower-level modules never import higher-level API or UI modules (no circular imports).

## State Storage

By default, runtime state lives outside the monitored root in `~/.sentinel/` (overridable via `SENTINEL_STATE_DIR`):

- `baseline.json` — signed envelope, one per monitored root profile
- `audit.jsonl` — append-only JSONL audit log, one line per event

Generated reports, local keys, and scan history are excluded from Git via `.gitignore`.

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Core engine | Python | 3.11+ |
| Backend | FastAPI + uvicorn | latest |
| Frontend | Vue 3 + Vite | 3.x / 5.x |
| Frontend language | JavaScript | ES modules |
| Testing | pytest | latest |
| Packaging | setuptools / pyproject.toml | — |
| CI runner | GitHub Actions | ubuntu-latest, Python 3.11 |

## Integration Points

- CLI and FastAPI share `src/sentinel/application.py` so INIT/VERIFY/ACCEPT is implemented exactly once.
- The Vue dashboard calls only `GET/POST /api/v1/*` through a single `api/client.js` module.
- JSON keys use `snake_case` across Python, API, and reports; Vue maps to `camelCase` internally only.
- The GitHub Action installs Sentinel from the trusted base commit and never executes pull-request code.
