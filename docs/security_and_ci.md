# Security and CI/CD: setup and behaviour (Person 2)

## Modules
| File | Purpose |
|---|---|
| `src/sentinel/security/baseline_signer.py` | `sign_baseline`, `verify_baseline`; HMAC-SHA256 over canonical JSON of the payload; security exceptions with stable error codes |
| `src/sentinel/security/audit_log.py` | `append_audit_event`, `verify_audit_chain`; JSONL log chained with SHA-256 |
| `src/sentinel/integrations/severity.py` | `classify_change` (alias `classify_severity`), `apply_severity`; the only list of sensitive paths |
| `src/sentinel/ci_runner.py` | CI entry point: builds a trusted baseline, verifies the tree under test, maps the result to an exit code |
| `.github/workflows/sentinel.yml` | the GitHub workflow that calls the wrapper |
| `ci/sentinel-ci.ignore` | what the CI run scans (supply-chain files) and skips (app code) |

## Key handling (local use)
* `SENTINEL_HMAC_KEY` holds a Base64 key of 32 random bytes, generated with
  `python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"`.
* Keep the key outside the repository and outside the monitored folder. Losing it makes existing baselines unverifiable.
* Sentinel never prints the key, returns it from the API, writes it to a report or includes it in an exception message.
  Keys shorter than 16 bytes are refused. A missing key is an explicit error (`HMAC_KEY_MISSING`), never silently replaced.

## State folders (one per monitored folder)
Each monitored folder has its own state folder: `<base>/roots/<id>/` holding `baseline.json`, `audit.jsonl` and `history.jsonl`. `<base>` is `SENTINEL_STATE_DIR` or `~/.sentinel`, and `<id>` is a short hash of the folder's absolute path (case-insensitive on Windows). The CLI and the dashboard resolve the same folder, and `<base>/tracked.json` lists the folders that have been initialised (used by the Tracked Folders tab). Initialising one folder never touches another folder's baseline. `--state-dir PATH` bypasses this and uses PATH directly. `history.jsonl` is an unsigned convenience log; the hash-chained audit log is the tamper-evident record, and clearing history writes a `HISTORY_CLEARED` audit entry.

## Exit codes (contract section 11.1)
| Code | Meaning |
|---|---|
| 0 | clean, or changes below the `--fail-on` threshold |
| 1 | changes that meet the configured failure threshold |
| 2 | invalid arguments, configuration or requested path |
| 3 | baseline missing/invalid, HMAC failure, key unavailable, audit integrity failure |
| 4 | incomplete scan or filesystem/I/O failure |
Order when several apply: 3, 4, 1, 0. The default CI policy is `--fail-on high` (contract 11.1 recommendation; the team confirms it).

## CI design (contract section 15)
1. The workflow checks out the **trusted base commit** and the **tree under test** into two separate folders.
2. Sentinel is installed from the trusted base commit only. Nothing from the pull request is executed.
3. A **random key per job** signs an ephemeral baseline built from the base tree. It exists only in memory, so no repository secret is needed and fork pull requests are checked too.
4. Both trees are copied to the same target path, so `root_path` is identical, then the tree under test is verified.
5. Changes are rated by `severity.py`; HIGH changes (workflow, Dockerfile, lockfile, manifest, deploy script) fail the job with exit code 1.
6. `ci/sentinel-ci.ignore` is read from the trusted base commit, so a pull request cannot shrink the scanned scope.
The persistent local baseline and the CI baseline are separate profiles.

## Limitations (also in the threat model)
* HMAC only protects against someone who cannot read the key. Anyone with the key can forge a baseline.
* The hash-chained audit log detects edits and deletions in the middle, not a full rewrite or tail truncation.
* A pull request can edit `.github/workflows/sentinel.yml` itself. Protect that file with CODEOWNERS and branch protection (required status check).
* The comparison is only as strong as the base commit: a malicious change already merged into the base is trusted.
* Third-party actions are referenced by version tag; pin them to reviewed commit SHAs before final submission.