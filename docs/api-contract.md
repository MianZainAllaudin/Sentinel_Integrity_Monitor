# API Contract

Base path: `/api/v1`

Endpoints:
- `GET /health` — health check
- `GET /status` — scan running flag + latest summary
- `POST /scans` — body `{ root_path }`, starts VERIFY
- `GET /scans` — list recent scans
- `GET /scans/{scan_id}` — one scan result
- `POST /accept` — body `{ scan_id, confirm: true }`

Responses use `{ success: bool, data: ... }` or `{ success: false, error: { code, message } }`.
