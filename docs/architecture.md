# Sentinel Architecture

## Modules
- `src/sentinel/core/` — scanning, baseline, diff, ignore (Person 1)
- `src/sentinel/security/` — HMAC signing, audit log (Person 2)
- `src/sentinel/integrations/severity.py` — severity classification (Person 2)
- `src/sentinel/application.py` — INIT/VERIFY/ACCEPT orchestration (Person 3)
- `src/sentinel/api/` — FastAPI backend (Person 3)
- `src/sentinel/reporting/` — JSON/HTML reports, webhook (Person 3)
- `src/sentinel/config/settings.py` — AppSettings, load_settings (Person 3)
- `frontend/` — Vue 3 dashboard (Person 3)

## Data flow
CLI and FastAPI both call `application.verify` / `application.accept` / `application.initialize`.
The Vue dashboard calls only `GET/POST /api/v1/*`.
