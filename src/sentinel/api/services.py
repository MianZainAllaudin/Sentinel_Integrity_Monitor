from pathlib import Path
from typing import Optional
from ..application import initialize, verify, accept
from ..config.settings import load_settings, AppSettings
from ..core.models import ScanResult


def start_scan(root_path: str) -> dict:
    root = Path(root_path)
    if not root.exists() or not root.is_dir():
        return {"success": False, "error": {"code": "INVALID_ROOT_PATH", "message": "root path is not a valid directory"}}
    settings = load_settings()
    result = verify(root, settings)
    return {"success": True, "data": _result_to_dict(result)}


def accept_changes(scan_id: str, confirm: bool) -> dict:
    if not confirm:
        return {"success": False, "error": {"code": "INVALID_REQUEST", "message": "confirmation required"}}
    settings = load_settings()
    result = accept(Path(settings.state_dir), scan_id, settings)
    return {"success": result.success, "data": {"message": result.message, "scan_id": result.scan_id}}


def get_status() -> dict:
    return {"success": True, "data": {"scanning": False}}


def _result_to_dict(result: ScanResult) -> dict:
    return {
        "schema_version": result.schema_version,
        "scan_id": result.scan_id,
        "root_path": result.root_path,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "status": result.status,
        "summary": result.summary,
        "changes": [c.__dict__ if hasattr(c, "__dict__") else c for c in result.changes],
        "errors": [e.__dict__ if hasattr(e, "__dict__") else e for e in result.errors],
    }
