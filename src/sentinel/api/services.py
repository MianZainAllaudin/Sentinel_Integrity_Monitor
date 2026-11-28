from pathlib import Path
from .. import history
from ..application import initialize, verify, accept
from ..config.settings import load_settings
from ..core.models import ScanResult
from ..security.audit_log import append_audit_event

_BAD_ROOT = {"success": False, "error": {"code": "INVALID_ROOT_PATH", "message": "root path is not a valid directory"}}


def start_scan(root_path: str) -> dict:
    root = Path(root_path)
    if not root.exists() or not root.is_dir():
        return _BAD_ROOT
    settings = load_settings()
    result = verify(root, settings)
    data = _result_to_dict(result)  # verify() already saved it to the persistent history
    return {"success": True, "data": data}


def init_baseline(root_path: str) -> dict:
    root = Path(root_path)
    if not root.exists() or not root.is_dir():
        return _BAD_ROOT
    result = initialize(root, load_settings())
    return {"success": result.success, "data": {"message": result.message, "root_path": result.root_path}}


def accept_changes(scan_id: str, confirm: bool) -> dict:
    if not confirm:
        return {"success": False, "error": {"code": "INVALID_REQUEST", "message": "confirmation required"}}
    settings = load_settings()
    scan = history.get_scan(settings.state_dir, scan_id)
    if scan is None:
        return {"success": False, "error": {"code": "SCAN_NOT_FOUND", "message": "unknown scan_id"}}
    if str(getattr(scan["status"], "value", scan["status"])) != "CHANGED":
        return {"success": False, "error": {"code": "ACCEPT_BLOCKED", "message": "only a CHANGED scan can be accepted"}}
    result = accept(Path(scan["root_path"]), scan_id, settings)
    if not result.success:
        return {"success": False, "error": {"code": "ACCEPT_BLOCKED", "message": result.message}}
    return {"success": True, "data": {"message": result.message, "scan_id": result.scan_id}}


def list_scans() -> dict:
    return {"success": True, "data": {"scans": history.list_scans(load_settings().state_dir)}}


def get_scan_by_id(scan_id: str):
    return history.get_scan(load_settings().state_dir, scan_id)


def clear_scans() -> dict:
    settings = load_settings()
    removed = history.clear_history(settings.state_dir)
    try:  # clearing history is recorded in the tamper-evident audit log
        append_audit_event(
            settings.audit_log_path or (settings.state_dir / "audit.jsonl"),
            "HISTORY_CLEARED", None, {"records_removed": removed},
        )
    except Exception:
        pass
    return {"success": True, "data": {"removed": removed}}


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
