from pathlib import Path
from typing import Optional
from .. import history, tracking
from ..application import initialize, verify, accept
from ..config.settings import load_settings
from ..core.models import ScanResult
from ..security.audit_log import append_audit_event

_BAD_ROOT = {"success": False, "error": {"code": "INVALID_ROOT_PATH", "message": "root path is not a valid directory"}}
_NOT_TRACKED = {"success": False, "error": {"code": "FOLDER_NOT_TRACKED", "message": "This folder is not tracked yet. Click Init Baseline to start tracking it."}}


def _valid_dir(root_path: str) -> bool:
    root = Path(root_path)
    return root.exists() and root.is_dir()


def start_scan(root_path: str) -> dict:
    if not _valid_dir(root_path):
        return _BAD_ROOT
    root = Path(root_path)
    base = load_settings()
    if not tracking.is_tracked(base.state_dir, root):
        return _NOT_TRACKED
    # verify() saves the result to this folder's own history
    result = verify(root, tracking.settings_for_root(base, root))
    return {"success": True, "data": _result_to_dict(result)}


def init_baseline(root_path: str) -> dict:
    if not _valid_dir(root_path):
        return _BAD_ROOT
    root = Path(root_path)
    base = load_settings()
    result = initialize(root, tracking.settings_for_root(base, root))
    if result.success:
        tracking.track_folder(base.state_dir, root)
    return {"success": result.success, "data": {"message": result.message, "root_path": result.root_path}}


def _find_scan(base_state_dir: Path, scan_id: str):
    """Look a scan up across every tracked folder. Returns (entry, scan) or (None, None)."""
    for entry in tracking.list_tracked(base_state_dir):
        scan = history.get_scan(tracking.state_dir_for(base_state_dir, Path(entry["root_path"])), scan_id)
        if scan is not None:
            return entry, scan
    return None, None


def accept_changes(scan_id: str, confirm: bool) -> dict:
    if not confirm:
        return {"success": False, "error": {"code": "INVALID_REQUEST", "message": "confirmation required"}}
    base = load_settings()
    entry, scan = _find_scan(base.state_dir, scan_id)
    if scan is None:
        return {"success": False, "error": {"code": "SCAN_NOT_FOUND", "message": "unknown scan_id"}}
    if str(getattr(scan["status"], "value", scan["status"])) != "CHANGED":
        return {"success": False, "error": {"code": "ACCEPT_BLOCKED", "message": "only a CHANGED scan can be accepted"}}
    root = Path(scan["root_path"])
    result = accept(root, scan_id, tracking.settings_for_root(base, root))
    if not result.success:
        return {"success": False, "error": {"code": "ACCEPT_BLOCKED", "message": result.message}}
    return {"success": True, "data": {"message": result.message, "scan_id": result.scan_id}}


def _selected_entries(base_state_dir: Path, folder_id: Optional[str]) -> list:
    entries = tracking.list_tracked(base_state_dir)
    if folder_id:
        entries = [e for e in entries if e["id"] == folder_id]
    return entries


def list_scans(folder_id: Optional[str] = None) -> dict:
    base = load_settings()
    scans = []
    for entry in _selected_entries(base.state_dir, folder_id):
        sd = tracking.state_dir_for(base.state_dir, Path(entry["root_path"]))
        for item in history.list_scans(sd):
            item["folder_id"] = entry["id"]
            scans.append(item)
    scans.sort(key=lambda s: s.get("completed_at") or "", reverse=True)
    return {"success": True, "data": {"scans": scans}}


def get_scan_by_id(scan_id: str):
    _, scan = _find_scan(load_settings().state_dir, scan_id)
    return scan


def clear_scans(folder_id: Optional[str] = None) -> dict:
    base = load_settings()
    removed = 0
    for entry in _selected_entries(base.state_dir, folder_id):
        sd = tracking.state_dir_for(base.state_dir, Path(entry["root_path"]))
        count = history.clear_history(sd)
        removed += count
        try:  # clearing history is recorded in that folder's tamper-evident audit log
            append_audit_event(sd / "audit.jsonl", "HISTORY_CLEARED", None, {"records_removed": count})
        except Exception:
            pass
    return {"success": True, "data": {"removed": removed}}


def list_folders() -> dict:
    base = load_settings()
    folders = []
    for entry in tracking.list_tracked(base.state_dir):
        root = Path(entry["root_path"])
        sd = tracking.state_dir_for(base.state_dir, root)
        recent = history.list_scans(sd)
        folders.append({
            "id": entry["id"],
            "root_path": entry["root_path"],
            "added_at": entry.get("added_at"),
            "state_dir": str(sd),
            "root_exists": root.is_dir(),
            "has_baseline": (sd / "baseline.json").is_file(),
            "scan_count": len(recent),
            "last_scan": recent[0] if recent else None,
        })
    return {"success": True, "data": {"folders": folders}}


def untrack(folder_id: str) -> dict:
    base = load_settings()
    if not tracking.untrack_folder(base.state_dir, folder_id):
        return {"success": False, "error": {"code": "FOLDER_NOT_FOUND", "message": "unknown folder id"}}
    return {"success": True, "data": {"id": folder_id}}


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
