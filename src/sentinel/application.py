from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
import uuid
import json
from .config.settings import AppSettings, OperationResult
from .core.models import ScanResult, ScanError, ChangeRecord, FileSnapshot, BaselineData
from .core.scanner import scan_directory
from .core.diff import compare_snapshots
from .core.baseline import build_baseline
from .security.baseline_signer import sign_baseline, verify_baseline
from .security.audit_log import append_audit_event
from .integrations.severity import apply_severity


def initialize(root: Path, settings: AppSettings) -> OperationResult:
    snapshots, errors = scan_directory(root, settings.ignore_file, settings.hash_chunk_size)
    baseline = build_baseline(root, snapshots)
    envelope = sign_baseline(baseline, settings.hmac_key)
    path = settings.baseline_path or (settings.state_dir / "baseline.json")
    path.write_text(json.dumps(envelope), encoding="utf-8")
    append_audit_event(
        settings.audit_log_path or (settings.state_dir / "audit.jsonl"),
        "INIT", None, {"status": "INITIALIZED"},
    )
    return OperationResult(
        operation="INIT",
        success=True,
        root_path=str(root),
        completed_at=datetime.now(timezone.utc).isoformat(),
        message="baseline created",
    )


def _load_verified_baseline(settings: AppSettings) -> Optional[BaselineData]:
    path = settings.baseline_path or (settings.state_dir / "baseline.json")
    if not path.exists():
        return None
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        return verify_baseline(envelope, settings.hmac_key)
    except Exception:
        return None


def _make_error_result(root: Path, status: str, message: str) -> ScanResult:
    now = datetime.now(timezone.utc).isoformat()
    sid = str(uuid.uuid4())
    return ScanResult(
        schema_version=1,
        scan_id=sid,
        root_path=str(root),
        started_at=now,
        completed_at=now,
        status=status,
        summary={"added": 0, "modified": 0, "deleted": 0, "moved": 0, "errors": 1},
        changes=[],
        errors=[ScanError(code=status, path=None, message=message)],
    )


def verify(root: Path, settings: AppSettings) -> ScanResult:
    now = datetime.now(timezone.utc)
    started_at = now.isoformat()
    sid = str(uuid.uuid4())
    baseline = _load_verified_baseline(settings)
    if baseline is None:
        return _make_error_result(root, "BASELINE_INVALID", "baseline could not be verified")
    snapshots, errors = scan_directory(root, settings.ignore_file, settings.hash_chunk_size)
    result = compare_snapshots(baseline, snapshots, errors)
    result.scan_id = sid
    result.started_at = started_at
    result.completed_at = datetime.now(timezone.utc).isoformat()
    result = apply_severity(result)
    append_audit_event(
        settings.audit_log_path or (settings.state_dir / "audit.jsonl"),
        "VERIFY_COMPLETED", sid, {"status": result.status, "change_count": len(result.changes)},
    )
    return result


def accept(root: Path, scan_id: str, settings: AppSettings) -> OperationResult:
    settings = settings
    baseline = _load_verified_baseline(settings)
    if baseline is None:
        return OperationResult(
            operation="ACCEPT",
            success=False,
            root_path=str(root),
            completed_at=datetime.now(timezone.utc).isoformat(),
            message="baseline invalid, accept blocked",
            scan_id=scan_id,
        )
    snapshots, errors = scan_directory(root, settings.ignore_file, settings.hash_chunk_size)
    if errors:
        return OperationResult(
            operation="ACCEPT",
            success=False,
            root_path=str(root),
            completed_at=datetime.now(timezone.utc).isoformat(),
            message="filesystem errors, accept blocked",
            scan_id=scan_id,
        )
    new_baseline = build_baseline(root, snapshots)
    envelope = sign_baseline(new_baseline, settings.hmac_key)
    path = settings.baseline_path or (settings.state_dir / "baseline.json")
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(envelope), encoding="utf-8")
    tmp.replace(path)
    append_audit_event(
        settings.audit_log_path or (settings.state_dir / "audit.jsonl"),
        "ACCEPT", scan_id, {"status": "ACCEPTED"},
    )
    return OperationResult(
        operation="ACCEPT",
        success=True,
        root_path=str(root),
        completed_at=datetime.now(timezone.utc).isoformat(),
        message="baseline accepted",
        scan_id=scan_id,
    )
