"""Persistent scan history stored as JSON Lines in the state folder.

Every verify (from the CLI or the dashboard) appends one record to
``<state_dir>/history.jsonl``. The file is a convenience log for the
dashboard. The tamper-evident record of events is the hash-chained audit
log; clearing the history is itself written to the audit log.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

HISTORY_FILENAME = "history.jsonl"
MAX_RECORDS = 500
_SUMMARY_KEYS = ("scan_id", "root_path", "started_at", "completed_at", "status", "summary")
_LOCK = threading.Lock()


def history_path(state_dir: Path) -> Path:
    return Path(state_dir) / HISTORY_FILENAME


def _read_all(path: Path) -> List[Dict[str, Any]]:
    """Return every readable record, oldest first. Corrupt lines are skipped."""
    if not path.exists():
        return []
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and record.get("scan_id"):
                records.append(record)
    return records


def _rewrite(path: Path, records: List[Dict[str, Any]]) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    tmp.replace(path)


def record_scan(state_dir: Path, scan: Dict[str, Any]) -> None:
    """Append one scan result (a JSON-safe dict) to the history."""
    path = history_path(state_dir)
    line = json.dumps(scan, ensure_ascii=False, separators=(",", ":"))
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        records = _read_all(path)
        if len(records) > MAX_RECORDS:
            _rewrite(path, records[-MAX_RECORDS:])


def list_scans(state_dir: Path) -> List[Dict[str, Any]]:
    """Return scan summaries (no change lists), newest first."""
    with _LOCK:
        records = _read_all(history_path(state_dir))
    return [{k: r.get(k) for k in _SUMMARY_KEYS} for r in reversed(records)]


def get_scan(state_dir: Path, scan_id: str) -> Optional[Dict[str, Any]]:
    """Return the full record for one scan, or None."""
    with _LOCK:
        records = _read_all(history_path(state_dir))
    for record in reversed(records):
        if record.get("scan_id") == scan_id:
            return record
    return None


def clear_history(state_dir: Path) -> int:
    """Delete all history records. Returns how many were removed."""
    path = history_path(state_dir)
    with _LOCK:
        count = len(_read_all(path))
        if path.exists():
            path.unlink()
    return count
