"""Per-folder state and the registry of tracked folders.

Every monitored folder gets its own state folder (baseline, audit log and
scan history) under ``<base state dir>/roots/<id>/``, where ``<id>`` is a
short hash of the folder's absolute path. The command line and the dashboard
both resolve the same location, so a baseline created by one is used by the
other. ``<base state dir>/tracked.json`` lists the folders that have been
initialised, which is what the dashboard's Tracked Folders tab shows.

Passing ``--state-dir`` to the CLI bypasses all of this and uses that folder
directly (a single custom state folder).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REGISTRY_FILENAME = "tracked.json"
ROOTS_DIRNAME = "roots"
_LOCK = threading.RLock()


def _normalized(root: Path) -> str:
    resolved = str(Path(root).expanduser().resolve())
    return resolved.lower() if os.name == "nt" else resolved


def root_id(root: Path) -> str:
    """Stable short id for a monitored folder (case-insensitive on Windows)."""
    return hashlib.sha256(_normalized(root).encode("utf-8")).hexdigest()[:16]


def state_dir_for(base_state_dir: Path, root: Path) -> Path:
    """The state folder that belongs to one monitored folder (not created)."""
    return Path(base_state_dir) / ROOTS_DIRNAME / root_id(root)


def settings_for_root(settings: Any, root: Path) -> Any:
    """Return a copy of ``settings`` whose state folder is the one for ``root``.

    Explicit baseline/audit-log overrides are dropped so the per-folder files
    are used. The state folder is created.
    """
    state_dir = state_dir_for(settings.state_dir, root)
    state_dir.mkdir(parents=True, exist_ok=True)
    return dataclasses.replace(settings, state_dir=state_dir, baseline_path=None, audit_log_path=None)


def _registry_path(base_state_dir: Path) -> Path:
    return Path(base_state_dir) / REGISTRY_FILENAME


def _load(base_state_dir: Path) -> List[Dict[str, Any]]:
    path = _registry_path(base_state_dir)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict) and e.get("id") and e.get("root_path")]


def _save(base_state_dir: Path, entries: List[Dict[str, Any]]) -> None:
    path = _registry_path(base_state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def list_tracked(base_state_dir: Path) -> List[Dict[str, Any]]:
    """All tracked folders, oldest first."""
    with _LOCK:
        return sorted(_load(base_state_dir), key=lambda e: e.get("added_at", ""))


def get_tracked(base_state_dir: Path, folder_id: str) -> Optional[Dict[str, Any]]:
    with _LOCK:
        for entry in _load(base_state_dir):
            if entry["id"] == folder_id:
                return entry
    return None


def is_tracked(base_state_dir: Path, root: Path) -> bool:
    return get_tracked(base_state_dir, root_id(root)) is not None


def track_folder(base_state_dir: Path, root: Path) -> Dict[str, Any]:
    """Register ``root`` as tracked (idempotent) and return its entry."""
    rid = root_id(root)
    with _LOCK:
        entries = _load(base_state_dir)
        for entry in entries:
            if entry["id"] == rid:
                return entry
        entry = {
            "id": rid,
            "root_path": Path(root).expanduser().resolve().as_posix(),  # same form as scan results
            "added_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        entries.append(entry)
        _save(base_state_dir, entries)
        return entry


def untrack_folder(base_state_dir: Path, folder_id: str) -> bool:
    """Stop tracking a folder. Its state folder is left on disk."""
    with _LOCK:
        entries = _load(base_state_dir)
        kept = [e for e in entries if e["id"] != folder_id]
        if len(kept) == len(entries):
            return False
        _save(base_state_dir, kept)
        return True
