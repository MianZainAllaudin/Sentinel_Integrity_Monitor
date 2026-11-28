"""Folder listing for the dashboard's folder picker.

The browser cannot reveal real file-system paths, so the (local-only) backend
lists directories on request. Only names are returned, never file contents.
"""

from __future__ import annotations

import os
import string
from pathlib import Path
from typing import Any, Dict, List, Optional

MAX_ENTRIES = 1000


class BrowseError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _drives() -> List[str]:
    if os.name != "nt":
        return ["/"]
    try:
        import ctypes

        mask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[attr-defined]
        return [f"{letter}:/" for i, letter in enumerate(string.ascii_uppercase) if mask & (1 << i)]
    except Exception:
        return [f"{c}:/" for c in string.ascii_uppercase if os.path.exists(f"{c}:\\")]


def _shortcuts() -> List[Dict[str, str]]:
    home = Path.home()
    links = [{"label": "Home", "path": home.as_posix()}]
    for name in ("Desktop", "Documents", "Downloads"):
        candidate = home / name
        if candidate.is_dir():
            links.append({"label": name, "path": candidate.as_posix()})
    links += [{"label": d, "path": d} for d in _drives()]
    return links


def list_directory(path: Optional[str]) -> Dict[str, Any]:
    """List the sub-folders and files of ``path`` (default: the home folder)."""
    target = Path(path).expanduser() if path and path.strip() else Path.home()
    try:
        resolved = target.resolve()
    except OSError as exc:
        raise BrowseError("INVALID_PATH", f"Cannot open that path: {exc}") from exc
    if not resolved.exists():
        raise BrowseError("INVALID_PATH", "That folder does not exist.")
    if not resolved.is_dir():
        raise BrowseError("INVALID_PATH", "That path is a file, not a folder.")

    entries: List[Dict[str, Any]] = []
    truncated = False
    try:
        with os.scandir(resolved) as it:
            for entry in it:
                try:
                    is_dir = entry.is_dir()
                except OSError:
                    continue
                entries.append({"name": entry.name, "path": Path(entry.path).as_posix(), "is_dir": is_dir})
                if len(entries) >= MAX_ENTRIES:
                    truncated = True
                    break
    except PermissionError as exc:
        raise BrowseError("ACCESS_DENIED", "You do not have permission to open that folder.") from exc
    except OSError as exc:
        raise BrowseError("INVALID_PATH", f"Cannot read that folder: {exc}") from exc

    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    parent = resolved.parent
    return {
        "path": resolved.as_posix(),
        "parent": None if parent == resolved else parent.as_posix(),
        "entries": entries,
        "truncated": truncated,
        "shortcuts": _shortcuts(),
    }
