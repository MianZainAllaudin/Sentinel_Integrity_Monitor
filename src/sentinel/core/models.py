"""Shared core data models, status enums, and canonical serializers (Person 1).

All modules (core, security, integrations, reporting, API, CLI) use these
models as the single source of truth defined in SENTINEL_GLOBAL_RULES.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 1
HASH_ALGORITHM = "sha256"

_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")


class ChangeStatus(str, Enum):
    """Allowed ChangeRecord.status values."""

    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    MOVED = "MOVED"

    def __str__(self) -> str:
        return self.value


class SeverityLevel(str, Enum):
    """Allowed ChangeRecord.severity values."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    def __str__(self) -> str:
        return self.value


class ScanStatus(str, Enum):
    """Allowed ScanResult.status values."""

    CLEAN = "CLEAN"
    CHANGED = "CHANGED"
    ERROR = "ERROR"
    BASELINE_INVALID = "BASELINE_INVALID"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class FileSnapshot:
    """Snapshot metadata and SHA-256 digest for one monitored file."""

    path: str
    sha256: str
    size_bytes: int
    mtime_ns: int


@dataclass(frozen=True)
class ScanError:
    """Structured error captured during scanning or verification."""

    code: str
    path: Optional[str]
    message: str


@dataclass(frozen=True)
class ChangeRecord:
    """Single detected difference between a baseline and current scan."""

    status: str
    path: str
    old_path: Optional[str]
    new_path: Optional[str]
    old_sha256: Optional[str]
    new_sha256: Optional[str]
    old_size_bytes: Optional[int]
    new_size_bytes: Optional[int]
    severity: str
    reason: str


@dataclass
class BaselineData:
    """Unwrapped baseline payload ready for signing or comparison."""

    schema_version: int
    root_path: str
    created_at: str
    hash_algorithm: str
    files: Dict[str, FileSnapshot]


@dataclass
class ScanResult:
    """Canonical verification result shared across CLI, API, and reporting."""

    schema_version: int
    scan_id: str
    root_path: str
    started_at: str
    completed_at: str
    status: str
    summary: Dict[str, int]
    changes: List[ChangeRecord]
    errors: List[ScanError]


def is_windows_style_path(path_str: str) -> bool:
    """Return True if *path_str* looks like a Windows drive or UNC path."""
    if not path_str:
        return False
    return bool(_WINDOWS_DRIVE_RE.match(path_str)) or path_str.startswith(("\\\\", "//"))


def normalize_root_path(root: Path) -> str:
    """Return a forward-slashed, non-empty string representation of *root*."""
    raw = str(root).replace("\\", "/")
    if _WINDOWS_DRIVE_RE.match(raw) or raw.startswith("//"):
        if re.match(r"^[A-Za-z]:/$", raw):
            return raw
        return raw.rstrip("/") or raw
    if root.is_absolute():
        posix = root.as_posix()
        return posix if posix == "/" else posix.rstrip("/")
    resolved = root.resolve().as_posix()
    return resolved if resolved == "/" else resolved.rstrip("/")


def _enum_str(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def snapshot_to_dict(snapshot: FileSnapshot) -> Dict[str, Any]:
    """Serialize a FileSnapshot to a canonical JSON-safe dictionary."""
    return {
        "path": snapshot.path,
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
        "mtime_ns": snapshot.mtime_ns,
    }


def baseline_to_dict(baseline: BaselineData) -> Dict[str, Any]:
    """Serialize BaselineData to the canonical baseline payload dictionary."""
    return {
        "schema_version": baseline.schema_version,
        "root_path": baseline.root_path,
        "created_at": baseline.created_at,
        "hash_algorithm": baseline.hash_algorithm,
        "files": {
            key: snapshot_to_dict(snap)
            for key, snap in baseline.files.items()
        },
    }


def change_record_to_dict(change: ChangeRecord) -> Dict[str, Any]:
    """Serialize a ChangeRecord to a canonical JSON-safe dictionary."""
    return {
        "status": _enum_str(change.status),
        "path": change.path,
        "old_path": change.old_path,
        "new_path": change.new_path,
        "old_sha256": change.old_sha256,
        "new_sha256": change.new_sha256,
        "old_size_bytes": change.old_size_bytes,
        "new_size_bytes": change.new_size_bytes,
        "severity": _enum_str(change.severity),
        "reason": change.reason,
    }


def scan_error_to_dict(error: ScanError) -> Dict[str, Any]:
    """Serialize a ScanError to a canonical JSON-safe dictionary."""
    return {
        "code": error.code,
        "path": error.path,
        "message": error.message,
    }


def scan_result_to_dict(result: ScanResult) -> Dict[str, Any]:
    """Serialize a ScanResult to the canonical JSON-safe dictionary."""
    return {
        "schema_version": result.schema_version,
        "scan_id": result.scan_id,
        "root_path": result.root_path,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "status": _enum_str(result.status),
        "summary": dict(result.summary),
        "changes": [change_record_to_dict(c) for c in result.changes],
        "errors": [scan_error_to_dict(e) for e in result.errors],
    }
