from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    sha256: str
    size_bytes: int
    mtime_ns: int


@dataclass(frozen=True)
class ScanError:
    code: str
    path: Optional[str]
    message: str


@dataclass(frozen=True)
class ChangeRecord:
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
    schema_version: int
    root_path: str
    created_at: str
    hash_algorithm: str
    files: Dict[str, FileSnapshot]


@dataclass
class ScanResult:
    schema_version: int
    scan_id: str
    root_path: str
    started_at: str
    completed_at: str
    status: str
    summary: Dict[str, int]
    changes: List[ChangeRecord]
    errors: List[ScanError]
