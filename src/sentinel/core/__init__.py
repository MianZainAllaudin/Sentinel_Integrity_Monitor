"""Core scanning, baseline, diffing, ignore-rule, and model APIs (Person 1)."""

from __future__ import annotations

from .baseline import (
    accept_snapshots,
    baseline_from_dict,
    build_baseline,
    load_baseline_json,
    save_baseline_json,
)
from .diff import compare_snapshots, has_snapshot_changed
from .ignore import IgnoreMatcher, IgnoreRule, load_ignore_matcher
from .models import (
    HASH_ALGORITHM,
    SCHEMA_VERSION,
    BaselineData,
    ChangeRecord,
    ChangeStatus,
    FileSnapshot,
    ScanError,
    ScanResult,
    ScanStatus,
    SeverityLevel,
    baseline_to_dict,
    change_record_to_dict,
    is_windows_style_path,
    normalize_root_path,
    scan_error_to_dict,
    scan_result_to_dict,
    snapshot_to_dict,
)
from .scanner import DEFAULT_CHUNK_SIZE, hash_file_sha256, scan_directory

__all__ = [
    "BaselineData",
    "ChangeRecord",
    "ChangeStatus",
    "DEFAULT_CHUNK_SIZE",
    "FileSnapshot",
    "HASH_ALGORITHM",
    "IgnoreMatcher",
    "IgnoreRule",
    "SCHEMA_VERSION",
    "ScanError",
    "ScanResult",
    "ScanStatus",
    "SeverityLevel",
    "accept_snapshots",
    "baseline_from_dict",
    "baseline_to_dict",
    "build_baseline",
    "change_record_to_dict",
    "compare_snapshots",
    "has_snapshot_changed",
    "hash_file_sha256",
    "is_windows_style_path",
    "load_baseline_json",
    "load_ignore_matcher",
    "normalize_root_path",
    "save_baseline_json",
    "scan_directory",
    "scan_error_to_dict",
    "scan_result_to_dict",
    "snapshot_to_dict",
]
