"""Baseline creation, validation, and pure-core JSON storage (Person 1).

Implements canonical baseline construction and serialization per
SENTINEL_GLOBAL_RULES.md without any dependency on security or API layers.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, List, Optional

from .models import (
    HASH_ALGORITHM,
    SCHEMA_VERSION,
    BaselineData,
    FileSnapshot,
    baseline_to_dict,
    normalize_root_path,
)

_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
_WINDOWS_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")


def _is_plain_int(value: Any) -> bool:
    """Return True if *value* is an int and not a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_relative_path(path: Any) -> str:
    """Validate and return a canonical relative snapshot path."""
    if not isinstance(path, str) or not path:
        raise ValueError("Snapshot path must be a non-empty string.")
    if "\x00" in path:
        raise ValueError(f"Snapshot path contains null byte: {path!r}")
    if path.startswith("/"):
        raise ValueError(f"Snapshot path must be relative without leading '/': {path!r}")
    if "\\" in path:
        raise ValueError(f"Snapshot path must use '/' separators: {path!r}")
    if _WINDOWS_DRIVE_PREFIX_RE.match(path):
        raise ValueError(f"Snapshot path must not include a Windows drive prefix: {path!r}")

    segments = path.split("/")
    for segment in segments:
        if segment in ("", ".", ".."):
            raise ValueError(
                f"Snapshot path contains invalid or traversal segment {segment!r}: {path!r}"
            )
    return path


def _validate_snapshot(snapshot: Any) -> FileSnapshot:
    """Validate a FileSnapshot instance and all of its canonical fields."""
    if not isinstance(snapshot, FileSnapshot):
        raise ValueError(f"Expected FileSnapshot instance, got {type(snapshot).__name__}.")

    _validate_relative_path(snapshot.path)

    if not isinstance(snapshot.sha256, str) or not _SHA256_HEX_RE.fullmatch(snapshot.sha256):
        raise ValueError(
            f"Snapshot sha256 for {snapshot.path!r} must be a 64-char lowercase hex digest."
        )
    if not _is_plain_int(snapshot.size_bytes) or snapshot.size_bytes < 0:
        raise ValueError(
            f"Snapshot size_bytes for {snapshot.path!r} must be a non-negative integer."
        )
    if not _is_plain_int(snapshot.mtime_ns):
        raise ValueError(
            f"Snapshot mtime_ns for {snapshot.path!r} must be an integer."
        )
    return snapshot


def _index_sorted_snapshots(snapshots: List[FileSnapshot]) -> Dict[str, FileSnapshot]:
    """Validate snapshots, reject duplicate/case collisions, and return sorted map."""
    if not isinstance(snapshots, list):
        raise ValueError("snapshots must be a list of FileSnapshot objects.")

    seen_casefold: Dict[str, str] = {}
    validated: List[FileSnapshot] = []
    for snap in snapshots:
        valid_snap = _validate_snapshot(snap)
        folded = valid_snap.path.casefold()
        if folded in seen_casefold:
            existing = seen_casefold[folded]
            raise ValueError(
                f"Duplicate or case-insensitive colliding snapshot path: "
                f"{valid_snap.path!r} conflicts with {existing!r}."
            )
        seen_casefold[folded] = valid_snap.path
        validated.append(valid_snap)

    validated.sort(key=lambda item: item.path)
    return {item.path: item for item in validated}


def _utc_now_iso() -> str:
    """Return the current UTC timestamp in canonical ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _coerce_root_path(root: Path) -> str:
    """Validate *root* and normalize it to a forward-slashed root path string."""
    if isinstance(root, Path):
        target = root
    elif isinstance(root, str) and root.strip():
        target = Path(root)
    else:
        raise ValueError("root must be a valid pathlib.Path or non-empty path string.")
    normalized = normalize_root_path(target)
    if not normalized:
        raise ValueError("Normalized root_path must not be empty.")
    return normalized


def build_baseline(
    root: Path,
    snapshots: List[FileSnapshot],
) -> BaselineData:
    """Create a validated BaselineData payload from *root* and *snapshots*.

    Args:
        root: Monitored root directory path.
        snapshots: List of FileSnapshot objects describing files under *root*.

    Returns:
        A canonical BaselineData object with sorted ``files`` entries.

    Raises:
        ValueError: If *root* is invalid, any snapshot field fails validation,
            or duplicate / case-insensitive colliding paths are present.
    """
    root_path = _coerce_root_path(root)
    files = _index_sorted_snapshots(snapshots)
    return BaselineData(
        schema_version=SCHEMA_VERSION,
        root_path=root_path,
        created_at=_utc_now_iso(),
        hash_algorithm=HASH_ALGORITHM,
        files=files,
    )


def baseline_from_dict(data: Dict[str, Any]) -> BaselineData:
    """Validate and deserialize a raw dictionary into a BaselineData object.

    Args:
        data: Parsed JSON dictionary matching the canonical baseline payload schema.

    Returns:
        Validated BaselineData instance with sorted ``files`` mapping.

    Raises:
        ValueError: If required keys are missing, types or values are invalid,
            or file entries fail snapshot/collision validation.
    """
    if not isinstance(data, dict):
        raise ValueError("Baseline payload must be a JSON object.")

    required_keys = ("schema_version", "root_path", "created_at", "hash_algorithm", "files")
    missing = [key for key in required_keys if key not in data]
    if missing:
        raise ValueError(f"Baseline payload missing required fields: {', '.join(missing)}.")

    schema_version = data["schema_version"]
    if not _is_plain_int(schema_version) or schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported baseline schema_version: {schema_version!r} (expected {SCHEMA_VERSION})."
        )

    root_path = data["root_path"]
    if not isinstance(root_path, str) or not root_path.strip() or "\x00" in root_path:
        raise ValueError("Baseline root_path must be a non-empty string.")

    created_at = data["created_at"]
    if not isinstance(created_at, str) or not created_at.strip():
        raise ValueError("Baseline created_at must be a non-empty UTC ISO-8601 string.")

    hash_algorithm = data["hash_algorithm"]
    if not isinstance(hash_algorithm, str) or hash_algorithm != HASH_ALGORITHM:
        raise ValueError(
            f"Unsupported baseline hash_algorithm: {hash_algorithm!r} (expected {HASH_ALGORITHM!r})."
        )

    raw_files = data["files"]
    if not isinstance(raw_files, dict):
        raise ValueError("Baseline files field must be a JSON object.")

    snapshots: List[FileSnapshot] = []
    for key, entry in raw_files.items():
        if not isinstance(key, str):
            raise ValueError("Baseline files keys must be strings.")
        if not isinstance(entry, dict):
            raise ValueError(f"Baseline file entry for {key!r} must be a JSON object.")

        snap_required = ("path", "sha256", "size_bytes", "mtime_ns")
        snap_missing = [field for field in snap_required if field not in entry]
        if snap_missing:
            raise ValueError(
                f"Baseline file entry {key!r} missing fields: {', '.join(snap_missing)}."
            )

        snap = FileSnapshot(
            path=entry["path"],
            sha256=entry["sha256"],
            size_bytes=entry["size_bytes"],
            mtime_ns=entry["mtime_ns"],
        )
        _validate_snapshot(snap)
        if snap.path != key:
            raise ValueError(
                f"Baseline file key {key!r} does not match entry path {snap.path!r}."
            )
        snapshots.append(snap)

    files = _index_sorted_snapshots(snapshots)
    return BaselineData(
        schema_version=schema_version,
        root_path=root_path,
        created_at=created_at,
        hash_algorithm=hash_algorithm,
        files=files,
    )


def save_baseline_json(baseline: BaselineData, output_path: Path) -> Path:
    """Atomically write *baseline* as UTF-8 JSON to *output_path*.

    Args:
        baseline: BaselineData object to serialize and persist.
        output_path: Destination file path for the JSON baseline.

    Returns:
        The resolved destination Path written to disk.

    Raises:
        ValueError: If *baseline* is not a valid BaselineData instance.
        OSError: If directory creation, writing, or atomic replacement fails.
    """
    if not isinstance(baseline, BaselineData):
        raise ValueError("baseline must be a BaselineData instance.")

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = baseline_to_dict(baseline)
    content = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.replace(destination)
        tmp_path = None
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()

    return destination


def load_baseline_json(input_path: Path) -> BaselineData:
    """Read and validate a UTF-8 baseline JSON file from *input_path*.

    Args:
        input_path: Path to a baseline JSON file matching the canonical payload schema.

    Returns:
        Validated BaselineData instance.

    Raises:
        FileNotFoundError: If *input_path* does not exist.
        OSError: If the file cannot be read.
        ValueError: If the file contains invalid JSON or fails schema validation.
    """
    source = Path(input_path)
    raw_text = source.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid baseline JSON in {source}: {exc}") from exc
    return baseline_from_dict(parsed)


def accept_snapshots(
    baseline: BaselineData,
    snapshots: List[FileSnapshot],
    root: Optional[Path] = None,
) -> BaselineData:
    """Produce an updated BaselineData from accepted *snapshots*.

    Args:
        baseline: Existing BaselineData whose root_path is retained unless *root* is given.
        snapshots: Full list of accepted FileSnapshot entries for the updated baseline.
        root: Optional new root directory path overriding ``baseline.root_path``.

    Returns:
        A new BaselineData instance reflecting the accepted *snapshots* and a fresh
        UTC ``created_at`` timestamp.

    Raises:
        ValueError: If *baseline* is invalid or any accepted snapshot fails validation.
    """
    if not isinstance(baseline, BaselineData):
        raise ValueError("baseline must be a BaselineData instance.")
    if baseline.schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported baseline schema_version: {baseline.schema_version!r}."
        )
    if baseline.hash_algorithm != HASH_ALGORITHM:
        raise ValueError(
            f"Unsupported baseline hash_algorithm: {baseline.hash_algorithm!r}."
        )

    if root is not None:
        root_path = _coerce_root_path(root)
    else:
        if not isinstance(baseline.root_path, str) or not baseline.root_path.strip():
            raise ValueError("Existing baseline root_path must be a non-empty string.")
        root_path = baseline.root_path

    files = _index_sorted_snapshots(snapshots)
    return BaselineData(
        schema_version=SCHEMA_VERSION,
        root_path=root_path,
        created_at=_utc_now_iso(),
        hash_algorithm=HASH_ALGORITHM,
        files=files,
    )


__all__ = [
    "accept_snapshots",
    "baseline_from_dict",
    "baseline_to_dict",
    "build_baseline",
    "load_baseline_json",
    "save_baseline_json",
]
