"""Recursive directory traversal and streamed SHA-256 hashing for Sentinel."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .ignore import load_ignore_matcher
from .models import FileSnapshot, ScanError, is_windows_style_path

DEFAULT_CHUNK_SIZE = 1_048_576


def _validate_chunk_size(chunk_size: int) -> None:
    """Ensure *chunk_size* is a positive integer (excluding booleans)."""
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer.")


def _format_ignore_error_path(root: Path, ignore_file: Optional[Path]) -> str:
    """Return a clean forward-slashed path label for IGNORE_FILE_ERROR."""
    target = ignore_file if ignore_file is not None else (root / ".sentinelignore")
    try:
        return target.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return str(target).replace("\\", "/")


def hash_file_sha256(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Compute the lowercase SHA-256 hex digest of *path* using streamed reads.

    Args:
        path: File path to hash.
        chunk_size: Read buffer size in bytes (must be a positive integer).

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        ValueError: If *chunk_size* is not a positive integer.
        OSError: If *path* cannot be opened or read.
    """
    _validate_chunk_size(chunk_size)
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def _hash_regular_file(
    file_path: Path,
    rel_path: str,
    chunk_size: int,
) -> Tuple[Optional[FileSnapshot], Optional[ScanError]]:
    """Stream-hash one regular file and verify file stability across the read."""
    try:
        with open(file_path, "rb") as handle:
            stat_before = os.fstat(handle.fileno())
            hasher = hashlib.sha256()
            total_read = 0
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                total_read += len(chunk)
                hasher.update(chunk)
            stat_after = os.fstat(handle.fileno())
    except PermissionError as exc:
        return None, ScanError(
            code="FILE_ACCESS_DENIED",
            path=rel_path,
            message=f"Permission denied reading file: {exc}",
        )
    except FileNotFoundError as exc:
        return None, ScanError(
            code="FILE_NOT_FOUND",
            path=rel_path,
            message=f"File disappeared during scan: {exc}",
        )
    except OSError as exc:
        return None, ScanError(
            code="FILE_READ_ERROR",
            path=rel_path,
            message=f"Failed to read file: {exc}",
        )

    if (
        total_read != stat_before.st_size
        or stat_after.st_size != stat_before.st_size
        or stat_after.st_mtime_ns != stat_before.st_mtime_ns
    ):
        return None, ScanError(
            code="UNSTABLE_FILE_READ",
            path=rel_path,
            message="File modified while being hashed.",
        )

    snapshot = FileSnapshot(
        path=rel_path,
        sha256=hasher.hexdigest().lower(),
        size_bytes=stat_before.st_size,
        mtime_ns=stat_before.st_mtime_ns,
    )
    return snapshot, None


def scan_directory(
    root: Path,
    ignore_file: Optional[Path] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Tuple[List[FileSnapshot], List[ScanError]]:
    """Recursively scan *root*, hashing non-ignored regular files in chunks.

    Args:
        root: Monitored root directory.
        ignore_file: Optional path to an ignore file; defaults to ``root / ".sentinelignore"``
            when present.
        chunk_size: Read buffer size in bytes for streamed SHA-256 hashing.

    Returns:
        Tuple of `(snapshots, errors)` sorted deterministically.

    Raises:
        ValueError: If *chunk_size* is not a positive integer.
    """
    _validate_chunk_size(chunk_size)

    raw_root = str(root)
    root_path = Path(root)

    try:
        exists = root_path.exists()
    except OSError as exc:
        return [], [
            ScanError(
                code="INVALID_ROOT",
                path=None,
                message=f"Cannot access root directory: {exc}",
            )
        ]

    if not exists:
        return [], [
            ScanError(
                code="ROOT_NOT_FOUND",
                path=None,
                message=f"Root directory does not exist: {root_path}",
            )
        ]

    try:
        is_dir = root_path.is_dir()
    except OSError as exc:
        return [], [
            ScanError(
                code="INVALID_ROOT",
                path=None,
                message=f"Cannot inspect root directory: {exc}",
            )
        ]

    if not is_dir:
        return [], [
            ScanError(
                code="INVALID_ROOT",
                path=None,
                message=f"Root path is not a directory: {root_path}",
            )
        ]

    case_insensitive = is_windows_style_path(raw_root) or (os.name == "nt")
    try:
        matcher = load_ignore_matcher(
            root_path,
            ignore_file=ignore_file,
            case_insensitive=case_insensitive,
        )
    except (OSError, UnicodeDecodeError) as exc:
        return [], [
            ScanError(
                code="IGNORE_FILE_ERROR",
                path=_format_ignore_error_path(root_path, ignore_file),
                message=f"Failed to load ignore file: {exc}",
            )
        ]

    snapshots: List[FileSnapshot] = []
    errors: List[ScanError] = []
    seen_casefold: Dict[str, str] = {}
    stack: List[Tuple[Path, str]] = [(root_path, "")]

    while stack:
        current_dir, rel_dir = stack.pop()
        try:
            with os.scandir(current_dir) as dir_iter:
                entries = sorted(dir_iter, key=lambda entry: entry.name)
        except PermissionError as exc:
            errors.append(
                ScanError(
                    code="DIR_ACCESS_DENIED",
                    path=rel_dir or None,
                    message=f"Permission denied listing directory: {exc}",
                )
            )
            continue
        except OSError as exc:
            errors.append(
                ScanError(
                    code="DIR_READ_ERROR",
                    path=rel_dir or None,
                    message=f"Failed to list directory: {exc}",
                )
            )
            continue

        subdirs: List[Tuple[Path, str]] = []
        for entry in entries:
            rel_path = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            try:
                if entry.is_symlink():
                    continue
                is_entry_dir = entry.is_dir(follow_symlinks=False)
                is_entry_file = False if is_entry_dir else entry.is_file(follow_symlinks=False)
            except PermissionError as exc:
                errors.append(
                    ScanError(
                        code="FILE_ACCESS_DENIED",
                        path=rel_path,
                        message=f"Permission denied inspecting entry: {exc}",
                    )
                )
                continue
            except OSError as exc:
                errors.append(
                    ScanError(
                        code="FILE_READ_ERROR",
                        path=rel_path,
                        message=f"Failed to inspect entry: {exc}",
                    )
                )
                continue

            if is_entry_dir:
                if matcher.is_ignored(rel_path, is_dir=True) and matcher.can_prune_directory(
                    rel_path
                ):
                    continue
                subdirs.append((Path(entry.path), rel_path))
            elif is_entry_file:
                if matcher.is_ignored(rel_path, is_dir=False):
                    continue

                folded = rel_path.casefold()
                if folded in seen_casefold:
                    errors.append(
                        ScanError(
                            code="PATH_CASE_COLLISION",
                            path=rel_path,
                            message=(
                                f"Case-insensitive path collision with '{seen_casefold[folded]}'."
                            ),
                        )
                    )
                    continue

                snapshot, err = _hash_regular_file(Path(entry.path), rel_path, chunk_size)
                if err is not None:
                    errors.append(err)
                elif snapshot is not None:
                    seen_casefold[folded] = rel_path
                    snapshots.append(snapshot)

        if subdirs:
            stack.extend(reversed(subdirs))

    snapshots.sort(key=lambda snap: snap.path)
    errors.sort(key=lambda err: (err.path or "", err.code, err.message))
    return snapshots, errors
