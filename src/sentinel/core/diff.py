"""Baseline-vs-current snapshot comparison and move detection (Person 1).

Implements pure-core change detection (ADDED, MODIFIED, DELETED, MOVED) using
size/mtime heuristics, SHA-256 verification, and O(N) bucketed move pairing.
Severity classification rules are intentionally delegated to Person 2.
"""

from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict, deque
from datetime import datetime, timezone
import os
from typing import DefaultDict, Dict, List, Optional, Set, Tuple
import uuid

from .models import (
    SCHEMA_VERSION,
    BaselineData,
    ChangeRecord,
    ChangeStatus,
    FileSnapshot,
    ScanError,
    ScanResult,
    ScanStatus,
    SeverityLevel,
    is_windows_style_path,
)

_EXACT_PAIRING_PRODUCT_LIMIT = 10_000


def _utc_now_iso() -> str:
    """Return the current UTC timestamp in canonical ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _basename_casefold(path: str) -> str:
    """Return the casefolded filename component of a forward-slashed path."""
    return path.rsplit("/", 1)[-1].casefold()


def _path_key(path: str, case_insensitive: bool) -> str:
    """Return the lookup key for *path* respecting Windows case-insensitivity."""
    return path.casefold() if case_insensitive else path


def has_snapshot_changed(base: FileSnapshot, current: FileSnapshot) -> bool:
    """Determine whether *current* represents modified file content vs *base*.

    Uses size and mtime_ns as a fast-path check and verifies SHA-256 digest
    alongside file size so mtime-only changes do not produce false positives.

    Args:
        base: Baseline FileSnapshot record.
        current: Current scan FileSnapshot record for the same path.

    Returns:
        True if file content hash or size changed; False otherwise.
    """
    if (
        base.size_bytes == current.size_bytes
        and base.mtime_ns == current.mtime_ns
        and base.sha256 == current.sha256
    ):
        return False
    return base.sha256 != current.sha256 or base.size_bytes != current.size_bytes


def _index_snapshots(
    snapshots: List[FileSnapshot],
    case_insensitive: bool,
    source_label: str,
    errors: List[ScanError],
) -> Dict[str, FileSnapshot]:
    """Index snapshots by normalized path key and record collision errors."""
    indexed: Dict[str, FileSnapshot] = {}
    for snap in sorted(snapshots, key=lambda item: item.path):
        key = _path_key(snap.path, case_insensitive)
        if key in indexed:
            existing = indexed[key]
            errors.append(
                ScanError(
                    code="PATH_CASE_COLLISION",
                    path=snap.path,
                    message=(
                        f"Case-insensitive path collision in {source_label}: "
                        f"'{snap.path}' conflicts with '{existing.path}'."
                    ),
                )
            )
            continue
        indexed[key] = snap
    return indexed


def _pair_by_nearest_mtime(
    old_items: List[Tuple[int, FileSnapshot]],
    new_items: List[Tuple[int, FileSnapshot]],
    matched_old: Set[int],
    matched_new: Set[int],
    pairs: List[Tuple[FileSnapshot, FileSnapshot]],
) -> None:
    """Pair remaining old/new items deterministically by closest mtime_ns."""
    if not old_items or not new_items:
        return

    if len(old_items) * len(new_items) <= _EXACT_PAIRING_PRODUCT_LIMIT:
        old_map = dict(old_items)
        new_map = dict(new_items)
        candidates: List[Tuple[int, str, str, int, int]] = []
        for old_idx, old_snap in old_items:
            for new_idx, new_snap in new_items:
                delta = abs(new_snap.mtime_ns - old_snap.mtime_ns)
                candidates.append(
                    (delta, old_snap.path, new_snap.path, old_idx, new_idx)
                )
        candidates.sort()
        for _, _, _, old_idx, new_idx in candidates:
            if old_idx in matched_old or new_idx in matched_new:
                continue
            matched_old.add(old_idx)
            matched_new.add(new_idx)
            pairs.append((old_map[old_idx], new_map[new_idx]))
        return

    # Large identical-hash bucket fallback: O(B log B) closest-mtime pairing.
    sorted_old = sorted(old_items, key=lambda item: (item[1].mtime_ns, item[1].path))
    sorted_new = sorted(new_items, key=lambda item: (item[1].mtime_ns, item[1].path))
    new_mtimes = [item[1].mtime_ns for item in sorted_new]
    count_new = len(sorted_new)

    # Disjoint-set next/prev links skip already matched positions in O(alpha(B)).
    next_free = list(range(count_new + 1))
    prev_free = list(range(count_new))

    def find_next(pos: int) -> int:
        while pos < count_new and next_free[pos] != pos:
            parent = next_free[pos]
            if parent < count_new:
                next_free[pos] = next_free[parent]
            pos = parent
        return pos

    def find_prev(pos: int) -> int:
        while pos >= 0 and prev_free[pos] != pos:
            parent = prev_free[pos]
            if parent < 0:
                return -1
            if prev_free[parent] >= 0:
                prev_free[pos] = prev_free[parent]
            pos = parent
        return pos

    def mark_used(pos: int) -> None:
        next_free[pos] = pos + 1
        prev_free[pos] = pos - 1

    for old_idx, old_snap in sorted_old:
        insert_pos = bisect_left(new_mtimes, old_snap.mtime_ns)
        right_pos = find_next(insert_pos)
        left_pos = find_prev(insert_pos - 1)

        chosen_pos = -1
        if left_pos >= 0 and right_pos < count_new:
            left_delta = abs(sorted_new[left_pos][1].mtime_ns - old_snap.mtime_ns)
            right_delta = abs(sorted_new[right_pos][1].mtime_ns - old_snap.mtime_ns)
            if left_delta < right_delta:
                chosen_pos = left_pos
            elif right_delta < left_delta:
                chosen_pos = right_pos
            else:
                chosen_pos = (
                    left_pos
                    if sorted_new[left_pos][1].path <= sorted_new[right_pos][1].path
                    else right_pos
                )
        elif right_pos < count_new:
            chosen_pos = right_pos
        elif left_pos >= 0:
            chosen_pos = left_pos
        else:
            break

        mark_used(chosen_pos)
        new_idx, new_snap = sorted_new[chosen_pos]
        matched_old.add(old_idx)
        matched_new.add(new_idx)
        pairs.append((old_snap, new_snap))


def _pair_bucket(
    old_bucket: List[FileSnapshot],
    new_bucket: List[FileSnapshot],
) -> Tuple[List[Tuple[FileSnapshot, FileSnapshot]], List[FileSnapshot], List[FileSnapshot]]:
    """Pair disappeared and newly appeared snapshots within one (size, sha256) bucket."""
    old_sorted = sorted(old_bucket, key=lambda snap: snap.path)
    new_sorted = sorted(new_bucket, key=lambda snap: snap.path)

    matched_old: Set[int] = set()
    matched_new: Set[int] = set()
    pairs: List[Tuple[FileSnapshot, FileSnapshot]] = []

    # Priority 1: exact (mtime_ns, basename.casefold())
    p1_new: DefaultDict[Tuple[int, str], deque[int]] = defaultdict(deque)
    for new_idx, new_snap in enumerate(new_sorted):
        p1_new[(new_snap.mtime_ns, _basename_casefold(new_snap.path))].append(new_idx)

    for old_idx, old_snap in enumerate(old_sorted):
        key = (old_snap.mtime_ns, _basename_casefold(old_snap.path))
        queue = p1_new.get(key)
        if queue:
            new_idx = queue.popleft()
            matched_old.add(old_idx)
            matched_new.add(new_idx)
            pairs.append((old_snap, new_sorted[new_idx]))

    # Priority 2: exact mtime_ns
    p2_new: DefaultDict[int, deque[int]] = defaultdict(deque)
    for new_idx, new_snap in enumerate(new_sorted):
        if new_idx not in matched_new:
            p2_new[new_snap.mtime_ns].append(new_idx)

    for old_idx, old_snap in enumerate(old_sorted):
        if old_idx in matched_old:
            continue
        queue = p2_new.get(old_snap.mtime_ns)
        if queue:
            new_idx = queue.popleft()
            matched_old.add(old_idx)
            matched_new.add(new_idx)
            pairs.append((old_snap, new_sorted[new_idx]))

    # Priority 3: exact basename.casefold() (closest mtime_ns first)
    old_by_base: DefaultDict[str, List[Tuple[int, FileSnapshot]]] = defaultdict(list)
    new_by_base: DefaultDict[str, List[Tuple[int, FileSnapshot]]] = defaultdict(list)
    for old_idx, old_snap in enumerate(old_sorted):
        if old_idx not in matched_old:
            old_by_base[_basename_casefold(old_snap.path)].append((old_idx, old_snap))
    for new_idx, new_snap in enumerate(new_sorted):
        if new_idx not in matched_new:
            new_by_base[_basename_casefold(new_snap.path)].append((new_idx, new_snap))

    for base_name in sorted(old_by_base):
        if base_name in new_by_base:
            _pair_by_nearest_mtime(
                old_by_base[base_name],
                new_by_base[base_name],
                matched_old,
                matched_new,
                pairs,
            )

    # Priority 4: remaining items by closest mtime_ns and deterministic paths
    rem_old = [
        (old_idx, old_snap)
        for old_idx, old_snap in enumerate(old_sorted)
        if old_idx not in matched_old
    ]
    rem_new = [
        (new_idx, new_snap)
        for new_idx, new_snap in enumerate(new_sorted)
        if new_idx not in matched_new
    ]
    _pair_by_nearest_mtime(rem_old, rem_new, matched_old, matched_new, pairs)

    unmatched_old = [
        snap for idx, snap in enumerate(old_sorted) if idx not in matched_old
    ]
    unmatched_new = [
        snap for idx, snap in enumerate(new_sorted) if idx not in matched_new
    ]
    return pairs, unmatched_old, unmatched_new


def _build_modified_reason(base: FileSnapshot, current: FileSnapshot) -> str:
    """Create a concise human-readable reason for a MODIFIED ChangeRecord."""
    hash_changed = base.sha256 != current.sha256
    size_changed = base.size_bytes != current.size_bytes
    if hash_changed and size_changed:
        return (
            f"SHA-256 content hash changed and file size changed "
            f"({base.size_bytes} -> {current.size_bytes} bytes)"
        )
    if hash_changed:
        return "SHA-256 content hash changed"
    return f"File size changed ({base.size_bytes} -> {current.size_bytes} bytes)"


def compare_snapshots(
    baseline: BaselineData,
    current_snapshots: List[FileSnapshot],
    scan_errors: Optional[List[ScanError]] = None,
) -> ScanResult:
    """Compare *current_snapshots* against *baseline* and return a ScanResult.

    Detects MODIFIED, MOVED (via O(N) size+SHA-256 bucketing and mtime/basename
    heuristics), DELETED, and ADDED files, as well as case-insensitive path
    collisions on Windows-style paths.

    Args:
        baseline: Trusted BaselineData to compare against.
        current_snapshots: List of FileSnapshot objects from the current scan.
        scan_errors: Optional list of ScanError objects encountered during scanning.

    Returns:
        Canonical ScanResult with deterministic sorted changes, summary counts,
        and overall scan status (``ERROR`` whenever errors is non-empty).
    """
    started_at = _utc_now_iso()
    errors: List[ScanError] = list(scan_errors) if scan_errors else []
    case_insensitive = is_windows_style_path(baseline.root_path) or (os.name == "nt")

    base_by_key = _index_snapshots(
        list(baseline.files.values()),
        case_insensitive=case_insensitive,
        source_label="baseline",
        errors=errors,
    )
    cur_by_key = _index_snapshots(
        current_snapshots,
        case_insensitive=case_insensitive,
        source_label="current scan",
        errors=errors,
    )

    changes: List[ChangeRecord] = []
    disappeared: List[FileSnapshot] = []
    appeared: List[FileSnapshot] = []

    for key, base_snap in base_by_key.items():
        cur_snap = cur_by_key.get(key)
        if cur_snap is None:
            disappeared.append(base_snap)
        elif has_snapshot_changed(base_snap, cur_snap):
            changes.append(
                ChangeRecord(
                    status=ChangeStatus.MODIFIED.value,
                    path=cur_snap.path,
                    old_path=None,
                    new_path=cur_snap.path,
                    old_sha256=base_snap.sha256,
                    new_sha256=cur_snap.sha256,
                    old_size_bytes=base_snap.size_bytes,
                    new_size_bytes=cur_snap.size_bytes,
                    severity=SeverityLevel.MEDIUM.value,
                    reason=_build_modified_reason(base_snap, cur_snap),
                )
            )

    for key, cur_snap in cur_by_key.items():
        if key not in base_by_key:
            appeared.append(cur_snap)

    # Group disappeared & appeared snapshots by (size_bytes, sha256) in O(N).
    old_buckets: DefaultDict[Tuple[int, str], List[FileSnapshot]] = defaultdict(list)
    new_buckets: DefaultDict[Tuple[int, str], List[FileSnapshot]] = defaultdict(list)
    for snap in disappeared:
        old_buckets[(snap.size_bytes, snap.sha256)].append(snap)
    for snap in appeared:
        new_buckets[(snap.size_bytes, snap.sha256)].append(snap)

    unmatched_deleted: List[FileSnapshot] = []
    unmatched_added: List[FileSnapshot] = []

    for bucket_key, old_bucket in old_buckets.items():
        new_bucket = new_buckets.get(bucket_key)
        if not new_bucket:
            unmatched_deleted.extend(old_bucket)
            continue
        moved_pairs, rem_old, rem_new = _pair_bucket(old_bucket, new_bucket)
        for old_snap, new_snap in moved_pairs:
            changes.append(
                ChangeRecord(
                    status=ChangeStatus.MOVED.value,
                    path=new_snap.path,
                    old_path=old_snap.path,
                    new_path=new_snap.path,
                    old_sha256=old_snap.sha256,
                    new_sha256=new_snap.sha256,
                    old_size_bytes=old_snap.size_bytes,
                    new_size_bytes=new_snap.size_bytes,
                    severity=SeverityLevel.LOW.value,
                    reason=(
                        f"File moved from '{old_snap.path}' to '{new_snap.path}' "
                        f"(SHA-256 verified)"
                    ),
                )
            )
        unmatched_deleted.extend(rem_old)
        unmatched_added.extend(rem_new)

    for bucket_key, new_bucket in new_buckets.items():
        if bucket_key not in old_buckets:
            unmatched_added.extend(new_bucket)

    for old_snap in unmatched_deleted:
        changes.append(
            ChangeRecord(
                status=ChangeStatus.DELETED.value,
                path=old_snap.path,
                old_path=old_snap.path,
                new_path=None,
                old_sha256=old_snap.sha256,
                new_sha256=None,
                old_size_bytes=old_snap.size_bytes,
                new_size_bytes=None,
                severity=SeverityLevel.MEDIUM.value,
                reason="File present in baseline is missing",
            )
        )

    for new_snap in unmatched_added:
        changes.append(
            ChangeRecord(
                status=ChangeStatus.ADDED.value,
                path=new_snap.path,
                old_path=None,
                new_path=new_snap.path,
                old_sha256=None,
                new_sha256=new_snap.sha256,
                old_size_bytes=None,
                new_size_bytes=new_snap.size_bytes,
                severity=SeverityLevel.LOW.value,
                reason="New file not present in baseline",
            )
        )

    changes.sort(key=lambda change: (change.path, change.status, change.old_path or ""))

    counts = {
        "added": 0,
        "modified": 0,
        "deleted": 0,
        "moved": 0,
        "errors": len(errors),
    }
    for change in changes:
        counts[change.status.lower()] += 1

    if errors:
        overall_status = ScanStatus.ERROR.value
    elif changes:
        overall_status = ScanStatus.CHANGED.value
    else:
        overall_status = ScanStatus.CLEAN.value

    completed_at = _utc_now_iso()
    return ScanResult(
        schema_version=SCHEMA_VERSION,
        scan_id=str(uuid.uuid4()),
        root_path=baseline.root_path,
        started_at=started_at,
        completed_at=completed_at,
        status=overall_status,
        summary=counts,
        changes=changes,
        errors=errors,
    )


__all__ = [
    "compare_snapshots",
    "has_snapshot_changed",
]
