"""Unit tests for sentinel.core.diff."""

from __future__ import annotations

from hashlib import sha256
import re
import unittest
from unittest.mock import patch
import uuid

from sentinel.core.baseline import build_baseline
from sentinel.core.diff import compare_snapshots, has_snapshot_changed
from sentinel.core.models import (
    SCHEMA_VERSION,
    BaselineData,
    FileSnapshot,
    ScanError,
)

_EMPTY_SHA = sha256(b"").hexdigest()
_UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _snap(
    path: str,
    label: str = "content",
    size_bytes: int = 100,
    mtime_ns: int = 1_730_000_000_000_000_000,
    sha_override: str | None = None,
) -> FileSnapshot:
    return FileSnapshot(
        path=path,
        sha256=sha_override if sha_override is not None else _digest(label),
        size_bytes=size_bytes,
        mtime_ns=mtime_ns,
    )


def _win_baseline(snapshots: list[FileSnapshot], root: str = "C:/Projects/MyApp") -> BaselineData:
    return BaselineData(
        schema_version=SCHEMA_VERSION,
        root_path=root,
        created_at="2026-11-14T12:30:00Z",
        hash_algorithm="sha256",
        files={snap.path: snap for snap in snapshots},
    )


class TestHasSnapshotChanged(unittest.TestCase):
    """Direct unit tests for size/mtime heuristics and SHA-256 verification."""

    def test_identical_metadata_and_hash_not_changed(self) -> None:
        base = _snap("a.txt", "v1", size_bytes=64, mtime_ns=1000)
        cur = _snap("a.txt", "v1", size_bytes=64, mtime_ns=1000)
        self.assertFalse(has_snapshot_changed(base, cur))

    def test_mtime_only_change_not_modified(self) -> None:
        base = _snap("a.txt", "v1", size_bytes=64, mtime_ns=1000)
        cur = _snap("a.txt", "v1", size_bytes=64, mtime_ns=2000)
        self.assertFalse(has_snapshot_changed(base, cur))

    def test_backdated_mtime_and_same_size_with_different_hash_is_modified(self) -> None:
        base = _snap("a.txt", "v1", size_bytes=64, mtime_ns=2000)
        cur = _snap("a.txt", "v2", size_bytes=64, mtime_ns=1000)
        self.assertTrue(has_snapshot_changed(base, cur))

    def test_identical_mtime_and_size_with_different_hash_is_modified(self) -> None:
        base = _snap("a.txt", "v1", size_bytes=64, mtime_ns=2000)
        cur = _snap("a.txt", "v2", size_bytes=64, mtime_ns=2000)
        self.assertTrue(has_snapshot_changed(base, cur))

    def test_size_change_even_with_same_hash_is_modified(self) -> None:
        base = _snap("a.txt", "v1", size_bytes=64, mtime_ns=1000)
        cur = _snap("a.txt", "v1", size_bytes=65, mtime_ns=1000)
        self.assertTrue(has_snapshot_changed(base, cur))


class TestBasicChangeStatuses(unittest.TestCase):
    """Verify CLEAN, ADDED, MODIFIED, DELETED, MOVED record shapes and heuristics."""

    def test_clean_when_baseline_and_current_match_exactly(self) -> None:
        snaps = [
            _snap("README.md", "readme", size_bytes=120, mtime_ns=1000),
            _snap("src/main.py", "main", size_bytes=450, mtime_ns=2000),
        ]
        baseline = _win_baseline(snaps)
        result = compare_snapshots(baseline, list(snaps))

        self.assertEqual(result.schema_version, SCHEMA_VERSION)
        uuid.UUID(result.scan_id)
        self.assertEqual(result.root_path, "C:/Projects/MyApp")
        self.assertRegex(result.started_at, _UTC_Z_RE)
        self.assertRegex(result.completed_at, _UTC_Z_RE)
        self.assertEqual(result.status, "CLEAN")
        self.assertEqual(
            result.summary,
            {"added": 0, "modified": 0, "deleted": 0, "moved": 0, "errors": 0},
        )
        self.assertEqual(result.changes, [])
        self.assertEqual(result.errors, [])

    def test_mtime_only_change_returns_clean_while_backdated_hash_change_returns_modified(self) -> None:
        base_snaps = [
            _snap("touched.txt", "same", size_bytes=50, mtime_ns=5000),
            _snap("tampered.txt", "orig", size_bytes=50, mtime_ns=5000),
        ]
        baseline = _win_baseline(base_snaps)

        # First scan: only mtime_ns changed for touched.txt, tampered.txt unchanged -> CLEAN
        clean_res = compare_snapshots(
            baseline,
            [
                _snap("touched.txt", "same", size_bytes=50, mtime_ns=9999),
                _snap("tampered.txt", "orig", size_bytes=50, mtime_ns=5000),
            ],
        )
        self.assertEqual(clean_res.status, "CLEAN")
        self.assertEqual(clean_res.changes, [])

        # Second scan: tampered.txt has backdated mtime_ns and identical size, different sha256 -> MODIFIED
        mod_res = compare_snapshots(
            baseline,
            [
                _snap("touched.txt", "same", size_bytes=50, mtime_ns=9999),
                _snap("tampered.txt", "evil", size_bytes=50, mtime_ns=1000),
            ],
        )
        self.assertEqual(mod_res.status, "CHANGED")
        self.assertEqual(mod_res.summary["modified"], 1)
        self.assertEqual(len(mod_res.changes), 1)
        rec = mod_res.changes[0]
        self.assertEqual(rec.status, "MODIFIED")
        self.assertIsNone(rec.old_path)
        self.assertEqual(rec.new_path, "tampered.txt")
        self.assertEqual(rec.path, "tampered.txt")
        self.assertEqual(rec.reason, "SHA-256 content hash changed")

    def test_added_record_fields(self) -> None:
        baseline = _win_baseline([])
        added_snap = _snap("src/new_module.py", "new-mod", size_bytes=321, mtime_ns=42)
        result = compare_snapshots(baseline, [added_snap])

        self.assertEqual(result.status, "CHANGED")
        self.assertEqual(
            result.summary,
            {"added": 1, "modified": 0, "deleted": 0, "moved": 0, "errors": 0},
        )
        self.assertEqual(len(result.changes), 1)
        rec = result.changes[0]
        self.assertEqual(rec.status, "ADDED")
        self.assertEqual(rec.path, "src/new_module.py")
        self.assertIsNone(rec.old_path)
        self.assertEqual(rec.new_path, "src/new_module.py")
        self.assertIsNone(rec.old_sha256)
        self.assertEqual(rec.new_sha256, _digest("new-mod"))
        self.assertIsNone(rec.old_size_bytes)
        self.assertEqual(rec.new_size_bytes, 321)

    def test_modified_record_fields_and_reason_variants(self) -> None:
        base_both = _snap("both.py", "v1", size_bytes=100, mtime_ns=10)
        base_hash = _snap("hash_only.py", "h1", size_bytes=100, mtime_ns=10)
        base_size = _snap("size_only.py", "same", size_bytes=100, mtime_ns=10)
        baseline = _win_baseline([base_both, base_hash, base_size])

        cur_both = _snap("both.py", "v2", size_bytes=140, mtime_ns=20)
        cur_hash = _snap("hash_only.py", "h2", size_bytes=100, mtime_ns=20)
        cur_size = _snap("size_only.py", "same", size_bytes=110, mtime_ns=20)

        result = compare_snapshots(baseline, [cur_both, cur_hash, cur_size])
        self.assertEqual(result.status, "CHANGED")
        self.assertEqual(result.summary["modified"], 3)

        by_path = {rec.path: rec for rec in result.changes}

        rec_both = by_path["both.py"]
        self.assertEqual(rec_both.status, "MODIFIED")
        self.assertIsNone(rec_both.old_path)
        self.assertEqual(rec_both.new_path, "both.py")
        self.assertEqual(rec_both.old_sha256, base_both.sha256)
        self.assertEqual(rec_both.new_sha256, cur_both.sha256)
        self.assertEqual(rec_both.old_size_bytes, 100)
        self.assertEqual(rec_both.new_size_bytes, 140)
        self.assertIn("SHA-256 content hash changed", rec_both.reason)
        self.assertIn("100 -> 140 bytes", rec_both.reason)

        rec_hash = by_path["hash_only.py"]
        self.assertIsNone(rec_hash.old_path)
        self.assertEqual(rec_hash.new_path, "hash_only.py")
        self.assertEqual(rec_hash.old_size_bytes, 100)
        self.assertEqual(rec_hash.new_size_bytes, 100)
        self.assertEqual(rec_hash.reason, "SHA-256 content hash changed")

        rec_size = by_path["size_only.py"]
        self.assertIsNone(rec_size.old_path)
        self.assertEqual(rec_size.new_path, "size_only.py")
        self.assertEqual(rec_size.reason, "File size changed (100 -> 110 bytes)")

    def test_deleted_record_fields(self) -> None:
        old_snap = _snap("legacy/old.py", "old-content", size_bytes=512, mtime_ns=900)
        baseline = _win_baseline([old_snap])
        result = compare_snapshots(baseline, [])

        self.assertEqual(result.status, "CHANGED")
        self.assertEqual(
            result.summary,
            {"added": 0, "modified": 0, "deleted": 1, "moved": 0, "errors": 0},
        )
        self.assertEqual(len(result.changes), 1)
        rec = result.changes[0]
        self.assertEqual(rec.status, "DELETED")
        self.assertEqual(rec.path, "legacy/old.py")
        self.assertEqual(rec.old_path, "legacy/old.py")
        self.assertIsNone(rec.new_path)
        self.assertEqual(rec.old_sha256, _digest("old-content"))
        self.assertIsNone(rec.new_sha256)
        self.assertEqual(rec.old_size_bytes, 512)
        self.assertIsNone(rec.new_size_bytes)

    def test_moved_record_fields(self) -> None:
        old_snap = _snap("old_dir/app.py", "app-body", size_bytes=256, mtime_ns=1500)
        new_snap = _snap("new_dir/app.py", "app-body", size_bytes=256, mtime_ns=1500)
        baseline = _win_baseline([old_snap])
        result = compare_snapshots(baseline, [new_snap])

        self.assertEqual(result.status, "CHANGED")
        self.assertEqual(
            result.summary,
            {"added": 0, "modified": 0, "deleted": 0, "moved": 1, "errors": 0},
        )
        self.assertEqual(len(result.changes), 1)
        rec = result.changes[0]
        self.assertEqual(rec.status, "MOVED")
        self.assertEqual(rec.path, "new_dir/app.py")
        self.assertEqual(rec.old_path, "old_dir/app.py")
        self.assertEqual(rec.new_path, "new_dir/app.py")
        self.assertEqual(rec.old_sha256, _digest("app-body"))
        self.assertEqual(rec.new_sha256, _digest("app-body"))
        self.assertEqual(rec.old_size_bytes, 256)
        self.assertEqual(rec.new_size_bytes, 256)


class TestMoveEdgeCasesAndHeuristics(unittest.TestCase):
    """Verify move disambiguation, copy handling, empty files, and O(B log B) fallback."""

    def test_copy_without_delete_is_added_not_moved(self) -> None:
        orig = _snap("src/orig.py", "shared", size_bytes=200, mtime_ns=1000)
        copy = _snap("backup/orig.py", "shared", size_bytes=200, mtime_ns=1000)
        baseline = _win_baseline([orig])
        result = compare_snapshots(baseline, [orig, copy])

        self.assertEqual(result.status, "CHANGED")
        self.assertEqual(
            result.summary,
            {"added": 1, "modified": 0, "deleted": 0, "moved": 0, "errors": 0},
        )
        self.assertEqual(len(result.changes), 1)
        self.assertEqual(result.changes[0].status, "ADDED")
        self.assertEqual(result.changes[0].path, "backup/orig.py")

    def test_one_deleted_and_two_identical_added_produces_one_moved_and_one_added(self) -> None:
        deleted_snap = _snap("docs/guide.md", "same-doc", size_bytes=300, mtime_ns=5000)
        copy_renamed = _snap("archive/copy.md", "same-doc", size_bytes=300, mtime_ns=9000)
        copy_exact_match = _snap("archive/guide.md", "same-doc", size_bytes=300, mtime_ns=5000)

        baseline = _win_baseline([deleted_snap])
        result = compare_snapshots(baseline, [copy_renamed, copy_exact_match])

        self.assertEqual(
            result.summary,
            {"added": 1, "modified": 0, "deleted": 0, "moved": 1, "errors": 0},
        )
        by_status = {rec.status: rec for rec in result.changes}
        self.assertEqual(by_status["MOVED"].old_path, "docs/guide.md")
        self.assertEqual(by_status["MOVED"].new_path, "archive/guide.md")
        self.assertEqual(by_status["ADDED"].new_path, "archive/copy.md")

    def test_duplicate_content_tie_breaking_priority_order(self) -> None:
        # Priority order: (mtime_ns, basename) > mtime_ns > basename > closest mtime_ns
        sha = _digest("identical-payload")
        size = 512

        # 1. (mtime_ns, basename) beats mtime-only and basename-only
        b1 = _win_baseline([_snap("old/Report.txt", "", size, 1000, sha_override=sha)])
        r1 = compare_snapshots(
            b1,
            [
                _snap("new/other.txt", "", size, 1000, sha_override=sha),    # P2: mtime only
                _snap("new/report.txt", "", size, 2000, sha_override=sha),   # P3: basename only
                _snap("new/REPORT.TXT", "", size, 1000, sha_override=sha),   # P1: (mtime, basename)
            ],
        )
        moved_1 = [c for c in r1.changes if c.status == "MOVED"]
        self.assertEqual(len(moved_1), 1)
        self.assertEqual(moved_1[0].new_path, "new/REPORT.TXT")

        # 2. mtime_ns beats basename-only (even if basename has close mtime)
        b2 = _win_baseline([_snap("old/alpha.txt", "", size, 5000, sha_override=sha)])
        r2 = compare_snapshots(
            b2,
            [
                _snap("new/alpha.txt", "", size, 5001, sha_override=sha),    # P3: basename only
                _snap("new/renamed.txt", "", size, 5000, sha_override=sha),  # P2: exact mtime
            ],
        )
        moved_2 = [c for c in r2.changes if c.status == "MOVED"]
        self.assertEqual(len(moved_2), 1)
        self.assertEqual(moved_2[0].new_path, "new/renamed.txt")

        # 3. basename beats closest-mtime fallback
        b3 = _win_baseline([_snap("old/config.yml", "", size, 10_000, sha_override=sha)])
        r3 = compare_snapshots(
            b3,
            [
                _snap("new/other.yml", "", size, 10_001, sha_override=sha),   # P4: closer mtime
                _snap("new/CONFIG.YML", "", size, 99_000, sha_override=sha),  # P3: basename match
            ],
        )
        moved_3 = [c for c in r3.changes if c.status == "MOVED"]
        self.assertEqual(len(moved_3), 1)
        self.assertEqual(moved_3[0].new_path, "new/CONFIG.YML")

        # 4. Closest mtime_ns wins when neither mtime nor basename matches
        b4 = _win_baseline([_snap("old/blob.bin", "", size, 10_000, sha_override=sha)])
        r4 = compare_snapshots(
            b4,
            [
                _snap("new/far.bin", "", size, 25_000, sha_override=sha),
                _snap("new/near.bin", "", size, 10_250, sha_override=sha),
            ],
        )
        moved_4 = [c for c in r4.changes if c.status == "MOVED"]
        self.assertEqual(len(moved_4), 1)
        self.assertEqual(moved_4[0].new_path, "new/near.bin")

    def test_empty_zero_byte_file_moved_vs_unmatched(self) -> None:
        # 1. Moved empty file
        empty_old = _snap("empty_a.txt", "", size_bytes=0, mtime_ns=100, sha_override=_EMPTY_SHA)
        empty_new = _snap("sub/empty_b.txt", "", size_bytes=0, mtime_ns=100, sha_override=_EMPTY_SHA)
        moved_res = compare_snapshots(_win_baseline([empty_old]), [empty_new])
        self.assertEqual(
            moved_res.summary,
            {"added": 0, "modified": 0, "deleted": 0, "moved": 1, "errors": 0},
        )
        self.assertEqual(moved_res.changes[0].old_path, "empty_a.txt")
        self.assertEqual(moved_res.changes[0].new_path, "sub/empty_b.txt")

        # 2. Unmatched empty file: baseline keeps empty_a.txt and current adds empty_b.txt -> ADDED
        added_res = compare_snapshots(_win_baseline([empty_old]), [empty_old, empty_new])
        self.assertEqual(
            added_res.summary,
            {"added": 1, "modified": 0, "deleted": 0, "moved": 0, "errors": 0},
        )
        self.assertEqual(added_res.changes[0].status, "ADDED")
        self.assertEqual(added_res.changes[0].path, "sub/empty_b.txt")

        # 3. Deleted empty file with no replacement -> DELETED
        del_res = compare_snapshots(_win_baseline([empty_old]), [])
        self.assertEqual(
            del_res.summary,
            {"added": 0, "modified": 0, "deleted": 1, "moved": 0, "errors": 0},
        )
        self.assertEqual(del_res.changes[0].status, "DELETED")
        self.assertEqual(del_res.changes[0].old_path, "empty_a.txt")

    def test_large_identical_hash_bucket_uses_deterministic_nlogn_fallback(self) -> None:
        # 110 deleted * 110 added = 12,100 > 10,000 exact pairing threshold.
        # Distinct mtimes and distinct basenames ensure P1/P2/P3 do not pre-match them,
        # forcing Priority 4 into the O(B log B) closest-mtime fallback.
        count = 110
        shared_sha = _digest("repeated-placeholder")
        old_snaps = [
            _snap(
                f"old_dir/old_{i:03d}.bin",
                "",
                size_bytes=64,
                mtime_ns=1_000_000 + i * 100,
                sha_override=shared_sha,
            )
            for i in range(count)
        ]
        new_snaps = [
            _snap(
                f"new_dir/new_{i:03d}.bin",
                "",
                size_bytes=64,
                mtime_ns=1_000_000 + i * 100 + (20 if i % 2 == 0 else -20),
                sha_override=shared_sha,
            )
            for i in range(count)
        ]

        baseline = _win_baseline(old_snaps)
        res1 = compare_snapshots(baseline, new_snaps)
        res2 = compare_snapshots(baseline, list(reversed(new_snaps)))

        self.assertEqual(res1.status, "CHANGED")
        self.assertEqual(
            res1.summary,
            {"added": 0, "modified": 0, "deleted": 0, "moved": count, "errors": 0},
        )
        pairs1 = [(c.old_path, c.new_path) for c in res1.changes]
        pairs2 = [(c.old_path, c.new_path) for c in res2.changes]
        self.assertEqual(pairs1, pairs2)
        self.assertEqual(len({p[0] for p in pairs1}), count)
        self.assertEqual(len({p[1] for p in pairs1}), count)


class TestCaseSensitivityErrorsAndOrdering(unittest.TestCase):
    """Verify Windows case-insensitive matching, errors, and deterministic sorting."""

    def test_windows_case_insensitive_matching_preserves_display_path(self) -> None:
        base_snap = _snap("Src/Main.py", "same-code", size_bytes=200, mtime_ns=1000)
        baseline = _win_baseline([base_snap], root="C:/Projects/MyApp")

        # Same content, different casing -> matched as same file (CLEAN)
        cur_same = _snap("src/main.py", "same-code", size_bytes=200, mtime_ns=1000)
        clean_res = compare_snapshots(baseline, [cur_same])
        self.assertEqual(clean_res.status, "CLEAN")
        self.assertEqual(clean_res.changes, [])

        # Changed content, different casing -> MODIFIED with current display path preserved
        cur_mod = _snap("src/main.py", "updated-code", size_bytes=250, mtime_ns=2000)
        mod_res = compare_snapshots(baseline, [cur_mod])
        self.assertEqual(mod_res.status, "CHANGED")
        self.assertEqual(
            mod_res.summary,
            {"added": 0, "modified": 1, "deleted": 0, "moved": 0, "errors": 0},
        )
        rec = mod_res.changes[0]
        self.assertEqual(rec.status, "MODIFIED")
        self.assertEqual(rec.path, "src/main.py")
        self.assertEqual(rec.new_path, "src/main.py")
        self.assertIsNone(rec.old_path)

    def test_posix_root_remains_case_sensitive_when_non_windows(self) -> None:
        base_snap = _snap("Src/Main.py", "same-code", size_bytes=200, mtime_ns=1000)
        baseline = build_baseline("/opt/myapp", [base_snap])  # type: ignore[arg-type]
        cur_snap = _snap("src/main.py", "same-code", size_bytes=200, mtime_ns=1000)

        with patch("sentinel.core.diff.os.name", "posix"):
            res = compare_snapshots(baseline, [cur_snap])
        self.assertEqual(res.status, "CHANGED")
        self.assertEqual(res.summary["moved"], 1)
        self.assertEqual(res.changes[0].old_path, "Src/Main.py")
        self.assertEqual(res.changes[0].new_path, "src/main.py")

    def test_path_case_collision_in_current_and_baseline_sets_error_status(self) -> None:
        # Collision in current snapshots on Windows root_path
        baseline = _win_baseline([_snap("README.md", "readme", 10, 1)], root="C:/Projects/MyApp")
        current = [
            _snap("README.md", "readme", 10, 1),
            _snap("src/Main.py", "main1", 20, 2),
            _snap("src/main.py", "main2", 25, 3),
        ]
        res_cur = compare_snapshots(baseline, current)
        self.assertEqual(res_cur.status, "ERROR")
        self.assertEqual(res_cur.summary["errors"], len(res_cur.errors))
        self.assertEqual(len(res_cur.errors), 1)
        self.assertEqual(res_cur.errors[0].code, "PATH_CASE_COLLISION")
        self.assertEqual(res_cur.errors[0].path, "src/main.py")

        # Collision already present inside BaselineData
        colliding_baseline = _win_baseline(
            [
                _snap("src/Main.py", "main1", 20, 2),
                _snap("src/main.py", "main2", 25, 3),
            ],
            root="C:/Projects/MyApp",
        )
        res_base = compare_snapshots(colliding_baseline, [_snap("src/Main.py", "main1", 20, 2)])
        self.assertEqual(res_base.status, "ERROR")
        self.assertEqual(res_base.summary["errors"], len(res_base.errors))
        self.assertEqual(len(res_base.errors), 1)
        self.assertEqual(res_base.errors[0].code, "PATH_CASE_COLLISION")

    def test_scan_errors_with_zero_changes_forces_error_status(self) -> None:
        snaps = [_snap("README.md", "readme", 50, 100)]
        baseline = _win_baseline(snaps)
        supplied_errors = [
            ScanError(
                code="FILE_ACCESS_DENIED",
                path="src/private.txt",
                message="The file could not be read.",
            )
        ]

        result = compare_snapshots(baseline, list(snaps), scan_errors=supplied_errors)
        self.assertEqual(result.status, "ERROR")
        self.assertEqual(result.changes, [])
        self.assertEqual(
            result.summary,
            {"added": 0, "modified": 0, "deleted": 0, "moved": 0, "errors": 1},
        )
        self.assertEqual(result.summary["errors"], len(result.errors))
        self.assertEqual(result.errors, supplied_errors)
        # Returned errors list should not alias caller's list
        self.assertIsNot(result.errors, supplied_errors)

    def test_combined_multi_change_scenario_summary_and_sort_order(self) -> None:
        baseline = _win_baseline(
            [
                _snap("unchanged.txt", "same", size_bytes=10, mtime_ns=100),
                _snap("b_mod.py", "mod-old", size_bytes=100, mtime_ns=200),
                _snap("c_del.py", "deleted-only", size_bytes=300, mtime_ns=300),
                _snap("z_old_loc.py", "moved-body", size_bytes=400, mtime_ns=400),
            ]
        )
        current = [
            _snap("unchanged.txt", "same", size_bytes=10, mtime_ns=100),
            _snap("a_added.py", "brand-new", size_bytes=50, mtime_ns=500),
            _snap("b_mod.py", "mod-new", size_bytes=125, mtime_ns=600),
            _snap("d_moved_loc.py", "moved-body", size_bytes=400, mtime_ns=400),
        ]

        result = compare_snapshots(baseline, current)
        self.assertEqual(result.status, "CHANGED")
        self.assertEqual(
            result.summary,
            {"added": 1, "modified": 1, "deleted": 1, "moved": 1, "errors": 0},
        )
        self.assertEqual(
            [(c.path, c.status, c.old_path) for c in result.changes],
            [
                ("a_added.py", "ADDED", None),
                ("b_mod.py", "MODIFIED", None),
                ("c_del.py", "DELETED", "c_del.py"),
                ("d_moved_loc.py", "MOVED", "z_old_loc.py"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
