"""Unit tests for sentinel.core.models."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import tempfile
import unittest
import os

from sentinel.core.models import (
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

_SAMPLE_SHA_A = "a" * 64
_SAMPLE_SHA_B = "b" * 64


class TestEnumsAndConstants(unittest.TestCase):
    """Verify canonical constants, string enum values, and str() formatting."""

    def test_schema_and_algorithm_constants(self) -> None:
        self.assertEqual(SCHEMA_VERSION, 1)
        self.assertEqual(HASH_ALGORITHM, "sha256")

    def test_change_status_values_and_str(self) -> None:
        expected = {
            ChangeStatus.ADDED: "ADDED",
            ChangeStatus.MODIFIED: "MODIFIED",
            ChangeStatus.DELETED: "DELETED",
            ChangeStatus.MOVED: "MOVED",
        }
        self.assertEqual(list(ChangeStatus), list(expected.keys()))
        for member, text in expected.items():
            self.assertIsInstance(member, str)
            self.assertEqual(member.value, text)
            self.assertEqual(str(member), text)
            self.assertEqual(member, text)

    def test_severity_level_values_and_str(self) -> None:
        expected = {
            SeverityLevel.LOW: "LOW",
            SeverityLevel.MEDIUM: "MEDIUM",
            SeverityLevel.HIGH: "HIGH",
        }
        self.assertEqual(list(SeverityLevel), list(expected.keys()))
        for member, text in expected.items():
            self.assertIsInstance(member, str)
            self.assertEqual(member.value, text)
            self.assertEqual(str(member), text)
            self.assertEqual(member, text)

    def test_scan_status_values_and_str(self) -> None:
        expected = {
            ScanStatus.CLEAN: "CLEAN",
            ScanStatus.CHANGED: "CHANGED",
            ScanStatus.ERROR: "ERROR",
            ScanStatus.BASELINE_INVALID: "BASELINE_INVALID",
        }
        self.assertEqual(list(ScanStatus), list(expected.keys()))
        for member, text in expected.items():
            self.assertIsInstance(member, str)
            self.assertEqual(member.value, text)
            self.assertEqual(str(member), text)
            self.assertEqual(member, text)


class TestDataclassesAndSerializers(unittest.TestCase):
    """Verify dataclass immutability and canonical JSON dict serializers."""

    def test_frozen_dataclasses_prevent_mutation(self) -> None:
        snap = FileSnapshot(path="src/main.py", sha256=_SAMPLE_SHA_A, size_bytes=10, mtime_ns=100)
        err = ScanError(code="FILE_ACCESS_DENIED", path="src/secret.txt", message="Denied")
        change = ChangeRecord(
            status=ChangeStatus.ADDED.value,
            path="src/new.py",
            old_path=None,
            new_path="src/new.py",
            old_sha256=None,
            new_sha256=_SAMPLE_SHA_A,
            old_size_bytes=None,
            new_size_bytes=10,
            severity=SeverityLevel.LOW.value,
            reason="New file",
        )

        with self.assertRaises(FrozenInstanceError):
            snap.size_bytes = 20  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            err.code = "OTHER"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            change.reason = "Changed"  # type: ignore[misc]

    def test_snapshot_to_dict(self) -> None:
        snap = FileSnapshot(
            path="src/main.py",
            sha256=_SAMPLE_SHA_A,
            size_bytes=1234,
            mtime_ns=1730000000000000000,
        )
        self.assertEqual(
            snapshot_to_dict(snap),
            {
                "path": "src/main.py",
                "sha256": _SAMPLE_SHA_A,
                "size_bytes": 1234,
                "mtime_ns": 1730000000000000000,
            },
        )

    def test_baseline_to_dict(self) -> None:
        snap_readme = FileSnapshot(
            path="README.md",
            sha256=_SAMPLE_SHA_A,
            size_bytes=100,
            mtime_ns=1730000000000000001,
        )
        snap_main = FileSnapshot(
            path="src/main.py",
            sha256=_SAMPLE_SHA_B,
            size_bytes=200,
            mtime_ns=1730000000000000002,
        )
        baseline = BaselineData(
            schema_version=1,
            root_path="C:/Projects/MyApp",
            created_at="2026-11-14T12:30:00Z",
            hash_algorithm="sha256",
            files={"README.md": snap_readme, "src/main.py": snap_main},
        )
        serialized = baseline_to_dict(baseline)
        self.assertEqual(
            serialized,
            {
                "schema_version": 1,
                "root_path": "C:/Projects/MyApp",
                "created_at": "2026-11-14T12:30:00Z",
                "hash_algorithm": "sha256",
                "files": {
                    "README.md": {
                        "path": "README.md",
                        "sha256": _SAMPLE_SHA_A,
                        "size_bytes": 100,
                        "mtime_ns": 1730000000000000001,
                    },
                    "src/main.py": {
                        "path": "src/main.py",
                        "sha256": _SAMPLE_SHA_B,
                        "size_bytes": 200,
                        "mtime_ns": 1730000000000000002,
                    },
                },
            },
        )
        self.assertEqual(json.loads(json.dumps(serialized)), serialized)

    def test_change_record_to_dict_serializes_enums_and_nulls(self) -> None:
        record = ChangeRecord(
            status=ChangeStatus.MODIFIED,  # type: ignore[arg-type]
            path="src/main.py",
            old_path=None,
            new_path="src/main.py",
            old_sha256=_SAMPLE_SHA_A,
            new_sha256=_SAMPLE_SHA_B,
            old_size_bytes=100,
            new_size_bytes=120,
            severity=SeverityLevel.HIGH,  # type: ignore[arg-type]
            reason="SHA-256 content hash changed",
        )
        serialized = change_record_to_dict(record)
        self.assertEqual(type(serialized["status"]), str)
        self.assertEqual(type(serialized["severity"]), str)
        self.assertEqual(
            serialized,
            {
                "status": "MODIFIED",
                "path": "src/main.py",
                "old_path": None,
                "new_path": "src/main.py",
                "old_sha256": _SAMPLE_SHA_A,
                "new_sha256": _SAMPLE_SHA_B,
                "old_size_bytes": 100,
                "new_size_bytes": 120,
                "severity": "HIGH",
                "reason": "SHA-256 content hash changed",
            },
        )
        raw_json = json.dumps(serialized)
        self.assertIn('"old_path": null', raw_json)
        self.assertNotIn("ChangeStatus", raw_json)
        self.assertNotIn("SeverityLevel", raw_json)

    def test_scan_error_to_dict(self) -> None:
        err_with_path = ScanError(
            code="FILE_ACCESS_DENIED",
            path="src/private.txt",
            message="The file could not be read.",
        )
        err_no_path = ScanError(
            code="ROOT_UNREADABLE",
            path=None,
            message="Root folder unavailable.",
        )
        self.assertEqual(
            scan_error_to_dict(err_with_path),
            {
                "code": "FILE_ACCESS_DENIED",
                "path": "src/private.txt",
                "message": "The file could not be read.",
            },
        )
        self.assertEqual(
            scan_error_to_dict(err_no_path),
            {
                "code": "ROOT_UNREADABLE",
                "path": None,
                "message": "Root folder unavailable.",
            },
        )

    def test_scan_result_to_dict(self) -> None:
        summary = {"added": 1, "modified": 0, "deleted": 0, "moved": 0, "errors": 1}
        change = ChangeRecord(
            status=ChangeStatus.ADDED.value,
            path="docs/notes.md",
            old_path=None,
            new_path="docs/notes.md",
            old_sha256=None,
            new_sha256=_SAMPLE_SHA_A,
            old_size_bytes=None,
            new_size_bytes=42,
            severity=SeverityLevel.LOW.value,
            reason="New file not present in baseline",
        )
        error = ScanError(
            code="FILE_ACCESS_DENIED",
            path="src/secret.key",
            message="Permission denied",
        )
        result = ScanResult(
            schema_version=1,
            scan_id="123e4567-e89b-12d3-a456-426614174000",
            root_path="C:/Projects/MyApp",
            started_at="2026-11-14T12:40:00Z",
            completed_at="2026-11-14T12:40:02Z",
            status=ScanStatus.ERROR,  # type: ignore[arg-type]
            summary=summary,
            changes=[change],
            errors=[error],
        )

        serialized = scan_result_to_dict(result)
        self.assertEqual(type(serialized["status"]), str)
        self.assertEqual(serialized["status"], "ERROR")
        self.assertIsNot(serialized["summary"], summary)
        self.assertEqual(
            serialized,
            {
                "schema_version": 1,
                "scan_id": "123e4567-e89b-12d3-a456-426614174000",
                "root_path": "C:/Projects/MyApp",
                "started_at": "2026-11-14T12:40:00Z",
                "completed_at": "2026-11-14T12:40:02Z",
                "status": "ERROR",
                "summary": {"added": 1, "modified": 0, "deleted": 0, "moved": 0, "errors": 1},
                "changes": [change_record_to_dict(change)],
                "errors": [scan_error_to_dict(error)],
            },
        )
        self.assertEqual(json.loads(json.dumps(serialized)), serialized)


class TestPathHelpers(unittest.TestCase):
    """Verify Windows-style path detection and root path normalization."""

    def test_is_windows_style_path_variants(self) -> None:
        true_cases = [
            "C:/Projects/MyApp",
            "C:\\Projects\\MyApp",
            "d:/",
            "Z:\\",
            "\\\\fileserver\\share\\proj",
            "//fileserver/share/proj",
        ]
        false_cases = [
            "",
            "/Users/dev/MyApp",
            "/var/log/sentinel",
            "/",
            "src/main.py",
            "relative\\sub",
            "C:relative_no_slash.txt",
        ]
        for path_str in true_cases:
            with self.subTest(path_str=path_str):
                self.assertTrue(is_windows_style_path(path_str))
        for path_str in false_cases:
            with self.subTest(path_str=path_str):
                self.assertFalse(is_windows_style_path(path_str))

    def test_normalize_root_path_windows_drive_and_trailing_slashes(self) -> None:
        self.assertEqual(normalize_root_path(Path("C:/Projects/MyApp")), "C:/Projects/MyApp")
        self.assertEqual(normalize_root_path(Path("C:/Projects/MyApp/")), "C:/Projects/MyApp")
        self.assertEqual(normalize_root_path(Path("C:\\Projects\\MyApp\\")), "C:/Projects/MyApp")
        self.assertEqual(normalize_root_path(Path("D:\\")), "D:/")

    def test_normalize_root_path_unc_paths(self) -> None:
        self.assertEqual(
            normalize_root_path(Path("\\\\server\\share\\folder")),
            "//server/share/folder",
        )
        self.assertEqual(
            normalize_root_path(Path("\\\\server\\share\\folder\\")),
            "//server/share/folder",
        )
        self.assertEqual(
            normalize_root_path(Path("//server/share/folder/")),
            "//server/share/folder",
        )


    @unittest.skipIf(os.name == "nt", "POSIX absolute paths do not exist on Windows")
    def test_normalize_root_path_posix_absolute_and_trailing_slash(self) -> None:
        self.assertEqual(normalize_root_path(Path("/")), "/")
        self.assertEqual(normalize_root_path(Path("/opt/sentinel/app/")), "/opt/sentinel/app")
        self.assertEqual(normalize_root_path(Path("/opt/sentinel/app")), "/opt/sentinel/app")

    def test_normalize_root_path_relative_path_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sub = Path(tmp_dir) / "nested" / "app"
            sub.mkdir(parents=True)
            abs_normalized = normalize_root_path(Path(f"{sub}/"))
            self.assertEqual(abs_normalized, sub.as_posix().rstrip("/"))

            rel = Path("nested/app")
            rel_normalized = normalize_root_path(rel)
            self.assertEqual(rel_normalized, rel.resolve().as_posix().rstrip("/"))
            self.assertNotIn("\\", rel_normalized)
            self.assertFalse(rel_normalized.endswith("/"))
            self.assertTrue(Path(rel_normalized).is_absolute())


if __name__ == "__main__":
    unittest.main()
