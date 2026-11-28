"""Unit tests for sentinel.core.baseline."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
import tempfile
import unittest

from sentinel.core.baseline import (
    accept_snapshots,
    baseline_from_dict,
    build_baseline,
    load_baseline_json,
    save_baseline_json,
)
from sentinel.core.models import (
    HASH_ALGORITHM,
    SCHEMA_VERSION,
    BaselineData,
    FileSnapshot,
    baseline_to_dict,
)

_SHA_A = "a" * 64
_SHA_B = "b" * 64
_SHA_C = "c" * 64
_UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _snap(
    path: str = "src/main.py",
    sha256: str = _SHA_A,
    size_bytes: int = 128,
    mtime_ns: int = 1_730_000_000_000_000_000,
) -> FileSnapshot:
    return FileSnapshot(path=path, sha256=sha256, size_bytes=size_bytes, mtime_ns=mtime_ns)


class TestBuildBaseline(unittest.TestCase):
    """Verify build_baseline canonical fields, sorting, and root normalization."""

    def test_build_baseline_metadata_and_lexicographical_sorting(self) -> None:
        snapshots = [
            _snap("z_last.txt", _SHA_C, 10, 3),
            _snap("src/main.py", _SHA_B, 20, 2),
            _snap("README.md", _SHA_A, 30, 1),
        ]
        baseline = build_baseline(Path("C:\\Projects\\MyApp\\"), snapshots)

        self.assertEqual(baseline.schema_version, SCHEMA_VERSION)
        self.assertEqual(baseline.schema_version, 1)
        self.assertEqual(baseline.hash_algorithm, HASH_ALGORITHM)
        self.assertEqual(baseline.hash_algorithm, "sha256")
        self.assertEqual(baseline.root_path, "C:/Projects/MyApp")
        self.assertRegex(baseline.created_at, _UTC_Z_RE)
        datetime.strptime(baseline.created_at, "%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(
            list(baseline.files.keys()),
            ["README.md", "src/main.py", "z_last.txt"],
        )

    def test_build_baseline_empty_snapshots_and_string_root(self) -> None:
        baseline = build_baseline("D:/Workspace/", [])  # type: ignore[arg-type]
        self.assertEqual(baseline.root_path, "D:/Workspace")
        self.assertEqual(baseline.files, {})

    def test_build_baseline_rejects_invalid_root_or_non_list(self) -> None:
        for bad_root in ("", "   ", None, 123):
            with self.subTest(bad_root=bad_root):
                with self.assertRaises(ValueError):
                    build_baseline(bad_root, [])  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            build_baseline(Path("C:/Projects/MyApp"), (_snap(),))  # type: ignore[arg-type]


class TestSnapshotValidation(unittest.TestCase):
    """Verify strict snapshot field validation and path collision rules."""

    def test_invalid_snapshot_paths_raise_value_error(self) -> None:
        bad_paths = [
            "",
            "/etc/passwd",
            "/src/main.py",
            "src\\main.py",
            "..",
            "../secret.txt",
            "src/../secret.txt",
            ".",
            "./main.py",
            "src/./main.py",
            "src//main.py",
            "src/main.py/",
            "C:main.py",
            "C:/Projects/main.py",
            "d:/main.py",
            "bad\x00path.txt",
        ]
        for bad_path in bad_paths:
            with self.subTest(bad_path=bad_path):
                with self.assertRaises(ValueError):
                    build_baseline(Path("C:/Projects/MyApp"), [_snap(path=bad_path)])

    def test_non_string_path_and_non_snapshot_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_baseline(Path("C:/Projects/MyApp"), [_snap(path=None)])  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            build_baseline(
                Path("C:/Projects/MyApp"),
                [{"path": "a.txt", "sha256": _SHA_A, "size_bytes": 1, "mtime_ns": 1}],  # type: ignore[list-item]
            )

    def test_invalid_sha256_rejected(self) -> None:
        bad_hashes = [
            "",
            "A" * 64,  # uppercase
            "a" * 63,  # short
            "a" * 65,  # long
            "g" * 64,  # non-hex
            f"{_SHA_A}\n",
            123,
        ]
        for bad_sha in bad_hashes:
            with self.subTest(bad_sha=bad_sha):
                with self.assertRaises(ValueError):
                    build_baseline(
                        Path("C:/Projects/MyApp"),
                        [_snap(sha256=bad_sha)],  # type: ignore[arg-type]
                    )

    def test_invalid_size_bytes_and_mtime_ns_rejected(self) -> None:
        for bad_size in (-1, -100, True, False, "10", 1.5, None):
            with self.subTest(bad_size=bad_size):
                with self.assertRaises(ValueError):
                    build_baseline(
                        Path("C:/Projects/MyApp"),
                        [_snap(size_bytes=bad_size)],  # type: ignore[arg-type]
                    )

        for bad_mtime in (True, False, "1730000000", 1.25, None):
            with self.subTest(bad_mtime=bad_mtime):
                with self.assertRaises(ValueError):
                    build_baseline(
                        Path("C:/Projects/MyApp"),
                        [_snap(mtime_ns=bad_mtime)],  # type: ignore[arg-type]
                    )

        # Zero size_bytes is valid
        baseline = build_baseline(Path("C:/Projects/MyApp"), [_snap(size_bytes=0, mtime_ns=0)])
        self.assertEqual(baseline.files["src/main.py"].size_bytes, 0)

    def test_duplicate_and_case_insensitive_path_collisions_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_baseline(
                Path("C:/Projects/MyApp"),
                [_snap("src/main.py", _SHA_A), _snap("src/main.py", _SHA_B)],
            )

        with self.assertRaises(ValueError):
            build_baseline(
                Path("C:/Projects/MyApp"),
                [_snap("src/Main.py", _SHA_A), _snap("src/main.py", _SHA_B)],
            )


class TestBaselineFromDict(unittest.TestCase):
    """Verify baseline_from_dict round-trips and strict schema checks."""

    def _valid_payload(self) -> dict:
        return {
            "schema_version": 1,
            "root_path": "C:/Projects/MyApp",
            "created_at": "2026-11-14T12:30:00Z",
            "hash_algorithm": "sha256",
            "files": {
                "z.txt": {
                    "path": "z.txt",
                    "sha256": _SHA_B,
                    "size_bytes": 20,
                    "mtime_ns": 200,
                },
                "README.md": {
                    "path": "README.md",
                    "sha256": _SHA_A,
                    "size_bytes": 10,
                    "mtime_ns": 100,
                },
            },
        }

    def test_valid_round_trip_sorts_files(self) -> None:
        payload = self._valid_payload()
        parsed = baseline_from_dict(payload)
        self.assertIsInstance(parsed, BaselineData)
        self.assertEqual(list(parsed.files.keys()), ["README.md", "z.txt"])
        self.assertEqual(baseline_to_dict(parsed)["root_path"], "C:/Projects/MyApp")
        self.assertEqual(baseline_from_dict(baseline_to_dict(parsed)), parsed)

    def test_missing_top_level_fields_raise_value_error(self) -> None:
        for field in ("schema_version", "root_path", "created_at", "hash_algorithm", "files"):
            with self.subTest(missing=field):
                payload = self._valid_payload()
                del payload[field]
                with self.assertRaises(ValueError):
                    baseline_from_dict(payload)

    def test_non_dict_and_wrong_metadata_values_raise_value_error(self) -> None:
        with self.assertRaises(ValueError):
            baseline_from_dict([])  # type: ignore[arg-type]

        bad_mutations = [
            {"schema_version": 2},
            {"schema_version": "1"},
            {"schema_version": True},
            {"hash_algorithm": "md5"},
            {"hash_algorithm": "SHA256"},
            {"root_path": ""},
            {"root_path": "   "},
            {"root_path": "C:/bad\x00path"},
            {"created_at": ""},
            {"created_at": "   "},
            {"files": []},
        ]
        for patch in bad_mutations:
            with self.subTest(patch=patch):
                payload = self._valid_payload()
                payload.update(patch)
                with self.assertRaises(ValueError):
                    baseline_from_dict(payload)

    def test_mismatched_key_missing_entry_field_and_case_collision(self) -> None:
        # Dict key != entry["path"]
        payload = self._valid_payload()
        payload["files"]["README.md"]["path"] = "OTHER.md"
        with self.assertRaises(ValueError):
            baseline_from_dict(payload)

        # Missing snapshot field
        for missing_field in ("path", "sha256", "size_bytes", "mtime_ns"):
            with self.subTest(missing_field=missing_field):
                p2 = self._valid_payload()
                del p2["files"]["README.md"][missing_field]
                with self.assertRaises(ValueError):
                    baseline_from_dict(p2)

        # Non-dict entry
        p3 = self._valid_payload()
        p3["files"]["README.md"] = "bad"
        with self.assertRaises(ValueError):
            baseline_from_dict(p3)

        # Case-insensitive collision in dict keys
        p4 = self._valid_payload()
        p4["files"]["readme.md"] = {
            "path": "readme.md",
            "sha256": _SHA_C,
            "size_bytes": 12,
            "mtime_ns": 300,
        }
        with self.assertRaises(ValueError):
            baseline_from_dict(p4)


class TestSaveAndLoadBaselineJson(unittest.TestCase):
    """Verify atomic UTF-8 persistence, directory creation, and load error handling."""

    def test_save_creates_parents_writes_utf8_atomically_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "state" / "nested" / "baseline.json"
            baseline = build_baseline(
                Path("C:/Users/José/Proj"),
                [
                    _snap("café/données.txt", _SHA_A, 15, 111),
                    _snap("README.md", _SHA_B, 5, 222),
                ],
            )
            saved_path = save_baseline_json(baseline, target)
            self.assertEqual(saved_path, target)
            self.assertTrue(target.exists())

            # Ensure no leftover temporary atomic-write files remain
            leftovers = [p.name for p in target.parent.iterdir() if p.name != "baseline.json"]
            self.assertEqual(leftovers, [])

            raw_text = target.read_text(encoding="utf-8")
            self.assertIn("café/données.txt", raw_text)
            loaded = load_baseline_json(target)
            self.assertEqual(loaded, baseline)

    def test_save_rejects_non_baseline_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(ValueError):
                save_baseline_json({"schema_version": 1}, Path(tmp_dir) / "bad.json")  # type: ignore[arg-type]

    def test_load_missing_file_and_invalid_json_or_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            missing = Path(tmp_dir) / "missing.json"
            with self.assertRaises(FileNotFoundError):
                load_baseline_json(missing)

            malformed = Path(tmp_dir) / "malformed.json"
            malformed.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline_json(malformed)

            wrong_schema = Path(tmp_dir) / "wrong_schema.json"
            wrong_schema.write_text(json.dumps({"schema_version": 99}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline_json(wrong_schema)


class TestAcceptSnapshots(unittest.TestCase):
    """Verify accept_snapshots updates files/timestamp and handles root overrides."""

    def test_accept_snapshots_preserves_root_and_updates_files_and_timestamp(self) -> None:
        initial = build_baseline(
            Path("C:/Projects/MyApp"),
            [_snap("old.txt", _SHA_A, 10, 100)],
        )
        initial.created_at = "2020-01-01T00:00:00Z"

        new_snaps = [
            _snap("z.txt", _SHA_C, 30, 300),
            _snap("a.txt", _SHA_B, 20, 200),
        ]
        updated = accept_snapshots(initial, new_snaps)

        self.assertEqual(updated.schema_version, SCHEMA_VERSION)
        self.assertEqual(updated.hash_algorithm, HASH_ALGORITHM)
        self.assertEqual(updated.root_path, "C:/Projects/MyApp")
        self.assertRegex(updated.created_at, _UTC_Z_RE)
        self.assertNotEqual(updated.created_at, "2020-01-01T00:00:00Z")
        self.assertEqual(list(updated.files.keys()), ["a.txt", "z.txt"])
        # Original baseline object was not mutated
        self.assertEqual(list(initial.files.keys()), ["old.txt"])

    def test_accept_snapshots_overrides_and_normalizes_root_path(self) -> None:
        initial = build_baseline(Path("C:/Projects/OldApp"), [_snap("a.txt", _SHA_A, 10, 100)])
        updated = accept_snapshots(
            initial,
            [_snap("b.txt", _SHA_B, 25, 250)],
            root=Path("D:\\MovedApp\\"),
        )
        self.assertEqual(updated.root_path, "D:/MovedApp")
        self.assertEqual(list(updated.files.keys()), ["b.txt"])

    def test_accept_snapshots_validates_baseline_and_new_snapshots(self) -> None:
        valid = build_baseline(Path("C:/Projects/MyApp"), [])

        with self.assertRaises(ValueError):
            accept_snapshots("not-a-baseline", [])  # type: ignore[arg-type]

        bad_version = BaselineData(
            schema_version=99,
            root_path="C:/Projects/MyApp",
            created_at="2026-11-14T12:30:00Z",
            hash_algorithm="sha256",
            files={},
        )
        with self.assertRaises(ValueError):
            accept_snapshots(bad_version, [])

        bad_algo = BaselineData(
            schema_version=1,
            root_path="C:/Projects/MyApp",
            created_at="2026-11-14T12:30:00Z",
            hash_algorithm="md5",
            files={},
        )
        with self.assertRaises(ValueError):
            accept_snapshots(bad_algo, [])

        bad_root = BaselineData(
            schema_version=1,
            root_path="   ",
            created_at="2026-11-14T12:30:00Z",
            hash_algorithm="sha256",
            files={},
        )
        with self.assertRaises(ValueError):
            accept_snapshots(bad_root, [])

        with self.assertRaises(ValueError):
            accept_snapshots(valid, [_snap("../escape.txt", _SHA_A)])


if __name__ == "__main__":
    unittest.main()
