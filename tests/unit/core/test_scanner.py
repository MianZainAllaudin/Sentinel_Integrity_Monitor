"""Unit tests for sentinel.core.scanner."""

from __future__ import annotations

import builtins
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.core.models import FileSnapshot, ScanError
from sentinel.core.scanner import hash_file_sha256, scan_directory


class _ReadSpyHandle:
    """File-handle proxy that records chunk sizes passed to read()."""

    def __init__(self, inner, read_sizes: list[int | None]) -> None:
        self._inner = inner
        self._read_sizes = read_sizes

    def read(self, size: int = -1):
        self._read_sizes.append(size)
        return self._inner.read(size)

    def fileno(self) -> int:
        return self._inner.fileno()

    def __enter__(self) -> _ReadSpyHandle:
        self._inner.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._inner.__exit__(exc_type, exc, tb)


class _FakeDirEntry:
    """Minimal os.DirEntry double for deterministic scanner tests."""

    def __init__(
        self,
        name: str,
        path: Path,
        *,
        is_dir: bool = False,
        is_file: bool = True,
        is_symlink: bool = False,
        inspect_error: Exception | None = None,
    ) -> None:
        self.name = name
        self.path = str(path)
        self._is_dir = is_dir
        self._is_file = is_file
        self._is_symlink = is_symlink
        self._inspect_error = inspect_error

    def is_symlink(self) -> bool:
        if self._inspect_error is not None:
            raise self._inspect_error
        return self._is_symlink

    def is_dir(self, follow_symlinks: bool = False) -> bool:
        if self._inspect_error is not None:
            raise self._inspect_error
        return self._is_dir

    def is_file(self, follow_symlinks: bool = False) -> bool:
        if self._inspect_error is not None:
            raise self._inspect_error
        return self._is_file


class _FakeScandirContext:
    """Context manager wrapper mimicking os.scandir()."""

    def __init__(self, entries: list[_FakeDirEntry]) -> None:
        self._entries = entries

    def __enter__(self) -> list[_FakeDirEntry]:
        return self._entries

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestScannerTraversalAndHashing(unittest.TestCase):
    """Tests for traversal ordering, path formatting, hashing, ignore pruning, and symlinks."""

    def test_recursive_traversal_sorted_forward_slashes_and_preserved_casing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            files = {
                "Z_root.txt": b"z-data",
                "a_first.txt": b"a-data",
                "Docs/README.md": b"# Sentinel\n",
                "Docs/guide.txt": b"guide",
                "Src/Main.py": b"print('hi')\n",
                "Src/Sub/Helper.py": b"def helper():\n    return 1\n",
            }
            for rel_path, content in files.items():
                full_path = root / rel_path
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_bytes(content)

            snapshots, errors = scan_directory(root)

            self.assertEqual(errors, [])
            expected_paths = sorted(files.keys())
            self.assertEqual([snap.path for snap in snapshots], expected_paths)

            for snap in snapshots:
                self.assertIsInstance(snap, FileSnapshot)
                self.assertNotIn("\\", snap.path)
                expected_bytes = files[snap.path]
                disk_stat = (root / snap.path).stat()
                self.assertEqual(
                    snap.sha256,
                    hashlib.sha256(expected_bytes).hexdigest().lower(),
                )
                self.assertEqual(snap.size_bytes, len(expected_bytes))
                self.assertEqual(snap.mtime_ns, disk_stat.st_mtime_ns)

    def test_empty_directory_returns_empty_lists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            snapshots, errors = scan_directory(Path(tmp_dir))

        self.assertEqual(snapshots, [])
        self.assertEqual(errors, [])

    def test_streamed_sha256_small_and_multichunk_honors_chunk_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            samples = {
                "empty.bin": b"",
                "tiny.bin": b"abc",
                "multi.bin": b"sentinel-chunk-" * 15,  # 225 bytes (> 7 and > 64)
                "binary.bin": bytes(range(256)) * 2,  # 512 bytes
            }
            for name, payload in samples.items():
                (root / name).write_bytes(payload)

            for chunk_size in (7, 64):
                with self.subTest(chunk_size=chunk_size):
                    for name, payload in samples.items():
                        expected_digest = hashlib.sha256(payload).hexdigest().lower()
                        self.assertEqual(
                            hash_file_sha256(root / name, chunk_size=chunk_size),
                            expected_digest,
                        )

                    snapshots, errors = scan_directory(root, chunk_size=chunk_size)
                    self.assertEqual(errors, [])
                    by_path = {snap.path: snap for snap in snapshots}
                    self.assertEqual(set(by_path.keys()), set(samples.keys()))
                    for name, payload in samples.items():
                        self.assertEqual(
                            by_path[name].sha256,
                            hashlib.sha256(payload).hexdigest().lower(),
                        )

            # Verify read(chunk_size) is invoked with exact chunk_size in both functions.
            multi_path = root / "multi.bin"
            real_open = builtins.open

            read_sizes_hash: list[int | None] = []

            def spy_open_hash(file, mode="r", *args, **kwargs):
                handle = real_open(file, mode, *args, **kwargs)
                if Path(file) == multi_path and "b" in mode:
                    return _ReadSpyHandle(handle, read_sizes_hash)
                return handle

            with patch("builtins.open", side_effect=spy_open_hash):
                digest = hash_file_sha256(multi_path, chunk_size=7)

            self.assertEqual(digest, hashlib.sha256(samples["multi.bin"]).hexdigest().lower())
            self.assertGreater(len(read_sizes_hash), 10)
            self.assertTrue(all(size == 7 for size in read_sizes_hash))

            read_sizes_scan: list[int | None] = []

            def spy_open_scan(file, mode="r", *args, **kwargs):
                handle = real_open(file, mode, *args, **kwargs)
                if Path(file) == multi_path and "b" in mode:
                    return _ReadSpyHandle(handle, read_sizes_scan)
                return handle

            with patch("builtins.open", side_effect=spy_open_scan):
                snapshots, errors = scan_directory(root, chunk_size=7)

            self.assertEqual(errors, [])
            self.assertEqual(len(snapshots), len(samples))
            self.assertGreater(len(read_sizes_scan), 10)
            self.assertTrue(all(size == 7 for size in read_sizes_scan))

    def test_sentinelignore_auto_discovery_and_directory_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / ".sentinelignore").write_text(
                "\n".join(
                    [
                        ".sentinelignore",
                        "node_modules/",
                        "*.log",
                        "re_included/",
                        "!re_included/keep.txt",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "main.py").write_text("print(1)\n", encoding="utf-8")
            (root / "app.log").write_text("ignored log\n", encoding="utf-8")
            (root / "node_modules" / "pkg").mkdir(parents=True)
            (root / "node_modules" / "pkg" / "index.js").write_text("ignored\n", encoding="utf-8")
            (root / "re_included").mkdir()
            (root / "re_included" / "keep.txt").write_text("kept\n", encoding="utf-8")
            (root / "re_included" / "drop.txt").write_text("dropped\n", encoding="utf-8")

            visited_dirs: list[Path] = []
            real_scandir = os.scandir

            def spy_scandir(path):
                visited_dirs.append(Path(path))
                return real_scandir(path)

            with patch("sentinel.core.scanner.os.scandir", side_effect=spy_scandir):
                snapshots, errors = scan_directory(root)

            self.assertEqual(errors, [])
            self.assertEqual(
                [snap.path for snap in snapshots],
                ["re_included/keep.txt", "src/main.py"],
            )
            self.assertNotIn(root / "node_modules", visited_dirs)
            self.assertNotIn(root / "node_modules" / "pkg", visited_dirs)
            self.assertIn(root / "re_included", visited_dirs)

    def test_explicit_ignore_file_overrides_default_sentinelignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as cfg_dir:
            root = Path(tmp_dir)
            (root / ".sentinelignore").write_text("*.txt\n", encoding="utf-8")
            (root / "keep.txt").write_text("keep\n", encoding="utf-8")
            (root / "drop.tmp").write_text("drop\n", encoding="utf-8")

            explicit_ignore = Path(cfg_dir) / "custom.ignore"
            explicit_ignore.write_text(".sentinelignore\n*.tmp\n", encoding="utf-8")

            snapshots, errors = scan_directory(root, ignore_file=explicit_ignore)

        self.assertEqual(errors, [])
        self.assertEqual([snap.path for snap in snapshots], ["keep.txt"])

    def test_symlinks_and_recursive_dir_symlinks_are_skipped_without_looping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            real_file = root / "real.txt"
            real_file.write_text("real", encoding="utf-8")
            sub_dir = root / "sub"
            sub_dir.mkdir()
            (sub_dir / "inner.txt").write_text("inner", encoding="utf-8")

            try:
                os.symlink(real_file, root / "file_link.txt")
                os.symlink(sub_dir, root / "dir_link", target_is_directory=True)
                os.symlink(root, sub_dir / "loop_to_root", target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"Symlink creation not supported or permitted: {exc}")

            snapshots, errors = scan_directory(root)

            self.assertEqual(errors, [])
            self.assertEqual([snap.path for snap in snapshots], ["real.txt", "sub/inner.txt"])

    def test_symlink_entry_skipped_via_scandir_mock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            real_path = root / "real.txt"
            real_path.write_text("ok", encoding="utf-8")

            entries = [
                _FakeDirEntry("real.txt", real_path, is_dir=False, is_file=True, is_symlink=False),
                _FakeDirEntry(
                    "loop_dir",
                    root / "loop_dir",
                    is_dir=True,
                    is_file=False,
                    is_symlink=True,
                ),
                _FakeDirEntry(
                    "link.txt",
                    root / "link.txt",
                    is_dir=False,
                    is_file=True,
                    is_symlink=True,
                ),
            ]

            with patch(
                "sentinel.core.scanner.os.scandir",
                return_value=_FakeScandirContext(entries),
            ):
                snapshots, errors = scan_directory(root)

        self.assertEqual(errors, [])
        self.assertEqual([snap.path for snap in snapshots], ["real.txt"])


class TestScannerValidationAndErrors(unittest.TestCase):
    """Tests for chunk_size validation and structured ScanError capture."""

    def test_invalid_chunk_size_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            target = root / "file.txt"
            target.write_text("data", encoding="utf-8")

            for invalid in (0, -4, True, False, "64"):
                with self.subTest(chunk_size=invalid):
                    with self.assertRaises(ValueError):
                        hash_file_sha256(target, chunk_size=invalid)  # type: ignore[arg-type]
                    with self.assertRaises(ValueError):
                        scan_directory(root, chunk_size=invalid)  # type: ignore[arg-type]

    def test_root_not_found_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            missing_root = Path(tmp_dir) / "does_not_exist"
            snapshots, errors = scan_directory(missing_root)

        self.assertEqual(snapshots, [])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, "ROOT_NOT_FOUND")
        self.assertIsNone(errors[0].path)

    def test_invalid_root_when_file_passed_as_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "not_a_dir.txt"
            file_path.write_text("content", encoding="utf-8")
            snapshots, errors = scan_directory(file_path)

        self.assertEqual(snapshots, [])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, "INVALID_ROOT")
        self.assertIsNone(errors[0].path)

    def test_missing_explicit_ignore_file_and_invalid_utf8_ignore_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as ext_dir:
            root = Path(tmp_dir)
            missing_inside = root / "missing.ignore"
            snapshots, errors = scan_directory(root, ignore_file=missing_inside)

            self.assertEqual(snapshots, [])
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0].code, "IGNORE_FILE_ERROR")
            self.assertEqual(errors[0].path, "missing.ignore")

            missing_outside = Path(ext_dir) / "outside.ignore"
            snapshots_ext, errors_ext = scan_directory(root, ignore_file=missing_outside)

            self.assertEqual(snapshots_ext, [])
            self.assertEqual(len(errors_ext), 1)
            self.assertEqual(errors_ext[0].code, "IGNORE_FILE_ERROR")
            self.assertIsNotNone(errors_ext[0].path)
            self.assertNotIn("\\", errors_ext[0].path or "")

            bad_default = root / ".sentinelignore"
            bad_default.write_bytes(b"\xff\xfe\xfd")
            snapshots_bad, errors_bad = scan_directory(root)

            self.assertEqual(snapshots_bad, [])
            self.assertEqual(len(errors_bad), 1)
            self.assertEqual(errors_bad[0].code, "IGNORE_FILE_ERROR")
            self.assertEqual(errors_bad[0].path, ".sentinelignore")

    def test_unstable_file_read_via_mocked_fstat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            stable_path = root / "stable.txt"
            changing_mtime_path = root / "changing_mtime.txt"
            changing_size_path = root / "changing_size.txt"
            stable_path.write_bytes(b"stable")
            changing_mtime_path.write_bytes(b"changing-mtime")
            changing_size_path.write_bytes(b"changing-size")

            real_open = builtins.open
            real_fstat = os.fstat
            active_fstats: dict[int, tuple[Path, int]] = {}

            class _TrackedHandle:
                def __init__(self, inner, path: Path) -> None:
                    self._inner = inner
                    self._path = path
                    self._fd = inner.fileno()
                    active_fstats[self._fd] = (path, 0)

                def read(self, size: int = -1):
                    return self._inner.read(size)

                def fileno(self) -> int:
                    return self._fd

                def __enter__(self):
                    self._inner.__enter__()
                    return self

                def __exit__(self, exc_type, exc, tb):
                    active_fstats.pop(self._fd, None)
                    return self._inner.__exit__(exc_type, exc, tb)

            def spy_open(file, mode="r", *args, **kwargs):
                handle = real_open(file, mode, *args, **kwargs)
                file_path = Path(file)
                if "b" in mode and file_path in (changing_mtime_path, changing_size_path):
                    return _TrackedHandle(handle, file_path)
                return handle

            def fake_fstat(fd: int):
                real_stat = real_fstat(fd)
                entry = active_fstats.get(fd)
                if entry is None:
                    return real_stat
                path, call_num = entry
                active_fstats[fd] = (path, call_num + 1)
                if call_num == 0:
                    return SimpleNamespace(
                        st_size=real_stat.st_size,
                        st_mtime_ns=real_stat.st_mtime_ns,
                    )
                if path == changing_mtime_path:
                    return SimpleNamespace(
                        st_size=real_stat.st_size,
                        st_mtime_ns=real_stat.st_mtime_ns + 500,
                    )
                return SimpleNamespace(
                    st_size=real_stat.st_size + 4,
                    st_mtime_ns=real_stat.st_mtime_ns,
                )

            with (
                patch("builtins.open", side_effect=spy_open),
                patch("sentinel.core.scanner.os.fstat", side_effect=fake_fstat),
            ):
                snapshots, errors = scan_directory(root)

        self.assertEqual([snap.path for snap in snapshots], ["stable.txt"])
        self.assertEqual(
            [(err.code, err.path) for err in errors],
            [
                ("UNSTABLE_FILE_READ", "changing_mtime.txt"),
                ("UNSTABLE_FILE_READ", "changing_size.txt"),
            ],
        )

    def test_file_access_denied_error_captured_while_siblings_succeed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            ok_path = root / "ok.txt"
            denied_path = root / "secret.txt"
            ok_path.write_text("readable", encoding="utf-8")
            denied_path.write_text("locked", encoding="utf-8")

            real_open = builtins.open

            def guarded_open(file, mode="r", *args, **kwargs):
                if Path(file) == denied_path and "b" in mode:
                    raise PermissionError("Permission denied")
                return real_open(file, mode, *args, **kwargs)

            with patch("builtins.open", side_effect=guarded_open):
                snapshots, errors = scan_directory(root)

            self.assertEqual([snap.path for snap in snapshots], ["ok.txt"])
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ScanError)
            self.assertEqual(errors[0].code, "FILE_ACCESS_DENIED")
            self.assertEqual(errors[0].path, "secret.txt")

            entries = [
                _FakeDirEntry("ok.txt", ok_path),
                _FakeDirEntry(
                    "stat_denied.txt",
                    root / "stat_denied.txt",
                    inspect_error=PermissionError("Cannot stat entry"),
                ),
            ]
            with patch(
                "sentinel.core.scanner.os.scandir",
                return_value=_FakeScandirContext(entries),
            ):
                inspect_snaps, inspect_errs = scan_directory(root)

            self.assertEqual([snap.path for snap in inspect_snaps], ["ok.txt"])
            self.assertEqual(len(inspect_errs), 1)
            self.assertEqual(inspect_errs[0].code, "FILE_ACCESS_DENIED")
            self.assertEqual(inspect_errs[0].path, "stat_denied.txt")

    def test_dir_access_denied_error_captured_for_subdir_and_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            ok_dir = root / "ok_dir"
            locked_dir = root / "locked_dir"
            ok_dir.mkdir()
            locked_dir.mkdir()
            (ok_dir / "a.txt").write_text("hello", encoding="utf-8")
            (locked_dir / "b.txt").write_text("hidden", encoding="utf-8")

            real_scandir = os.scandir

            def guarded_scandir(path):
                if Path(path) == locked_dir:
                    raise PermissionError("Directory locked")
                return real_scandir(path)

            with patch("sentinel.core.scanner.os.scandir", side_effect=guarded_scandir):
                snapshots, errors = scan_directory(root)

            self.assertEqual([snap.path for snap in snapshots], ["ok_dir/a.txt"])
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0].code, "DIR_ACCESS_DENIED")
            self.assertEqual(errors[0].path, "locked_dir")

            with patch(
                "sentinel.core.scanner.os.scandir",
                side_effect=PermissionError("Root locked"),
            ):
                root_snapshots, root_errors = scan_directory(root)

            self.assertEqual(root_snapshots, [])
            self.assertEqual(len(root_errors), 1)
            self.assertEqual(root_errors[0].code, "DIR_ACCESS_DENIED")
            self.assertIsNone(root_errors[0].path)

    def test_case_insensitive_path_collision_detected_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            upper_path = root / "Main.py"
            other_path = root / "alpha.py"
            upper_content = b"print('Main')\n"
            other_content = b"print('alpha')\n"
            upper_path.write_bytes(upper_content)
            other_path.write_bytes(other_content)

            # Yield lowercase "main.py" before "Main.py" to prove sorting deterministically
            # retains "Main.py" and reports "main.py" as the colliding duplicate.
            mocked_entries = [
                _FakeDirEntry("main.py", root / "main.py"),
                _FakeDirEntry("alpha.py", other_path),
                _FakeDirEntry("Main.py", upper_path),
            ]

            with patch(
                "sentinel.core.scanner.os.scandir",
                return_value=_FakeScandirContext(mocked_entries),
            ):
                snapshots, errors = scan_directory(root)

        self.assertEqual([snap.path for snap in snapshots], ["Main.py", "alpha.py"])
        by_path = {snap.path: snap for snap in snapshots}
        self.assertEqual(by_path["Main.py"].sha256, hashlib.sha256(upper_content).hexdigest())
        self.assertEqual(by_path["alpha.py"].sha256, hashlib.sha256(other_content).hexdigest())

        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, "PATH_CASE_COLLISION")
        self.assertEqual(errors[0].path, "main.py")
        self.assertIn("Main.py", errors[0].message)


if __name__ == "__main__":
    unittest.main()
