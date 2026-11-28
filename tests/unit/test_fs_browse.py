import tempfile
import unittest
from pathlib import Path

from sentinel.api import fs_browse


class TestListDirectory(unittest.TestCase):
    def test_folders_first_then_files_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "zeta").mkdir()
            (root / "Alpha").mkdir()
            (root / "b.txt").write_text("x", encoding="utf-8")
            (root / "A.txt").write_text("x", encoding="utf-8")
            data = fs_browse.list_directory(str(root))
            self.assertEqual([e["name"] for e in data["entries"]], ["Alpha", "zeta", "A.txt", "b.txt"])
            self.assertEqual([e["is_dir"] for e in data["entries"]], [True, True, False, False])
            self.assertEqual(data["path"], root.resolve().as_posix())
            self.assertEqual(data["parent"], root.resolve().parent.as_posix())
            self.assertFalse(data["truncated"])

    def test_default_is_home_and_has_shortcuts(self) -> None:
        data = fs_browse.list_directory(None)
        self.assertEqual(data["path"], Path.home().resolve().as_posix())
        labels = [s["label"] for s in data["shortcuts"]]
        self.assertIn("Home", labels)
        self.assertTrue(len(labels) >= 2)  # at least one drive/root

    def test_missing_path_and_file_path_are_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(fs_browse.BrowseError) as ctx:
                fs_browse.list_directory(str(Path(tmp) / "nope"))
            self.assertEqual(ctx.exception.code, "INVALID_PATH")
            f = Path(tmp) / "file.txt"
            f.write_text("x", encoding="utf-8")
            with self.assertRaises(fs_browse.BrowseError) as ctx:
                fs_browse.list_directory(str(f))
            self.assertEqual(ctx.exception.code, "INVALID_PATH")

    def test_unicode_and_space_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "my docs").mkdir()
            (Path(tmp) / "café").mkdir()
            names = [e["name"] for e in fs_browse.list_directory(tmp)["entries"]]
            self.assertEqual(sorted(names), sorted(["my docs", "café"]))

    def test_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(7):
                (Path(tmp) / f"d{i}").mkdir()
            old = fs_browse.MAX_ENTRIES
            fs_browse.MAX_ENTRIES = 5
            try:
                data = fs_browse.list_directory(tmp)
            finally:
                fs_browse.MAX_ENTRIES = old
            self.assertEqual(len(data["entries"]), 5)
            self.assertTrue(data["truncated"])


class TestBrowseEndpoint(unittest.TestCase):
    def test_endpoint_lists_and_reports_errors(self) -> None:
        from fastapi.testclient import TestClient
        from sentinel.api.main import app

        client = TestClient(app)
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "sub").mkdir()
            r = client.get("/api/v1/fs/list", params={"path": tmp})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["data"]["entries"][0]["name"], "sub")
            bad = client.get("/api/v1/fs/list", params={"path": str(Path(tmp) / "missing")})
            self.assertEqual(bad.status_code, 400)
            self.assertEqual(bad.json()["error"]["code"], "INVALID_PATH")
        self.assertEqual(client.get("/api/v1/fs/list").status_code, 200)  # defaults to home


if __name__ == "__main__":
    unittest.main()
