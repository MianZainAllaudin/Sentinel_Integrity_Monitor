import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel import cli, tracking

KEY = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="


class TestTrackingHelpers(unittest.TestCase):
    def test_root_id_is_stable_and_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a", Path(tmp) / "b"
            a.mkdir()
            b.mkdir()
            self.assertEqual(tracking.root_id(a), tracking.root_id(a))
            self.assertEqual(tracking.root_id(a), tracking.root_id(Path(tmp) / "a" / ".." / "a"))
            self.assertNotEqual(tracking.root_id(a), tracking.root_id(b))
            self.assertEqual(len(tracking.root_id(a)), 16)

    def test_state_dirs_are_separate_per_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "state"
            a, b = Path(tmp) / "a", Path(tmp) / "b"
            self.assertNotEqual(tracking.state_dir_for(base, a), tracking.state_dir_for(base, b))
            self.assertEqual(tracking.state_dir_for(base, a).parent, base / "roots")

    def test_registry_track_list_untrack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "state"
            a, b = Path(tmp) / "a", Path(tmp) / "b"
            a.mkdir()
            b.mkdir()
            self.assertEqual(tracking.list_tracked(base), [])
            e1 = tracking.track_folder(base, a)
            self.assertEqual(tracking.track_folder(base, a), e1)  # idempotent
            tracking.track_folder(base, b)
            self.assertEqual(len(tracking.list_tracked(base)), 2)
            self.assertTrue(tracking.is_tracked(base, a))
            self.assertTrue(tracking.untrack_folder(base, e1["id"]))
            self.assertFalse(tracking.untrack_folder(base, e1["id"]))
            self.assertFalse(tracking.is_tracked(base, a))
            self.assertTrue(tracking.is_tracked(base, b))

    def test_corrupt_registry_reads_as_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "tracked.json").write_text("{not json", encoding="utf-8")
            self.assertEqual(tracking.list_tracked(base), [])


class TestCliAndDashboardAgree(unittest.TestCase):
    def _env(self, state: Path):
        return mock.patch.dict(os.environ, {"SENTINEL_HMAC_KEY": KEY, "SENTINEL_STATE_DIR": str(state)})

    def _folders(self, tmp: Path):
        a, b = tmp / "a", tmp / "b"
        for d, name in ((a, "a.txt"), (b, "b.txt")):
            d.mkdir()
            (d / name).write_text(name, encoding="utf-8")
        return a, b

    def test_two_folders_do_not_overwrite_each_other(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            a, b = self._folders(Path(tmp))
            self.assertEqual(cli.main(["init", str(a)]), 0)
            self.assertEqual(cli.main(["init", str(b)]), 0)
            self.assertEqual(cli.main(["verify", str(a)]), 0)  # still clean after B was initialised
            self.assertEqual(cli.main(["verify", str(b)]), 0)
            (a / "new.txt").write_text("x", encoding="utf-8")
            self.assertEqual(cli.main(["verify", str(a)]), 1)
            self.assertEqual(cli.main(["verify", str(b)]), 0)  # B unaffected by A's change

    def test_cli_init_is_visible_to_the_dashboard_and_the_reverse(self) -> None:
        from fastapi.testclient import TestClient
        from sentinel.api.main import app

        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            a, b = self._folders(Path(tmp))
            client = TestClient(app)
            cli.main(["init", str(a)])  # created on the command line
            folders = client.get("/api/v1/folders").json()["data"]["folders"]
            self.assertEqual([f["root_path"] for f in folders], [a.resolve().as_posix()])
            self.assertTrue(folders[0]["has_baseline"])
            self.assertEqual(client.post("/api/v1/scans", json={"root_path": str(a)}).json()["data"]["status"], "CLEAN")

            self.assertEqual(client.post("/api/v1/baselines", json={"root_path": str(b)}).status_code, 200)  # created in the dashboard
            self.assertEqual(cli.main(["verify", str(b)]), 0)  # CLI uses the same baseline
            (b / "extra.txt").write_text("x", encoding="utf-8")
            self.assertEqual(cli.main(["verify", str(b)]), 1)
            scans = client.get("/api/v1/scans").json()["data"]["scans"]  # CLI scans are in the dashboard history
            self.assertIn(b.resolve().as_posix(), [s["root_path"] for s in scans])

    def test_untracked_folder_is_refused_by_the_dashboard(self) -> None:
        from fastapi.testclient import TestClient
        from sentinel.api.main import app

        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            a, _ = self._folders(Path(tmp))
            r = TestClient(app).post("/api/v1/scans", json={"root_path": str(a)})
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.json()["error"]["code"], "FOLDER_NOT_TRACKED")

    def test_history_listing_filter_and_clear_per_folder(self) -> None:
        from fastapi.testclient import TestClient
        from sentinel.api.main import app

        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            a, b = self._folders(Path(tmp))
            client = TestClient(app)
            for d in (a, b):
                client.post("/api/v1/baselines", json={"root_path": str(d)})
            client.post("/api/v1/scans", json={"root_path": str(a)})
            client.post("/api/v1/scans", json={"root_path": str(b)})
            client.post("/api/v1/scans", json={"root_path": str(b)})
            ids = {f["root_path"]: f["id"] for f in client.get("/api/v1/folders").json()["data"]["folders"]}
            self.assertEqual(len(client.get("/api/v1/scans").json()["data"]["scans"]), 3)
            only_b = client.get("/api/v1/scans", params={"folder_id": ids[b.resolve().as_posix()]}).json()["data"]["scans"]
            self.assertEqual(len(only_b), 2)
            self.assertEqual(client.delete("/api/v1/scans", params={"folder_id": ids[b.resolve().as_posix()]}).json()["data"]["removed"], 2)
            left = client.get("/api/v1/scans").json()["data"]["scans"]
            self.assertEqual([s["root_path"] for s in left], [a.resolve().as_posix()])

    def test_untrack_hides_the_folder_but_keeps_its_files(self) -> None:
        from fastapi.testclient import TestClient
        from sentinel.api.main import app

        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            state = Path(tmp) / "state"
            a, _ = self._folders(Path(tmp))
            client = TestClient(app)
            client.post("/api/v1/baselines", json={"root_path": str(a)})
            fid = client.get("/api/v1/folders").json()["data"]["folders"][0]["id"]
            self.assertEqual(client.delete(f"/api/v1/folders/{fid}").status_code, 200)
            self.assertEqual(client.delete(f"/api/v1/folders/{fid}").status_code, 404)
            self.assertEqual(client.get("/api/v1/folders").json()["data"]["folders"], [])
            self.assertTrue((tracking.state_dir_for(state, a) / "baseline.json").is_file())

    def test_explicit_state_dir_bypasses_per_folder_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            a, _ = self._folders(Path(tmp))
            custom = Path(tmp) / "custom"
            self.assertEqual(cli.main(["init", str(a), "--state-dir", str(custom)]), 0)
            self.assertTrue((custom / "baseline.json").is_file())
            self.assertEqual(tracking.list_tracked(Path(tmp) / "state"), [])


if __name__ == "__main__":
    unittest.main()
