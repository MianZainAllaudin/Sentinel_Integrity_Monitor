import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel import history


def _scan(i: int, status: str = "CLEAN") -> dict:
    return {
        "scan_id": f"id-{i}", "root_path": "/r", "started_at": "t0", "completed_at": f"t{i}",
        "status": status, "summary": {"added": 0, "modified": 0, "deleted": 0, "moved": 0, "errors": 0},
        "changes": [{"path": "a.txt", "status": "ADDED", "severity": "LOW"}], "errors": [],
    }


class TestHistoryStore(unittest.TestCase):
    def test_empty_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(history.list_scans(Path(tmp)), [])
            self.assertIsNone(history.get_scan(Path(tmp), "x"))
            self.assertEqual(history.clear_history(Path(tmp)), 0)

    def test_record_list_get_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for i in range(3):
                history.record_scan(d, _scan(i))
            ids = [s["scan_id"] for s in history.list_scans(d)]
            self.assertEqual(ids, ["id-2", "id-1", "id-0"])
            self.assertNotIn("changes", history.list_scans(d)[0])
            full = history.get_scan(d, "id-1")
            self.assertEqual(full["changes"][0]["path"], "a.txt")

    def test_persists_in_a_file_across_restarts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            history.record_scan(d, _scan(1))
            self.assertTrue((d / "history.jsonl").is_file())
            # a "restart" is just a fresh read of the same folder
            self.assertEqual(len(history.list_scans(d)), 1)

    def test_clear_removes_everything_and_reports_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for i in range(4):
                history.record_scan(d, _scan(i))
            self.assertEqual(history.clear_history(d), 4)
            self.assertEqual(history.list_scans(d), [])
            history.record_scan(d, _scan(9))
            self.assertEqual(len(history.list_scans(d)), 1)

    def test_corrupt_lines_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            history.record_scan(d, _scan(1))
            with (d / "history.jsonl").open("a", encoding="utf-8") as fh:
                fh.write("{not json\n\n[1,2]\n")
            history.record_scan(d, _scan(2))
            self.assertEqual([s["scan_id"] for s in history.list_scans(d)], ["id-2", "id-1"])

    def test_history_is_trimmed_to_the_maximum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            with mock.patch.object(history, "MAX_RECORDS", 5):
                for i in range(8):
                    history.record_scan(d, _scan(i))
            ids = [s["scan_id"] for s in history.list_scans(d)]
            self.assertEqual(ids, ["id-7", "id-6", "id-5", "id-4", "id-3"])

    def test_unicode_paths_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            s = _scan(1)
            s["changes"][0]["path"] = "my docs/unicode_é.txt"
            history.record_scan(d, s)
            self.assertEqual(history.get_scan(d, "id-1")["changes"][0]["path"], "my docs/unicode_é.txt")


class TestHistoryIntegration(unittest.TestCase):
    def _env(self, state: Path):
        key = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="  # base64 of a 32-byte string
        return mock.patch.dict(os.environ, {"SENTINEL_HMAC_KEY": key, "SENTINEL_STATE_DIR": str(state)})

    def test_cli_verify_is_recorded_and_visible_to_the_api(self) -> None:
        from fastapi.testclient import TestClient
        from sentinel import cli
        from sentinel.api.main import app

        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            root = Path(tmp) / "root"
            root.mkdir()
            (root / "a.txt").write_text("one", encoding="utf-8")
            self.assertEqual(cli.main(["init", str(root)]), 0)
            (root / "b.txt").write_text("two", encoding="utf-8")
            self.assertEqual(cli.main(["verify", str(root)]), 1)

            client = TestClient(app)
            scans = client.get("/api/v1/scans").json()["data"]["scans"]
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0]["status"], "CHANGED")
            detail = client.get(f"/api/v1/scans/{scans[0]['scan_id']}").json()["data"]
            self.assertEqual(detail["changes"][0]["path"], "b.txt")

    def test_api_scans_are_saved_and_accept_works_from_saved_history(self) -> None:
        from fastapi.testclient import TestClient
        from sentinel import cli
        from sentinel.api.main import app

        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            root = Path(tmp) / "root"
            root.mkdir()
            (root / "a.txt").write_text("one", encoding="utf-8")
            cli.main(["init", str(root)])
            (root / "b.txt").write_text("two", encoding="utf-8")
            client = TestClient(app)
            sid = client.post("/api/v1/scans", json={"root_path": str(root)}).json()["data"]["scan_id"]
            # a brand-new client/app object stands in for a backend restart
            client2 = TestClient(app)
            self.assertEqual(len(client2.get("/api/v1/scans").json()["data"]["scans"]), 1)
            self.assertTrue(client2.post("/api/v1/accept", json={"scan_id": sid, "confirm": True}).json()["success"])
            self.assertEqual(client2.post("/api/v1/scans", json={"root_path": str(root)}).json()["data"]["status"], "CLEAN")
            self.assertEqual(len(client2.get("/api/v1/scans").json()["data"]["scans"]), 2)

    def test_baseline_invalid_scans_are_recorded_too(self) -> None:
        from fastapi.testclient import TestClient
        from sentinel import tracking
        from sentinel.api.main import app

        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            state = Path(tmp) / "state"
            root = Path(tmp) / "root"
            root.mkdir()
            client = TestClient(app)
            self.assertEqual(client.post("/api/v1/baselines", json={"root_path": str(root)}).status_code, 200)
            (tracking.state_dir_for(state, root) / "baseline.json").unlink()  # attacker deletes the baseline
            r = client.post("/api/v1/scans", json={"root_path": str(root)}).json()["data"]
            self.assertEqual(r["status"], "BASELINE_INVALID")
            scans = client.get("/api/v1/scans").json()["data"]["scans"]
            self.assertEqual([s["status"] for s in scans], ["BASELINE_INVALID"])

    def test_clear_endpoint_empties_history_and_is_audited(self) -> None:
        from fastapi.testclient import TestClient
        from sentinel import cli, tracking
        from sentinel.api.main import app
        from sentinel.security.audit_log import verify_audit_chain

        with tempfile.TemporaryDirectory() as tmp, self._env(Path(tmp) / "state"):
            state = Path(tmp) / "state"
            root = Path(tmp) / "root"
            root.mkdir()
            (root / "a.txt").write_text("one", encoding="utf-8")
            cli.main(["init", str(root)])
            cli.main(["verify", str(root)])
            cli.main(["verify", str(root)])
            client = TestClient(app)
            self.assertEqual(len(client.get("/api/v1/scans").json()["data"]["scans"]), 2)
            res = client.delete("/api/v1/scans").json()
            self.assertEqual(res["data"]["removed"], 2)
            self.assertEqual(client.get("/api/v1/scans").json()["data"]["scans"], [])
            self.assertEqual(client.get("/api/v1/scans/anything").status_code, 404)
            sd = tracking.state_dir_for(state, root)
            self.assertIn("HISTORY_CLEARED", (sd / "audit.jsonl").read_text(encoding="utf-8"))
            chain = verify_audit_chain(sd / "audit.jsonl")
            valid = chain["valid"] if isinstance(chain, dict) else chain.valid
            self.assertTrue(valid)
            self.assertTrue((sd / "baseline.json").is_file())  # clearing history never touches the baseline


if __name__ == "__main__":
    unittest.main()
