import json
from pathlib import Path
import tempfile
from sentinel.reporting.json_report import write_json_report
from sentinel.core.models import ScanResult, ChangeRecord, ScanError


def _result():
    return ScanResult(
        schema_version=1,
        scan_id="abc-123",
        root_path="C:/proj",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:02Z",
        status="CLEAN",
        summary={"added": 0, "modified": 0, "deleted": 0, "moved": 0, "errors": 0},
        changes=[],
        errors=[],
    )


def test_json_report_keys():
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "report.json"
        write_json_report(_result(), out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["scan_id"] == "abc-123"
        assert data["status"] == "CLEAN"
        assert data["summary"]["added"] == 0
