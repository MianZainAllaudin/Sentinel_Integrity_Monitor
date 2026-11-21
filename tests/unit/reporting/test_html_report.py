from pathlib import Path
import tempfile
from sentinel.reporting.html_report import write_html_report, _escape
from sentinel.core.models import ScanResult


def test_escape():
    assert _escape("<script>") == "&lt;script&gt;"


def test_html_report_escapes():
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "report.html"
        result = ScanResult(
            schema_version=1,
            scan_id="x",
            root_path="C:/proj",
            started_at="t1",
            completed_at="t2",
            status="CLEAN",
            summary={"added": 0, "modified": 0, "deleted": 0, "moved": 0, "errors": 0},
            changes=[],
            errors=[],
        )
        write_html_report(result, out)
        html = out.read_text(encoding="utf-8")
        assert "C:/proj" in html
        assert "<script>" not in html
