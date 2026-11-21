from sentinel.reporting.webhook import send_webhook_alert
from sentinel.core.models import ScanResult


def test_webhook_missing_url():
    result = ScanResult(
        schema_version=1, scan_id="x", root_path="r",
        started_at="t1", completed_at="t2", status="CLEAN",
        summary={"added": 0, "modified": 0, "deleted": 0, "moved": 0, "errors": 0},
        changes=[], errors=[],
    )
    res = send_webhook_alert(result, "discord", "")
    assert res["success"] is False
    assert res["code"] == "WEBHOOK_NOT_CONFIGURED"
