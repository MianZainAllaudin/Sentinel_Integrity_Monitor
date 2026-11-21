from pathlib import Path
from ..core.models import ScanResult


def send_webhook_alert(
    result: ScanResult,
    provider: str,
    webhook_url: str,
) -> dict:
    if not webhook_url:
        return {"success": False, "code": "WEBHOOK_NOT_CONFIGURED", "message": "webhook url not set"}
    return {
        "success": False,
        "code": "WEBHOOK_DELIVERY_FAILED",
        "message": f"{provider} webhook not implemented in this build",
    }
