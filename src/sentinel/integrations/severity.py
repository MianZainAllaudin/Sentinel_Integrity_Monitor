from ..core.models import ChangeRecord, ScanResult


def classify_change(change: ChangeRecord) -> str:
    return "LOW"


def apply_severity(result: ScanResult) -> ScanResult:
    return result
