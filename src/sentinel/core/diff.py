from typing import List, Optional
from .models import BaselineData, FileSnapshot, ScanError, ScanResult


def compare_snapshots(
    baseline: BaselineData,
    current_snapshots: List[FileSnapshot],
    scan_errors: Optional[List[ScanError]] = None,
) -> ScanResult:
    raise NotImplementedError
