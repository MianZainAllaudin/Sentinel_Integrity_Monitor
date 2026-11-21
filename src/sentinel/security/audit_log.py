from pathlib import Path
from typing import Dict, Any, Optional


def append_audit_event(
    log_path: Path,
    event_type: str,
    scan_id: Optional[str],
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    raise NotImplementedError


def verify_audit_chain(
    log_path: Path,
) -> Dict[str, Any]:
    raise NotImplementedError
