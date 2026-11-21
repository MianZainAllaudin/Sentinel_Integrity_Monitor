from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import base64
import os


@dataclass(frozen=True)
class AppSettings:
    state_dir: Path
    hmac_key: bytes
    baseline_path: Optional[Path] = None
    audit_log_path: Optional[Path] = None
    ignore_file: Optional[Path] = None
    hash_chunk_size: int = 1048576
    webhook_provider: Optional[str] = None
    webhook_url: Optional[str] = None


@dataclass(frozen=True)
class OperationResult:
    operation: str
    success: bool
    root_path: str
    completed_at: str
    message: str
    scan_id: Optional[str] = None


def load_settings() -> AppSettings:
    raw = os.getenv("SENTINEL_HMAC_KEY")
    if not raw:
        raise RuntimeError("SENTINEL_HMAC_KEY is not set")
    try:
        key = base64.b64decode(raw)
    except Exception:
        raise RuntimeError("SENTINEL_HMAC_KEY is not valid base64")
    state_dir = Path(os.getenv("SENTINEL_STATE_DIR", Path.home() / ".sentinel"))
    state_dir.mkdir(parents=True, exist_ok=True)
    return AppSettings(
        state_dir=state_dir,
        hmac_key=key,
    )
