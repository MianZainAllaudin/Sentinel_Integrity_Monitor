from typing import Dict, Any
from ..core.models import BaselineData


def sign_baseline(
    payload: BaselineData,
    key: bytes,
    key_id: str = "local-v1",
) -> Dict[str, Any]:
    raise NotImplementedError


def verify_baseline(
    envelope: Dict[str, Any],
    key: bytes,
) -> BaselineData:
    raise NotImplementedError
