from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class ScanStartRequest(BaseModel):
    root_path: str


class ScanAcceptRequest(BaseModel):
    scan_id: str
    confirm: bool


class ErrorResponse(BaseModel):
    success: bool = False
    error: Dict[str, str]


class ScanResultResponse(BaseModel):
    success: bool = True
    data: Dict[str, Any]


class HealthResponse(BaseModel):
    success: bool = True
    data: Dict[str, str]
