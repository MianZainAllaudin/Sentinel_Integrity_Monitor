from fastapi import APIRouter, HTTPException
from .schemas import ScanStartRequest, ScanAcceptRequest, HealthResponse
from .services import start_scan, accept_changes, get_status

router = APIRouter(prefix="/api/v1")


@router.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(data={"status": "ok"})


@router.get("/status")
def status():
    return get_status()


@router.post("/scans")
def start_scan_endpoint(body: ScanStartRequest):
    result = start_scan(body.root_path)
    if not result.get("success", False):
        raise HTTPException(status_code=400, detail=result.get("error", {}))
    return result


@router.get("/scans")
def list_scans():
    return {"success": True, "data": {"scans": []}}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    return {"success": True, "data": {"scan_id": scan_id}}


@router.post("/accept")
def accept_endpoint(body: ScanAcceptRequest):
    result = accept_changes(body.scan_id, body.confirm)
    if not result.get("success", False):
        raise HTTPException(status_code=400, detail=result.get("error", {}))
    return result
