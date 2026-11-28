from fastapi import APIRouter, HTTPException
from .schemas import ScanStartRequest, ScanAcceptRequest, HealthResponse
from .services import start_scan, accept_changes, get_status, init_baseline, list_scans as svc_list_scans, get_scan_by_id, clear_scans

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
    return svc_list_scans()


@router.delete("/scans")
def clear_scans_endpoint():
    return clear_scans()


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = get_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": "unknown scan_id"})
    return {"success": True, "data": scan}


@router.post("/baselines")
def init_endpoint(body: ScanStartRequest):
    result = init_baseline(body.root_path)
    if not result.get("success", False):
        raise HTTPException(status_code=400, detail=result.get("error", {"code": "INIT_FAILED", "message": "init failed"}))
    return result

@router.post("/accept")
def accept_endpoint(body: ScanAcceptRequest):
    result = accept_changes(body.scan_id, body.confirm)
    if not result.get("success", False):
        raise HTTPException(status_code=400, detail=result.get("error", {}))
    return result
