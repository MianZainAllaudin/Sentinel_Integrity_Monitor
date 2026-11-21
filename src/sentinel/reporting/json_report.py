import json
from pathlib import Path
from ..core.models import ScanResult


def write_json_report(result: ScanResult, output_path: Path) -> Path:
    data = {
        "schema_version": result.schema_version,
        "scan_id": result.scan_id,
        "root_path": result.root_path,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "status": result.status,
        "summary": result.summary,
        "changes": [c.__dict__ for c in result.changes],
        "errors": [e.__dict__ for e in result.errors],
    }
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return output_path
