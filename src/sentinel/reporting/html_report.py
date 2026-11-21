from pathlib import Path
from ..core.models import ScanResult


def _escape(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def write_html_report(result: ScanResult, output_path: Path) -> Path:
    rows = ""
    for c in result.changes:
        rows += (
            "<tr>"
            f"<td>{_escape(c.status)}</td>"
            f"<td>{_escape(c.path)}</td>"
            f"<td>{_escape(c.severity)}</td>"
            f"<td>{_escape(c.reason)}</td>"
            "</tr>"
        )
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Sentinel Report</title></head>
<body>
<h1>Sentinel Scan Report</h1>
<p><strong>Status:</strong> {_escape(result.status)}</p>
<p><strong>Root:</strong> {_escape(result.root_path)}</p>
<p><strong>Scan ID:</strong> {_escape(result.scan_id)}</p>
<p><strong>Started:</strong> {_escape(result.started_at)}</p>
<p><strong>Completed:</strong> {_escape(result.completed_at)}</p>
<h2>Summary</h2>
<ul>
<li>Added: {result.summary.get('added', 0)}</li>
<li>Modified: {result.summary.get('modified', 0)}</li>
<li>Deleted: {result.summary.get('deleted', 0)}</li>
<li>Moved: {result.summary.get('moved', 0)}</li>
<li>Errors: {result.summary.get('errors', 0)}</li>
</ul>
<h2>Changes</h2>
<table border="1" cellpadding="4">
<tr><th>Status</th><th>Path</th><th>Severity</th><th>Reason</th></tr>
{rows}
</table>
<h2>Errors</h2>
<ul>
{"".join(f"<li>{_escape(e.code)}: {_escape(e.message)}</li>" for e in result.errors)}
</ul>
</body>
</html>"""
    output_path.write_text(html, encoding="utf-8")
    return output_path
