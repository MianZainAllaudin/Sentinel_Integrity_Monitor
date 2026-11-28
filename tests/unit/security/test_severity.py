import pytest

from sentinel.core.models import ChangeRecord, ScanResult
from sentinel.integrations.severity import apply_severity, classify_change


def change(path, status="MODIFIED", old_path=None, new_path=None):
    return ChangeRecord(
        status=status, path=path, old_path=old_path, new_path=new_path or path,
        old_sha256=None, new_sha256=None, old_size_bytes=None, new_size_bytes=None,
        severity="LOW", reason="test",
    )


@pytest.mark.parametrize("path", [
    ".github/workflows/sentinel.yml",
    ".github/workflows/deploy.yaml",
    "sub/.github/workflows/ci.yml",
    "Dockerfile",
    "services/api/Dockerfile.prod",
    "build/app.dockerfile",
    "docker-compose.yml",
    "package.json",
    "frontend/package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "go.sum",
    "scripts/deploy.sh",
    "deploy/run.ps1",
    ".sentinelignore",
    ".npmrc",
    "action.yml",
    ".GITHUB\\Workflows\\Build.YML",
    "./Dockerfile",
])
def test_supply_chain_files_are_high(path):
    assert classify_change(change(path)) == "HIGH"


@pytest.mark.parametrize("path", ["src/main.py", "app.js", "run.bat", "tool.exe", "config.json", ".env", "settings.ini"])
def test_code_and_config_are_medium(path):
    assert classify_change(change(path)) == "MEDIUM"


@pytest.mark.parametrize("path", ["README.md", "notes.txt", "logo.png", "docs/guide.pdf"])
def test_documents_are_low(path):
    assert classify_change(change(path)) == "LOW"


@pytest.mark.parametrize("status", ["ADDED", "MODIFIED", "DELETED", "MOVED"])
def test_status_does_not_lower_a_sensitive_file(status):
    assert classify_change(change("Dockerfile", status=status)) == "HIGH"


def test_move_into_sensitive_location_is_high():
    moved = change("deploy/readme.txt", status="MOVED", old_path="notes/readme.txt", new_path="deploy/readme.txt")
    assert classify_change(moved) == "HIGH"


def test_move_out_of_sensitive_location_is_high():
    moved = change("notes/x.txt", status="MOVED", old_path=".github/workflows/x.txt", new_path="notes/x.txt")
    assert classify_change(moved) == "HIGH"


def test_apply_severity_sets_values_without_mutating_input():
    original = ScanResult(
        schema_version=1, scan_id="s", root_path="r", started_at="a", completed_at="b",
        status="CHANGED",
        summary={"added": 0, "modified": 3, "deleted": 0, "moved": 0, "errors": 0},
        changes=[change(".github/workflows/ci.yml"), change("src/a.py"), change("README.md")],
        errors=[],
    )
    updated = apply_severity(original)
    assert [c.severity for c in updated.changes] == ["HIGH", "MEDIUM", "LOW"]
    assert [c.severity for c in original.changes] == ["LOW", "LOW", "LOW"]
    assert updated.status == "CHANGED" and updated.scan_id == "s"


def test_contract_alias_classify_severity_matches_classify_change():
    from sentinel.integrations.severity import classify_severity
    assert classify_severity(change("Dockerfile")) == classify_change(change("Dockerfile")) == "HIGH"