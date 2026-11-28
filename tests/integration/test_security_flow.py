import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel import application
from sentinel.config.settings import AppSettings
from sentinel.core.models import BaselineData, FileSnapshot, ScanResult
from sentinel.security.audit_log import verify_audit_chain

SNAP = FileSnapshot("app/main.py", "a" * 64, 5, 1)


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setattr(application, "scan_directory", lambda root, ignore, chunk: ([SNAP], []))
    monkeypatch.setattr(
        application, "build_baseline",
        lambda root, snaps: BaselineData(1, "C:/Proj", "2026-11-28T00:00:00Z", "sha256", {s.path: s for s in snaps}),
    )
    monkeypatch.setattr(
        application, "compare_snapshots",
        lambda baseline, snaps, errors: ScanResult(
            1, "x", "C:/Proj", "t", "t", "CLEAN",
            {"added": 0, "modified": 0, "deleted": 0, "moved": 0, "errors": 0}, [], []),
    )
    return AppSettings(state_dir=tmp_path / "state", hmac_key=os.urandom(32))


def test_tampered_baseline_is_rejected_and_audit_chain_stays_valid(settings, tmp_path):
    settings.state_dir.mkdir()
    application.initialize(tmp_path, settings)
    baseline_file = settings.state_dir / "baseline.json"
    assert application.verify(tmp_path, settings).status == "CLEAN"

    envelope = json.loads(baseline_file.read_text(encoding="utf-8"))
    envelope["payload"]["files"]["app/main.py"]["sha256"] = "f" * 64  # attacker edits baseline
    baseline_file.write_text(json.dumps(envelope), encoding="utf-8")

    assert application.verify(tmp_path, settings).status == "BASELINE_INVALID"
    chain = verify_audit_chain(settings.state_dir / "audit.jsonl")
    assert chain["valid"] is True and chain["entries_checked"] >= 2


def test_baseline_signed_with_other_key_is_rejected(settings, tmp_path):
    settings.state_dir.mkdir()
    application.initialize(tmp_path, settings)
    other = AppSettings(state_dir=settings.state_dir, hmac_key=os.urandom(32))
    assert application.verify(tmp_path, other).status == "BASELINE_INVALID"


def test_accept_refuses_a_tampered_baseline_and_does_not_overwrite_it(settings, tmp_path):
    settings.state_dir.mkdir()
    application.initialize(tmp_path, settings)
    baseline_file = settings.state_dir / "baseline.json"
    envelope = json.loads(baseline_file.read_text(encoding="utf-8"))
    envelope["payload"]["files"]["app/main.py"]["sha256"] = "f" * 64
    baseline_file.write_text(json.dumps(envelope), encoding="utf-8")
    tampered_bytes = baseline_file.read_bytes()

    outcome = application.accept(tmp_path, "scan-1", settings)

    assert outcome.success is False
    assert baseline_file.read_bytes() == tampered_bytes  # never replaced after a failed check