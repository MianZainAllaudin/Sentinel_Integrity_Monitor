import pytest
import json
from sentinel import ci_runner
from sentinel.application import OperationResult
from sentinel.core.models import ChangeRecord, ScanError, ScanResult
from sentinel.security.baseline_signer import InvalidSignatureError


def make_result(status="CLEAN", changes=(), errors=()):
    summary = {"added": 0, "modified": len(changes), "deleted": 0, "moved": 0, "errors": len(errors)}
    return ScanResult(1, "scan-1", "root", "t1", "t2", status, summary, list(changes), list(errors))


def change(path, severity):
    return ChangeRecord("MODIFIED", path, None, path, "a" * 64, "b" * 64, 1, 2, severity, "SHA-256 content hash changed")


@pytest.fixture
def trees(tmp_path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    for tree, text in ((base, "old"), (head, "new")):
        (tree / ".git").mkdir(parents=True)
        (tree / ".git" / "config").write_text("secret-git-data")
        (tree / ".github" / "workflows").mkdir(parents=True)
        (tree / ".github" / "workflows" / "ci.yml").write_text(text)
    (base / "ci").mkdir()
    (base / "ci" / "sentinel-ci.ignore").write_text("src/\n")
    return base, head


def argv(trees, *extra):
    base, head = trees
    return ["--base-dir", str(base), "--head-dir", str(head), *extra]


def fake_engine(monkeypatch, result, seen=None):
    seen = seen if seen is not None else {}

    def fake_initialize(root, settings):
        seen["init_target"] = root
        seen["init_content"] = (root / ".github" / "workflows" / "ci.yml").read_text()
        seen["git_copied_on_init"] = (root / ".git").exists()
        seen["ignore_file"] = settings.ignore_file
        seen["key_len"] = len(settings.hmac_key)
        return OperationResult("INIT", True, str(root), "t", "baseline created", None)

    def fake_verify(root, settings):
        seen["verify_target"] = root
        seen["verify_content"] = (root / ".github" / "workflows" / "ci.yml").read_text()
        return result

    monkeypatch.setattr(ci_runner.application, "initialize", fake_initialize)
    monkeypatch.setattr(ci_runner.application, "verify", fake_verify)
    return seen


def test_base_is_baselined_then_head_is_verified_at_the_same_path(trees, monkeypatch):
    seen = fake_engine(monkeypatch, make_result())
    assert ci_runner.main(argv(trees)) == 0
    assert seen["init_content"] == "old" and seen["verify_content"] == "new"
    assert seen["init_target"] == seen["verify_target"]
    assert seen["git_copied_on_init"] is False
    assert seen["key_len"] == 32


def test_ignore_file_comes_from_the_trusted_base_tree(trees, monkeypatch):
    seen = fake_engine(monkeypatch, make_result())
    ci_runner.main(argv(trees))
    assert seen["ignore_file"] == trees[0].resolve() / "ci" / "sentinel-ci.ignore"


def test_default_policy_fails_on_high_only(trees, monkeypatch):
    fake_engine(monkeypatch, make_result("CHANGED", [change("README.md", "LOW")]))
    assert ci_runner.main(argv(trees)) == 0
    fake_engine(monkeypatch, make_result("CHANGED", [change(".github/workflows/ci.yml", "HIGH")]))
    assert ci_runner.main(argv(trees)) == 1


def test_fail_on_any_and_medium(trees, monkeypatch):
    fake_engine(monkeypatch, make_result("CHANGED", [change("README.md", "LOW")]))
    assert ci_runner.main(argv(trees, "--fail-on", "any")) == 1
    assert ci_runner.main(argv(trees, "--fail-on", "medium")) == 0
    fake_engine(monkeypatch, make_result("CHANGED", [change("a.py", "MEDIUM")]))
    assert ci_runner.main(argv(trees, "--fail-on", "medium")) == 1


def test_baseline_invalid_exits_3(trees, monkeypatch):
    fake_engine(monkeypatch, make_result("BASELINE_INVALID"))
    assert ci_runner.main(argv(trees)) == 3


def test_scan_errors_exit_4_even_if_status_is_clean(trees, monkeypatch):
    fake_engine(monkeypatch, make_result("CLEAN", errors=[ScanError("FILE_ACCESS_DENIED", "a", "denied")]))
    assert ci_runner.main(argv(trees)) == 4


def test_security_failure_beats_changes(trees, monkeypatch):
    fake_engine(monkeypatch, make_result("BASELINE_INVALID", [change("a.py", "HIGH")]))
    assert ci_runner.main(argv(trees)) == 3


def test_security_exception_exits_3_with_stable_code(trees, monkeypatch, capsys):
    def boom(root, settings):
        raise InvalidSignatureError("signature mismatch")
    monkeypatch.setattr(ci_runner.application, "initialize", boom)
    assert ci_runner.main(argv(trees)) == 3
    assert "HMAC_VERIFICATION_FAILED" in capsys.readouterr().out


def test_engine_not_ready_or_io_failure_exits_4(trees, monkeypatch):
    def not_ready(root, settings):
        raise NotImplementedError
    monkeypatch.setattr(ci_runner.application, "initialize", not_ready)
    assert ci_runner.main(argv(trees)) == 4


def test_invalid_folder_exits_2(tmp_path, monkeypatch):
    fake_engine(monkeypatch, make_result())
    code = ci_runner.main(["--base-dir", str(tmp_path / "nope"), "--head-dir", str(tmp_path)])
    assert code == 2


def test_missing_arguments_exit_2():
    with pytest.raises(SystemExit) as info:
        ci_runner.main([])
    assert info.value.code == 2


def test_annotation_escapes_newlines(trees, monkeypatch, capsys):
    fake_engine(monkeypatch, make_result("CHANGED", [change("evil\n::error::injected", "HIGH")]))
    ci_runner.main(argv(trees))
    out = capsys.readouterr().out
    assert "evil%0A::error::injected" in out
    assert "\n::error::injected" not in out


def test_reports_and_audit_path_are_honoured(trees, monkeypatch, tmp_path):
    fake_engine(monkeypatch, make_result())
    json_out, html_out = tmp_path / "r.json", tmp_path / "r.html"
    code = ci_runner.main(argv(trees, "--report-json", str(json_out), "--report-html", str(html_out)))
    assert code == 0 and json_out.is_file() and html_out.is_file()
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["root_path"] == str(trees[1].resolve())  # head path shown, not the temp folder