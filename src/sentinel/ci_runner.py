from __future__ import annotations

import argparse
import dataclasses
import os
import shutil
import tempfile
from pathlib import Path

from . import application
from .config.settings import AppSettings
from .core.models import ScanResult
from .reporting.html_report import write_html_report
from .reporting.json_report import write_json_report
from .security.baseline_signer import SecurityError

EXIT_OK = 0
EXIT_POLICY_VIOLATION = 1
EXIT_INVALID_USAGE = 2
EXIT_SECURITY = 3
EXIT_INCOMPLETE = 4

DEFAULT_FAIL_ON = "high"  # contract 11.1 recommended demo policy; the team must confirm
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
_THRESHOLD = {"any": 1, "medium": 2, "high": 3}


def _escape(text: str) -> str:
    """Escape text for a GitHub workflow command (prevents annotation injection)."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _annotate(level: str, title: str, message: str) -> None:
    print(f"::{level} title={_escape(title)}::{_escape(message)}")


def violations(result: ScanResult, fail_on: str) -> list:
    """Changes whose severity is at or above the configured threshold."""
    limit = _THRESHOLD[fail_on]
    return [c for c in result.changes if _RANK.get(c.severity, 3) >= limit]


def decide_exit_code(result: ScanResult, fail_on: str) -> int:
    """Map a ScanResult to the contract exit code (priority 3, 4, 1, 0)."""
    if result.status == "BASELINE_INVALID":
        return EXIT_SECURITY
    if result.status == "ERROR" or result.summary.get("errors", 0) > 0:
        return EXIT_INCOMPLETE
    if violations(result, fail_on):
        return EXIT_POLICY_VIOLATION
    return EXIT_OK


def _write_step_summary(result: ScanResult) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    s = result.summary
    lines = [
        f"## Sentinel: {result.status}",
        "",
        f"Added {s.get('added', 0)} | Modified {s.get('modified', 0)} | Deleted {s.get('deleted', 0)} | "
        f"Moved {s.get('moved', 0)} | Errors {s.get('errors', 0)}",
        "",
    ]
    if result.changes:
        lines += ["| Severity | Status | Path |", "|---|---|---|"]
        lines += [f"| {c.severity} | {c.status} | `{c.path}` |" for c in result.changes]
    with open(target, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def _populate(source: Path, target: Path) -> None:
    """Make ``target`` an exact copy of ``source`` (without .git), keeping metadata."""
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target, symlinks=True, ignore=shutil.ignore_patterns(".git"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-ci",
        description="Compare a tree under test with a trusted base tree using Sentinel",
    )
    parser.add_argument("--base-dir", required=True, help="trusted base-commit checkout")
    parser.add_argument("--head-dir", required=True, help="checkout under test (pull request)")
    parser.add_argument("--ignore-file", default=None,
                        help="ignore rules; default: <base-dir>/ci/sentinel-ci.ignore if present")
    parser.add_argument("--fail-on", choices=tuple(_THRESHOLD), default=DEFAULT_FAIL_ON)
    parser.add_argument("--audit-log", default=None, help="keep the audit log here (e.g. for upload)")
    parser.add_argument("--report-json", default=None)
    parser.add_argument("--report-html", default=None)
    return parser


def run(args: argparse.Namespace) -> int:
    """Run the ephemeral-baseline comparison and return the exit code."""
    base = Path(args.base_dir).resolve()
    head = Path(args.head_dir).resolve()
    if not base.is_dir() or not head.is_dir():
        _annotate("error", "Sentinel INVALID_ROOT_PATH", "base-dir and head-dir must be existing folders")
        return EXIT_INVALID_USAGE
    ignore_file = Path(args.ignore_file).resolve() if args.ignore_file else None
    if ignore_file is None and (base / "ci" / "sentinel-ci.ignore").is_file():
        ignore_file = base / "ci" / "sentinel-ci.ignore"  # always the TRUSTED copy

    with tempfile.TemporaryDirectory(prefix="sentinel-ci-") as work_name:
        work = Path(work_name)
        state = work / "state"
        state.mkdir()
        target = work / "target"
        settings = AppSettings(
            state_dir=state,
            hmac_key=os.urandom(32),  # job-local key: memory only, never printed or stored
            baseline_path=state / "baseline.json",
            audit_log_path=Path(args.audit_log).resolve() if args.audit_log else state / "audit.jsonl",
            ignore_file=ignore_file,
        )

        _populate(base, target)
        outcome = application.initialize(target, settings)
        if not outcome.success:
            _annotate("error", "Sentinel", f"could not build the trusted baseline: {outcome.message}")
            return EXIT_INCOMPLETE

        _populate(head, target)
        result = application.verify(target, settings)

    result = dataclasses.replace(result, root_path=str(head))  # never expose the temp path
    if args.report_json:
        write_json_report(result, Path(args.report_json))
    if args.report_html:
        write_html_report(result, Path(args.report_html))

    s = result.summary
    print(
        f"Sentinel scan {result.scan_id}: {result.status} (added={s.get('added', 0)}, "
        f"modified={s.get('modified', 0)}, deleted={s.get('deleted', 0)}, "
        f"moved={s.get('moved', 0)}, errors={s.get('errors', 0)}); fail-on={args.fail_on}"
    )
    for change in result.changes:
        print(_escape(f"  {change.severity:<6} {change.status:<8} {change.path}  ({change.reason})"))
    for change in violations(result, args.fail_on):
        _annotate("error", f"Sentinel {change.severity} {change.status}", f"{change.path}: {change.reason}")
    for error in result.errors:
        _annotate("error", f"Sentinel {error.code}", error.message)
    _write_step_summary(result)
    return decide_exit_code(result, args.fail_on)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)  # invalid arguments exit with code 2 (argparse)
    try:
        return run(args)
    except SecurityError as exc:
        _annotate("error", f"Sentinel {exc.code}", str(exc))
        return EXIT_SECURITY
    except (RuntimeError, OSError) as exc:
        _annotate("error", "Sentinel FAILURE", f"{type(exc).__name__}: {exc}")
        return EXIT_INCOMPLETE


if __name__ == "__main__":
    raise SystemExit(main())