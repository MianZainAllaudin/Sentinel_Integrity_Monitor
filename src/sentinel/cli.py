"""Command-line interface for Sentinel artifact integrity monitor."""

from __future__ import annotations

import argparse
import base64
import binascii
from enum import Enum
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Sequence
import uuid

from . import __version__, application
from .config.settings import AppSettings, OperationResult
from .core.models import ScanResult, ScanStatus, scan_result_to_dict
from .reporting.html_report import write_html_report
from .reporting.json_report import write_json_report

EXIT_CLEAN = 0
EXIT_CHANGED = 1
EXIT_ERROR = 2

DEFAULT_CHUNK_SIZE = 1_048_576


def _enum_str(value: Any) -> Any:
    """Return the underlying value when *value* is an Enum."""
    return value.value if isinstance(value, Enum) else value


def _positive_int(raw_value: str) -> int:
    """Parse a strictly positive integer CLI argument."""
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid positive integer value: {raw_value!r}"
        ) from exc
    if value <= 0:
        raise argparse.ArgumentTypeError(
            f"chunk size must be a positive integer, got {value}"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level CLI argument parser."""
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--state-dir",
        dest="state_dir",
        default=None,
        metavar="PATH",
        help="Override SENTINEL_STATE_DIR (default: $SENTINEL_STATE_DIR or ~/.sentinel).",
    )
    common_parser.add_argument(
        "--baseline",
        dest="baseline",
        default=None,
        metavar="PATH",
        help="Path to the signed baseline file.",
    )
    common_parser.add_argument(
        "--audit-log",
        dest="audit_log",
        default=None,
        metavar="PATH",
        help="Path to the hash-chained audit log (.jsonl).",
    )
    common_parser.add_argument(
        "--ignore-file",
        "--ignore",
        dest="ignore_file",
        default=None,
        metavar="PATH",
        help="Path to .sentinelignore rule file.",
    )
    common_parser.add_argument(
        "--chunk-size",
        dest="chunk_size",
        type=_positive_int,
        default=DEFAULT_CHUNK_SIZE,
        metavar="INT",
        help=f"File hashing chunk size in bytes (default: {DEFAULT_CHUNK_SIZE}).",
    )
    common_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit canonical JSON output to stdout instead of console text.",
    )

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel artifact integrity and tamper-detection CLI.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
        required=True,
    )

    init_parser = subparsers.add_parser(
        "init",
        parents=[common_parser],
        help="Scan a folder and create a signed baseline.",
    )
    init_parser.add_argument(
        "root_path",
        nargs="?",
        default=".",
        help="Target directory to monitor (default: current directory).",
    )

    verify_parser = subparsers.add_parser(
        "verify",
        parents=[common_parser],
        help="Verify a folder against its signed baseline.",
    )
    verify_parser.add_argument(
        "root_path",
        nargs="?",
        default=".",
        help="Target directory to verify (default: current directory).",
    )
    verify_parser.add_argument(
        "--json-out",
        dest="json_out",
        default=None,
        metavar="PATH",
        help="Write canonical JSON scan report to PATH.",
    )
    verify_parser.add_argument(
        "--html-out",
        dest="html_out",
        default=None,
        metavar="PATH",
        help="Write HTML scan report to PATH.",
    )

    accept_parser = subparsers.add_parser(
        "accept",
        parents=[common_parser],
        help="Approve current folder state and sign a new baseline.",
    )
    accept_parser.add_argument(
        "root_path",
        nargs="?",
        default=".",
        help="Target directory to accept (default: current directory).",
    )
    accept_parser.add_argument(
        "--scan-id",
        dest="scan_id",
        default=None,
        metavar="ID",
        help="Scan ID recorded in the audit log (default: generated UUID4).",
    )
    accept_parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        default=False,
        help="Confirm baseline acceptance non-interactively.",
    )

    return parser


def _decode_hmac_key_from_env() -> bytes:
    """Read and strictly base64-decode SENTINEL_HMAC_KEY without leaking secrets."""
    raw = os.getenv("SENTINEL_HMAC_KEY")
    if raw is None or raw == "":
        raise RuntimeError("SENTINEL_HMAC_KEY is not set")
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise RuntimeError("SENTINEL_HMAC_KEY is not valid base64") from None
    if not key:
        raise RuntimeError("SENTINEL_HMAC_KEY must decode to a non-empty key")
    return key


def build_settings_from_args(args: argparse.Namespace) -> AppSettings:
    """Resolve AppSettings from parsed CLI arguments and environment variables.

    Args:
        args: Parsed CLI argument namespace.

    Returns:
        Configured ``AppSettings`` with ensured state and parent directories.

    Raises:
        RuntimeError: If ``SENTINEL_HMAC_KEY`` is missing, empty, or invalid base64.
        ValueError: If any supplied path option is empty or ``chunk_size`` is invalid.
        OSError: If required directories cannot be created.
    """
    hmac_key = _decode_hmac_key_from_env()

    raw_state_dir = getattr(args, "state_dir", None)
    if raw_state_dir is not None:
        if not str(raw_state_dir).strip():
            raise ValueError("state_dir path must not be empty")
        state_dir = Path(raw_state_dir)
    else:
        env_state_dir = os.getenv("SENTINEL_STATE_DIR")
        state_dir = Path(env_state_dir) if env_state_dir else (Path.home() / ".sentinel")
    state_dir.mkdir(parents=True, exist_ok=True)

    raw_baseline = getattr(args, "baseline", None)
    if raw_baseline is None:
        raw_baseline = getattr(args, "baseline_path", None)
    baseline_path: Optional[Path] = None
    if raw_baseline is not None:
        if not str(raw_baseline).strip():
            raise ValueError("baseline path must not be empty")
        baseline_path = Path(raw_baseline)
        baseline_path.parent.mkdir(parents=True, exist_ok=True)

    raw_audit_log = getattr(args, "audit_log", None)
    if raw_audit_log is None:
        raw_audit_log = getattr(args, "audit_log_path", None)
    audit_log_path: Optional[Path] = None
    if raw_audit_log is not None:
        if not str(raw_audit_log).strip():
            raise ValueError("audit_log path must not be empty")
        audit_log_path = Path(raw_audit_log)
        audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    raw_ignore = getattr(args, "ignore_file", None)
    ignore_file: Optional[Path] = None
    if raw_ignore is not None:
        if not str(raw_ignore).strip():
            raise ValueError("ignore_file path must not be empty")
        ignore_file = Path(raw_ignore)

    chunk_size = getattr(args, "chunk_size", None)
    if chunk_size is None:
        chunk_size = getattr(args, "hash_chunk_size", DEFAULT_CHUNK_SIZE)
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")

    return AppSettings(
        state_dir=state_dir,
        hmac_key=hmac_key,
        baseline_path=baseline_path,
        audit_log_path=audit_log_path,
        ignore_file=ignore_file,
        hash_chunk_size=chunk_size,
    )


def _operation_result_to_dict(result: OperationResult) -> Dict[str, Any]:
    """Serialize an OperationResult to a JSON-safe dictionary."""
    return {
        "operation": result.operation,
        "success": result.success,
        "root_path": result.root_path,
        "completed_at": result.completed_at,
        "message": result.message,
        "scan_id": result.scan_id,
    }


def _format_operation_summary(result: OperationResult) -> str:
    """Format an OperationResult into a readable console summary."""
    outcome = "SUCCESS" if result.success else "FAILED"
    lines = [
        f"Sentinel {result.operation}: {outcome}",
        f"Root: {result.root_path}",
        f"Completed: {result.completed_at}",
    ]
    if result.scan_id is not None:
        lines.append(f"Scan ID: {result.scan_id}")
    lines.append(f"Message: {result.message}")
    return "\n".join(lines)


def _format_scan_summary(result: ScanResult) -> str:
    """Format a ScanResult into a readable console summary."""
    status = _enum_str(result.status)
    summary = result.summary or {}
    lines = [
        f"Sentinel VERIFY: {status}",
        f"Root: {result.root_path}",
        f"Scan ID: {result.scan_id}",
        f"Started: {result.started_at}",
        f"Completed: {result.completed_at}",
        (
            "Summary: "
            f"added={summary.get('added', 0)}, "
            f"modified={summary.get('modified', 0)}, "
            f"deleted={summary.get('deleted', 0)}, "
            f"moved={summary.get('moved', 0)}, "
            f"errors={summary.get('errors', len(result.errors))}"
        ),
    ]
    if result.changes:
        lines.append("Changes:")
        for change in result.changes:
            c_status = _enum_str(change.status)
            c_severity = _enum_str(change.severity)
            row = f"  [{c_status}] [{c_severity}] {change.path} ({change.reason})"
            if change.old_path and change.old_path != change.path:
                row = f"{row} [from: {change.old_path}]"
            lines.append(row)
    if result.errors:
        lines.append("Errors:")
        for err in result.errors:
            if err.path:
                lines.append(f"  [{err.code}] {err.path}: {err.message}")
            else:
                lines.append(f"  [{err.code}] {err.message}")
    return "\n".join(lines)


def _emit_error(code: str, message: str, *, use_json: bool) -> None:
    """Emit a CLI error either as canonical JSON on stdout or text on stderr."""
    if use_json:
        payload = {
            "success": False,
            "error": {
                "code": code,
                "message": message,
            },
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"Error [{code}]: {message}", file=sys.stderr)


def _verify_exit_code(status: Any) -> int:
    """Map a ScanResult status string or enum to a Sentinel process exit code."""
    normalized = _enum_str(status)
    if normalized == ScanStatus.CLEAN.value:
        return EXIT_CLEAN
    if normalized == ScanStatus.CHANGED.value:
        return EXIT_CHANGED
    if normalized in (ScanStatus.ERROR.value, ScanStatus.BASELINE_INVALID.value):
        return EXIT_ERROR
    return EXIT_ERROR


def _run_command(args: argparse.Namespace, root: Path, settings: AppSettings) -> int:
    """Dispatch the parsed subcommand to the shared application service layer."""
    use_json = bool(getattr(args, "json", False))

    if args.command == "init":
        op_result = application.initialize(root, settings)
        if use_json:
            print(json.dumps(_operation_result_to_dict(op_result), indent=2, ensure_ascii=False))
        else:
            print(_format_operation_summary(op_result))
        return EXIT_CLEAN if op_result.success else EXIT_ERROR

    if args.command == "accept":
        scan_id = getattr(args, "scan_id", None) or str(uuid.uuid4())
        if not getattr(args, "yes", False) and sys.stdin.isatty():
            answer = input(f"Accept the current state of {root} as the new baseline? [y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                print("Sentinel ACCEPT: CANCELLED")
                return EXIT_ERROR
        op_result = application.accept(root, scan_id, settings)
        if use_json:
            print(json.dumps(_operation_result_to_dict(op_result), indent=2, ensure_ascii=False))
        else:
            print(_format_operation_summary(op_result))
        return EXIT_CLEAN if op_result.success else EXIT_ERROR

    if args.command == "verify":
        result = application.verify(root, settings)

        json_out_raw = getattr(args, "json_out", None)
        if json_out_raw is not None:
            if not str(json_out_raw).strip():
                raise ValueError("json-out path must not be empty")
            json_out_path = Path(json_out_raw)
            json_out_path.parent.mkdir(parents=True, exist_ok=True)
            write_json_report(result, json_out_path)

        html_out_raw = getattr(args, "html_out", None)
        if html_out_raw is not None:
            if not str(html_out_raw).strip():
                raise ValueError("html-out path must not be empty")
            html_out_path = Path(html_out_raw)
            html_out_path.parent.mkdir(parents=True, exist_ok=True)
            write_html_report(result, html_out_path)

        if use_json:
            print(json.dumps(scan_result_to_dict(result), indent=2, ensure_ascii=False))
        else:
            print(_format_scan_summary(result))
        return _verify_exit_code(result.status)

    raise ValueError(f"Unsupported command: {args.command}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Execute the Sentinel CLI and return a process exit code.

    Args:
        argv: Optional sequence of CLI arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Exit code ``0`` (clean/success), ``1`` (changes detected), or ``2`` (error).
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    use_json = bool(getattr(args, "json", False))

    raw_root = getattr(args, "root_path", ".")
    if not raw_root or not str(raw_root).strip():
        _emit_error("INVALID_ROOT_PATH", "Root path must not be empty.", use_json=use_json)
        return EXIT_ERROR

    root = Path(raw_root)
    if not root.exists() or not root.is_dir():
        _emit_error(
            "INVALID_ROOT_PATH",
            f"Root path is not an existing directory: {root}",
            use_json=use_json,
        )
        return EXIT_ERROR

    try:
        settings = build_settings_from_args(args)
        return _run_command(args, root, settings)
    except NotImplementedError as exc:
        detail = str(exc).strip()
        message = (
            "Required core or security module is not implemented yet "
            "(security or core stub may not be merged yet)"
        )
        if detail:
            message = f"{message}: {detail}"
        _emit_error("NOT_IMPLEMENTED", message, use_json=use_json)
        return EXIT_ERROR
    except RuntimeError as exc:
        _emit_error(
            "CONFIGURATION_ERROR",
            str(exc) or "Runtime configuration error.",
            use_json=use_json,
        )
        return EXIT_ERROR
    except ValueError as exc:
        _emit_error(
            "INVALID_ARGUMENT",
            str(exc) or "Invalid argument value.",
            use_json=use_json,
        )
        return EXIT_ERROR
    except OSError as exc:
        _emit_error(
            "FILESYSTEM_ERROR",
            str(exc) or "Filesystem operation failed.",
            use_json=use_json,
        )
        return EXIT_ERROR
    except Exception as exc:
        _emit_error(
            "RUNTIME_ERROR",
            str(exc) or f"Command failed with {type(exc).__name__}.",
            use_json=use_json,
        )
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
