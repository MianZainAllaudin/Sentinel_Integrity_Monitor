"""Comprehensive CLI and sample-artifact compliance tests for Sentinel (Person 1).

Uses only Python's standard library ``unittest`` so tests run cleanly under
both ``python3 -m unittest`` and ``pytest``.
"""

from __future__ import annotations

import base64
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from sentinel import __version__, application, cli
from sentinel.core.baseline import baseline_from_dict
from sentinel.core.models import (
    BaselineData,
    ScanError,
    baseline_to_dict,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_BASELINE_PATH = REPO_ROOT / "docs" / "samples" / "sample-baseline.json"
SAMPLE_SCAN_RESULT_PATH = REPO_ROOT / "docs" / "samples" / "sample-scan-result.json"
SAMPLE_HMAC_KEY = b"example-sample-key-for-docs-only"


class SecurityError(Exception):
    """Test security exception matching Person 2 verification failures."""


def _canonical_json_bytes(data: object) -> bytes:
    """Serialize *data* with the canonical UTF-8 JSON format from Global Rules 7.3."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sign_baseline_canonical(
    payload: BaselineData,
    key: bytes,
    key_id: str = "local-v1",
) -> dict[str, object]:
    """In-test canonical HMAC-SHA256 baseline signer conforming to Rules 7.2-7.3."""
    payload_dict = baseline_to_dict(payload)
    digest = hmac.new(key, _canonical_json_bytes(payload_dict), hashlib.sha256).hexdigest()
    return {
        "payload": payload_dict,
        "signature": {
            "algorithm": "hmac-sha256",
            "key_id": key_id,
            "value": digest,
        },
    }


def _verify_baseline_canonical(
    envelope: dict[str, object],
    key: bytes,
) -> BaselineData:
    """In-test canonical HMAC-SHA256 baseline verifier conforming to Rules 7.2-7.3."""
    if not isinstance(envelope, dict):
        raise SecurityError("Baseline envelope must be a JSON object.")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise SecurityError("Baseline envelope missing payload or signature.")
    if signature.get("algorithm") != "hmac-sha256":
        raise SecurityError("Unsupported baseline signature algorithm.")
    supplied_sig = signature.get("value")
    if not isinstance(supplied_sig, str) or not supplied_sig:
        raise SecurityError("Missing baseline signature value.")
    expected_sig = hmac.new(key, _canonical_json_bytes(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, supplied_sig):
        raise SecurityError("Baseline HMAC signature verification failed.")
    return baseline_from_dict(payload)


def _append_audit_event_canonical(
    log_path: Path,
    event_type: str,
    scan_id: str | None,
    payload: dict[str, object],
) -> dict[str, object]:
    """In-test hash-chained JSONL audit appender conforming to Global Rules 7.6."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    previous_hash = "0" * 64
    sequence = 1
    if log_path.exists():
        lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last = json.loads(lines[-1])
            sequence = int(last["sequence"]) + 1
            previous_hash = str(last["entry_hash"])

    entry: dict[str, object] = {
        "sequence": sequence,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": event_type,
        "scan_id": scan_id,
        "previous_hash": previous_hash,
        "payload": payload,
    }
    entry_hash = hashlib.sha256(_canonical_json_bytes(entry)).hexdigest()
    entry["entry_hash"] = entry_hash
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Execute ``cli.main(argv)`` while capturing stdout and stderr."""
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        code = cli.main(argv)
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


def _valid_b64_key(raw: bytes = b"0123456789abcdef0123456789abcdef") -> str:
    """Return base64-encoded key material for test environment setup."""
    return base64.b64encode(raw).decode("ascii")


class TestCliArgumentParsing(unittest.TestCase):
    """Tests for ``cli.build_parser`` and CLI option validation."""

    def test_default_root_path_and_shared_defaults_for_all_subcommands(self) -> None:
        parser = cli.build_parser()
        for subcommand in ("init", "verify", "accept"):
            with self.subTest(subcommand=subcommand):
                args = parser.parse_args([subcommand])
                self.assertEqual(args.command, subcommand)
                self.assertEqual(args.root_path, ".")
                self.assertIsNone(args.state_dir)
                self.assertIsNone(args.baseline)
                self.assertIsNone(args.audit_log)
                self.assertIsNone(args.ignore_file)
                self.assertEqual(args.chunk_size, cli.DEFAULT_CHUNK_SIZE)
                self.assertFalse(args.json)

    def test_shared_options_parsed_on_each_subcommand(self) -> None:
        parser = cli.build_parser()
        for subcommand in ("init", "verify", "accept"):
            with self.subTest(subcommand=subcommand, ignore_flag="--ignore-file"):
                args = parser.parse_args(
                    [
                        subcommand,
                        "/tmp/project",
                        "--state-dir",
                        "/tmp/state",
                        "--baseline",
                        "/tmp/custom/base.json",
                        "--audit-log",
                        "/tmp/custom/audit.jsonl",
                        "--ignore-file",
                        "/tmp/custom/.sentinelignore",
                        "--chunk-size",
                        "4096",
                        "--json",
                    ]
                )
                self.assertEqual(args.root_path, "/tmp/project")
                self.assertEqual(args.state_dir, "/tmp/state")
                self.assertEqual(args.baseline, "/tmp/custom/base.json")
                self.assertEqual(args.audit_log, "/tmp/custom/audit.jsonl")
                self.assertEqual(args.ignore_file, "/tmp/custom/.sentinelignore")
                self.assertEqual(args.chunk_size, 4096)
                self.assertTrue(args.json)

            with self.subTest(subcommand=subcommand, ignore_flag="--ignore"):
                args_alias = parser.parse_args(
                    [subcommand, "--ignore", "/tmp/alt.ignore"]
                )
                self.assertEqual(args_alias.ignore_file, "/tmp/alt.ignore")

    def test_verify_specific_options(self) -> None:
        parser = cli.build_parser()
        defaults = parser.parse_args(["verify"])
        self.assertIsNone(defaults.json_out)
        self.assertIsNone(defaults.html_out)

        args = parser.parse_args(
            [
                "verify",
                "./target",
                "--json-out",
                "./out/result.json",
                "--html-out",
                "./out/report.html",
            ]
        )
        self.assertEqual(args.root_path, "./target")
        self.assertEqual(args.json_out, "./out/result.json")
        self.assertEqual(args.html_out, "./out/report.html")

    def test_accept_specific_options(self) -> None:
        parser = cli.build_parser()
        defaults = parser.parse_args(["accept"])
        self.assertIsNone(defaults.scan_id)
        self.assertFalse(defaults.yes)

        short_args = parser.parse_args(["accept", "./app", "--scan-id", "scan-123", "-y"])
        self.assertEqual(short_args.root_path, "./app")
        self.assertEqual(short_args.scan_id, "scan-123")
        self.assertTrue(short_args.yes)

        long_args = parser.parse_args(["accept", "--yes"])
        self.assertTrue(long_args.yes)

    def test_version_flag_exits_zero_and_prints_version(self) -> None:
        parser = cli.build_parser()
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), f"sentinel {__version__}")

    def test_invalid_chunk_size_rejected_by_parser(self) -> None:
        parser = cli.build_parser()
        for bad_value in ("0", "-1", "abc"):
            with self.subTest(chunk_size=bad_value):
                err = io.StringIO()
                with redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
                    parser.parse_args(["verify", "--chunk-size", bad_value])
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("--chunk-size", err.getvalue())

    def test_missing_subcommand_exits_two(self) -> None:
        parser = cli.build_parser()
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
            parser.parse_args([])
        self.assertEqual(ctx.exception.code, 2)


class TestBuildSettingsFromArgs(unittest.TestCase):
    """Tests for ``cli.build_settings_from_args`` and env/path resolution."""

    def test_missing_hmac_key_raises_runtime_error_and_cli_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            state_dir = Path(tmp) / "state"
            parser = cli.build_parser()
            args = parser.parse_args(["init", str(root), "--state-dir", str(state_dir)])

            env = {k: v for k, v in os.environ.items() if k != "SENTINEL_HMAC_KEY"}
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(RuntimeError) as ctx:
                    cli.build_settings_from_args(args)
                self.assertIn("SENTINEL_HMAC_KEY", str(ctx.exception))

                code, out, err = _run_cli(["init", str(root), "--state-dir", str(state_dir)])
                self.assertEqual(code, cli.EXIT_ERROR)
                self.assertEqual(out, "")
                self.assertIn("CONFIGURATION_ERROR", err)
                self.assertIn("SENTINEL_HMAC_KEY", err)

    def test_invalid_base64_hmac_key_fails_without_leaking_key_material(self) -> None:
        bad_secret = "super-secret-invalid-base64!"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            state_dir = Path(tmp) / "state"
            parser = cli.build_parser()
            args = parser.parse_args(["verify", str(root), "--state-dir", str(state_dir)])

            with mock.patch.dict(os.environ, {"SENTINEL_HMAC_KEY": bad_secret}, clear=False):
                with self.assertRaises(RuntimeError) as ctx:
                    cli.build_settings_from_args(args)
                self.assertNotIn(bad_secret, str(ctx.exception))

                code_txt, out_txt, err_txt = _run_cli(
                    ["verify", str(root), "--state-dir", str(state_dir)]
                )
                self.assertEqual(code_txt, cli.EXIT_ERROR)
                self.assertEqual(out_txt, "")
                self.assertIn("CONFIGURATION_ERROR", err_txt)
                self.assertNotIn(bad_secret, err_txt)
                self.assertNotIn(bad_secret, out_txt)

                code_json, out_json, err_json = _run_cli(
                    ["verify", str(root), "--state-dir", str(state_dir), "--json"]
                )
                self.assertEqual(code_json, cli.EXIT_ERROR)
                self.assertEqual(err_json, "")
                payload = json.loads(out_json)
                self.assertFalse(payload["success"])
                self.assertEqual(payload["error"]["code"], "CONFIGURATION_ERROR")
                self.assertNotIn(bad_secret, out_json)
                self.assertNotIn(bad_secret, err_json)

    def test_state_dir_creates_target_dir_and_does_not_touch_home_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp) / "fake_home"
            fake_home.mkdir()
            custom_state = Path(tmp) / "nested" / "custom_state"
            self.assertFalse(custom_state.exists())

            parser = cli.build_parser()
            args = parser.parse_args(["init", "--state-dir", str(custom_state)])

            with (
                mock.patch.dict(
                    os.environ,
                    {"SENTINEL_HMAC_KEY": _valid_b64_key()},
                    clear=False,
                ),
                mock.patch("pathlib.Path.home", return_value=fake_home) as mock_home,
            ):
                settings = cli.build_settings_from_args(args)

            mock_home.assert_not_called()
            self.assertEqual(settings.state_dir, custom_state)
            self.assertTrue(custom_state.is_dir())
            self.assertFalse((fake_home / ".sentinel").exists())

    def test_baseline_and_audit_log_parent_dirs_created_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base_tmp = Path(tmp)
            state_dir = base_tmp / "state"
            baseline_file = base_tmp / "deep" / "baselines" / "prod.json"
            audit_file = base_tmp / "deep" / "logs" / "audit.jsonl"

            self.assertFalse(baseline_file.parent.exists())
            self.assertFalse(audit_file.parent.exists())

            parser = cli.build_parser()
            args = parser.parse_args(
                [
                    "verify",
                    "--state-dir",
                    str(state_dir),
                    "--baseline",
                    str(baseline_file),
                    "--audit-log",
                    str(audit_file),
                ]
            )

            with mock.patch.dict(
                os.environ,
                {"SENTINEL_HMAC_KEY": _valid_b64_key()},
                clear=False,
            ):
                settings = cli.build_settings_from_args(args)

            self.assertEqual(settings.baseline_path, baseline_file)
            self.assertEqual(settings.audit_log_path, audit_file)
            self.assertTrue(baseline_file.parent.is_dir())
            self.assertTrue(audit_file.parent.is_dir())
            self.assertFalse(baseline_file.exists())
            self.assertFalse(audit_file.exists())

    def test_env_state_dir_and_home_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp) / "home"
            fake_home.mkdir()
            env_state = Path(tmp) / "env_state"
            parser = cli.build_parser()
            args = parser.parse_args(["verify"])

            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "SENTINEL_HMAC_KEY": _valid_b64_key(),
                        "SENTINEL_STATE_DIR": str(env_state),
                    },
                    clear=False,
                ),
                mock.patch("pathlib.Path.home", return_value=fake_home),
            ):
                settings_env = cli.build_settings_from_args(args)
            self.assertEqual(settings_env.state_dir, env_state)
            self.assertTrue(env_state.is_dir())
            self.assertFalse((fake_home / ".sentinel").exists())

            env_no_state = {
                k: v for k, v in os.environ.items() if k != "SENTINEL_STATE_DIR"
            }
            env_no_state["SENTINEL_HMAC_KEY"] = _valid_b64_key()
            with (
                mock.patch.dict(os.environ, env_no_state, clear=True),
                mock.patch("pathlib.Path.home", return_value=fake_home),
            ):
                settings_home = cli.build_settings_from_args(args)
            self.assertEqual(settings_home.state_dir, fake_home / ".sentinel")
            self.assertTrue((fake_home / ".sentinel").is_dir())

    def test_invalid_namespace_values_raise_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"SENTINEL_HMAC_KEY": _valid_b64_key()},
                clear=False,
            ):
                ns_bad_chunk = cli.argparse.Namespace(
                    state_dir=tmp,
                    baseline=None,
                    audit_log=None,
                    ignore_file=None,
                    chunk_size=0,
                )
                with self.assertRaises(ValueError):
                    cli.build_settings_from_args(ns_bad_chunk)

                ns_bool_chunk = cli.argparse.Namespace(
                    state_dir=tmp,
                    baseline=None,
                    audit_log=None,
                    ignore_file=None,
                    chunk_size=True,
                )
                with self.assertRaises(ValueError):
                    cli.build_settings_from_args(ns_bool_chunk)

                ns_empty_baseline = cli.argparse.Namespace(
                    state_dir=tmp,
                    baseline="   ",
                    audit_log=None,
                    ignore_file=None,
                    chunk_size=1024,
                )
                with self.assertRaises(ValueError):
                    cli.build_settings_from_args(ns_empty_baseline)


class TestCliErrorHandling(unittest.TestCase):
    """Tests for root-path checks, unmerged stubs, and CLI error envelopes."""

    def test_missing_and_non_directory_root_path_return_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_dir = Path(tmp) / "does_not_exist"
            regular_file = Path(tmp) / "file.txt"
            regular_file.write_text("hello", encoding="utf-8")

            with mock.patch.dict(
                os.environ,
                {"SENTINEL_HMAC_KEY": _valid_b64_key()},
                clear=False,
            ):
                for bad_root in (str(missing_dir), str(regular_file), "   "):
                    with self.subTest(bad_root=bad_root, mode="text"):
                        code, out, err = _run_cli(["verify", bad_root])
                        self.assertEqual(code, cli.EXIT_ERROR)
                        self.assertEqual(out, "")
                        self.assertIn("INVALID_ROOT_PATH", err)

                    with self.subTest(bad_root=bad_root, mode="json"):
                        code, out, err = _run_cli(["verify", bad_root, "--json"])
                        self.assertEqual(code, cli.EXIT_ERROR)
                        self.assertEqual(err, "")
                        payload = json.loads(out)
                        self.assertFalse(payload["success"])
                        self.assertEqual(payload["error"]["code"], "INVALID_ROOT_PATH")

    

    def test_generic_security_and_runtime_exceptions_return_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            state_dir = Path(tmp) / "state"

            with mock.patch.dict(
                os.environ,
                {"SENTINEL_HMAC_KEY": _valid_b64_key()},
                clear=False,
            ):
                with mock.patch.object(
                    application,
                    "verify",
                    side_effect=SecurityError("Signature check exploded"),
                ):
                    code_txt, out_txt, err_txt = _run_cli(
                        ["verify", str(root), "--state-dir", str(state_dir)]
                    )
                    self.assertEqual(code_txt, cli.EXIT_ERROR)
                    self.assertEqual(out_txt, "")
                    self.assertIn("RUNTIME_ERROR", err_txt)
                    self.assertIn("Signature check exploded", err_txt)

                    code_json, out_json, err_json = _run_cli(
                        ["verify", str(root), "--state-dir", str(state_dir), "--json"]
                    )
                    self.assertEqual(code_json, cli.EXIT_ERROR)
                    self.assertEqual(err_json, "")
                    payload = json.loads(out_json)
                    self.assertFalse(payload["success"])
                    self.assertEqual(payload["error"]["code"], "RUNTIME_ERROR")
                    self.assertIn("Signature check exploded", payload["error"]["message"])

                with mock.patch.object(
                    application,
                    "verify",
                    side_effect=OSError("Disk I/O failure"),
                ):
                    os_code, _, os_err = _run_cli(
                        ["verify", str(root), "--state-dir", str(state_dir)]
                    )
                    self.assertEqual(os_code, cli.EXIT_ERROR)
                    self.assertIn("FILESYSTEM_ERROR", os_err)

                bad_out_code, _, bad_out_err = _run_cli(
                    ["verify", str(root), "--state-dir", str(state_dir), "--json-out", "  "]
                )
                self.assertEqual(bad_out_code, cli.EXIT_ERROR)
                self.assertIn("INVALID_ARGUMENT", bad_out_err)


class TestCliEndToEndWorkflow(unittest.TestCase):
    """End-to-end CLI workflow tests exercising real core, application, and reporting."""

    def setUp(self) -> None:
        self._env_patcher = mock.patch.dict(
            os.environ,
            {"SENTINEL_HMAC_KEY": _valid_b64_key()},
            clear=False,
        )
        self._sign_patcher = mock.patch.object(
            application, "sign_baseline", side_effect=_sign_baseline_canonical
        )
        self._verify_patcher = mock.patch.object(
            application, "verify_baseline", side_effect=_verify_baseline_canonical
        )
        self._audit_patcher = mock.patch.object(
            application, "append_audit_event", side_effect=_append_audit_event_canonical
        )
        self._env_patcher.start()
        self._sign_patcher.start()
        self._verify_patcher.start()
        self._audit_patcher.start()

    def tearDown(self) -> None:
        self._audit_patcher.stop()
        self._verify_patcher.stop()
        self._sign_patcher.stop()
        self._env_patcher.stop()

    def test_full_lifecycle_init_verify_change_report_accept_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "monitored"
            state_dir = base / "state"
            reports_dir = base / "reports"
            json_out = reports_dir / "nested" / "scan.json"
            html_out = reports_dir / "nested" / "scan.html"

            (root / "src").mkdir(parents=True)
            (root / "config").mkdir(parents=True)
            (root / "build").mkdir(parents=True)

            (root / ".sentinelignore").write_text("*.log\nbuild/\n", encoding="utf-8")
            (root / "README.md").write_text("# Demo Project\n", encoding="utf-8")
            (root / "src" / "main.py").write_text("print('v1')\n", encoding="utf-8")
            (root / "src" / "legacy.py").write_text("def old():\n    return 1\n", encoding="utf-8")
            (root / "config" / "settings.json").write_text(
                '{"mode": "prod", "retries": 3}\n', encoding="utf-8"
            )
            (root / "debug.log").write_text("ignored log\n", encoding="utf-8")
            (root / "build" / "artifact.bin").write_bytes(b"\x00\x01\x02")

            # 1. init -> exit 0
            init_code, init_out, init_err = _run_cli(
                ["init", str(root), "--state-dir", str(state_dir), "--chunk-size", "64", "--json"]
            )
            self.assertEqual(init_code, cli.EXIT_CLEAN)
            self.assertEqual(init_err, "")
            init_payload = json.loads(init_out)
            self.assertEqual(init_payload["operation"], "INIT")
            self.assertTrue(init_payload["success"])

            baseline_path = state_dir / "baseline.json"
            audit_path = state_dir / "audit.jsonl"
            self.assertTrue(baseline_path.is_file())
            self.assertTrue(audit_path.is_file())

            baseline_doc = json.loads(baseline_path.read_text(encoding="utf-8"))
            tracked_files = set(baseline_doc["payload"]["files"].keys())
            self.assertEqual(
                tracked_files,
                {
                    ".sentinelignore",
                    "README.md",
                    "config/settings.json",
                    "src/legacy.py",
                    "src/main.py",
                },
            )

            # 2. verify CLEAN -> exit 0 (ignored changes must not trigger CHANGED)
            (root / "debug.log").write_text("changed ignored log\n", encoding="utf-8")
            (root / "build" / "extra.bin").write_bytes(b"\xff\xfe")
            clean_code, clean_out, clean_err = _run_cli(
                ["verify", str(root), "--state-dir", str(state_dir)]
            )
            self.assertEqual(clean_code, cli.EXIT_CLEAN)
            self.assertEqual(clean_err, "")
            self.assertIn("Sentinel VERIFY: CLEAN", clean_out)
            self.assertIn("added=0, modified=0, deleted=0, moved=0, errors=0", clean_out)

            # 3. Mutate files: ADDED, MODIFIED, DELETED, MOVED
            (root / "src" / "added.py").write_text("def new_fn():\n    return 2\n", encoding="utf-8")
            (root / "src" / "main.py").write_text("print('v2 - updated')\n", encoding="utf-8")
            (root / "src" / "legacy.py").unlink()
            (root / "config" / "settings.json").rename(root / "config" / "app_settings.json")

            # 4. verify CHANGED with --json-out, --html-out, and --json -> exit 1
            chg_code, chg_out, chg_err = _run_cli(
                [
                    "verify",
                    str(root),
                    "--state-dir",
                    str(state_dir),
                    "--json-out",
                    str(json_out),
                    "--html-out",
                    str(html_out),
                    "--json",
                ]
            )
            self.assertEqual(chg_code, cli.EXIT_CHANGED)
            self.assertEqual(chg_err, "")

            chg_data = json.loads(chg_out)
            self.assertEqual(chg_data["status"], "CHANGED")
            self.assertEqual(
                chg_data["summary"],
                {"added": 1, "modified": 1, "deleted": 1, "moved": 1, "errors": 0},
            )
            by_status = {item["status"]: item for item in chg_data["changes"]}
            self.assertEqual(set(by_status.keys()), {"ADDED", "MODIFIED", "DELETED", "MOVED"})
            self.assertEqual(by_status["ADDED"]["path"], "src/added.py")
            self.assertEqual(by_status["MODIFIED"]["path"], "src/main.py")
            self.assertEqual(by_status["DELETED"]["path"], "src/legacy.py")
            self.assertEqual(by_status["MOVED"]["path"], "config/app_settings.json")
            self.assertEqual(by_status["MOVED"]["old_path"], "config/settings.json")
            self.assertEqual(by_status["MOVED"]["new_path"], "config/app_settings.json")

            # Validate generated JSON and HTML report files
            self.assertTrue(json_out.is_file())
            self.assertTrue(html_out.is_file())

            report_json = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(report_json["scan_id"], chg_data["scan_id"])
            self.assertEqual(report_json["status"], "CHANGED")
            self.assertEqual(report_json["summary"], chg_data["summary"])
            self.assertEqual(
                {c["path"] for c in report_json["changes"]},
                {"src/added.py", "src/main.py", "src/legacy.py", "config/app_settings.json"},
            )

            report_html = html_out.read_text(encoding="utf-8")
            self.assertIn(chg_data["scan_id"], report_html)
            self.assertIn("CHANGED", report_html)
            for expected_path in (
                "src/added.py",
                "src/main.py",
                "src/legacy.py",
                "config/app_settings.json",
            ):
                self.assertIn(expected_path, report_html)

            # 5. accept with --scan-id and -y -> exit 0
            acc_code, acc_out, acc_err = _run_cli(
                [
                    "accept",
                    str(root),
                    "--state-dir",
                    str(state_dir),
                    "--scan-id",
                    chg_data["scan_id"],
                    "-y",
                    "--json",
                ]
            )
            self.assertEqual(acc_code, cli.EXIT_CLEAN)
            self.assertEqual(acc_err, "")
            acc_data = json.loads(acc_out)
            self.assertEqual(acc_data["operation"], "ACCEPT")
            self.assertTrue(acc_data["success"])
            self.assertEqual(acc_data["scan_id"], chg_data["scan_id"])

            # 6. verify CLEAN after accept -> exit 0
            post_code, post_out, post_err = _run_cli(
                ["verify", str(root), "--state-dir", str(state_dir), "--json"]
            )
            self.assertEqual(post_code, cli.EXIT_CLEAN)
            self.assertEqual(post_err, "")
            post_data = json.loads(post_out)
            self.assertEqual(post_data["status"], "CLEAN")
            self.assertEqual(post_data["changes"], [])
            self.assertEqual(post_data["errors"], [])

            # Audit log contains hash-chained INIT, 3 VERIFY_COMPLETED, and ACCEPT
            audit_entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(
                [e["event_type"] for e in audit_entries],
                ["INIT", "VERIFY_COMPLETED", "VERIFY_COMPLETED", "ACCEPT", "VERIFY_COMPLETED"],
            )
            self.assertEqual(audit_entries[3]["scan_id"], chg_data["scan_id"])
            self.assertEqual(audit_entries[0]["previous_hash"], "0" * 64)
            for idx in range(1, len(audit_entries)):
                self.assertEqual(
                    audit_entries[idx]["previous_hash"],
                    audit_entries[idx - 1]["entry_hash"],
                )

    def test_custom_baseline_audit_and_ignore_paths_and_text_changed_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "proj"
            root.mkdir()
            (root / "keep.txt").write_text("keep", encoding="utf-8")
            (root / "skip.tmp").write_text("skip", encoding="utf-8")

            custom_ignore = base / "custom.ignore"
            custom_ignore.write_text("*.tmp\n", encoding="utf-8")
            custom_state = base / "state"
            custom_baseline = base / "custom" / "sub" / "baseline.json"
            custom_audit = base / "custom" / "logs" / "audit.jsonl"

            init_code, init_out, _ = _run_cli(
                [
                    "init",
                    str(root),
                    "--state-dir",
                    str(custom_state),
                    "--baseline",
                    str(custom_baseline),
                    "--audit-log",
                    str(custom_audit),
                    "--ignore",
                    str(custom_ignore),
                ]
            )
            self.assertEqual(init_code, cli.EXIT_CLEAN)
            self.assertIn("Sentinel INIT: SUCCESS", init_out)
            self.assertTrue(custom_baseline.is_file())
            self.assertTrue(custom_audit.is_file())
            self.assertFalse((custom_state / "baseline.json").exists())

            (root / "skip.tmp").write_text("changed skip", encoding="utf-8")
            (root / "keep.txt").write_text("changed keep", encoding="utf-8")
            v_code, v_out, _ = _run_cli(
                [
                    "verify",
                    str(root),
                    "--state-dir",
                    str(custom_state),
                    "--baseline",
                    str(custom_baseline),
                    "--audit-log",
                    str(custom_audit),
                    "--ignore-file",
                    str(custom_ignore),
                ]
            )
            self.assertEqual(v_code, cli.EXIT_CHANGED)
            self.assertIn("Sentinel VERIFY: CHANGED", v_out)
            self.assertIn("[MODIFIED]", v_out)
            self.assertIn("keep.txt", v_out)
            self.assertNotIn("skip.tmp", v_out)

    def test_tampered_baseline_returns_exit_two_and_blocks_accept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "monitored"
            root.mkdir()
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            state_dir = base / "state"

            init_code, _, _ = _run_cli(
                ["init", str(root), "--state-dir", str(state_dir)]
            )
            self.assertEqual(init_code, cli.EXIT_CLEAN)

            baseline_path = state_dir / "baseline.json"
            envelope = json.loads(baseline_path.read_text(encoding="utf-8"))
            # Tamper with payload without re-signing.
            envelope["payload"]["files"]["app.py"]["sha256"] = "0" * 64
            tampered_text = json.dumps(envelope)
            baseline_path.write_text(tampered_text, encoding="utf-8")
            tampered_bytes = baseline_path.read_bytes()

            v_code, v_out, v_err = _run_cli(
                ["verify", str(root), "--state-dir", str(state_dir), "--json"]
            )
            self.assertEqual(v_code, cli.EXIT_ERROR)
            self.assertEqual(v_err, "")
            v_data = json.loads(v_out)
            self.assertEqual(v_data["status"], "BASELINE_INVALID")

            a_code, a_out, a_err = _run_cli(
                ["accept", str(root), "--state-dir", str(state_dir), "-y", "--json"]
            )
            self.assertEqual(a_code, cli.EXIT_ERROR)
            self.assertEqual(a_err, "")
            a_data = json.loads(a_out)
            self.assertEqual(a_data["operation"], "ACCEPT")
            self.assertFalse(a_data["success"])
            self.assertEqual(baseline_path.read_bytes(), tampered_bytes)

    def test_wrong_key_and_missing_baseline_return_baseline_invalid_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "monitored"
            root.mkdir()
            (root / "doc.txt").write_text("hello", encoding="utf-8")
            state_dir = base / "state"

            # Missing baseline -> verify exit 2, accept exit 2
            v_missing, v_out, _ = _run_cli(
                ["verify", str(root), "--state-dir", str(state_dir), "--json"]
            )
            self.assertEqual(v_missing, cli.EXIT_ERROR)
            self.assertEqual(json.loads(v_out)["status"], "BASELINE_INVALID")

            a_missing, a_out, _ = _run_cli(
                ["accept", str(root), "--state-dir", str(state_dir), "--yes", "--json"]
            )
            self.assertEqual(a_missing, cli.EXIT_ERROR)
            self.assertFalse(json.loads(a_out)["success"])

            # Create baseline with key 1, then verify/accept with key 2
            self.assertEqual(
                _run_cli(["init", str(root), "--state-dir", str(state_dir)])[0],
                cli.EXIT_CLEAN,
            )
            baseline_path = state_dir / "baseline.json"
            original_bytes = baseline_path.read_bytes()

            wrong_key = _valid_b64_key(b"wrong-key-32-bytes-long-abcdefgh")
            with mock.patch.dict(os.environ, {"SENTINEL_HMAC_KEY": wrong_key}, clear=False):
                wk_v_code, wk_v_out, _ = _run_cli(
                    ["verify", str(root), "--state-dir", str(state_dir), "--json"]
                )
                self.assertEqual(wk_v_code, cli.EXIT_ERROR)
                self.assertEqual(json.loads(wk_v_out)["status"], "BASELINE_INVALID")

                wk_a_code, wk_a_out, _ = _run_cli(
                    ["accept", str(root), "--state-dir", str(state_dir), "-y", "--json"]
                )
                self.assertEqual(wk_a_code, cli.EXIT_ERROR)
                self.assertFalse(json.loads(wk_a_out)["success"])
                self.assertEqual(baseline_path.read_bytes(), original_bytes)

    def test_verify_with_scan_errors_returns_exit_two_and_blocks_accept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "monitored"
            root.mkdir()
            (root / "ok.txt").write_text("ok", encoding="utf-8")
            state_dir = base / "state"

            init_code, _, _ = _run_cli(
                ["init", str(root), "--state-dir", str(state_dir)]
            )
            self.assertEqual(init_code, cli.EXIT_CLEAN)
            baseline_path = state_dir / "baseline.json"
            original_bytes = baseline_path.read_bytes()

            scan_err = ScanError(
                code="FILE_ACCESS_DENIED",
                path="secret.txt",
                message="Permission denied reading file.",
            )
            with mock.patch.object(
                application,
                "scan_directory",
                return_value=([], [scan_err]),
            ):
                v_code, v_out, v_err = _run_cli(
                    ["verify", str(root), "--state-dir", str(state_dir), "--json"]
                )
                self.assertEqual(v_code, cli.EXIT_ERROR)
                self.assertEqual(v_err, "")
                v_data = json.loads(v_out)
                self.assertEqual(v_data["status"], "ERROR")
                self.assertEqual(v_data["summary"]["errors"], 1)
                self.assertEqual(v_data["errors"][0]["code"], "FILE_ACCESS_DENIED")
                self.assertEqual(v_data["errors"][0]["path"], "secret.txt")

                a_code, a_out, a_err = _run_cli(
                    ["accept", str(root), "--state-dir", str(state_dir), "-y", "--json"]
                )
                self.assertEqual(a_code, cli.EXIT_ERROR)
                self.assertEqual(a_err, "")
                a_data = json.loads(a_out)
                self.assertEqual(a_data["operation"], "ACCEPT")
                self.assertFalse(a_data["success"])
                self.assertEqual(baseline_path.read_bytes(), original_bytes)


class TestCliSubprocessAndSamples(unittest.TestCase):
    """Subprocess CLI smoke test and canonical sample-artifact compliance checks."""

    def test_subprocess_help_exits_zero(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT / "src")
        proc = subprocess.run(
            [sys.executable, "-m", "sentinel", "--help"],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("Sentinel", proc.stdout)
        self.assertIn("init", proc.stdout)
        self.assertIn("verify", proc.stdout)
        self.assertIn("accept", proc.stdout)

    def test_sample_baseline_validates_schema_and_hmac_signature(self) -> None:
        doc = json.loads(SAMPLE_BASELINE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(set(doc.keys()), {"payload", "signature"})

        baseline = baseline_from_dict(doc["payload"])
        self.assertEqual(baseline.schema_version, 1)
        self.assertEqual(baseline.hash_algorithm, "sha256")
        self.assertEqual(
            set(baseline.files.keys()),
            {
                "README.md",
                "config/settings.json",
                "src/legacy_helper.py",
                "src/main.py",
            },
        )

        signature = doc["signature"]
        self.assertEqual(signature["algorithm"], "hmac-sha256")
        self.assertEqual(signature["key_id"], "local-v1")

        expected_sig = hmac.new(
            SAMPLE_HMAC_KEY,
            _canonical_json_bytes(doc["payload"]),
            hashlib.sha256,
        ).hexdigest()
        self.assertTrue(hmac.compare_digest(expected_sig, signature["value"]))

        verified = _verify_baseline_canonical(doc, SAMPLE_HMAC_KEY)
        self.assertEqual(verified, baseline)
        with self.assertRaises(SecurityError):
            _verify_baseline_canonical(doc, b"incorrect-sample-key-for-test")

    def test_sample_scan_result_matches_canonical_contract(self) -> None:
        doc = json.loads(SAMPLE_SCAN_RESULT_PATH.read_text(encoding="utf-8"))
        sample_baseline = json.loads(SAMPLE_BASELINE_PATH.read_text(encoding="utf-8"))

        required_top_keys = {
            "schema_version",
            "scan_id",
            "root_path",
            "started_at",
            "completed_at",
            "status",
            "summary",
            "changes",
            "errors",
        }
        self.assertEqual(set(doc.keys()), required_top_keys)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["root_path"], sample_baseline["payload"]["root_path"])
        self.assertIn(doc["status"], {"CLEAN", "CHANGED", "ERROR", "BASELINE_INVALID"})

        summary = doc["summary"]
        self.assertEqual(
            set(summary.keys()),
            {"added", "modified", "deleted", "moved", "errors"},
        )

        allowed_change_statuses = {"ADDED", "MODIFIED", "DELETED", "MOVED"}
        allowed_severities = {"LOW", "MEDIUM", "HIGH"}
        required_change_keys = {
            "status",
            "path",
            "old_path",
            "new_path",
            "old_sha256",
            "new_sha256",
            "old_size_bytes",
            "new_size_bytes",
            "severity",
            "reason",
        }

        counts = {"added": 0, "modified": 0, "deleted": 0, "moved": 0}
        for change in doc["changes"]:
            self.assertEqual(set(change.keys()), required_change_keys)
            c_status = change["status"]
            self.assertIn(c_status, allowed_change_statuses)
            self.assertIn(change["severity"], allowed_severities)
            self.assertIsInstance(change["reason"], str)
            self.assertTrue(change["reason"].strip())
            counts[c_status.lower()] += 1

            if c_status == "ADDED":
                self.assertIsNone(change["old_path"])
                self.assertEqual(change["new_path"], change["path"])
                self.assertIsNone(change["old_sha256"])
                self.assertIsInstance(change["new_sha256"], str)
                self.assertIsNone(change["old_size_bytes"])
                self.assertIsInstance(change["new_size_bytes"], int)
            elif c_status == "MODIFIED":
                self.assertIsNone(change["old_path"])
                self.assertEqual(change["new_path"], change["path"])
                self.assertIsInstance(change["old_sha256"], str)
                self.assertIsInstance(change["new_sha256"], str)
                self.assertIsInstance(change["old_size_bytes"], int)
                self.assertIsInstance(change["new_size_bytes"], int)
            elif c_status == "DELETED":
                self.assertEqual(change["old_path"], change["path"])
                self.assertIsNone(change["new_path"])
                self.assertIsInstance(change["old_sha256"], str)
                self.assertIsNone(change["new_sha256"])
                self.assertIsInstance(change["old_size_bytes"], int)
                self.assertIsNone(change["new_size_bytes"])
            elif c_status == "MOVED":
                self.assertIsInstance(change["old_path"], str)
                self.assertEqual(change["new_path"], change["path"])
                self.assertNotEqual(change["old_path"], change["new_path"])
                self.assertEqual(change["old_sha256"], change["new_sha256"])
                self.assertEqual(change["old_size_bytes"], change["new_size_bytes"])

        self.assertEqual(summary["added"], counts["added"])
        self.assertEqual(summary["modified"], counts["modified"])
        self.assertEqual(summary["deleted"], counts["deleted"])
        self.assertEqual(summary["moved"], counts["moved"])
        self.assertEqual(summary["errors"], len(doc["errors"]))


if __name__ == "__main__":
    unittest.main()
