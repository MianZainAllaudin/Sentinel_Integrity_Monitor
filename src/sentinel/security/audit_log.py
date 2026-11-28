"""Hash-chained, append-only audit log in JSON Lines format (Person 2).

Each entry stores the SHA-256 of the previous entry, so editing or removing an
entry in the middle breaks the chain (contract section 7.6).

Known limitation (documented in the threat model): someone who can replace the
whole file can recompute a valid chain, and truncating the tail is not
detectable without a separately stored checkpoint.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .baseline_signer import SecurityError

GENESIS_HASH = "0" * 64
_ENTRY_FIELDS = {
    "sequence", "timestamp", "event_type", "scan_id",
    "previous_hash", "payload", "entry_hash",
}
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_LOCK = threading.Lock()


class AuditLogError(SecurityError):
    """The audit log cannot be appended to safely (corrupt tail, bad input)."""

    code = "AUDIT_CHAIN_INVALID"


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _entry_hash(entry: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON of every field except entry_hash."""
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_tail(log_path: Path) -> tuple[int, str]:
    """Return (last_sequence, last_entry_hash); (0, GENESIS_HASH) when empty."""
    if not log_path.exists():
        return 0, GENESIS_HASH
    lines = log_path.read_bytes().decode("utf-8", errors="replace").splitlines()
    lines = [ln for ln in lines if ln.strip()]
    if not lines:
        return 0, GENESIS_HASH
    try:
        last = json.loads(lines[-1])
        ok = (
            isinstance(last, dict)
            and set(last) == _ENTRY_FIELDS
            and isinstance(last["sequence"], int)
            and isinstance(last["entry_hash"], str)
            and hmac.compare_digest(_entry_hash(last), last["entry_hash"])
        )
    except (ValueError, TypeError):
        ok = False
    if not ok:
        raise AuditLogError("audit log tail is corrupt; run verify_audit_chain")
    return last["sequence"], last["entry_hash"]


def append_audit_event(
    log_path: Path,
    event_type: str,
    scan_id: str | None,
    payload: dict[str, object],
) -> dict[str, object]:
    """Append one chained event and return it.

    Args:
        log_path: the .jsonl file (parent folders are created).
        event_type: e.g. INIT, VERIFY_COMPLETED, ACCEPT, BASELINE_REJECTED.
        scan_id: related scan UUID or None.
        payload: small JSON-serialisable dict. Never put keys or secrets in it.

    Raises:
        AuditLogError: bad input, or the existing log tail is corrupt.
    """
    if not isinstance(event_type, str) or not event_type:
        raise AuditLogError("event_type must be a non-empty string")
    if not isinstance(payload, dict):
        raise AuditLogError("payload must be a dict")
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with _LOCK:
        last_sequence, previous_hash = _read_tail(log_path)
        entry: dict[str, Any] = {
            "sequence": last_sequence + 1,
            "timestamp": _utc_now(),
            "event_type": event_type,
            "scan_id": scan_id,
            "previous_hash": previous_hash,
            "payload": payload,
        }
        try:
            entry["entry_hash"] = _entry_hash(entry)
            line = json.dumps(
                entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
        except (TypeError, ValueError) as exc:
            raise AuditLogError("payload is not JSON serialisable") from exc
        with open(log_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    return entry


def verify_audit_chain(
    log_path: Path,
) -> dict[str, object]:
    """Check sequence continuity, previous-hash links and every entry hash.

    Never raises for a bad log; returns
    ``{"valid", "entries_checked", "error", "last_sequence", "last_entry_hash"}``.
    ``entries_checked`` counts entries verified before the first failure.
    A missing or empty log is reported valid with 0 entries.
    """
    log_path = Path(log_path)
    result: dict[str, object] = {
        "valid": True,
        "entries_checked": 0,
        "error": None,
        "last_sequence": 0,
        "last_entry_hash": GENESIS_HASH,
    }
    if not log_path.exists():
        return result

    def fail(message: str) -> dict[str, object]:
        result["valid"] = False
        result["error"] = message
        return result

    try:
        text = log_path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return fail("log is not valid UTF-8")

    expected_sequence = 1
    previous_hash = GENESIS_HASH
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            return fail(f"line {line_number}: blank line inside the log")
        try:
            entry = json.loads(line)
        except ValueError:
            return fail(f"line {line_number}: not valid JSON")
        if not isinstance(entry, dict) or set(entry) != _ENTRY_FIELDS:
            return fail(f"line {line_number}: entry fields do not match the schema")
        sequence = entry["sequence"]
        if isinstance(sequence, bool) or sequence != expected_sequence:
            return fail(f"line {line_number}: expected sequence {expected_sequence}")
        if entry["previous_hash"] != previous_hash:
            return fail(f"entry {sequence}: previous_hash does not match the chain")
        stored = entry["entry_hash"]
        try:
            computed = _entry_hash(entry)
        except (TypeError, ValueError):
            return fail(f"entry {sequence}: cannot be hashed")
        if not isinstance(stored, str) or not _HASH_RE.match(stored) or not hmac.compare_digest(
            computed, stored
        ):
            return fail(f"entry {sequence}: entry_hash does not match its content")
        previous_hash = stored
        expected_sequence += 1
        result["entries_checked"] = sequence
        result["last_sequence"] = sequence
        result["last_entry_hash"] = stored
    return result


