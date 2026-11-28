"""HMAC-SHA256 signing and verification of baselines (Person 2).

The signed bytes are the canonical JSON of the baseline *payload* only
(contract section 7.3). The signature lives next to the payload in an
envelope, never inside it.

Public API (contract section 8.3):
    sign_baseline(payload, key, key_id="local-v1") -> envelope dict
    verify_baseline(envelope, key) -> BaselineData  (raises SecurityError)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

from ..core.models import BaselineData, FileSnapshot

SUPPORTED_SCHEMA_VERSION = 1
HASH_ALGORITHM = "sha256"
SIGNATURE_ALGORITHM = "hmac-sha256"
MIN_KEY_BYTES = 16

_PAYLOAD_FIELDS = {"schema_version", "root_path", "created_at", "hash_algorithm", "files"}
_SNAPSHOT_FIELDS = {"path", "sha256", "size_bytes", "mtime_ns"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SecurityError(Exception):
    """Base class for every security failure. Messages never contain the key.

    ``code`` is one of the stable error codes from contract section 16.
    """

    code = "BASELINE_INVALID"


class KeyConfigurationError(SecurityError):
    """The HMAC key is missing, empty or too short."""

    code = "HMAC_KEY_MISSING"


class MalformedBaselineError(SecurityError):
    """The envelope or payload does not follow the baseline schema."""

    code = "BASELINE_INVALID"


class InvalidSignatureError(SecurityError):
    """The signature does not match: tampered baseline or wrong key."""

    code = "HMAC_VERIFICATION_FAILED"


def _check_key(key: object) -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
        raise KeyConfigurationError(
            f"HMAC key is missing or shorter than {MIN_KEY_BYTES} bytes"
        )
    return bytes(key)


def baseline_to_payload(baseline: BaselineData) -> dict[str, Any]:
    """Convert BaselineData to the plain-dict payload that gets signed."""
    return {
        "schema_version": baseline.schema_version,
        "root_path": baseline.root_path,
        "created_at": baseline.created_at,
        "hash_algorithm": baseline.hash_algorithm,
        "files": {
            name: {
                "path": snap.path,
                "sha256": snap.sha256,
                "size_bytes": snap.size_bytes,
                "mtime_ns": snap.mtime_ns,
            }
            for name, snap in baseline.files.items()
        },
    }


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:  # includes UnicodeEncodeError
        raise MalformedBaselineError("payload cannot be serialised canonically") from exc


def _signature_hex(payload: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical_bytes(payload), hashlib.sha256).hexdigest()


def _is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_payload(payload: dict[str, Any]) -> BaselineData:
    """Strictly validate a payload dict and build BaselineData from it."""
    if set(payload) != _PAYLOAD_FIELDS:
        raise MalformedBaselineError("payload fields do not match schema version 1")
    if payload["schema_version"] != SUPPORTED_SCHEMA_VERSION or not _is_plain_int(
        payload["schema_version"]
    ):
        raise MalformedBaselineError("unsupported baseline schema_version")
    if payload["hash_algorithm"] != HASH_ALGORITHM:
        raise MalformedBaselineError("unsupported hash_algorithm")
    if not isinstance(payload["root_path"], str) or not payload["root_path"]:
        raise MalformedBaselineError("root_path must be a non-empty string")
    if not isinstance(payload["created_at"], str) or not payload["created_at"]:
        raise MalformedBaselineError("created_at must be a non-empty string")
    files = payload["files"]
    if not isinstance(files, dict):
        raise MalformedBaselineError("files must be an object")

    parsed: dict[str, FileSnapshot] = {}
    for name, entry in files.items():
        if not isinstance(entry, dict) or set(entry) != _SNAPSHOT_FIELDS:
            raise MalformedBaselineError("file entry fields do not match the schema")
        if not isinstance(entry["path"], str) or not entry["path"]:
            raise MalformedBaselineError("file entry path must be a non-empty string")
        if not isinstance(entry["sha256"], str) or not _SHA256_RE.match(entry["sha256"]):
            raise MalformedBaselineError("file entry sha256 must be 64 lowercase hex chars")
        if not _is_plain_int(entry["size_bytes"]) or entry["size_bytes"] < 0:
            raise MalformedBaselineError("file entry size_bytes must be a non-negative int")
        if not _is_plain_int(entry["mtime_ns"]):
            raise MalformedBaselineError("file entry mtime_ns must be an int")
        parsed[name] = FileSnapshot(
            path=entry["path"],
            sha256=entry["sha256"],
            size_bytes=entry["size_bytes"],
            mtime_ns=entry["mtime_ns"],
        )
    return BaselineData(
        schema_version=payload["schema_version"],
        root_path=payload["root_path"],
        created_at=payload["created_at"],
        hash_algorithm=payload["hash_algorithm"],
        files=parsed,
    )


def sign_baseline(
    payload: BaselineData,
    key: bytes,
    key_id: str = "local-v1",
) -> dict[str, object]:
    """Sign a baseline and return the envelope ``{"payload", "signature"}``.

    Args:
        payload: baseline to authenticate.
        key: secret HMAC key (>= 16 bytes). Never stored or logged here.
        key_id: label stored in the envelope, for future key rotation.

    Raises:
        KeyConfigurationError: key missing or too short.
        MalformedBaselineError: baseline does not follow the schema.
    """
    secret = _check_key(key)
    payload_dict = baseline_to_payload(payload)
    _parse_payload(payload_dict)  # never sign something that fails our own schema
    return {
        "payload": payload_dict,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "value": _signature_hex(payload_dict, secret),
        },
    }


def verify_baseline(
    envelope: dict[str, object],
    key: bytes,
) -> BaselineData:
    """Authenticate an envelope and return the trusted BaselineData.

    Raises:
        KeyConfigurationError: key missing or too short.
        MalformedBaselineError: envelope or payload malformed.
        InvalidSignatureError: signature mismatch (tampering or wrong key).
    Unverified data is never returned.
    """
    secret = _check_key(key)
    if not isinstance(envelope, dict):
        raise MalformedBaselineError("baseline envelope must be a JSON object")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise MalformedBaselineError("envelope needs 'payload' and 'signature' objects")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        raise MalformedBaselineError("unsupported signature algorithm")
    supplied = signature.get("value")
    if not isinstance(supplied, str) or not supplied:
        raise MalformedBaselineError("signature value missing")

    expected = _signature_hex(payload, secret)
    if not hmac.compare_digest(expected.encode("ascii"), supplied.encode("utf-8")):
        raise InvalidSignatureError(
            "baseline signature mismatch: baseline was modified or signed with a different key"
        )
    return _parse_payload(payload)
