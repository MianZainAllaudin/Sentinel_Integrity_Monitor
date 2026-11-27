import json

import pytest

from sentinel.core.models import BaselineData, FileSnapshot
from sentinel.security.baseline_signer import (
    InvalidSignatureError,
    KeyConfigurationError,
    MalformedBaselineError,
    SecurityError,
    sign_baseline,
    verify_baseline,
)

KEY = b"k" * 32
SHA_A = "a" * 64
SHA_B = "b" * 64


def make_baseline(order=("README.md", "src/main.py")) -> BaselineData:
    files = {
        "README.md": FileSnapshot("README.md", SHA_A, 10, 1730000000000000000),
        "src/main.py": FileSnapshot("src/main.py", SHA_B, 20, 1730000000000000001),
    }
    return BaselineData(
        schema_version=1,
        root_path="C:/Projects/MyApp",
        created_at="2026-11-14T12:30:00Z",
        hash_algorithm="sha256",
        files={name: files[name] for name in order},
    )


def roundtrip(envelope):
    """Simulate saving to disk and loading again."""
    return json.loads(json.dumps(envelope))


def test_sign_then_verify_returns_same_data():
    baseline = make_baseline()
    envelope = sign_baseline(baseline, KEY)
    assert envelope["signature"]["algorithm"] == "hmac-sha256"
    assert envelope["signature"]["key_id"] == "local-v1"
    assert verify_baseline(roundtrip(envelope), KEY) == baseline


def test_signature_does_not_depend_on_dict_order():
    a = sign_baseline(make_baseline(("README.md", "src/main.py")), KEY)
    b = sign_baseline(make_baseline(("src/main.py", "README.md")), KEY)
    assert a["signature"]["value"] == b["signature"]["value"]


def test_modified_hash_is_rejected():
    envelope = roundtrip(sign_baseline(make_baseline(), KEY))
    envelope["payload"]["files"]["src/main.py"]["sha256"] = "c" * 64
    with pytest.raises(InvalidSignatureError):
        verify_baseline(envelope, KEY)


def test_added_file_entry_is_rejected():
    envelope = roundtrip(sign_baseline(make_baseline(), KEY))
    envelope["payload"]["files"]["evil.exe"] = {
        "path": "evil.exe", "sha256": SHA_A, "size_bytes": 1, "mtime_ns": 1,
    }
    with pytest.raises(InvalidSignatureError):
        verify_baseline(envelope, KEY)


def test_removed_file_entry_is_rejected():
    envelope = roundtrip(sign_baseline(make_baseline(), KEY))
    del envelope["payload"]["files"]["README.md"]
    with pytest.raises(InvalidSignatureError):
        verify_baseline(envelope, KEY)


def test_wrong_key_is_rejected():
    envelope = sign_baseline(make_baseline(), KEY)
    with pytest.raises(InvalidSignatureError):
        verify_baseline(envelope, b"x" * 32)


def test_tampered_signature_is_rejected():
    envelope = roundtrip(sign_baseline(make_baseline(), KEY))
    envelope["signature"]["value"] = "0" * 64
    with pytest.raises(InvalidSignatureError):
        verify_baseline(envelope, KEY)


@pytest.mark.parametrize("bad_key", [None, b"", b"short", "string-key-not-bytes"])
def test_missing_or_weak_key_is_explicit_error(bad_key):
    with pytest.raises(KeyConfigurationError):
        sign_baseline(make_baseline(), bad_key)
    with pytest.raises(KeyConfigurationError):
        verify_baseline({"payload": {}, "signature": {}}, bad_key)


@pytest.mark.parametrize(
    "envelope",
    [
        None,
        [],
        {},
        {"payload": {}},
        {"payload": {}, "signature": {}},
        {"payload": {}, "signature": {"algorithm": "md5", "value": "x"}},
        {"payload": {}, "signature": {"algorithm": "hmac-sha256", "value": ""}},
    ],
)
def test_malformed_envelope_raises_security_error(envelope):
    with pytest.raises(SecurityError):
        verify_baseline(envelope, KEY)


def test_validly_signed_but_wrong_schema_is_rejected():
    envelope = roundtrip(sign_baseline(make_baseline(), KEY))
    # re-sign a payload with an extra field using the right key: still refused by schema check
    import hashlib, hmac
    envelope["payload"]["unexpected"] = 1
    canonical = json.dumps(envelope["payload"], sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    envelope["signature"]["value"] = hmac.new(KEY, canonical, hashlib.sha256).hexdigest()
    with pytest.raises(MalformedBaselineError):
        verify_baseline(envelope, KEY)


def test_sign_refuses_invalid_baseline():
    baseline = make_baseline()
    baseline.hash_algorithm = "md5"
    with pytest.raises(MalformedBaselineError):
        sign_baseline(baseline, KEY)


def test_error_messages_never_contain_the_key():
    secret = b"super-secret-key-material-123456"
    envelope = sign_baseline(make_baseline(), secret)
    envelope["payload"]["root_path"] = "D:/other"
    with pytest.raises(InvalidSignatureError) as info:
        verify_baseline(envelope, secret)
    assert secret.decode() not in str(info.value)