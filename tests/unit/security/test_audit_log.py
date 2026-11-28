import json

from sentinel.security.audit_log import GENESIS_HASH, append_audit_event, verify_audit_chain


def make_log(tmp_path, count=4):
    log = tmp_path / "state" / "audit.jsonl"
    for i in range(count):
        append_audit_event(log, "VERIFY_COMPLETED", f"scan-{i}", {"status": "CLEAN", "change_count": i})
    return log


def read_entries(log):
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def write_entries(log, entries):
    log.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")


def test_missing_log_is_valid_and_empty(tmp_path):
    result = verify_audit_chain(tmp_path / "none.jsonl")
    assert result["valid"] is True and result["entries_checked"] == 0 and result["error"] is None


def test_first_entry_uses_genesis_hash_and_chain_links(tmp_path):
    log = make_log(tmp_path, 3)
    entries = read_entries(log)
    assert [e["sequence"] for e in entries] == [1, 2, 3]
    assert entries[0]["previous_hash"] == GENESIS_HASH
    assert entries[1]["previous_hash"] == entries[0]["entry_hash"]
    assert entries[2]["previous_hash"] == entries[1]["entry_hash"]
    assert entries[0]["timestamp"].endswith("Z")


def test_untouched_log_verifies(tmp_path):
    result = verify_audit_chain(make_log(tmp_path, 5))
    assert result["valid"] is True
    assert result["entries_checked"] == 5
    assert result["last_sequence"] == 5
    assert result["error"] is None


def test_edited_payload_is_detected(tmp_path):
    log = make_log(tmp_path)
    entries = read_entries(log)
    entries[1]["payload"]["status"] = "CLEAN-FORGED"
    write_entries(log, entries)
    result = verify_audit_chain(log)
    assert result["valid"] is False and "entry 2" in result["error"]
    assert result["entries_checked"] == 1


def test_deleted_middle_entry_is_detected(tmp_path):
    log = make_log(tmp_path)
    entries = read_entries(log)
    del entries[1]
    write_entries(log, entries)
    assert verify_audit_chain(log)["valid"] is False


def test_reordered_entries_are_detected(tmp_path):
    log = make_log(tmp_path)
    entries = read_entries(log)
    entries[1], entries[2] = entries[2], entries[1]
    write_entries(log, entries)
    assert verify_audit_chain(log)["valid"] is False


def test_edited_entry_with_recomputed_own_hash_still_breaks_next_link(tmp_path):
    from sentinel.security.audit_log import _entry_hash
    log = make_log(tmp_path)
    entries = read_entries(log)
    entries[1]["payload"]["status"] = "FORGED"
    entries[1]["entry_hash"] = _entry_hash(entries[1])
    write_entries(log, entries)
    result = verify_audit_chain(log)
    assert result["valid"] is False and "entry 3" in result["error"]


def test_garbage_line_is_reported_not_raised(tmp_path):
    log = make_log(tmp_path, 2)
    with open(log, "a", encoding="utf-8") as fh:
        fh.write("not json\n")
    assert verify_audit_chain(log)["valid"] is False


def test_append_refuses_corrupt_tail(tmp_path):
    import pytest
    from sentinel.security.audit_log import AuditLogError
    log = make_log(tmp_path, 2)
    with open(log, "a", encoding="utf-8") as fh:
        fh.write("garbage\n")
    with pytest.raises(AuditLogError):
        append_audit_event(log, "VERIFY_COMPLETED", None, {})


def test_known_limitation_tail_truncation_is_not_detected(tmp_path):
    """Documented limitation: dropping the LAST entries leaves a valid chain."""
    log = make_log(tmp_path, 4)
    entries = read_entries(log)
    write_entries(log, entries[:2])
    result = verify_audit_chain(log)
    assert result["valid"] is True and result["entries_checked"] == 2


def test_known_limitation_full_rewrite_with_recomputed_chain_is_valid(tmp_path):
    """Documented limitation: an attacker who rewrites the whole log can re-chain it."""
    from sentinel.security.audit_log import _entry_hash
    log = make_log(tmp_path, 3)
    entries = read_entries(log)
    previous = GENESIS_HASH
    for entry in entries:
        entry["payload"] = {"status": "CLEAN", "change_count": 0}
        entry["previous_hash"] = previous
        entry["entry_hash"] = _entry_hash(entry)
        previous = entry["entry_hash"]
    write_entries(log, entries)
    assert verify_audit_chain(log)["valid"] is True


def test_audit_error_has_stable_code():
    from sentinel.security.audit_log import AuditLogError
    assert AuditLogError.code == "AUDIT_CHAIN_INVALID"