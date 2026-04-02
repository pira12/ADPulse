"""Tests for PolicyManager CRUD, expiry, and finding application."""
import sys, os, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import date, timedelta
from modules.policy_manager import PolicyManager


def _pm(tmp_path=None):
    """Create a PolicyManager backed by a temp file."""
    if tmp_path is None:
        tmp_path = tempfile.mktemp(suffix=".json")
    return PolicyManager(tmp_path), tmp_path


def test_set_and_get():
    pm, _ = _pm()
    pm.set_status("KERB-001", "accepted_risk", "Legacy app", "alice", "2030-01-01")
    entry = pm.get("KERB-001")
    assert entry["status"] == "accepted_risk"
    assert entry["reason"] == "Legacy app"
    assert entry["set_by"] == "alice"
    assert entry["expires"] == "2030-01-01"


def test_persists_to_disk():
    _, path = _pm()
    pm1 = PolicyManager(path)
    pm1.set_status("ACL-001", "in_remediation", "Ticket open", "bob")
    # Create a new instance from same path
    pm2 = PolicyManager(path)
    assert pm2.get("ACL-001")["status"] == "in_remediation"


def test_clear_removes_entry():
    pm, _ = _pm()
    pm.set_status("FOO-001", "resolved", "Fixed")
    pm.clear("FOO-001")
    assert pm.get("FOO-001") is None


def test_clear_missing_key_is_safe():
    pm, _ = _pm()
    pm.clear("NONEXISTENT")  # should not raise


def test_invalid_status_raises():
    pm, _ = _pm()
    try:
        pm.set_status("X-001", "invalid_state", "reason")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_expiry_removes_expired_entries():
    pm, _ = _pm()
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    pm.set_status("OLD-001", "accepted_risk", "Expired", expires=yesterday)
    pm.set_status("NEW-001", "accepted_risk", "Not expired", expires="2099-01-01")

    expired = pm.check_expiry()
    assert "OLD-001" in expired
    assert pm.get("OLD-001") is None   # removed
    assert pm.get("NEW-001") is not None  # still there


def test_resolved_reappearance_clears_entry():
    pm, _ = _pm()
    pm.set_status("KERB-001", "resolved", "Fixed last week")
    cleared = pm.handle_resolved_reappearance({"KERB-001", "OTHER-001"})
    assert "KERB-001" in cleared
    assert pm.get("KERB-001") is None


def test_apply_to_findings_splits_correctly():
    pm, _ = _pm()
    pm.set_status("KERB-001", "accepted_risk", "Known")
    pm.set_status("ACCT-001", "in_remediation", "In progress")
    pm.set_status("COMP-001", "resolved", "Fixed")

    findings = [
        {"finding_id": "KERB-001", "severity": "HIGH", "title": "Kerberoastable"},
        {"finding_id": "ACCT-001", "severity": "MEDIUM", "title": "Stale account"},
        {"finding_id": "COMP-001", "severity": "LOW", "title": "Stale computer"},
        {"finding_id": "NEW-001",  "severity": "CRITICAL", "title": "New finding"},
    ]
    active, suppressed = pm.apply_to_findings(findings)

    # accepted_risk and resolved are suppressed
    suppressed_ids = {f["finding_id"] for f in suppressed}
    assert "KERB-001" in suppressed_ids
    assert "COMP-001" in suppressed_ids

    # in_remediation stays active but gets policy_status field
    active_ids = {f["finding_id"] for f in active}
    assert "ACCT-001" in active_ids
    assert "NEW-001" in active_ids

    acct = next(f for f in active if f["finding_id"] == "ACCT-001")
    assert acct["policy_status"] == "in_remediation"
    assert acct["policy_reason"] == "In progress"

    # Unaffected finding has no policy fields
    new = next(f for f in active if f["finding_id"] == "NEW-001")
    assert "policy_status" not in new


def test_list_all_includes_all_entries():
    pm, _ = _pm()
    pm.set_status("A-001", "accepted_risk", "reason a")
    pm.set_status("B-001", "in_remediation", "reason b")
    entries = pm.list_all()
    ids = {e["finding_id"] for e in entries}
    assert "A-001" in ids
    assert "B-001" in ids
